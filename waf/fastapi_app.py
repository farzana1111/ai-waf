"""FastAPI-based AI-WAF application.

The app exposes two surfaces:

1. **WAF Proxy** (``/``) — every request received here is inspected by the WAF
   engine and, if clean, forwarded to the configured upstream service.

2. **Management API** (``/waf/``) — lightweight endpoints for health checks,
   statistics, and manual evaluation.
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from waf.waf_config import WAFConfig
from waf.engine import WAFDecision, WAFEngine


# ── Request / Response schemas (module-level so FastAPI can resolve them) ────

class EvaluateRequest(BaseModel):
    method: str = Field(default="GET", description="HTTP method")
    path: str = Field(default="/", description="Request path")
    query_string: str = Field(default="", description="Raw query string (no leading ?)")
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = Field(default="", description="Request body as a string")
    client_ip: str = Field(default="127.0.0.1", description="Client IP address")


class EvaluateResponse(BaseModel):
    request_id: str
    allow: bool
    action: str
    threat_detected: bool
    rule_matches: list[dict[str, Any]]
    rule_score: float
    ml_label: str | None
    ml_confidence: float | None
    combined_score: float
    latency_ms: float

# ── Application factory ──────────────────────────────────────────────────────

_STARTUP_TIME = time.time()
_request_count = 0
_threat_count = 0
_blocked_count = 0


def create_app(config: WAFConfig | None = None) -> FastAPI:
    """Construct and return the WAF FastAPI application.

    Parameters
    ----------
    config:
        Optional pre-built :class:`~waf.config.WAFConfig`.  If omitted, one is
        created from environment variables / defaults.
    """
    cfg = config or WAFConfig()
    engine = WAFEngine(config=cfg)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        engine.warm_up()
        yield

    app = FastAPI(
        title="AI-WAF",
        description="AI-Powered Web Application Firewall with ML-based threat detection",
        version="0.1.0",
        lifespan=lifespan,
    )

    # ── Management API ────────────────────────────────────────────────────────

    @app.get("/waf/health", tags=["management"])
    async def health() -> dict[str, Any]:
        """Health check endpoint."""
        return {
            "status": "ok",
            "uptime_seconds": round(time.time() - _STARTUP_TIME, 1),
            "mode": cfg.mode,
            "ml_enabled": cfg.enable_ml,
            "rules_enabled": cfg.enable_rules,
        }

    @app.get("/waf/stats", tags=["management"])
    async def stats() -> dict[str, Any]:
        """Request / threat statistics since startup."""
        return {
            "total_requests": _request_count,
            "threats_detected": _threat_count,
            "requests_blocked": _blocked_count,
            "uptime_seconds": round(time.time() - _STARTUP_TIME, 1),
        }

    @app.post("/waf/evaluate", response_model=EvaluateResponse, tags=["management"])
    async def evaluate(req: EvaluateRequest) -> EvaluateResponse:
        """Manually evaluate an HTTP request payload through the WAF engine.

        This endpoint is useful for testing / integration — it does *not* proxy
        the request to upstream.
        """
        decision: WAFDecision = engine.evaluate(
            client_ip=req.client_ip,
            method=req.method,
            path=req.path,
            query_string=req.query_string,
            headers=req.headers,
            body=req.body,
        )
        return EvaluateResponse(
            request_id=decision.request_id,
            allow=decision.allow,
            action=decision.action,
            threat_detected=decision.threat_detected,
            rule_matches=[
                {
                    "rule_id": m.rule.rule_id,
                    "category": m.rule.category,
                    "severity": m.rule.severity,
                    "description": m.rule.description,
                    "matched_value": m.matched_value,
                }
                for m in decision.rule_matches
            ],
            rule_score=decision.rule_score,
            ml_label=decision.ml_result.label if decision.ml_result else None,
            ml_confidence=decision.ml_result.confidence if decision.ml_result else None,
            combined_score=decision.combined_score,
            latency_ms=decision.latency_ms,
        )

    # ── Transparent proxy ─────────────────────────────────────────────────────

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
        tags=["proxy"],
        include_in_schema=False,
    )
    async def proxy(request: Request, path: str) -> Response:
        """WAF proxy — inspect then forward to upstream."""
        global _request_count, _threat_count, _blocked_count  # noqa: PLW0603

        _request_count += 1
        client_ip = (request.client.host if request.client else "unknown")

        # Read body (limit to 1 MB to avoid memory exhaustion)
        body_bytes = await request.body()
        body_str = body_bytes[:1_048_576].decode("utf-8", errors="replace")

        headers_dict: dict[str, str] = dict(request.headers)

        decision: WAFDecision = engine.evaluate(
            client_ip=client_ip,
            method=request.method,
            path="/" + path,
            query_string=str(request.url.query),
            headers=headers_dict,
            body=body_str,
        )

        if decision.threat_detected:
            _threat_count += 1

        if not decision.allow:
            _blocked_count += 1
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Forbidden",
                    "message": "Request blocked by AI-WAF",
                    "request_id": decision.request_id,
                },
                headers={"X-WAF-Request-ID": decision.request_id},
            )

        # Forward to upstream
        upstream = cfg.upstream_url.rstrip("/")
        url = f"{upstream}/{path}"
        if request.url.query:
            url = f"{url}?{request.url.query}"

        fwd_headers = {
            k: v
            for k, v in headers_dict.items()
            if k.lower() not in {"host", "content-length", "transfer-encoding"}
        }
        fwd_headers["X-WAF-Request-ID"] = decision.request_id
        fwd_headers["X-Forwarded-For"] = client_ip

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                upstream_resp = await client.request(
                    method=request.method,
                    url=url,
                    headers=fwd_headers,
                    content=body_bytes,
                )
        except httpx.ConnectError:
            return JSONResponse(
                status_code=502,
                content={"error": "Bad Gateway", "message": "Upstream service unreachable"},
            )
        except httpx.TimeoutException:
            return JSONResponse(
                status_code=504,
                content={"error": "Gateway Timeout", "message": "Upstream timed out"},
            )

        resp_headers = dict(upstream_resp.headers)
        # Strip hop-by-hop headers
        for h in ("transfer-encoding", "connection", "keep-alive", "upgrade"):
            resp_headers.pop(h, None)
        resp_headers["X-WAF-Request-ID"] = decision.request_id

        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=resp_headers,
            media_type=upstream_resp.headers.get("content-type"),
        )

    return app
