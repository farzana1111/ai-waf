"""Reverse-proxy Flask application for the AI-WAF.

Intercepts every incoming HTTP request, runs it through the detection
pipeline, and either blocks the request or forwards it to the
configured backend server.
"""

import logging
import urllib.parse

import requests as http_requests
from flask import Flask, Response, jsonify, request

from waf.config.settings import Settings
from waf.core.request_parser import ParsedRequest, parse_flask_request
from waf.core.response_handler import (
    DetectionResult,
    create_block_response,
    create_rate_limit_response,
    make_decision,
)

logger = logging.getLogger(__name__)

# Headers that must not be forwarded to the backend verbatim because
# they are managed by the proxy layer itself.
_HOP_BY_HOP_HEADERS = frozenset({
    "host",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
})


def create_app(config=None) -> Flask:
    """Application factory for the WAF reverse-proxy.

    Args:
        config: Optional :class:`~waf.config.settings.Settings` instance
            or a plain dict.  When *None*, a default ``Settings`` object
            is created.

    Returns:
        A configured :class:`~flask.Flask` application.
    """
    app = Flask(__name__)

    if isinstance(config, dict):
        settings = Settings()
        app.config.update(config)
    elif isinstance(config, Settings):
        settings = config
    else:
        settings = Settings()

    app.config["WAF_SETTINGS"] = settings
    app.config["SECRET_KEY"] = settings.secret_key

    # ------------------------------------------------------------------
    # Health-check endpoint
    # ------------------------------------------------------------------

    @app.route("/health")
    def health():
        return jsonify({"status": "healthy"})

    # ------------------------------------------------------------------
    # Main request interception
    # ------------------------------------------------------------------

    @app.before_request
    def waf_intercept():
        # Let the health-check and management API endpoints bypass
        # the WAF pipeline.
        if request.path == "/health" or request.path.startswith("/api/"):
            return None

        parsed = parse_flask_request(request)

        logger.info(
            "request received",
            extra={
                "request_id": parsed.request_id,
                "method": parsed.method,
                "path": parsed.path,
                "client_ip": parsed.client_ip,
            },
        )

        # --- Detection pipeline (placeholder) ------------------------
        # When ML models and rule engines are wired in, they will
        # populate this list.  For now the WAF operates in pass-through
        # mode so that the proxy is functional before models are loaded.
        detection_results: list[DetectionResult] = []

        action, result = make_decision(detection_results)

        if action == "block" and result is not None:
            logger.warning(
                "request blocked",
                extra={
                    "request_id": parsed.request_id,
                    "threat_type": result.threat_type,
                    "confidence": result.confidence,
                },
            )
            return create_block_response(result, parsed.request_id)

        if action == "rate_limit":
            logger.warning(
                "request rate-limited",
                extra={"request_id": parsed.request_id},
            )
            return create_rate_limit_response(parsed.request_id)

        # --- Forward to backend --------------------------------------
        backend_url = settings.backend_url
        return forward_request(parsed, backend_url)

    return app


def forward_request(parsed_request: ParsedRequest, backend_url: str) -> Response:
    """Forward the parsed request to the backend server.

    Constructs the target URL, copies safe headers, and streams the
    response back to the original client.
    """
    target_url = f"{backend_url.rstrip('/')}{parsed_request.path}"
    if parsed_request.query_params:
        qs = urllib.parse.urlencode(parsed_request.query_params)
        target_url = f"{target_url}?{qs}"

    forward_headers = {
        key: value
        for key, value in parsed_request.headers.items()
        if key.lower() not in _HOP_BY_HOP_HEADERS
    }
    forward_headers["X-Forwarded-For"] = parsed_request.client_ip
    forward_headers["X-Request-ID"] = parsed_request.request_id

    try:
        backend_resp = http_requests.request(
            method=parsed_request.method,
            url=target_url,
            headers=forward_headers,
            data=parsed_request.body.encode("utf-8") if parsed_request.body else None,
            cookies=parsed_request.cookies,
            allow_redirects=False,
            timeout=30,
        )
    except http_requests.RequestException as exc:
        logger.error("backend request failed", extra={"error": str(exc)})
        return Response("Bad Gateway", status=502)

    # Build the response to send back to the client, filtering out
    # hop-by-hop headers from the backend response.
    excluded = _HOP_BY_HOP_HEADERS | {"content-encoding", "content-length"}
    response_headers = [
        (k, v)
        for k, v in backend_resp.headers.items()
        if k.lower() not in excluded
    ]

    return Response(
        response=backend_resp.content,
        status=backend_resp.status_code,
        headers=response_headers,
    )
