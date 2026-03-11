"""Core WAF engine — orchestrates rule-based and ML detection.

:class:`WAFEngine` is the single integration point for request evaluation.
It applies the rule engine first (fast, deterministic) and optionally the ML
detector (probabilistic).  The final decision honours the configured
:attr:`~waf.config.WAFConfig.mode`.
"""

from __future__ import annotations

import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from waf.config import WAFConfig
from waf.detector import DetectionResult, ThreatDetector
from waf.features import RequestFeatures, extract_features
from waf.logger import get_logger, log_threat, setup_logging
from waf.rules import RuleMatch, run_rules, score_from_matches


@dataclass
class WAFDecision:
    """Result of evaluating a single HTTP request through the WAF engine."""

    request_id: str
    allow: bool                        # True → pass; False → block
    action: str                        # "allow" | "block" | "monitor"
    threat_detected: bool
    rule_matches: list[RuleMatch]
    rule_score: float
    ml_result: DetectionResult | None
    combined_score: float
    client_ip: str
    method: str
    path: str
    latency_ms: float
    extra: dict[str, Any] = field(default_factory=dict)


class _RateLimiter:
    """Simple sliding-window per-IP rate limiter."""

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self._max = max_requests
        self._window = window_seconds
        self._buckets: dict[str, deque[float]] = {}

    def is_allowed(self, ip: str) -> bool:
        now = time.monotonic()
        window_start = now - self._window
        if ip not in self._buckets:
            self._buckets[ip] = deque()
        bucket = self._buckets[ip]
        # Evict old timestamps
        while bucket and bucket[0] < window_start:
            bucket.popleft()
        if len(bucket) >= self._max:
            return False
        bucket.append(now)
        return True


class WAFEngine:
    """The WAF engine.

    Parameters
    ----------
    config:
        :class:`~waf.config.WAFConfig` instance.  Defaults to loading from
        environment variables.
    """

    def __init__(self, config: WAFConfig | None = None) -> None:
        self.config = config or WAFConfig()
        self._logger = setup_logging(self.config)
        self._detector = ThreatDetector(
            model_path=self.config.model_path,
            confidence_threshold=self.config.ml_confidence_threshold,
        )
        self._rate_limiter: _RateLimiter | None = None
        if self.config.rate_limit_enabled:
            self._rate_limiter = _RateLimiter(
                max_requests=self.config.rate_limit_requests,
                window_seconds=self.config.rate_limit_window_seconds,
            )

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def warm_up(self) -> None:
        """Pre-load the ML model to avoid cold-start latency on first request."""
        if self.config.enable_ml:
            self._detector.load()

    # ── Main evaluation ───────────────────────────────────────────────────────

    def evaluate(
        self,
        *,
        client_ip: str,
        method: str,
        path: str,
        query_string: str = "",
        headers: dict[str, str] | None = None,
        body: str = "",
    ) -> WAFDecision:
        """Evaluate an HTTP request and return a :class:`WAFDecision`.

        This is the primary public API of the WAF engine.
        """
        t0 = time.perf_counter()
        request_id = str(uuid.uuid4())
        headers = headers or {}

        # ── 1. Rate limiting ─────────────────────────────────────────────────
        if self._rate_limiter and not self._rate_limiter.is_allowed(client_ip):
            return self._make_decision(
                request_id=request_id,
                client_ip=client_ip,
                method=method,
                path=path,
                rule_matches=[],
                rule_score=1.0,
                ml_result=None,
                threat_detected=True,
                threat_type="rate_limit_exceeded",
                t0=t0,
            )

        # ── 2. Feature extraction ────────────────────────────────────────────
        features: RequestFeatures = extract_features(
            method=method,
            path=path,
            query_string=query_string,
            headers=headers,
            body=body,
        )

        # ── 3. Rule-based detection ──────────────────────────────────────────
        rule_matches: list[RuleMatch] = []
        rule_score = 0.0
        if self.config.enable_rules:
            user_agent = {k.lower(): v for k, v in headers.items()}.get("user-agent", "")
            rule_matches = run_rules(
                combined_text=features.combined_text,
                path=path,
                user_agent=user_agent,
            )
            rule_score = score_from_matches(rule_matches)

        # ── 4. ML detection ──────────────────────────────────────────────────
        ml_result: DetectionResult | None = None
        if self.config.enable_ml:
            try:
                ml_result = self._detector.predict(features)
            except Exception as exc:  # noqa: BLE001
                self._logger.warning("ML detection failed: %s", exc)

        # ── 5. Combined decision ─────────────────────────────────────────────
        ml_score = 0.0
        ml_threat = False
        if ml_result:
            ml_score = ml_result.confidence if ml_result.is_threat else 0.0
            ml_threat = ml_result.is_threat

        # Weight: rules 60 %, ML 40 % (or 100 % rules if ML disabled)
        if self.config.enable_ml and ml_result is not None:
            combined_score = 0.6 * rule_score + 0.4 * ml_score
        else:
            combined_score = rule_score

        threat_detected = bool(rule_matches) or ml_threat

        # Determine threat type for logging
        if rule_matches:
            threat_type = rule_matches[0].rule.category
        elif ml_result and ml_result.is_threat:
            threat_type = ml_result.label
        else:
            threat_type = "none"

        return self._make_decision(
            request_id=request_id,
            client_ip=client_ip,
            method=method,
            path=path,
            rule_matches=rule_matches,
            rule_score=rule_score,
            ml_result=ml_result,
            threat_detected=threat_detected,
            threat_type=threat_type,
            combined_score=combined_score,
            t0=t0,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _make_decision(
        self,
        *,
        request_id: str,
        client_ip: str,
        method: str,
        path: str,
        rule_matches: list[RuleMatch],
        rule_score: float,
        ml_result: DetectionResult | None,
        threat_detected: bool,
        threat_type: str,
        combined_score: float = 1.0,
        t0: float,
    ) -> WAFDecision:
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        if not threat_detected:
            return WAFDecision(
                request_id=request_id,
                allow=True,
                action="allow",
                threat_detected=False,
                rule_matches=rule_matches,
                rule_score=rule_score,
                ml_result=ml_result,
                combined_score=combined_score,
                client_ip=client_ip,
                method=method,
                path=path,
                latency_ms=latency_ms,
            )

        # Threat detected
        if self.config.mode == "block":
            action = "block"
            allow = False
        else:
            action = "monitor"
            allow = True

        log_threat(
            get_logger(),
            request_id=request_id,
            client_ip=client_ip,
            method=method,
            path=path,
            threat_type=threat_type,
            source="rules" if rule_matches else "ml",
            score=combined_score,
            action=action,
            details={
                "rule_ids": [m.rule.rule_id for m in rule_matches],
                "ml_label": ml_result.label if ml_result else None,
                "ml_confidence": ml_result.confidence if ml_result else None,
            },
        )

        return WAFDecision(
            request_id=request_id,
            allow=allow,
            action=action,
            threat_detected=True,
            rule_matches=rule_matches,
            rule_score=rule_score,
            ml_result=ml_result,
            combined_score=combined_score,
            client_ip=client_ip,
            method=method,
            path=path,
            latency_ms=latency_ms,
        )
