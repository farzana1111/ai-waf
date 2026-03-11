"""WAF response decision engine.

Evaluates detection results and produces the appropriate HTTP response
(block, rate-limit, or pass-through).
"""

from dataclasses import dataclass, field

from flask import jsonify


@dataclass
class DetectionResult:
    """Outcome of a single detection check (ML model or rule engine)."""

    is_threat: bool = False
    threat_type: str = ""
    confidence: float = 0.0
    details: dict = field(default_factory=dict)
    source: str = "rule"  # "ml" or "rule"


def create_block_response(detection_result: DetectionResult, request_id: str):
    """Return a Flask JSON response that blocks the request (HTTP 403).

    The response body includes the threat type, confidence score, and
    request identifier so that operators can correlate logs with blocked
    requests.
    """
    response = jsonify({
        "error": "Request blocked by WAF",
        "threat_type": detection_result.threat_type,
        "confidence": detection_result.confidence,
        "request_id": request_id,
    })
    response.status_code = 403
    return response


def create_rate_limit_response(request_id: str):
    """Return a Flask JSON response for rate-limited requests (HTTP 429).

    Includes a ``Retry-After`` header to inform the client when it may
    retry.
    """
    response = jsonify({
        "error": "Rate limit exceeded",
        "request_id": request_id,
    })
    response.status_code = 429
    response.headers["Retry-After"] = "60"
    return response


def create_pass_response():
    """Signal that the request should be forwarded to the backend.

    Returns ``None`` to indicate no WAF intervention is needed.
    """
    return None


def make_decision(detection_results: list[DetectionResult]):
    """Evaluate a list of detection results and return the most severe action.

    Returns a tuple of ``(action, result)`` where *action* is one of
    ``"block"``, ``"rate_limit"``, or ``"pass"`` and *result* is the
    :class:`DetectionResult` that drove the decision (``None`` for pass).

    Priority order:
      1. Any threat with confidence ≥ 0.7 → ``"block"``
      2. A ``rate_limit`` threat type → ``"rate_limit"``
      3. Otherwise → ``"pass"``
    """
    if not detection_results:
        return "pass", None

    threats = [r for r in detection_results if r.is_threat]
    if not threats:
        return "pass", None

    # Pick the highest-confidence threat
    worst = max(threats, key=lambda r: r.confidence)

    if worst.confidence >= 0.7:
        return "block", worst

    if any(r.threat_type == "rate_limit" for r in threats):
        rate_result = next(r for r in threats if r.threat_type == "rate_limit")
        return "rate_limit", rate_result

    return "pass", None
