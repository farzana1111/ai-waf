"""Real-time alert management for detected threats.

Provides a thread-safe :class:`AlertManager` that logs alerts locally
and optionally forwards them to an external webhook.

When *webhook_url* is set, the ``requests`` library is required for
HTTP delivery.
"""

import json
import logging
import threading
import time
import uuid

logger = logging.getLogger(__name__)

try:
    import requests as _requests_lib
except ImportError:
    _requests_lib = None  # type: ignore[assignment]


class AlertManager:
    """Create and dispatch WAF alerts in a thread-safe manner.

    When a *webhook_url* is configured, alerts are POSTed there;
    otherwise they are emitted via the standard Python logger.
    """

    def __init__(self, webhook_url: str | None = None) -> None:
        self._webhook_url = webhook_url
        self._lock = threading.Lock()

    def create_alert(self, detection_result, parsed_request) -> dict:
        """Build a structured alert dict from detection and request data.

        Args:
            detection_result: A :class:`~waf.core.response_handler.DetectionResult`.
            parsed_request: A :class:`~waf.core.request_parser.ParsedRequest`.

        Returns:
            A dictionary describing the alert.
        """
        return {
            "alert_id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "threat_type": detection_result.threat_type,
            "confidence": detection_result.confidence,
            "source": detection_result.source,
            "details": detection_result.details,
            "request": {
                "method": parsed_request.method,
                "path": parsed_request.path,
                "client_ip": parsed_request.client_ip,
                "request_id": parsed_request.request_id,
            },
        }

    def send_alert(self, alert_type: str, details: dict) -> None:
        """Dispatch an alert of *alert_type* with *details*.

        If a webhook URL is configured the alert is POSTed there;
        otherwise it is logged at WARNING level.  All operations are
        serialised with a lock so that callers from multiple threads
        do not interleave.
        """
        with self._lock:
            alert_payload = {
                "alert_id": str(uuid.uuid4()),
                "alert_type": alert_type,
                "timestamp": time.time(),
                **details,
            }

            if self._webhook_url:
                self._post_webhook(alert_payload)
            else:
                logger.warning(
                    "WAF Alert [%s]: %s",
                    alert_type,
                    json.dumps(alert_payload, default=str),
                )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _post_webhook(self, payload: dict) -> None:
        """POST *payload* to the configured webhook URL."""
        if _requests_lib is None:
            logger.error(
                "Cannot send webhook alert: 'requests' package is not installed"
            )
            return

        try:
            response = _requests_lib.post(
                self._webhook_url,  # type: ignore[arg-type]
                json=payload,
                timeout=5,
            )
            if response.ok:
                logger.info("Alert sent to webhook (status %d)", response.status_code)
            else:
                logger.error(
                    "Webhook returned %d: %s",
                    response.status_code,
                    response.text[:200],
                )
        except Exception:
            logger.error("Failed to send alert to webhook", exc_info=True)
