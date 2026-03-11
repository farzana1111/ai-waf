"""Thread-safe, per-IP rate limiter with burst support."""

import threading
import time

from waf.core.response_handler import DetectionResult


class RateLimiter:
    """Track request rates per client IP and flag excessive traffic."""

    def __init__(self, requests_per_minute: int = 100, burst_size: int = 20):
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        self._lock = threading.Lock()
        # Mapping of client_ip -> list of request timestamps
        self._requests: dict[str, list[float]] = {}

    def check(self, client_ip: str) -> DetectionResult:
        """Check whether *client_ip* exceeds the rate limit."""
        now = time.time()
        window_start = now - 60.0

        with self._lock:
            self._cleanup(window_start)

            timestamps = self._requests.setdefault(client_ip, [])
            timestamps.append(now)

            # Count requests in the last minute
            recent = [ts for ts in timestamps if ts > window_start]
            self._requests[client_ip] = recent
            request_count = len(recent)

        # Check burst: more than burst_size requests in last 2 seconds
        burst_window = now - 2.0
        burst_count = sum(1 for ts in recent if ts > burst_window)

        if burst_count > self.burst_size:
            confidence = min(burst_count / self.burst_size, 1.0)
            return DetectionResult(
                is_threat=True,
                threat_type="rate_limit",
                confidence=round(confidence, 4),
                details={
                    "reason": "burst",
                    "burst_count": burst_count,
                    "burst_limit": self.burst_size,
                },
                source="rule",
            )

        if request_count > self.requests_per_minute:
            confidence = min(request_count / self.requests_per_minute, 1.0)
            return DetectionResult(
                is_threat=True,
                threat_type="rate_limit",
                confidence=round(confidence, 4),
                details={
                    "reason": "sustained",
                    "request_count": request_count,
                    "limit": self.requests_per_minute,
                },
                source="rule",
            )

        return DetectionResult(is_threat=False)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _cleanup(self, window_start: float) -> None:
        """Remove entries with no timestamps within the active window.

        Must be called while ``self._lock`` is held.
        """
        stale_ips = [
            ip for ip, timestamps in self._requests.items()
            if not any(ts > window_start for ts in timestamps)
        ]
        for ip in stale_ips:
            del self._requests[ip]
