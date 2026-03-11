"""Prometheus-compatible WAF metrics.

Tries to use the ``prometheus_client`` library when available and
falls back to simple in-memory counters so that metrics collection
works without any extra dependencies.
"""

import logging
import threading
import time

logger = logging.getLogger(__name__)

try:
    from prometheus_client import Counter, Histogram, Info  # type: ignore[import-untyped]

    _HAS_PROMETHEUS = True
except ImportError:
    _HAS_PROMETHEUS = False


class WAFMetrics:
    """Collect WAF operational metrics.

    When ``prometheus_client`` is installed, native Prometheus counter
    and histogram objects are used.  Otherwise an equivalent dict-based
    fallback keeps metrics in memory (useful for the ``/metrics`` JSON
    API endpoint).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()

        if _HAS_PROMETHEUS:
            self._request_counter = Counter(
                "waf_requests_total",
                "Total HTTP requests processed",
                ["method", "path", "status_code"],
            )
            self._detection_counter = Counter(
                "waf_detections_total",
                "Total threat detections",
                ["threat_type", "action"],
            )
            self._latency_histogram = Histogram(
                "waf_request_latency_seconds",
                "Request processing latency in seconds",
            )
        else:
            self._requests: dict[str, int] = {}
            self._detections: dict[str, int] = {}
            self._latencies: list[float] = []
            self._total_requests = 0
            self._total_detections = 0

    def record_request(self, method: str, path: str, status_code: int) -> None:
        """Record an incoming request."""
        if _HAS_PROMETHEUS:
            self._request_counter.labels(
                method=method, path=path, status_code=str(status_code)
            ).inc()
        else:
            with self._lock:
                key = f"{method}:{path}:{status_code}"
                self._requests[key] = self._requests.get(key, 0) + 1
                self._total_requests += 1

    def record_detection(self, threat_type: str, action: str) -> None:
        """Record a threat detection event."""
        if _HAS_PROMETHEUS:
            self._detection_counter.labels(
                threat_type=threat_type, action=action
            ).inc()
        else:
            with self._lock:
                key = f"{threat_type}:{action}"
                self._detections[key] = self._detections.get(key, 0) + 1
                self._total_detections += 1

    def record_latency(self, duration: float) -> None:
        """Record request processing latency in seconds."""
        if _HAS_PROMETHEUS:
            self._latency_histogram.observe(duration)
        else:
            with self._lock:
                self._latencies.append(duration)

    def get_metrics(self) -> dict:
        """Return a snapshot of all collected metrics as a plain dict.

        When using ``prometheus_client`` the values are read from the
        native collectors.  With the fallback implementation the
        in-memory counters are returned directly.
        """
        if _HAS_PROMETHEUS:
            requests_total = 0.0
            detections_total = 0.0
            for metric in self._request_counter.collect():
                for sample in metric.samples:
                    if sample.name.endswith("_total"):
                        requests_total += sample.value
            for metric in self._detection_counter.collect():
                for sample in metric.samples:
                    if sample.name.endswith("_total"):
                        detections_total += sample.value

            return {
                "requests_total": int(requests_total),
                "detections_total": int(detections_total),
                "backend": "prometheus_client",
            }

        with self._lock:
            avg_latency = (
                sum(self._latencies) / len(self._latencies)
                if self._latencies
                else 0.0
            )
            return {
                "requests_total": self._total_requests,
                "detections_total": self._total_detections,
                "requests_by_key": dict(self._requests),
                "detections_by_key": dict(self._detections),
                "average_latency_seconds": round(avg_latency, 6),
                "latency_samples": len(self._latencies),
                "backend": "in_memory",
            }
