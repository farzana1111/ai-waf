"""Statistical / ML-based anomaly detection for HTTP requests."""

import logging

from waf.core.response_handler import DetectionResult

logger = logging.getLogger(__name__)

# Thresholds for statistical anomaly checks
_MAX_PAYLOAD_LENGTH = 10_000
_MAX_ENTROPY = 5.5
_MAX_SPECIAL_CHAR_COUNT = 50
_MAX_PARAM_COUNT = 30
_MAX_URL_DEPTH = 15
_MAX_PARAM_LENGTH = 2_000


class AnomalyDetector:
    """Detect anomalous requests through statistical checks and an optional ML model."""

    def __init__(self, model_path: str | None = None, threshold: float = 0.8):
        self.threshold = threshold
        self.model = None
        if model_path:
            try:
                import joblib

                self.model = joblib.load(model_path)
                logger.info("Anomaly ML model loaded from %s", model_path)
            except Exception:
                logger.warning(
                    "Could not load anomaly model from %s; falling back to statistical checks",
                    model_path,
                )

    def detect(self, features: dict) -> DetectionResult:
        """Run anomaly detection on the extracted *features* and return a ``DetectionResult``."""
        # Try ML first when available
        if self.model is not None:
            try:
                is_threat, confidence = self._ml_detect(features)
                if is_threat:
                    return DetectionResult(
                        is_threat=True,
                        threat_type="anomaly",
                        confidence=confidence,
                        details={"method": "ml"},
                        source="ml",
                    )
            except Exception:
                logger.debug("ML anomaly detection failed; falling back to statistics", exc_info=True)

        # Statistical fallback / primary
        is_threat, confidence = self._statistical_detect(features)
        return DetectionResult(
            is_threat=is_threat,
            threat_type="anomaly" if is_threat else "",
            confidence=confidence,
            details={"method": "statistical"},
            source="rule",
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _statistical_detect(self, features: dict) -> tuple[bool, float]:
        """Basic statistical anomaly scoring against known thresholds."""
        anomaly_scores: list[float] = []

        payload_length = features.get("payload_length", 0)
        if payload_length > _MAX_PAYLOAD_LENGTH:
            anomaly_scores.append(min(payload_length / (_MAX_PAYLOAD_LENGTH * 2), 1.0))

        entropy = features.get("entropy", 0.0)
        if entropy > _MAX_ENTROPY:
            anomaly_scores.append(min(entropy / (_MAX_ENTROPY * 1.5), 1.0))

        special_chars = features.get("special_char_count", 0)
        if special_chars > _MAX_SPECIAL_CHAR_COUNT:
            anomaly_scores.append(min(special_chars / (_MAX_SPECIAL_CHAR_COUNT * 2), 1.0))

        param_count = features.get("param_count", 0)
        if param_count > _MAX_PARAM_COUNT:
            anomaly_scores.append(min(param_count / (_MAX_PARAM_COUNT * 2), 1.0))

        url_depth = features.get("url_depth", 0)
        if url_depth > _MAX_URL_DEPTH:
            anomaly_scores.append(min(url_depth / (_MAX_URL_DEPTH * 2), 1.0))

        max_param_length = features.get("max_param_length", 0)
        if max_param_length > _MAX_PARAM_LENGTH:
            anomaly_scores.append(min(max_param_length / (_MAX_PARAM_LENGTH * 2), 1.0))

        uppercase_ratio = features.get("uppercase_ratio", 0.0)
        if uppercase_ratio > 0.8:
            anomaly_scores.append(uppercase_ratio)

        if not anomaly_scores:
            return False, 0.0

        confidence = sum(anomaly_scores) / len(anomaly_scores)
        is_threat = confidence >= self.threshold
        return is_threat, round(confidence, 4)

    def _ml_detect(self, features: dict) -> tuple[bool, float]:
        """Return ``(is_threat, confidence)`` using the loaded ML model."""
        feature_vector = [list(features.values())]
        probabilities = self.model.predict_proba(feature_vector)
        confidence = float(probabilities[0][1])
        return confidence >= self.threshold, confidence
