"""Tests for waf.detector — ML threat detection."""

from __future__ import annotations

import pytest

from waf.detector import DetectionResult, ThreatDetector
from waf.features import extract_features


@pytest.fixture(scope="module")
def detector(tmp_path_factory) -> ThreatDetector:
    """Return a ThreatDetector with a model trained into a temp directory."""
    model_dir = tmp_path_factory.mktemp("models")
    model_path = model_dir / "threat_model.joblib"
    det = ThreatDetector(model_path=model_path, confidence_threshold=0.50)
    det.load()
    return det


class TestThreatDetector:
    def test_model_loads(self, detector: ThreatDetector):
        assert detector.is_loaded

    def test_returns_detection_result(self, detector: ThreatDetector):
        features = extract_features(method="GET", path="/api/users")
        result = detector.predict(features)
        assert isinstance(result, DetectionResult)
        assert result.label
        assert 0.0 <= result.confidence <= 1.0

    def test_normal_request_classified_as_normal(self, detector: ThreatDetector):
        features = extract_features(
            method="GET", path="/api/items", query_string="page=1&limit=10"
        )
        result = detector.predict(features)
        # Normal requests should predominantly be classified as "normal"
        assert result.label == "normal" or not result.is_threat

    def test_sqli_detected(self, detector: ThreatDetector):
        features = extract_features(
            method="GET",
            path="/search",
            query_string="q=' OR '1'='1 UNION SELECT null--",
        )
        result = detector.predict(features)
        assert result.is_threat or result.label == "sql_injection"

    def test_xss_detected(self, detector: ThreatDetector):
        features = extract_features(
            method="GET",
            path="/search",
            query_string="q=<script>alert(1)</script>",
        )
        result = detector.predict(features)
        assert result.is_threat or result.label == "xss"

    def test_cmdi_detected(self, detector: ThreatDetector):
        features = extract_features(
            method="GET",
            path="/ping",
            query_string="host=127.0.0.1;cat /etc/passwd",
        )
        result = detector.predict(features)
        assert result.is_threat or result.label == "command_injection"

    def test_all_scores_sum_to_one(self, detector: ThreatDetector):
        features = extract_features(method="GET", path="/test")
        result = detector.predict(features)
        total = sum(result.all_scores.values())
        assert abs(total - 1.0) < 0.01

    def test_all_scores_contains_normal_key(self, detector: ThreatDetector):
        features = extract_features(method="GET", path="/test")
        result = detector.predict(features)
        assert "normal" in result.all_scores

    def test_lazy_load_on_predict(self, tmp_path):
        """Detector should auto-load on first predict call."""
        model_path = tmp_path / "lazy_model.joblib"
        det = ThreatDetector(model_path=model_path, confidence_threshold=0.50)
        assert not det.is_loaded
        features = extract_features(method="GET", path="/x")
        result = det.predict(features)
        assert det.is_loaded
        assert isinstance(result, DetectionResult)

    def test_confidence_threshold_respected(self, tmp_path):
        """With threshold=1.0 nothing should be flagged as threat."""
        model_path = tmp_path / "strict_model.joblib"
        det = ThreatDetector(model_path=model_path, confidence_threshold=1.0)
        det.load()
        features = extract_features(
            method="GET", path="/users", query_string="id=1 UNION SELECT null--"
        )
        result = det.predict(features)
        # With threshold=1.0 confidence can never reach 1.0 for a classifier
        assert result.is_threat is False
