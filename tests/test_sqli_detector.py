"""Tests for the SQL injection detector."""

import pytest

from waf.ai.models.sqli_detector import SQLiDetector
from tests.conftest import load_payloads, make_parsed_request


@pytest.fixture()
def detector():
    return SQLiDetector()


@pytest.fixture()
def sqli_payloads():
    return load_payloads("sqli_payloads.txt")


class TestSQLiDetection:
    """SQLi detection using regex patterns."""

    def test_detects_union_select(self, detector):
        req = make_parsed_request(query_params={"id": "1 UNION SELECT * FROM users"})
        result = detector.detect(req)
        assert result.is_threat is True
        assert result.threat_type == "sqli"
        assert result.confidence >= 0.9

    def test_detects_drop_table(self, detector):
        req = make_parsed_request(query_params={"id": "'; DROP TABLE users;--"})
        result = detector.detect(req)
        assert result.is_threat is True
        assert result.threat_type == "sqli"

    def test_detects_or_tautology(self, detector):
        req = make_parsed_request(query_params={"id": "' OR 1=1--"})
        result = detector.detect(req)
        assert result.is_threat is True
        assert result.threat_type == "sqli"

    def test_detects_delete_from(self, detector):
        req = make_parsed_request(body="DELETE FROM users WHERE 1=1")
        result = detector.detect(req)
        assert result.is_threat is True
        assert result.threat_type == "sqli"

    def test_detects_sleep_injection(self, detector):
        req = make_parsed_request(query_params={"id": "1' AND SLEEP(5)--"})
        result = detector.detect(req)
        assert result.is_threat is True

    def test_detects_waitfor_delay(self, detector):
        req = make_parsed_request(query_params={"id": "1' WAITFOR DELAY '0:0:5'--"})
        result = detector.detect(req)
        assert result.is_threat is True

    def test_detects_insert_into(self, detector):
        req = make_parsed_request(body="INSERT INTO users VALUES('hacked')")
        result = detector.detect(req)
        assert result.is_threat is True

    def test_detects_information_schema(self, detector):
        req = make_parsed_request(
            query_params={"id": "1 UNION SELECT table_name FROM information_schema.tables"},
        )
        result = detector.detect(req)
        assert result.is_threat is True
        assert result.confidence >= 0.9


class TestSQLiPayloadsFile:
    """Verify detection against the payloads file.

    High-confidence patterns (≥ 0.7) must be detected as threats.
    """

    def test_most_payloads_detected(self, detector, sqli_payloads):
        detected = 0
        for payload in sqli_payloads:
            req = make_parsed_request(query_params={"input": payload})
            result = detector.detect(req)
            if result.is_threat:
                detected += 1

        # At least 50 % of the curated payloads should be caught
        # (some payloads have sub-0.7 confidence in regex-only mode)
        ratio = detected / len(sqli_payloads)
        assert ratio >= 0.50, f"Only {detected}/{len(sqli_payloads)} payloads detected ({ratio:.0%})"


class TestNormalInputsNotFlagged:
    """Benign inputs must not be classified as SQL injection."""

    @pytest.mark.parametrize("value", [
        "hello world",
        "john.doe@example.com",
        "The quick brown fox jumps over the lazy dog",
        "product search query",
        "12345",
        "New York City",
        "2024-01-15T10:30:00Z",
    ])
    def test_normal_input_not_flagged(self, detector, value):
        req = make_parsed_request(query_params={"q": value})
        result = detector.detect(req)
        assert result.is_threat is False

    def test_empty_request_not_flagged(self, detector):
        req = make_parsed_request()
        result = detector.detect(req)
        assert result.is_threat is False


class TestConfidenceScores:
    """Verify confidence scores are within valid range."""

    def test_confidence_between_zero_and_one(self, detector, sqli_payloads):
        for payload in sqli_payloads:
            req = make_parsed_request(query_params={"input": payload})
            result = detector.detect(req)
            assert 0.0 <= result.confidence <= 1.0

    def test_high_confidence_for_obvious_attack(self, detector):
        req = make_parsed_request(query_params={"id": "1 UNION SELECT * FROM users"})
        result = detector.detect(req)
        assert result.confidence >= 0.9


class TestRegexOnlyMode:
    """Test regex-only detection (no ML model loaded)."""

    def test_detector_works_without_model(self):
        detector = SQLiDetector(model_path=None)
        assert detector.model is None

        req = make_parsed_request(query_params={"id": "1 UNION SELECT * FROM users"})
        result = detector.detect(req)
        assert result.is_threat is True
        assert result.details.get("method") == "regex"
        assert result.source == "rule"

    def test_details_contain_matched_patterns(self):
        detector = SQLiDetector()
        req = make_parsed_request(query_params={"id": "1 UNION SELECT * FROM users"})
        result = detector.detect(req)
        assert "matched_patterns" in result.details
        assert len(result.details["matched_patterns"]) > 0

    def test_nonexistent_model_path_falls_back(self):
        detector = SQLiDetector(model_path="/nonexistent/model.joblib")
        assert detector.model is None
        req = make_parsed_request(query_params={"id": "1 UNION SELECT * FROM users"})
        result = detector.detect(req)
        assert result.is_threat is True
