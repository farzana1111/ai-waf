"""Tests for the XSS detector."""

import pytest

from waf.ai.models.xss_detector import XSSDetector
from tests.conftest import load_payloads, make_parsed_request


@pytest.fixture()
def detector():
    return XSSDetector()


@pytest.fixture()
def xss_payloads():
    return load_payloads("xss_payloads.txt")


class TestXSSDetection:
    """XSS detection using regex patterns."""

    def test_detects_script_tag(self, detector):
        req = make_parsed_request(query_params={"q": "<script>alert('XSS')</script>"})
        result = detector.detect(req)
        assert result.is_threat is True
        assert result.threat_type == "xss"
        assert result.confidence >= 0.9

    def test_detects_img_onerror(self, detector):
        req = make_parsed_request(query_params={"q": "<img src=x onerror=alert(1)>"})
        result = detector.detect(req)
        assert result.is_threat is True
        assert result.threat_type == "xss"

    def test_detects_javascript_uri(self, detector):
        req = make_parsed_request(query_params={"url": "javascript:alert(document.cookie)"})
        result = detector.detect(req)
        assert result.is_threat is True

    def test_detects_svg_onload(self, detector):
        req = make_parsed_request(query_params={"q": "<svg onload=alert(1)>"})
        result = detector.detect(req)
        assert result.is_threat is True

    def test_detects_body_onload(self, detector):
        req = make_parsed_request(query_params={"q": "<body onload=alert(1)>"})
        result = detector.detect(req)
        assert result.is_threat is True

    def test_detects_iframe(self, detector):
        req = make_parsed_request(query_params={"q": '<iframe src="javascript:alert(1)">'})
        result = detector.detect(req)
        assert result.is_threat is True

    def test_detects_eval(self, detector):
        req = make_parsed_request(query_params={"q": "eval('alert(1)')"})
        result = detector.detect(req)
        assert result.is_threat is True

    def test_detects_document_cookie(self, detector):
        req = make_parsed_request(body="<script>document.cookie</script>")
        result = detector.detect(req)
        assert result.is_threat is True

    def test_detects_document_write(self, detector):
        req = make_parsed_request(body="document.write('<h1>XSS</h1>')")
        result = detector.detect(req)
        assert result.is_threat is True


class TestXSSPayloadsFile:
    """Verify detection against the XSS payloads file."""

    def test_most_payloads_detected(self, detector, xss_payloads):
        detected = 0
        for payload in xss_payloads:
            req = make_parsed_request(query_params={"input": payload})
            result = detector.detect(req)
            if result.is_threat:
                detected += 1

        ratio = detected / len(xss_payloads)
        assert ratio >= 0.70, f"Only {detected}/{len(xss_payloads)} payloads detected ({ratio:.0%})"


class TestNormalHTMLNotFlagged:
    """Benign HTML/text must not be classified as XSS."""

    @pytest.mark.parametrize("value", [
        "hello world",
        "john.doe@example.com",
        "The quick brown fox",
        "<h1>Welcome</h1>",
        "<p>Normal paragraph</p>",
        "Price: $19.99",
        "2024-01-15",
        "https://example.com/page",
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

    def test_confidence_between_zero_and_one(self, detector, xss_payloads):
        for payload in xss_payloads:
            req = make_parsed_request(query_params={"input": payload})
            result = detector.detect(req)
            assert 0.0 <= result.confidence <= 1.0

    def test_high_confidence_for_script_tag(self, detector):
        req = make_parsed_request(query_params={"q": "<script>alert(1)</script>"})
        result = detector.detect(req)
        assert result.confidence >= 0.9


class TestRegexOnlyMode:
    """Test regex-only detection (no ML model loaded)."""

    def test_detector_works_without_model(self):
        detector = XSSDetector(model_path=None)
        assert detector.model is None

        req = make_parsed_request(query_params={"q": "<script>alert(1)</script>"})
        result = detector.detect(req)
        assert result.is_threat is True
        assert result.details.get("method") == "regex"
        assert result.source == "rule"

    def test_details_contain_matched_patterns(self):
        detector = XSSDetector()
        req = make_parsed_request(query_params={"q": "<script>alert(1)</script>"})
        result = detector.detect(req)
        assert "matched_patterns" in result.details
        assert len(result.details["matched_patterns"]) > 0

    def test_nonexistent_model_path_falls_back(self):
        detector = XSSDetector(model_path="/nonexistent/model.joblib")
        assert detector.model is None
        req = make_parsed_request(query_params={"q": "<script>alert(1)</script>"})
        result = detector.detect(req)
        assert result.is_threat is True
