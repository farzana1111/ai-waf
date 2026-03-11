"""Tests for the FeatureExtractor."""

import math

import pytest

from waf.ai.feature_extractor import FeatureExtractor, _shannon_entropy
from tests.conftest import make_parsed_request

EXPECTED_KEYS = {
    "payload_length",
    "special_char_count",
    "entropy",
    "has_script_tag",
    "has_sql_keywords",
    "has_xss_patterns",
    "url_depth",
    "param_count",
    "has_encoded_content",
    "uppercase_ratio",
    "digit_ratio",
    "max_param_length",
}


@pytest.fixture()
def extractor():
    return FeatureExtractor()


class TestFeatureKeys:
    """Ensure the feature dict always contains the expected keys."""

    def test_all_keys_present_for_empty_request(self, extractor):
        req = make_parsed_request()
        features = extractor.extract(req)
        assert set(features.keys()) == EXPECTED_KEYS

    def test_all_keys_present_for_normal_request(self, extractor):
        req = make_parsed_request(
            path="/search",
            query_params={"q": "hello world"},
        )
        features = extractor.extract(req)
        assert set(features.keys()) == EXPECTED_KEYS


class TestNormalRequest:
    """Feature values for a benign request."""

    def test_normal_request_features(self, extractor):
        req = make_parsed_request(
            path="/api/search",
            query_params={"q": "hello world", "page": "1"},
        )
        features = extractor.extract(req)

        assert features["payload_length"] > 0
        assert features["special_char_count"] == 0
        assert features["has_script_tag"] is False
        assert features["has_sql_keywords"] is False
        assert features["has_xss_patterns"] is False
        assert features["param_count"] == 2
        assert features["url_depth"] == 2  # api/search

    def test_empty_request_features(self, extractor):
        req = make_parsed_request()
        features = extractor.extract(req)

        assert features["payload_length"] == 0
        assert features["entropy"] == 0.0
        assert features["param_count"] == 0
        assert features["max_param_length"] == 0


class TestSQLiFeatures:
    """Features extracted from requests containing SQL injection payloads."""

    def test_sqli_payload_has_sql_keywords(self, extractor):
        req = make_parsed_request(
            query_params={"id": "1 UNION SELECT * FROM users"},
        )
        features = extractor.extract(req)
        assert features["has_sql_keywords"] is True

    def test_sqli_payload_special_chars(self, extractor):
        req = make_parsed_request(
            query_params={"id": "' OR '1'='1' --"},
        )
        features = extractor.extract(req)
        assert features["special_char_count"] > 0

    def test_sqli_in_body(self, extractor):
        req = make_parsed_request(body="SELECT password FROM users WHERE 1=1")
        features = extractor.extract(req)
        assert features["has_sql_keywords"] is True


class TestXSSFeatures:
    """Features extracted from requests containing XSS payloads."""

    def test_xss_payload_has_script_tag(self, extractor):
        req = make_parsed_request(
            query_params={"q": "<script>alert(1)</script>"},
        )
        features = extractor.extract(req)
        assert features["has_script_tag"] is True
        assert features["has_xss_patterns"] is True

    def test_xss_event_handler(self, extractor):
        req = make_parsed_request(
            query_params={"q": '<img src=x onerror=alert(1)>'},
        )
        features = extractor.extract(req)
        assert features["has_xss_patterns"] is True

    def test_xss_javascript_uri(self, extractor):
        req = make_parsed_request(
            query_params={"url": "javascript:alert(document.cookie)"},
        )
        features = extractor.extract(req)
        assert features["has_xss_patterns"] is True


class TestEntropy:
    """Verify Shannon entropy calculations."""

    def test_empty_string_entropy(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char_entropy(self):
        assert _shannon_entropy("aaaa") == 0.0

    def test_uniform_distribution_entropy(self):
        # "ab" repeated → 2 equally likely chars → entropy = 1.0
        entropy = _shannon_entropy("abababab")
        assert math.isclose(entropy, 1.0, abs_tol=0.01)

    def test_high_entropy_for_random_data(self):
        # Many distinct characters → higher entropy
        data = "aB3$xY7!kL9@mN2#"
        entropy = _shannon_entropy(data)
        assert entropy > 3.0

    def test_entropy_is_non_negative(self):
        assert _shannon_entropy("test") >= 0.0


class TestURLDepth:
    """Test URL depth calculation."""

    def test_root_path(self, extractor):
        req = make_parsed_request(path="/")
        features = extractor.extract(req)
        assert features["url_depth"] == 0

    def test_nested_path(self, extractor):
        req = make_parsed_request(path="/a/b/c/d")
        features = extractor.extract(req)
        assert features["url_depth"] == 4


class TestMaxParamLength:
    """Test max_param_length feature."""

    def test_no_params(self, extractor):
        req = make_parsed_request()
        features = extractor.extract(req)
        assert features["max_param_length"] == 0

    def test_long_param(self, extractor):
        req = make_parsed_request(query_params={"a": "short", "b": "x" * 100})
        features = extractor.extract(req)
        assert features["max_param_length"] == 100
