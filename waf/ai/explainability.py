"""Explainable AI — generate human-readable explanations for detection results."""

from waf.core.response_handler import DetectionResult

# Feature descriptions used in explanations
_FEATURE_DESCRIPTIONS: dict[str, str] = {
    "payload_length": "Total payload length",
    "special_char_count": "Number of special characters",
    "entropy": "Shannon entropy of the payload",
    "has_script_tag": "Presence of <script> tags",
    "has_sql_keywords": "Presence of SQL keywords",
    "has_xss_patterns": "Presence of XSS patterns",
    "url_depth": "URL path depth",
    "param_count": "Number of query parameters",
    "has_encoded_content": "Presence of encoded content",
    "uppercase_ratio": "Ratio of uppercase characters",
    "digit_ratio": "Ratio of digit characters",
    "max_param_length": "Length of longest parameter value",
}

# What each threat type means in plain language
_THREAT_SUMMARIES: dict[str, str] = {
    "sqli": "SQL Injection attempt detected",
    "xss": "Cross-Site Scripting (XSS) attempt detected",
    "anomaly": "Anomalous request detected",
    "rate_limit": "Rate limit exceeded",
}

# Features most relevant per threat type (ordered by importance)
_THREAT_FEATURES: dict[str, list[str]] = {
    "sqli": [
        "has_sql_keywords",
        "special_char_count",
        "entropy",
        "payload_length",
        "has_encoded_content",
    ],
    "xss": [
        "has_xss_patterns",
        "has_script_tag",
        "special_char_count",
        "entropy",
        "has_encoded_content",
    ],
    "anomaly": [
        "payload_length",
        "entropy",
        "special_char_count",
        "param_count",
        "url_depth",
        "uppercase_ratio",
        "max_param_length",
    ],
    "rate_limit": [],
}


class ExplainabilityEngine:
    """Produce structured, human-readable explanations for WAF decisions."""

    def explain(self, detection_result: DetectionResult, features: dict) -> dict:
        """Return an explanation dict for the given *detection_result* and *features*.

        The returned dict contains:
        - ``threat_type``: e.g. ``"sqli"``
        - ``confidence``: detection confidence ``[0, 1]``
        - ``summary``: one-line human-readable summary
        - ``contributing_features``: list of dicts with feature detail
        - ``details``: raw details from the detection result
        """
        threat_type = detection_result.threat_type
        summary = _THREAT_SUMMARIES.get(threat_type, "Unknown threat detected")

        contributing = self._rank_features(threat_type, features)

        return {
            "threat_type": threat_type,
            "confidence": detection_result.confidence,
            "summary": summary,
            "contributing_features": contributing,
            "details": detection_result.details,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _rank_features(threat_type: str, features: dict) -> list[dict]:
        """Pick the most relevant features for *threat_type* and annotate them."""
        relevant_keys = _THREAT_FEATURES.get(threat_type, list(features.keys()))
        result: list[dict] = []
        for key in relevant_keys:
            if key not in features:
                continue
            value = features[key]
            # Only include features that have a "truthy" signal
            if isinstance(value, bool) and not value:
                continue
            if isinstance(value, (int, float)) and value == 0:
                continue
            result.append({
                "feature": key,
                "value": value,
                "description": _FEATURE_DESCRIPTIONS.get(key, key),
            })
        return result
