"""Feature extraction from parsed HTTP requests for ML-based detection."""

import math
import re
from collections import Counter

from waf.core.request_parser import ParsedRequest


# Characters considered special/suspicious in payloads
_SPECIAL_CHARS = set("'\"<>;(){}|&`$\\")
_SPECIAL_PATTERNS = re.compile(r"--|/\*|\*/")

_SQL_KEYWORDS = re.compile(
    r"\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|EXECUTE|"
    r"TRUNCATE|MERGE|GRANT|REVOKE|HAVING|WHERE|FROM|INTO|VALUES|TABLE|"
    r"DATABASE|OR|AND|ORDER\s+BY|GROUP\s+BY|DECLARE|CAST|CONVERT|WAITFOR|"
    r"BENCHMARK|SLEEP|LOAD_FILE|OUTFILE|INFORMATION_SCHEMA)\b",
    re.IGNORECASE,
)

_XSS_PATTERNS = re.compile(
    r"(?:<\s*script|javascript\s*:|on(?:error|load|click|mouseover|focus|blur)"
    r"\s*=|eval\s*\(|document\.cookie|document\.location|window\.location|"
    r"alert\s*\(|prompt\s*\(|confirm\s*\(|String\.fromCharCode|innerHTML|"
    r"outerHTML|\.write\s*\(|\.writeln\s*\()",
    re.IGNORECASE,
)

_SCRIPT_TAG = re.compile(r"<\s*/?\s*script", re.IGNORECASE)

_ENCODING_SEQUENCES = re.compile(r"(%[0-9a-fA-F]{2}|&#\d+;|&#x[0-9a-fA-F]+;|\\u[0-9a-fA-F]{4})")


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of *data*."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy


class FeatureExtractor:
    """Extract numerical / boolean features from a ``ParsedRequest`` for ML models."""

    def extract(self, parsed_request: ParsedRequest) -> dict:
        """Return a feature dictionary for the given *parsed_request*."""
        payload = self._build_payload(parsed_request)

        payload_length = len(payload)
        alpha_chars = sum(1 for c in payload if c.isalpha())
        upper_chars = sum(1 for c in payload if c.isupper())
        digit_chars = sum(1 for c in payload if c.isdigit())

        param_values = list(parsed_request.query_params.values())
        max_param_length = max((len(v) for v in param_values), default=0)

        return {
            "payload_length": payload_length,
            "special_char_count": self._count_special_chars(payload),
            "entropy": _shannon_entropy(payload),
            "has_script_tag": bool(_SCRIPT_TAG.search(payload)),
            "has_sql_keywords": bool(_SQL_KEYWORDS.search(payload)),
            "has_xss_patterns": bool(_XSS_PATTERNS.search(payload)),
            "url_depth": self._url_depth(parsed_request.path),
            "param_count": len(parsed_request.query_params),
            "has_encoded_content": bool(_ENCODING_SEQUENCES.search(payload)),
            "uppercase_ratio": (upper_chars / alpha_chars) if alpha_chars else 0.0,
            "digit_ratio": (digit_chars / payload_length) if payload_length else 0.0,
            "max_param_length": max_param_length,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_payload(parsed_request: ParsedRequest) -> str:
        """Concatenate all user-supplied data into a single string."""
        parts = []
        parts.extend(parsed_request.query_params.values())
        if parsed_request.body:
            parts.append(parsed_request.body)
        return " ".join(parts)

    @staticmethod
    def _count_special_chars(text: str) -> int:
        count = sum(1 for ch in text if ch in _SPECIAL_CHARS)
        count += len(_SPECIAL_PATTERNS.findall(text))
        return count

    @staticmethod
    def _url_depth(path: str) -> int:
        return len([seg for seg in path.split("/") if seg])
