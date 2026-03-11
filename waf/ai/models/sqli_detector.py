"""SQL Injection detection using regex patterns and optional ML model."""

import logging
import re

from waf.core.request_parser import ParsedRequest
from waf.core.response_handler import DetectionResult

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Common SQLi regex patterns ordered roughly by severity / frequency  #
# ------------------------------------------------------------------ #
_SQLI_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    (re.compile(r"\bUNION\b.*\bSELECT\b", re.I), "UNION SELECT", 0.95),
    (re.compile(r"\bSELECT\b.*\bFROM\b.*\bINFORMATION_SCHEMA\b", re.I), "Information schema access", 0.95),
    (re.compile(r"\bDROP\b\s+\bTABLE\b", re.I), "DROP TABLE", 0.95),
    (re.compile(r"\bDROP\b\s+\bDATABASE\b", re.I), "DROP DATABASE", 0.95),
    (re.compile(r"\bINSERT\b\s+\bINTO\b", re.I), "INSERT INTO", 0.85),
    (re.compile(r"\bDELETE\b\s+\bFROM\b", re.I), "DELETE FROM", 0.85),
    (re.compile(r"\bUPDATE\b\s+\w+\s+\bSET\b", re.I), "UPDATE SET", 0.85),
    (re.compile(r"\bEXEC(?:UTE)?\b\s*\(", re.I), "EXEC/EXECUTE", 0.90),
    (re.compile(r"\bWAITFOR\b\s+\bDELAY\b", re.I), "Time-based SQLi (WAITFOR)", 0.90),
    (re.compile(r"\bBENCHMARK\b\s*\(", re.I), "Time-based SQLi (BENCHMARK)", 0.90),
    (re.compile(r"\bSLEEP\b\s*\(", re.I), "Time-based SQLi (SLEEP)", 0.90),
    (re.compile(r"\bLOAD_FILE\b\s*\(", re.I), "File access (LOAD_FILE)", 0.90),
    (re.compile(r"\bINTO\b\s+\b(?:OUT|DUMP)FILE\b", re.I), "File write (OUTFILE)", 0.90),
    (re.compile(r"(?:^|\s)OR\s+1\s*=\s*1", re.I), "OR 1=1 tautology", 0.90),
    (re.compile(r"(?:^|\s)OR\s+'[^']*'\s*=\s*'[^']*'", re.I), "OR string tautology", 0.90),
    (re.compile(r"(?:^|\s)OR\s+\"[^\"]*\"\s*=\s*\"[^\"]*\"", re.I), "OR string tautology (double-quoted)", 0.90),
    (re.compile(r"';\s*--"), "Quote then comment", 0.85),
    (re.compile(r"--\s*$", re.M), "SQL line comment", 0.60),
    (re.compile(r"/\*.*?\*/", re.S), "SQL block comment", 0.55),
    (re.compile(r"\bHAVING\b\s+\d+\s*=\s*\d+", re.I), "HAVING tautology", 0.85),
    (re.compile(r"\bORDER\s+BY\s+\d+", re.I), "ORDER BY column enumeration", 0.60),
    (re.compile(r"\bGROUP\s+BY\s+\d+", re.I), "GROUP BY column enumeration", 0.60),
    (re.compile(r"\bCAST\b\s*\(", re.I), "CAST function", 0.50),
    (re.compile(r"\bCONVERT\b\s*\(", re.I), "CONVERT function", 0.50),
    (re.compile(r"\bDECLARE\b\s+@", re.I), "Variable declaration", 0.80),
]


class SQLiDetector:
    """Detect SQL injection attacks via regex rules and an optional ML model."""

    def __init__(self, model_path: str | None = None, threshold: float = 0.7):
        self.threshold = threshold
        self.model = None
        if model_path:
            try:
                import joblib

                self.model = joblib.load(model_path)
                logger.info("SQLi ML model loaded from %s", model_path)
            except Exception:
                logger.warning("Could not load SQLi model from %s; falling back to regex", model_path)

    def detect(self, parsed_request: ParsedRequest, features: dict | None = None) -> DetectionResult:
        """Run detection on *parsed_request* and return a ``DetectionResult``."""
        payload = self._build_payload(parsed_request)

        # Try ML first when available
        if self.model is not None and features is not None:
            try:
                is_threat, confidence = self._ml_detect(features)
                if is_threat:
                    return DetectionResult(
                        is_threat=True,
                        threat_type="sqli",
                        confidence=confidence,
                        details={"method": "ml"},
                        source="ml",
                    )
            except Exception:
                logger.debug("ML detection failed; falling back to regex", exc_info=True)

        # Regex fallback / primary
        is_threat, confidence, matched = self._regex_detect(payload)
        return DetectionResult(
            is_threat=is_threat,
            threat_type="sqli" if is_threat else "",
            confidence=confidence,
            details={"method": "regex", "matched_patterns": matched},
            source="rule",
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_payload(parsed_request: ParsedRequest) -> str:
        parts = list(parsed_request.query_params.values())
        if parsed_request.body:
            parts.append(parsed_request.body)
        return " ".join(parts)

    @staticmethod
    def _regex_detect(payload: str) -> tuple[bool, float, list[str]]:
        """Return ``(is_threat, confidence, matched_pattern_names)``."""
        matched: list[str] = []
        max_confidence = 0.0

        for pattern, name, weight in _SQLI_PATTERNS:
            if pattern.search(payload):
                matched.append(name)
                max_confidence = max(max_confidence, weight)

        is_threat = max_confidence >= 0.7 and len(matched) > 0
        return is_threat, max_confidence, matched

    def _ml_detect(self, features: dict) -> tuple[bool, float]:
        """Return ``(is_threat, confidence)`` using the loaded ML model."""
        feature_vector = [list(features.values())]
        probabilities = self.model.predict_proba(feature_vector)
        confidence = float(probabilities[0][1])
        return confidence >= self.threshold, confidence
