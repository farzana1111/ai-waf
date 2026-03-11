"""Cross-Site Scripting (XSS) detection using regex patterns and optional ML model."""

import logging
import re

from waf.core.request_parser import ParsedRequest
from waf.core.response_handler import DetectionResult

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Common XSS regex patterns                                          #
# ------------------------------------------------------------------ #
_XSS_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    (re.compile(r"<\s*script\b", re.I), "<script> tag", 0.95),
    (re.compile(r"</\s*script\s*>", re.I), "</script> closing tag", 0.90),
    (re.compile(r"\bjavascript\s*:", re.I), "javascript: URI", 0.90),
    (re.compile(r"\bvbscript\s*:", re.I), "vbscript: URI", 0.90),
    (re.compile(r"\bon(?:error|load|click|mouseover|mouseout|focus|blur|submit|"
                r"change|keyup|keydown|keypress|input|dblclick|contextmenu|"
                r"mouseenter|mouseleave|resize|unload|beforeunload)\s*=", re.I),
     "Event handler attribute", 0.90),
    (re.compile(r"\beval\s*\(", re.I), "eval() call", 0.90),
    (re.compile(r"\bdocument\.cookie\b", re.I), "document.cookie access", 0.90),
    (re.compile(r"\bdocument\.location\b", re.I), "document.location access", 0.85),
    (re.compile(r"\bwindow\.location\b", re.I), "window.location access", 0.85),
    (re.compile(r"\balert\s*\(", re.I), "alert() call", 0.80),
    (re.compile(r"\bprompt\s*\(", re.I), "prompt() call", 0.80),
    (re.compile(r"\bconfirm\s*\(", re.I), "confirm() call", 0.80),
    (re.compile(r"\bString\.fromCharCode\b", re.I), "String.fromCharCode", 0.85),
    (re.compile(r"\binnerHTML\b", re.I), "innerHTML assignment", 0.75),
    (re.compile(r"\bouterHTML\b", re.I), "outerHTML assignment", 0.75),
    (re.compile(r"\.write\s*\(", re.I), "document.write()", 0.80),
    (re.compile(r"\.writeln\s*\(", re.I), "document.writeln()", 0.80),
    (re.compile(r"<\s*img\b[^>]*\bon\w+\s*=", re.I), "<img> with event handler", 0.90),
    (re.compile(r"<\s*svg\b[^>]*\bon\w+\s*=", re.I), "<svg> with event handler", 0.90),
    (re.compile(r"<\s*iframe\b", re.I), "<iframe> tag", 0.80),
    (re.compile(r"<\s*object\b", re.I), "<object> tag", 0.75),
    (re.compile(r"<\s*embed\b", re.I), "<embed> tag", 0.75),
    (re.compile(r"\bsetTimeout\s*\(", re.I), "setTimeout()", 0.65),
    (re.compile(r"\bsetInterval\s*\(", re.I), "setInterval()", 0.65),
    (re.compile(r"\bFunction\s*\(", re.I), "Function() constructor", 0.85),
    (re.compile(r"<\s*body\b[^>]*\bon\w+\s*=", re.I), "<body> with event handler", 0.90),
    (re.compile(r"expression\s*\(", re.I), "CSS expression()", 0.80),
    (re.compile(r"url\s*\(\s*['\"]?\s*javascript:", re.I), "CSS url(javascript:)", 0.90),
]


class XSSDetector:
    """Detect XSS attacks via regex rules and an optional ML model."""

    def __init__(self, model_path: str | None = None, threshold: float = 0.7):
        self.threshold = threshold
        self.model = None
        if model_path:
            try:
                import joblib

                self.model = joblib.load(model_path)
                logger.info("XSS ML model loaded from %s", model_path)
            except Exception:
                logger.warning("Could not load XSS model from %s; falling back to regex", model_path)

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
                        threat_type="xss",
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
            threat_type="xss" if is_threat else "",
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

        for pattern, name, weight in _XSS_PATTERNS:
            if pattern.search(payload):
                matched.append(name)
                max_confidence = max(max_confidence, weight)

        is_threat = max_confidence >= 0.7 and len(matched) > 0  # baseline regex threshold
        return is_threat, max_confidence, matched

    def _ml_detect(self, features: dict) -> tuple[bool, float]:
        """Return ``(is_threat, confidence)`` using the loaded ML model."""
        feature_vector = [list(features.values())]
        probabilities = self.model.predict_proba(feature_vector)
        confidence = float(probabilities[0][1])
        return confidence >= self.threshold, confidence
