"""Rule-based detection engine.

Matches incoming requests against a set of configurable regex rules
and returns detection results for any matches found.
"""

import logging
import re

from waf.core.request_parser import ParsedRequest
from waf.core.response_handler import DetectionResult

logger = logging.getLogger(__name__)


class RuleEngine:
    """Evaluate parsed HTTP requests against a list of regex-based rules.

    Each rule specifies a regex *pattern*, a *target* field to inspect
    (``url``, ``body``, ``headers``, or ``all``), a *severity* level,
    and an *action* (``block`` or ``log``).
    """

    def __init__(self) -> None:
        self._rules: list[dict] = []
        self._compiled: list[tuple[dict, re.Pattern]] = []

    def load_rules(self, rules_list: list[dict]) -> None:
        """Load rules from a list of rule dictionaries.

        Each dict must contain the keys ``id``, ``name``, ``pattern``,
        ``target``, ``severity``, and ``action``.  Previously loaded
        rules are replaced.
        """
        self._rules = list(rules_list)
        self._compiled = []
        for rule in self._rules:
            try:
                compiled = re.compile(rule["pattern"])
                self._compiled.append((rule, compiled))
            except re.error:
                logger.warning(
                    "Invalid regex in rule %s (%s): %s",
                    rule.get("id", "?"),
                    rule.get("name", "?"),
                    rule.get("pattern", ""),
                )

    def evaluate(self, parsed_request: ParsedRequest) -> list[DetectionResult]:
        """Evaluate *parsed_request* against all loaded rules.

        Returns a list of :class:`DetectionResult` objects, one for
        every rule that matched.
        """
        results: list[DetectionResult] = []
        for rule, pattern in self._compiled:
            text = self._extract_target(parsed_request, rule.get("target", "all"))
            if pattern.search(text):
                confidence = _severity_to_confidence(rule.get("severity", "medium"))
                results.append(
                    DetectionResult(
                        is_threat=True,
                        threat_type=rule.get("name", "unknown"),
                        confidence=confidence,
                        details={
                            "rule_id": rule.get("id", ""),
                            "rule_name": rule.get("name", ""),
                            "severity": rule.get("severity", "medium"),
                            "action": rule.get("action", "log"),
                            "target": rule.get("target", "all"),
                        },
                        source="rule",
                    )
                )
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_target(parsed_request: ParsedRequest, target: str) -> str:
        """Build the text payload to match against for a given *target*."""
        if target == "url":
            parts = [parsed_request.path]
            parts.extend(parsed_request.query_params.values())
            return " ".join(parts)

        if target == "body":
            return parsed_request.body or ""

        if target == "headers":
            return " ".join(parsed_request.headers.values())

        # "all" – concatenate everything
        parts = [
            parsed_request.path,
            *parsed_request.query_params.values(),
            parsed_request.body or "",
            *parsed_request.headers.values(),
        ]
        return " ".join(parts)


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

_SEVERITY_MAP: dict[str, float] = {
    "critical": 0.95,
    "high": 0.85,
    "medium": 0.70,
    "low": 0.50,
    "info": 0.30,
}


def _severity_to_confidence(severity: str) -> float:
    """Map a severity label to a numeric confidence score."""
    return _SEVERITY_MAP.get(severity.lower(), 0.70)
