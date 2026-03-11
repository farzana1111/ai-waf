"""Rule-based detection engine using OWASP-inspired patterns.

Each :class:`Rule` defines a regex pattern applied to the normalised request
text.  If matched, the rule reports a :class:`RuleMatch` with a threat category
and severity.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

ThreatCategory = Literal[
    "sql_injection",
    "xss",
    "command_injection",
    "path_traversal",
    "ldap_injection",
    "xxe",
    "ssrf",
    "rce",
    "scanner",
    "suspicious",
]

Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Rule:
    """A single detection rule."""

    rule_id: str
    category: ThreatCategory
    severity: Severity
    description: str
    pattern: re.Pattern[str]

    @classmethod
    def compile(
        cls,
        rule_id: str,
        category: ThreatCategory,
        severity: Severity,
        description: str,
        pattern: str,
        flags: int = re.IGNORECASE,
    ) -> "Rule":
        return cls(
            rule_id=rule_id,
            category=category,
            severity=severity,
            description=description,
            pattern=re.compile(pattern, flags),
        )


@dataclass
class RuleMatch:
    """Result of a single rule firing on a request."""

    rule: Rule
    matched_value: str
    location: str  # e.g. "query", "body", "header:user-agent"


# ── Rule definitions ─────────────────────────────────────────────────────────

_SQL_INJECTION_RULES: list[Rule] = [
    Rule.compile(
        "SQLi-001",
        "sql_injection",
        "critical",
        "Classic SQL injection tautology",
        r"(?:'|\"|`|--|#|/\*|\*/|;)\s*(?:or|and|xor)\s+[\w'\"]+\s*=\s*[\w'\"]+",
    ),
    Rule.compile(
        "SQLi-002",
        "sql_injection",
        "critical",
        "UNION SELECT injection",
        r"\bunion\b[\w\s,()]*\bselect\b",
    ),
    Rule.compile(
        "SQLi-003",
        "sql_injection",
        "high",
        "SQL command execution (xp_cmdshell / exec)",
        r"\b(?:exec(?:ute)?|xp_cmdshell|sp_executesql|sp_makewebtask)\b",
    ),
    Rule.compile(
        "SQLi-004",
        "sql_injection",
        "high",
        "SQL comment sequence",
        r"(?:--|#|/\*[\s\S]*?\*/)",
    ),
    Rule.compile(
        "SQLi-005",
        "sql_injection",
        "medium",
        "SQL keyword sequence",
        r"\b(?:select|insert|update|delete|drop|create|alter|truncate|replace)\b"
        r"[\s\S]{0,30}\b(?:from|into|table|database|where)\b",
    ),
    Rule.compile(
        "SQLi-006",
        "sql_injection",
        "high",
        "Stacked queries / batch separator",
        r";\s*(?:drop|create|alter|insert|update|delete|select|exec)\b",
    ),
    Rule.compile(
        "SQLi-007",
        "sql_injection",
        "medium",
        "Boolean-based blind SQL injection",
        r"\b(?:and|or)\s+\d+\s*[=<>!]+\s*\d+",
    ),
    Rule.compile(
        "SQLi-008",
        "sql_injection",
        "high",
        "Time-based blind SQL injection",
        r"\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(",
    ),
]

_XSS_RULES: list[Rule] = [
    Rule.compile(
        "XSS-001",
        "xss",
        "high",
        "Script tag injection",
        r"<\s*script[\s>]",
    ),
    Rule.compile(
        "XSS-002",
        "xss",
        "high",
        "JavaScript event handler injection",
        r"\bon\w+\s*=\s*['\"]?(?:javascript:|[^'\">\s]+\()",
    ),
    Rule.compile(
        "XSS-003",
        "xss",
        "high",
        "javascript: URI scheme",
        r"javascript\s*:",
    ),
    Rule.compile(
        "XSS-004",
        "xss",
        "medium",
        "HTML tag injection with attributes",
        r"<\s*(?:img|iframe|svg|object|embed|link|meta|form)\b[^>]*>",
    ),
    Rule.compile(
        "XSS-005",
        "xss",
        "medium",
        "DOM-based XSS sinks",
        r"\b(?:document\.write|innerHTML|outerHTML|eval|setTimeout|setInterval)\s*\(",
    ),
    Rule.compile(
        "XSS-006",
        "xss",
        "low",
        "HTML entity / encoding obfuscation",
        r"&#x?[0-9a-fA-F]{1,6};|&#\d+;",
    ),
    Rule.compile(
        "XSS-007",
        "xss",
        "high",
        "VBScript injection",
        r"vbscript\s*:",
    ),
]

_CMD_INJECTION_RULES: list[Rule] = [
    Rule.compile(
        "CMDi-001",
        "command_injection",
        "critical",
        "Shell pipe / chaining operators",
        r"(?:;|\||&&|\$\(|`)\s*\w+",
    ),
    Rule.compile(
        "CMDi-002",
        "command_injection",
        "critical",
        "Common shell command injection",
        r"\b(?:cat|ls|id|whoami|uname|curl|wget|bash|sh|nc|netcat|python|perl|ruby|php)\b"
        r"\s+(?:-\w+\s+)?[/'.\w]",
    ),
    Rule.compile(
        "CMDi-003",
        "command_injection",
        "high",
        "Null byte injection",
        r"%00|\x00",
    ),
    Rule.compile(
        "CMDi-004",
        "command_injection",
        "high",
        "Command substitution",
        r"\$\([^)]{1,100}\)|\$\{[^}]{1,100}\}|`[^`]{1,100}`",
    ),
]

_PATH_TRAVERSAL_RULES: list[Rule] = [
    Rule.compile(
        "PT-001",
        "path_traversal",
        "high",
        "Directory traversal sequence",
        r"\.{2}[/\\]",
    ),
    Rule.compile(
        "PT-002",
        "path_traversal",
        "high",
        "URL-encoded path traversal",
        r"%2e%2e[%2f%5c]|%252e%252e[%252f%255c]",
        re.IGNORECASE,
    ),
    Rule.compile(
        "PT-003",
        "path_traversal",
        "medium",
        "Absolute path injection",
        r"(?:^|[\s=])(?:/etc/|/proc/|/sys/|/var/|/tmp/|/root/|/home/|C:\\\\|\\\\\\\\)",
    ),
]

_LDAP_INJECTION_RULES: list[Rule] = [
    Rule.compile(
        "LDAP-001",
        "ldap_injection",
        "high",
        "LDAP special characters",
        r"[*()\\\x00]",
    ),
    Rule.compile(
        "LDAP-002",
        "ldap_injection",
        "medium",
        "LDAP filter injection",
        r"\(\s*[|&!]\s*\(",
    ),
]

_XXE_RULES: list[Rule] = [
    Rule.compile(
        "XXE-001",
        "xxe",
        "critical",
        "XML external entity declaration",
        r"<!(?:DOCTYPE|ENTITY)\s+\w+\s+(?:SYSTEM|PUBLIC)\s+['\"]",
    ),
    Rule.compile(
        "XXE-002",
        "xxe",
        "high",
        "XML entity reference to file",
        r"<!ENTITY\s+\w+\s+['\"]file://",
    ),
]

_SSRF_RULES: list[Rule] = [
    Rule.compile(
        "SSRF-001",
        "ssrf",
        "high",
        "Internal network access attempt",
        r"(?:https?|ftp)://(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0"
        r"|169\.254\.\d+\.\d+|::1|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+"
        r"|192\.168\.\d+\.\d+)",
    ),
    Rule.compile(
        "SSRF-002",
        "ssrf",
        "medium",
        "Cloud metadata endpoint",
        r"169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com",
    ),
]

_SCANNER_RULES: list[Rule] = [
    Rule.compile(
        "SCAN-001",
        "scanner",
        "low",
        "Common scanner / fuzzer user-agent",
        r"(?:nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz|acunetix"
        r"|nessus|openvas|w3af|zap|burpsuite|metasploit|havij)",
    ),
    Rule.compile(
        "SCAN-002",
        "scanner",
        "low",
        "Directory/file probe patterns",
        r"/(?:\.git|\.env|\.htaccess|wp-admin|phpMyAdmin|admin|config|backup"
        r"|\.DS_Store|web\.config|crossdomain\.xml|robots\.txt|\.bash_history)(?:/|$)",
    ),
]

ALL_RULES: list[Rule] = (
    _SQL_INJECTION_RULES
    + _XSS_RULES
    + _CMD_INJECTION_RULES
    + _PATH_TRAVERSAL_RULES
    + _LDAP_INJECTION_RULES
    + _XXE_RULES
    + _SSRF_RULES
    + _SCANNER_RULES
)

_SEVERITY_SCORE: dict[Severity, float] = {
    "low": 0.25,
    "medium": 0.50,
    "high": 0.75,
    "critical": 1.00,
}


def run_rules(*, combined_text: str, path: str = "", user_agent: str = "") -> list[RuleMatch]:
    """Apply all rules to the request and return every match.

    Parameters
    ----------
    combined_text:
        Pre-built string combining decoded path + query + body (from
        :func:`~waf.features.extract_features`).
    path:
        Raw request path for path-traversal checks.
    user_agent:
        Raw ``User-Agent`` header value for scanner detection.
    """
    matches: list[RuleMatch] = []
    for rule in ALL_RULES:
        # Scanner rules run against the user-agent specifically
        if rule.category == "scanner" and rule.rule_id == "SCAN-001":
            target = user_agent
        elif rule.category == "path_traversal":
            target = path + " " + combined_text
        else:
            target = combined_text

        m = rule.pattern.search(target)
        if m:
            matches.append(
                RuleMatch(
                    rule=rule,
                    matched_value=target[max(0, m.start() - 10) : m.end() + 10],
                    location="combined",
                )
            )
    return matches


def score_from_matches(matches: list[RuleMatch]) -> float:
    """Return an aggregate threat score in *[0, 1]* from a list of matches.

    Multiple lower-severity matches accumulate; a single critical match
    immediately yields 1.0.
    """
    if not matches:
        return 0.0
    total = sum(_SEVERITY_SCORE[m.rule.severity] for m in matches)
    return min(1.0, total / max(1, len(matches)) + 0.1 * (len(matches) - 1))
