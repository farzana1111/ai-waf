#!/usr/bin/env python3
"""Smoke-test script for AI-WAF.

Exercises the WAF engine directly (no network required) against a battery
of known-good and known-malicious payloads and prints a pass/fail report.

Usage
-----
    python -m scripts.smoke_test          # default: block mode, rules only
    python -m scripts.smoke_test --ml     # enable ML detector too
    python -m scripts.smoke_test --mode monitor  # monitor mode (log but allow)

Exit code 0 = all checks passed, 1 = at least one failed.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass

from waf.engine import WAFEngine
from waf.waf_config import WAFConfig


# ── Test definitions ──────────────────────────────────────────────────────────

@dataclass
class _TestCase:
    """A single smoke-test expectation."""

    name: str
    method: str
    path: str
    query_string: str
    body: str
    headers: dict[str, str]
    expect_blocked: bool  # True → threat should be detected
    category_hint: str    # e.g. "sql_injection" (informational only)


_CASES: list[_TestCase] = [
    # ── Clean requests (should be ALLOWED) ────────────────────────────────
    _TestCase(
        name="Clean GET request",
        method="GET",
        path="/api/users",
        query_string="page=1&limit=20",
        body="",
        headers={"User-Agent": "Mozilla/5.0"},
        expect_blocked=False,
        category_hint="none",
    ),
    _TestCase(
        name="Clean POST with JSON body",
        method="POST",
        path="/api/login",
        query_string="",
        body='{"username": "alice", "password": "correct-horse-battery-staple"}',
        headers={"Content-Type": "application/json"},
        expect_blocked=False,
        category_hint="none",
    ),
    _TestCase(
        name="Clean search query",
        method="GET",
        path="/search",
        query_string="q=best+restaurants+near+me",
        body="",
        headers={},
        expect_blocked=False,
        category_hint="none",
    ),

    # ── SQL Injection (should be BLOCKED) ─────────────────────────────────
    _TestCase(
        name="SQLi — OR tautology",
        method="GET",
        path="/search",
        query_string="q=' OR '1'='1",
        body="",
        headers={},
        expect_blocked=True,
        category_hint="sql_injection",
    ),
    _TestCase(
        name="SQLi — UNION SELECT",
        method="GET",
        path="/products",
        query_string="id=1 UNION SELECT username,password FROM users--",
        body="",
        headers={},
        expect_blocked=True,
        category_hint="sql_injection",
    ),
    _TestCase(
        name="SQLi — DROP TABLE",
        method="POST",
        path="/form",
        query_string="",
        body="name=admin'; DROP TABLE users;--",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        expect_blocked=True,
        category_hint="sql_injection",
    ),
    _TestCase(
        name="SQLi — time-based blind (SLEEP)",
        method="GET",
        path="/item",
        query_string="id=1 AND SLEEP(5)",
        body="",
        headers={},
        expect_blocked=True,
        category_hint="sql_injection",
    ),

    # ── Cross-Site Scripting (should be BLOCKED) ──────────────────────────
    _TestCase(
        name="XSS — script tag",
        method="GET",
        path="/search",
        query_string="q=<script>alert('xss')</script>",
        body="",
        headers={},
        expect_blocked=True,
        category_hint="xss",
    ),
    _TestCase(
        name="XSS — img onerror",
        method="GET",
        path="/profile",
        query_string="bio=<img src=x onerror=alert(1)>",
        body="",
        headers={},
        expect_blocked=True,
        category_hint="xss",
    ),
    _TestCase(
        name="XSS — javascript: URI",
        method="GET",
        path="/redirect",
        query_string="url=javascript:alert(document.cookie)",
        body="",
        headers={},
        expect_blocked=True,
        category_hint="xss",
    ),

    # ── Command Injection (should be BLOCKED) ─────────────────────────────
    _TestCase(
        name="CMDi — semicolon chaining",
        method="GET",
        path="/ping",
        query_string="host=127.0.0.1;cat /etc/passwd",
        body="",
        headers={},
        expect_blocked=True,
        category_hint="command_injection",
    ),
    _TestCase(
        name="CMDi — backtick execution",
        method="GET",
        path="/lookup",
        query_string="domain=`whoami`",
        body="",
        headers={},
        expect_blocked=True,
        category_hint="command_injection",
    ),

    # ── Path Traversal (should be BLOCKED) ────────────────────────────────
    _TestCase(
        name="Path traversal — ../../etc/passwd",
        method="GET",
        path="/files/../../etc/passwd",
        query_string="",
        body="",
        headers={},
        expect_blocked=True,
        category_hint="path_traversal",
    ),

    # ── SSRF (should be BLOCKED) ──────────────────────────────────────────
    _TestCase(
        name="SSRF — localhost",
        method="GET",
        path="/proxy",
        query_string="url=http://127.0.0.1:8080/admin",
        body="",
        headers={},
        expect_blocked=True,
        category_hint="ssrf",
    ),
    _TestCase(
        name="SSRF — cloud metadata",
        method="GET",
        path="/fetch",
        query_string="url=http://169.254.169.254/latest/meta-data/",
        body="",
        headers={},
        expect_blocked=True,
        category_hint="ssrf",
    ),

    # ── XXE (should be BLOCKED) ───────────────────────────────────────────
    _TestCase(
        name="XXE — DOCTYPE ENTITY",
        method="POST",
        path="/xml",
        query_string="",
        body='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        headers={"Content-Type": "application/xml"},
        expect_blocked=True,
        category_hint="xxe",
    ),

    # ── Scanner Detection (should be BLOCKED) ────────────────────────────
    _TestCase(
        name="Scanner — sqlmap User-Agent",
        method="GET",
        path="/",
        query_string="",
        body="",
        headers={"User-Agent": "sqlmap/1.7"},
        expect_blocked=True,
        category_hint="scanner",
    ),
]


# ── Runner ────────────────────────────────────────────────────────────────────

_GREEN = "\033[92m"
_RED = "\033[91m"
_YELLOW = "\033[93m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _run(engine: WAFEngine, *, mode: str) -> bool:
    """Run all test cases and return True if every check passed."""
    passed = 0
    failed = 0
    total = len(_CASES)

    print(f"\n{_BOLD}{'='*70}")
    print(f" AI-WAF Smoke Test  —  mode={mode}  ({total} test cases)")
    print(f"{'='*70}{_RESET}\n")

    for tc in _CASES:
        decision = engine.evaluate(
            client_ip="127.0.0.1",
            method=tc.method,
            path=tc.path,
            query_string=tc.query_string,
            headers=tc.headers,
            body=tc.body,
        )

        # In block mode: threat_detected should match expect_blocked
        # In monitor mode: threat_detected should still be True for attacks,
        #   but allow=True (not blocked)
        detected = decision.threat_detected

        if mode == "block":
            ok = detected == tc.expect_blocked
        else:
            # monitor mode — attacks should still be *detected* even if allowed
            ok = detected == tc.expect_blocked

        status = f"{_GREEN}PASS{_RESET}" if ok else f"{_RED}FAIL{_RESET}"
        blocked_label = "BLOCKED" if not decision.allow else "ALLOWED"

        if ok:
            passed += 1
        else:
            failed += 1

        extra = ""
        if decision.rule_matches:
            ids = [m.rule.rule_id for m in decision.rule_matches]
            extra = f"  rules={ids}"
        if decision.ml_result and decision.ml_result.is_threat:
            extra += f"  ml={decision.ml_result.label}({decision.ml_result.confidence:.2f})"

        print(
            f"  [{status}] {tc.name:<45s} "
            f"expect={'BLOCK' if tc.expect_blocked else 'ALLOW':<6s} "
            f"got={blocked_label:<8s} "
            f"score={decision.combined_score:.2f}"
            f"{extra}"
        )

    print(f"\n{_BOLD}{'─'*70}")
    color = _GREEN if failed == 0 else _RED
    print(f" Result: {color}{passed}/{total} passed{_RESET}")
    if failed:
        print(f" {_RED}{failed} test(s) FAILED{_RESET}")
    print(f"{_BOLD}{'─'*70}{_RESET}\n")

    return failed == 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run AI-WAF smoke tests (no network required)."
    )
    parser.add_argument(
        "--ml",
        action="store_true",
        default=False,
        help="Enable ML detector (requires trained model; default: rules only).",
    )
    parser.add_argument(
        "--mode",
        choices=["block", "monitor"],
        default="block",
        help="WAF enforcement mode (default: block).",
    )
    args = parser.parse_args()

    config = WAFConfig(
        enable_ml=args.ml,
        enable_rules=True,
        mode=args.mode,
        rate_limit_enabled=False,  # disable for smoke tests
    )
    engine = WAFEngine(config=config)

    if args.ml:
        engine.warm_up()

    ok = _run(engine, mode=args.mode)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
