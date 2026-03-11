"""Tests for waf.core — WAFEngine integration."""

from __future__ import annotations

import pytest

from waf.config import WAFConfig
from waf.core import WAFDecision, WAFEngine


def _make_engine(**kwargs) -> WAFEngine:
    """Return a WAFEngine with ML disabled by default for speed."""
    config = WAFConfig(enable_ml=False, mode="block", **kwargs)
    return WAFEngine(config=config)


class TestWAFEngine:
    def test_clean_request_allowed(self):
        engine = _make_engine()
        decision = engine.evaluate(
            client_ip="1.2.3.4",
            method="GET",
            path="/api/users",
            query_string="page=1",
        )
        assert isinstance(decision, WAFDecision)
        assert decision.allow is True
        assert decision.action == "allow"
        assert decision.threat_detected is False

    def test_sql_injection_blocked(self):
        engine = _make_engine()
        decision = engine.evaluate(
            client_ip="1.2.3.4",
            method="GET",
            path="/search",
            query_string="q=' OR '1'='1 UNION SELECT null--",
        )
        assert decision.allow is False
        assert decision.action == "block"
        assert decision.threat_detected is True
        assert any(m.rule.category == "sql_injection" for m in decision.rule_matches)

    def test_xss_blocked(self):
        engine = _make_engine()
        decision = engine.evaluate(
            client_ip="1.2.3.4",
            method="GET",
            path="/x",
            query_string="q=<script>alert(1)</script>",
        )
        assert decision.threat_detected is True
        assert decision.allow is False

    def test_command_injection_blocked(self):
        engine = _make_engine()
        decision = engine.evaluate(
            client_ip="1.2.3.4",
            method="GET",
            path="/ping",
            query_string="host=127.0.0.1;cat /etc/passwd",
        )
        assert decision.threat_detected is True
        assert decision.allow is False

    def test_monitor_mode_allows_threats(self):
        engine = WAFEngine(config=WAFConfig(enable_ml=False, mode="monitor"))
        decision = engine.evaluate(
            client_ip="1.2.3.4",
            method="GET",
            path="/x",
            query_string="q=<script>alert(1)</script>",
        )
        assert decision.threat_detected is True
        assert decision.allow is True
        assert decision.action == "monitor"

    def test_path_traversal_blocked(self):
        engine = _make_engine()
        decision = engine.evaluate(
            client_ip="1.2.3.4",
            method="GET",
            path="../../etc/passwd",
        )
        assert decision.threat_detected is True

    def test_ssrf_blocked(self):
        engine = _make_engine()
        decision = engine.evaluate(
            client_ip="1.2.3.4",
            method="GET",
            path="/fetch",
            query_string="url=http://127.0.0.1/admin",
        )
        assert decision.threat_detected is True

    def test_scanner_detected(self):
        engine = _make_engine()
        decision = engine.evaluate(
            client_ip="1.2.3.4",
            method="GET",
            path="/admin",
            headers={"User-Agent": "sqlmap/1.0-dev"},
        )
        assert decision.threat_detected is True

    def test_decision_has_request_id(self):
        engine = _make_engine()
        decision = engine.evaluate(client_ip="1.2.3.4", method="GET", path="/x")
        assert decision.request_id
        assert len(decision.request_id) == 36  # UUID format

    def test_decision_latency_positive(self):
        engine = _make_engine()
        decision = engine.evaluate(client_ip="1.2.3.4", method="GET", path="/x")
        assert decision.latency_ms >= 0

    def test_rate_limit_blocks_after_limit(self):
        engine = WAFEngine(
            config=WAFConfig(
                enable_ml=False,
                mode="block",
                rate_limit_enabled=True,
                rate_limit_requests=3,
                rate_limit_window_seconds=60,
            )
        )
        ip = "10.0.0.1"
        results = [
            engine.evaluate(client_ip=ip, method="GET", path="/x")
            for _ in range(5)
        ]
        # First 3 should be allowed (clean request), 4th & 5th rate-limited
        allowed = [r.allow for r in results]
        assert allowed[:3] == [True, True, True]
        assert allowed[3] is False
        assert allowed[4] is False

    def test_rules_disabled_passes_sqli(self):
        engine = WAFEngine(config=WAFConfig(enable_rules=False, enable_ml=False, mode="block"))
        decision = engine.evaluate(
            client_ip="1.2.3.4",
            method="GET",
            path="/x",
            query_string="q=' OR '1'='1",
        )
        # No rules, no ML → should pass
        assert decision.allow is True

    def test_combined_score_bounded(self):
        engine = _make_engine()
        decision = engine.evaluate(
            client_ip="1.2.3.4",
            method="GET",
            path="/x",
            query_string="q=' OR '1'='1 UNION SELECT null--",
        )
        assert 0.0 <= decision.combined_score <= 1.0

    def test_warm_up_does_not_raise(self):
        engine = WAFEngine(config=WAFConfig(enable_ml=False))
        engine.warm_up()  # should not raise even without ML

    def test_xxe_blocked(self):
        engine = _make_engine()
        body = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        decision = engine.evaluate(
            client_ip="1.2.3.4", method="POST", path="/api/xml", body=body
        )
        assert decision.threat_detected is True
