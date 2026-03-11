"""Tests for the rule engine."""

import pytest

from waf.rules.rule_engine import RuleEngine
from waf.rules.rule_loader import load_default_rules
from tests.conftest import make_parsed_request


@pytest.fixture()
def engine():
    return RuleEngine()


@pytest.fixture()
def engine_with_defaults():
    eng = RuleEngine()
    eng.load_rules(load_default_rules())
    return eng


SAMPLE_RULES = [
    {
        "id": "TEST-001",
        "name": "Test SQLi Rule",
        "pattern": r"(?i)\bUNION\b.*\bSELECT\b",
        "target": "all",
        "severity": "high",
        "action": "block",
    },
    {
        "id": "TEST-002",
        "name": "Test XSS Rule",
        "pattern": r"(?i)<\s*script",
        "target": "all",
        "severity": "high",
        "action": "block",
    },
    {
        "id": "TEST-003",
        "name": "Test Info Rule",
        "pattern": r"(?i)debug=true",
        "target": "url",
        "severity": "info",
        "action": "log",
    },
]


class TestRuleLoading:
    """Test loading and managing rules."""

    def test_load_rules(self, engine):
        engine.load_rules(SAMPLE_RULES)
        assert len(engine.get_rules()) == 3

    def test_load_rules_replaces_previous(self, engine):
        engine.load_rules(SAMPLE_RULES)
        engine.load_rules(SAMPLE_RULES[:1])
        assert len(engine.get_rules()) == 1

    def test_get_rules_returns_copy(self, engine):
        engine.load_rules(SAMPLE_RULES)
        rules = engine.get_rules()
        rules.clear()
        assert len(engine.get_rules()) == 3

    def test_add_rule(self, engine):
        engine.load_rules(SAMPLE_RULES[:1])
        engine.add_rule(SAMPLE_RULES[1])
        assert len(engine.get_rules()) == 2

    def test_invalid_regex_skipped(self, engine):
        bad_rules = [
            {
                "id": "BAD", "name": "Bad Rule", "pattern": "[invalid(",
                "target": "all", "severity": "high", "action": "block",
            },
        ]
        engine.load_rules(bad_rules)
        # Rule is stored but the invalid regex won't match anything
        req = make_parsed_request(query_params={"q": "anything"})
        results = engine.evaluate(req)
        assert len(results) == 0


class TestDefaultRules:
    """Test that default rules load and work correctly."""

    def test_default_rules_load(self):
        rules = load_default_rules()
        assert len(rules) > 0

    def test_default_rules_have_required_fields(self):
        rules = load_default_rules()
        required = {"id", "name", "pattern", "target", "severity", "action"}
        for rule in rules:
            assert required.issubset(set(rule.keys())), f"Rule {rule.get('id')} missing fields"

    def test_default_rules_loaded_in_engine(self, engine_with_defaults):
        rules = engine_with_defaults.get_rules()
        assert len(rules) >= 8


class TestSQLiRuleMatching:
    """Test rule matching for SQL injection patterns."""

    def test_union_select_detected(self, engine_with_defaults):
        req = make_parsed_request(query_params={"id": "1 UNION SELECT * FROM users"})
        results = engine_with_defaults.evaluate(req)
        assert len(results) > 0
        assert any(r.is_threat for r in results)

    def test_drop_table_detected(self, engine_with_defaults):
        req = make_parsed_request(body="DROP TABLE users")
        results = engine_with_defaults.evaluate(req)
        assert any(r.is_threat for r in results)

    def test_delete_from_detected(self, engine_with_defaults):
        req = make_parsed_request(body="DELETE FROM users WHERE 1=1")
        results = engine_with_defaults.evaluate(req)
        assert any(r.is_threat for r in results)

    def test_sql_comment_detected(self, engine_with_defaults):
        req = make_parsed_request(query_params={"id": "1' -- "})
        results = engine_with_defaults.evaluate(req)
        assert len(results) > 0


class TestXSSRuleMatching:
    """Test rule matching for XSS patterns."""

    def test_script_tag_detected(self, engine_with_defaults):
        req = make_parsed_request(query_params={"q": "<script>alert(1)</script>"})
        results = engine_with_defaults.evaluate(req)
        assert any(r.is_threat for r in results)

    def test_event_handler_detected(self, engine_with_defaults):
        req = make_parsed_request(query_params={"q": '<img onerror=alert(1)>'})
        results = engine_with_defaults.evaluate(req)
        assert any(r.is_threat for r in results)

    def test_javascript_uri_detected(self, engine_with_defaults):
        req = make_parsed_request(query_params={"q": "javascript:alert(1)"})
        results = engine_with_defaults.evaluate(req)
        assert any(r.is_threat for r in results)


class TestCleanRequestsPassing:
    """Clean requests should not trigger any rules."""

    @pytest.mark.parametrize("path,params", [
        ("/", {}),
        ("/search", {"q": "hello world"}),
        ("/users/123", {}),
        ("/api/data", {"page": "1", "limit": "10"}),
    ])
    def test_clean_request_no_matches(self, engine_with_defaults, path, params):
        req = make_parsed_request(path=path, query_params=params)
        results = engine_with_defaults.evaluate(req)
        assert len(results) == 0


class TestRuleTargets:
    """Test that rules respect their target field."""

    def test_url_target_matches_path(self, engine):
        rules = [
            {
                "id": "T1", "name": "URL Rule", "pattern": r"admin",
                "target": "url", "severity": "high", "action": "block",
            },
        ]
        engine.load_rules(rules)
        req = make_parsed_request(path="/admin/panel")
        results = engine.evaluate(req)
        assert len(results) == 1

    def test_body_target_ignores_url(self, engine):
        rules = [
            {
                "id": "T2", "name": "Body Rule", "pattern": r"secret",
                "target": "body", "severity": "high", "action": "block",
            },
        ]
        engine.load_rules(rules)
        req = make_parsed_request(path="/secret", body="nothing here")
        results = engine.evaluate(req)
        assert len(results) == 0

    def test_body_target_matches_body(self, engine):
        rules = [
            {
                "id": "T3", "name": "Body Rule", "pattern": r"secret",
                "target": "body", "severity": "high", "action": "block",
            },
        ]
        engine.load_rules(rules)
        req = make_parsed_request(body="this is a secret")
        results = engine.evaluate(req)
        assert len(results) == 1

    def test_headers_target(self, engine):
        rules = [
            {
                "id": "T4", "name": "Header Rule", "pattern": r"evil-agent",
                "target": "headers", "severity": "medium", "action": "log",
            },
        ]
        engine.load_rules(rules)
        req = make_parsed_request(headers={"User-Agent": "evil-agent/1.0"})
        results = engine.evaluate(req)
        assert len(results) == 1


class TestSeverityConfidence:
    """Verify severity-to-confidence mapping in results."""

    @pytest.mark.parametrize("severity,min_conf,max_conf", [
        ("critical", 0.90, 1.0),
        ("high", 0.80, 0.90),
        ("medium", 0.65, 0.75),
        ("low", 0.45, 0.55),
        ("info", 0.25, 0.35),
    ])
    def test_severity_maps_to_confidence(self, engine, severity, min_conf, max_conf):
        rules = [
            {
                "id": "SEV", "name": "Severity Test", "pattern": r"trigger",
                "target": "all", "severity": severity, "action": "block",
            },
        ]
        engine.load_rules(rules)
        req = make_parsed_request(body="trigger")
        results = engine.evaluate(req)
        assert len(results) == 1
        assert min_conf <= results[0].confidence <= max_conf


class TestDetectionResultFields:
    """Ensure detection results contain the expected metadata."""

    def test_result_has_rule_details(self, engine):
        engine.load_rules(SAMPLE_RULES[:1])
        req = make_parsed_request(query_params={"id": "1 UNION SELECT * FROM users"})
        results = engine.evaluate(req)
        assert len(results) == 1
        result = results[0]
        assert result.is_threat is True
        assert result.source == "rule"
        assert result.details["rule_id"] == "TEST-001"
        assert result.details["rule_name"] == "Test SQLi Rule"
        assert result.details["severity"] == "high"
        assert result.details["action"] == "block"
