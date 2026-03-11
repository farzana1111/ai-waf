"""Tests for waf.rules — rule-based detection engine."""

from __future__ import annotations

import pytest

from waf.rules import (
    ALL_RULES,
    RuleMatch,
    run_rules,
    score_from_matches,
)


class TestRuleEngine:
    # ── SQL Injection ────────────────────────────────────────────────────────
    def test_sqli_tautology(self):
        matches = run_rules(combined_text="' OR '1'='1")
        assert any(m.rule.category == "sql_injection" for m in matches)

    def test_sqli_union_select(self):
        matches = run_rules(combined_text="1 UNION SELECT null,null FROM users")
        assert any(m.rule.rule_id == "SQLi-002" for m in matches)

    def test_sqli_exec_xp_cmdshell(self):
        matches = run_rules(combined_text="1; EXEC xp_cmdshell('dir')")
        assert any(m.rule.category == "sql_injection" for m in matches)

    def test_sqli_sleep(self):
        matches = run_rules(combined_text="1' AND SLEEP(5)--")
        assert any(m.rule.rule_id == "SQLi-008" for m in matches)

    def test_sqli_drop_table(self):
        matches = run_rules(combined_text="'; DROP TABLE users--")
        assert any(m.rule.category == "sql_injection" for m in matches)

    # ── XSS ─────────────────────────────────────────────────────────────────
    def test_xss_script_tag(self):
        matches = run_rules(combined_text="<script>alert(1)</script>")
        assert any(m.rule.rule_id == "XSS-001" for m in matches)

    def test_xss_onerror(self):
        matches = run_rules(combined_text="<img src=x onerror=alert(1)>")
        assert any(m.rule.category == "xss" for m in matches)

    def test_xss_javascript_uri(self):
        matches = run_rules(combined_text="javascript:alert(document.cookie)")
        assert any(m.rule.rule_id == "XSS-003" for m in matches)

    def test_xss_dom_sink(self):
        matches = run_rules(combined_text="document.write(location.hash)")
        assert any(m.rule.category == "xss" for m in matches)

    # ── Command Injection ────────────────────────────────────────────────────
    def test_cmdi_pipe(self):
        matches = run_rules(combined_text="127.0.0.1;cat /etc/passwd")
        assert any(m.rule.category == "command_injection" for m in matches)

    def test_cmdi_backtick(self):
        matches = run_rules(combined_text="`whoami`")
        assert any(m.rule.category == "command_injection" for m in matches)

    def test_cmdi_dollar_subshell(self):
        matches = run_rules(combined_text="$(id)")
        assert any(m.rule.category == "command_injection" for m in matches)

    # ── Path Traversal ───────────────────────────────────────────────────────
    def test_path_traversal_dotdot(self):
        matches = run_rules(
            combined_text="../../etc/passwd",
            path="../../etc/passwd",
        )
        assert any(m.rule.category == "path_traversal" for m in matches)

    def test_path_traversal_url_encoded(self):
        matches = run_rules(combined_text="%2e%2e%2fetc%2fpasswd")
        assert any(m.rule.category == "path_traversal" for m in matches)

    # ── LDAP Injection ───────────────────────────────────────────────────────
    def test_ldap_special_chars(self):
        matches = run_rules(combined_text="*)(uid=*))(|(uid=*")
        assert any(m.rule.category == "ldap_injection" for m in matches)

    # ── XXE ──────────────────────────────────────────────────────────────────
    def test_xxe_system_entity(self):
        matches = run_rules(
            combined_text='<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        )
        assert any(m.rule.category == "xxe" for m in matches)

    # ── SSRF ─────────────────────────────────────────────────────────────────
    def test_ssrf_localhost(self):
        matches = run_rules(combined_text="http://localhost/admin")
        assert any(m.rule.category == "ssrf" for m in matches)

    def test_ssrf_metadata(self):
        matches = run_rules(combined_text="http://169.254.169.254/latest/meta-data/")
        assert any(m.rule.category == "ssrf" for m in matches)

    # ── Scanner detection ────────────────────────────────────────────────────
    def test_scanner_sqlmap(self):
        matches = run_rules(
            combined_text="GET /x", user_agent="sqlmap/1.0-dev"
        )
        assert any(m.rule.category == "scanner" for m in matches)

    def test_scanner_nikto(self):
        matches = run_rules(combined_text="GET /x", user_agent="Nikto/2.1.6")
        assert any(m.rule.category == "scanner" for m in matches)

    # ── Clean requests ───────────────────────────────────────────────────────
    def test_clean_request_no_matches(self):
        matches = run_rules(combined_text="GET /api/users?page=1&limit=20")
        # May have 0 matches — if any matched, none should be critical
        assert all(m.rule.severity != "critical" for m in matches)

    def test_normal_search_query_no_critical_matches(self):
        matches = run_rules(combined_text="GET /search?q=hello+world&lang=en")
        assert not any(m.rule.severity == "critical" for m in matches)

    # ── Score calculation ────────────────────────────────────────────────────
    def test_score_zero_for_empty_matches(self):
        assert score_from_matches([]) == 0.0

    def test_score_positive_for_matches(self):
        matches = run_rules(combined_text="' OR '1'='1 UNION SELECT null--")
        if matches:
            assert score_from_matches(matches) > 0.0

    def test_score_bounded(self):
        matches = run_rules(
            combined_text=(
                "'; DROP TABLE users; EXEC xp_cmdshell('id'); "
                "UNION SELECT null,null FROM information_schema.tables--"
            )
        )
        score = score_from_matches(matches)
        assert 0.0 <= score <= 1.0

    # ── Rule catalogue ───────────────────────────────────────────────────────
    def test_all_rules_have_unique_ids(self):
        ids = [r.rule_id for r in ALL_RULES]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs detected"

    def test_all_rules_have_valid_category(self):
        valid_cats = {
            "sql_injection", "xss", "command_injection", "path_traversal",
            "ldap_injection", "xxe", "ssrf", "rce", "scanner", "suspicious",
        }
        for rule in ALL_RULES:
            assert rule.category in valid_cats

    def test_all_rules_have_valid_severity(self):
        valid_sev = {"low", "medium", "high", "critical"}
        for rule in ALL_RULES:
            assert rule.severity in valid_sev
