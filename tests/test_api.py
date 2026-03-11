"""Tests for waf.api — FastAPI endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from waf.api import create_app
from waf.config import WAFConfig


@pytest.fixture(scope="module")
def client() -> TestClient:
    cfg = WAFConfig(enable_ml=False, mode="block")
    app = create_app(config=cfg)
    return TestClient(app, raise_server_exceptions=True)


class TestHealthAndStats:
    def test_health_ok(self, client: TestClient):
        resp = client.get("/waf/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "uptime_seconds" in data

    def test_stats_structure(self, client: TestClient):
        resp = client.get("/waf/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_requests" in data
        assert "threats_detected" in data
        assert "requests_blocked" in data


class TestEvaluateEndpoint:
    def test_clean_request(self, client: TestClient):
        resp = client.post(
            "/waf/evaluate",
            json={
                "method": "GET",
                "path": "/api/users",
                "query_string": "page=1",
                "client_ip": "1.2.3.4",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["allow"] is True
        assert data["threat_detected"] is False
        assert data["action"] == "allow"

    def test_sqli_request_blocked(self, client: TestClient):
        resp = client.post(
            "/waf/evaluate",
            json={
                "method": "GET",
                "path": "/search",
                "query_string": "q=' OR '1'='1 UNION SELECT null--",
                "client_ip": "1.2.3.4",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["threat_detected"] is True
        assert data["allow"] is False
        assert data["action"] == "block"
        assert len(data["rule_matches"]) > 0

    def test_xss_request_blocked(self, client: TestClient):
        resp = client.post(
            "/waf/evaluate",
            json={
                "method": "GET",
                "path": "/x",
                "query_string": "q=<script>alert(1)</script>",
                "client_ip": "1.2.3.4",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["threat_detected"] is True
        assert data["allow"] is False

    def test_response_has_request_id(self, client: TestClient):
        resp = client.post(
            "/waf/evaluate",
            json={"method": "GET", "path": "/x", "client_ip": "1.2.3.4"},
        )
        assert resp.status_code == 200
        assert "request_id" in resp.json()

    def test_rule_match_details_present(self, client: TestClient):
        resp = client.post(
            "/waf/evaluate",
            json={
                "method": "GET",
                "path": "/x",
                "query_string": "q=<script>alert(1)</script>",
                "client_ip": "1.2.3.4",
            },
        )
        data = resp.json()
        assert data["threat_detected"] is True
        match = data["rule_matches"][0]
        assert "rule_id" in match
        assert "category" in match
        assert "severity" in match
        assert "description" in match

    def test_path_traversal_blocked(self, client: TestClient):
        resp = client.post(
            "/waf/evaluate",
            json={
                "method": "GET",
                "path": "../../etc/passwd",
                "client_ip": "1.2.3.4",
            },
        )
        data = resp.json()
        assert data["threat_detected"] is True

    def test_combined_score_present(self, client: TestClient):
        resp = client.post(
            "/waf/evaluate",
            json={"method": "GET", "path": "/x", "client_ip": "1.2.3.4"},
        )
        data = resp.json()
        assert "combined_score" in data
        assert 0.0 <= data["combined_score"] <= 1.0


class TestProxyBlocking:
    """Test the proxy route blocks threats even without a real upstream."""

    def test_sqli_returns_403(self, client: TestClient):
        resp = client.get("/search?q=' OR '1'='1 UNION SELECT null--")
        assert resp.status_code == 403
        body = resp.json()
        assert body["error"] == "Forbidden"
        assert "request_id" in body

    def test_xss_returns_403(self, client: TestClient):
        resp = client.get("/x?q=<script>alert(1)</script>")
        assert resp.status_code == 403

    def test_waf_request_id_header_on_block(self, client: TestClient):
        resp = client.get("/x?q=<script>alert(1)</script>")
        assert "x-waf-request-id" in resp.headers

    def test_clean_request_proxied_or_502(self, client: TestClient):
        """Clean requests should either proxy (upstream not running → 502) or succeed."""
        resp = client.get("/api/users?page=1")
        assert resp.status_code in {200, 502, 504}
