"""Tests for the WAF management API endpoints."""

import pytest

from waf.api.routes import api, _recent_detections
from waf.core.proxy import create_app


@pytest.fixture()
def app():
    """Create a Flask application with the API blueprint registered."""
    application = create_app()
    application.config["TESTING"] = True
    # Register the API blueprint if not already registered
    if "api" not in application.blueprints:
        application.register_blueprint(api)
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def api_key(app):
    return app.config["WAF_SETTINGS"].api_key


class TestAuthentication:
    """API endpoints require a valid X-API-Key header."""

    def test_missing_api_key_returns_401(self, client):
        resp = client.get("/api/status")
        assert resp.status_code == 401

    def test_wrong_api_key_returns_401(self, client):
        resp = client.get("/api/status", headers={"X-API-Key": "wrong-key-12345"})
        assert resp.status_code == 401

    def test_valid_api_key_succeeds(self, client, api_key):
        resp = client.get("/api/status", headers={"X-API-Key": api_key})
        assert resp.status_code == 200

    def test_unauthorized_response_body(self, client):
        resp = client.get("/api/status")
        data = resp.get_json()
        assert data["error"] == "Unauthorized"
        assert "message" in data


class TestStatusEndpoint:
    """Tests for GET /api/status."""

    def test_status_returns_running(self, client, api_key):
        resp = client.get("/api/status", headers={"X-API-Key": api_key})
        data = resp.get_json()
        assert data["status"] == "running"

    def test_status_has_version(self, client, api_key):
        resp = client.get("/api/status", headers={"X-API-Key": api_key})
        data = resp.get_json()
        assert "version" in data

    def test_status_has_uptime(self, client, api_key):
        resp = client.get("/api/status", headers={"X-API-Key": api_key})
        data = resp.get_json()
        assert "uptime_seconds" in data
        assert isinstance(data["uptime_seconds"], (int, float))

    def test_status_has_mode(self, client, api_key):
        resp = client.get("/api/status", headers={"X-API-Key": api_key})
        data = resp.get_json()
        assert "mode" in data


class TestMetricsEndpoint:
    """Tests for GET /api/metrics."""

    def test_metrics_returns_200(self, client, api_key):
        resp = client.get("/api/metrics", headers={"X-API-Key": api_key})
        assert resp.status_code == 200

    def test_metrics_returns_json(self, client, api_key):
        resp = client.get("/api/metrics", headers={"X-API-Key": api_key})
        data = resp.get_json()
        assert data is not None


class TestRulesEndpoint:
    """Tests for GET/POST /api/rules."""

    def test_list_rules_returns_rules(self, client, api_key):
        resp = client.get("/api/rules", headers={"X-API-Key": api_key})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "rules" in data
        assert "count" in data
        assert isinstance(data["rules"], list)

    def test_list_rules_count_matches(self, client, api_key):
        resp = client.get("/api/rules", headers={"X-API-Key": api_key})
        data = resp.get_json()
        assert data["count"] == len(data["rules"])

    def test_add_rule(self, client, api_key):
        new_rule = {
            "id": "TEST-API-001",
            "name": "API Test Rule",
            "pattern": r"test-pattern",
            "target": "all",
            "severity": "medium",
            "action": "log",
        }
        resp = client.post(
            "/api/rules",
            json=new_rule,
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["message"] == "Rule added"
        assert data["rule_id"] == "TEST-API-001"

    def test_add_rule_missing_fields(self, client, api_key):
        resp = client.post(
            "/api/rules",
            json={"id": "INCOMPLETE"},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data

    def test_add_rule_invalid_json(self, client, api_key):
        resp = client.post(
            "/api/rules",
            data="not json",
            content_type="text/plain",
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 400


class TestThreatsEndpoint:
    """Tests for GET /api/threats."""

    def test_list_threats_returns_200(self, client, api_key):
        resp = client.get("/api/threats", headers={"X-API-Key": api_key})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "threats" in data
        assert "count" in data

    def test_threats_with_limit(self, client, api_key):
        resp = client.get("/api/threats?limit=5", headers={"X-API-Key": api_key})
        assert resp.status_code == 200


class TestRulesEndpointAuth:
    """Rules endpoints also require authentication."""

    def test_list_rules_requires_auth(self, client):
        resp = client.get("/api/rules")
        assert resp.status_code == 401

    def test_add_rule_requires_auth(self, client):
        resp = client.post("/api/rules", json={"id": "X"})
        assert resp.status_code == 401
