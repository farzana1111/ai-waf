"""Tests for the WAF reverse-proxy Flask application."""

from flask import Flask

from waf.core.proxy import create_app


class TestCreateApp:
    """Tests for the ``create_app`` factory."""

    def test_returns_flask_app(self):
        app = create_app()
        assert isinstance(app, Flask)

    def test_app_has_waf_settings(self):
        app = create_app()
        assert "WAF_SETTINGS" in app.config

    def test_create_app_with_dict_config(self):
        app = create_app(config={"EXTRA": "value"})
        assert isinstance(app, Flask)
        assert app.config.get("EXTRA") == "value"


class TestHealthEndpoint:
    """Tests for the ``/health`` endpoint."""

    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_returns_json(self, client):
        resp = client.get("/health")
        data = resp.get_json()
        assert data == {"status": "healthy"}

    def test_health_content_type(self, client):
        resp = client.get("/health")
        assert "application/json" in resp.content_type


class TestUnknownRoutes:
    """Requests to arbitrary paths are intercepted by the WAF pipeline."""

    def test_unknown_route_does_not_500(self, client):
        resp = client.get("/nonexistent")
        # The proxy will attempt to forward to backend which will fail,
        # resulting in a 502 Bad Gateway (not a 500 server error).
        assert resp.status_code in (404, 502)

    def test_post_to_unknown_route(self, client):
        resp = client.post("/some/path", data="test body")
        assert resp.status_code in (404, 502)
