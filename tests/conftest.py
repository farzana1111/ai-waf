"""Shared fixtures for the AI-WAF test suite."""

import pathlib

import pytest

from waf.core.proxy import create_app
from waf.core.request_parser import ParsedRequest

PAYLOADS_DIR = pathlib.Path(__file__).parent / "payloads"


@pytest.fixture()
def app():
    """Create a Flask application configured for testing."""
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture()
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture()
def api_key(app):
    """Return the configured API key for the test app."""
    return app.config["WAF_SETTINGS"].api_key


def make_parsed_request(**kwargs) -> ParsedRequest:
    """Helper to build a ``ParsedRequest`` with sensible defaults."""
    defaults = {
        "method": "GET",
        "path": "/",
        "query_params": {},
        "headers": {},
        "body": "",
        "cookies": {},
        "user_agent": "test-agent",
        "client_ip": "127.0.0.1",
        "content_type": "text/html",
        "request_id": "test-request-id",
    }
    defaults.update(kwargs)
    return ParsedRequest(**defaults)


def load_payloads(filename: str) -> list[str]:
    """Load newline-delimited payloads from the payloads directory."""
    filepath = PAYLOADS_DIR / filename
    return [
        line
        for line in filepath.read_text().splitlines()
        if line.strip()
    ]
