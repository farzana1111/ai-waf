"""API key authentication middleware for the WAF management API."""

import functools
import logging

from flask import current_app, jsonify, request

logger = logging.getLogger(__name__)


def validate_api_key(key: str) -> bool:
    """Check whether *key* matches the configured API key.

    The expected key is read from the application's
    ``WAF_SETTINGS.api_key`` at call time so that configuration
    changes take effect without restarting the server.
    """
    if not key:
        return False
    settings = current_app.config.get("WAF_SETTINGS")
    if settings is None:
        return False
    return key == settings.api_key


def require_api_key(f):
    """Decorator that enforces ``X-API-Key`` header authentication.

    Returns a ``401`` JSON response when the header is missing or
    contains an invalid key.
    """

    @functools.wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key", "")
        if not validate_api_key(api_key):
            logger.warning(
                "Unauthorized API request from %s to %s",
                request.remote_addr,
                request.path,
            )
            return jsonify({"error": "Unauthorized", "message": "Invalid or missing API key"}), 401
        return f(*args, **kwargs)

    return decorated
