"""HTTP request parsing and normalization for the WAF pipeline.

Converts framework-specific request objects into a unified
``ParsedRequest`` representation with all values decoded and
normalized so that downstream detection engines operate on
clean, canonical input.
"""

import uuid
from dataclasses import dataclass, field
from urllib.parse import parse_qs

from waf.utils.encoding import decode_all


@dataclass
class ParsedRequest:
    """Normalized representation of an incoming HTTP request."""

    method: str = ""
    path: str = ""
    query_params: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    user_agent: str = ""
    client_ip: str = ""
    content_type: str = ""
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))


def normalize_value(value: str) -> str:
    """Decode and normalize a single string value.

    Applies URL, HTML-entity, and base64 decoding recursively until the
    value stabilizes.  Returns the original value when *value* is not a
    string.
    """
    if not isinstance(value, str):
        return value
    return decode_all(value)


def parse_query_string(qs: str) -> dict[str, str]:
    """Parse a raw query string into a dict of normalized values.

    Multi-valued keys are joined with commas.  Both keys and values are
    run through :func:`normalize_value`.
    """
    parsed = parse_qs(qs, keep_blank_values=True)
    result: dict[str, str] = {}
    for key, values in parsed.items():
        normalized_key = normalize_value(key)
        normalized_values = [normalize_value(v) for v in values]
        result[normalized_key] = ",".join(normalized_values)
    return result


def parse_flask_request(flask_request) -> ParsedRequest:
    """Convert a Flask/Werkzeug request object into a :class:`ParsedRequest`.

    All header values, query parameters, cookies, and body text are
    normalized through :func:`normalize_value` so that detection engines
    receive decoded input.
    """
    headers = {
        key: normalize_value(value)
        for key, value in flask_request.headers
    }

    query_params = parse_query_string(flask_request.query_string.decode("utf-8", errors="replace"))

    cookies = {
        key: normalize_value(value)
        for key, value in flask_request.cookies.items()
    }

    body = ""
    try:
        raw = flask_request.get_data(as_text=True)
        body = normalize_value(raw) if raw else ""
    except Exception:
        body = ""

    return ParsedRequest(
        method=flask_request.method,
        path=normalize_value(flask_request.path),
        query_params=query_params,
        headers=headers,
        body=body,
        cookies=cookies,
        user_agent=normalize_value(flask_request.user_agent.string or ""),
        client_ip=flask_request.remote_addr or "",
        content_type=flask_request.content_type or "",
        request_id=str(uuid.uuid4()),
    )
