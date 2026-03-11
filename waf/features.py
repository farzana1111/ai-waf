"""HTTP request feature extraction for ML-based threat detection."""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RequestFeatures:
    """Flat feature set extracted from an incoming HTTP request."""

    # Raw text used as input to the TF-IDF vectoriser
    combined_text: str = ""

    # Numeric / boolean features used alongside text
    url_length: int = 0
    body_length: int = 0
    num_params: int = 0
    num_headers: int = 0
    has_cookie: bool = False
    has_auth_header: bool = False

    # Suspicion indicators derived by simple heuristics (NOT rule matches)
    special_char_ratio: float = 0.0
    digit_ratio: float = 0.0
    uppercase_ratio: float = 0.0
    hex_encoded_count: int = 0
    url_encoded_count: int = 0
    null_byte_present: bool = False
    long_param_value: bool = False  # any param value > 200 chars

    # Metadata (not used directly in the model, but useful for logging)
    method: str = ""
    path: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


# ── Helpers ──────────────────────────────────────────────────────────────────

_HEX_RE = re.compile(r"(?:0x[0-9a-fA-F]+|\\x[0-9a-fA-F]{2})", re.IGNORECASE)
_URL_ENC_RE = re.compile(r"%[0-9a-fA-F]{2}", re.IGNORECASE)
_SPECIAL_CHARS = set(r"'\";<>|&`(){}[]\\/=!$@#^*+?~")


def _ratio(text: str, chars: set[str]) -> float:
    if not text:
        return 0.0
    return sum(1 for c in text if c in chars) / len(text)


def _decode_url(value: str) -> str:
    """Best-effort URL-decode a string (handles double-encoding)."""
    try:
        decoded = urllib.parse.unquote_plus(value)
        # One more pass to catch double-encoding
        if decoded != value:
            decoded = urllib.parse.unquote_plus(decoded)
    except Exception:  # noqa: BLE001
        decoded = value
    return decoded


def extract_features(
    *,
    method: str,
    path: str,
    query_string: str = "",
    headers: dict[str, str] | None = None,
    body: str = "",
) -> RequestFeatures:
    """Extract a :class:`RequestFeatures` object from an HTTP request.

    Parameters
    ----------
    method:
        HTTP verb (GET, POST, …).
    path:
        Request path (without query string).
    query_string:
        Raw query string (without leading ``?``).
    headers:
        Mapping of header name → value (case-insensitive lookup works).
    body:
        Raw request body as a string.
    """
    headers = headers or {}
    lower_headers = {k.lower(): v for k, v in headers.items()}

    # ── Parse query parameters ───────────────────────────────────────────────
    parsed_params: list[tuple[str, str]] = urllib.parse.parse_qsl(
        query_string, keep_blank_values=True
    )

    # ── Decode body as form data if applicable ───────────────────────────────
    content_type = lower_headers.get("content-type", "")
    body_params: list[tuple[str, str]] = []
    if "application/x-www-form-urlencoded" in content_type and body:
        try:
            body_params = urllib.parse.parse_qsl(body, keep_blank_values=True)
        except Exception:  # noqa: BLE001
            pass

    all_param_values = [v for _, v in parsed_params + body_params]
    num_params = len(parsed_params) + len(body_params)

    # ── Build combined text for TF-IDF ───────────────────────────────────────
    decoded_path = _decode_url(path)
    decoded_qs = _decode_url(query_string)
    decoded_body = _decode_url(body)

    # Include header values that often carry payloads
    header_text_parts = []
    for hname in ("user-agent", "referer", "x-forwarded-for", "cookie"):
        if hname in lower_headers:
            header_text_parts.append(_decode_url(lower_headers[hname]))

    combined_text = " ".join(
        filter(None, [method, decoded_path, decoded_qs, decoded_body] + header_text_parts)
    )

    # ── Character-level statistics ───────────────────────────────────────────
    all_text = combined_text
    special_char_ratio = _ratio(all_text, _SPECIAL_CHARS)
    digit_ratio = _ratio(all_text, set("0123456789"))
    uppercase_ratio = _ratio(all_text, set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
    hex_encoded_count = len(_HEX_RE.findall(all_text))
    url_encoded_count = len(_URL_ENC_RE.findall(path + query_string + body))
    null_byte_present = "\x00" in all_text or "%00" in (path + query_string + body).lower()
    long_param_value = any(len(v) > 200 for v in all_param_values)

    return RequestFeatures(
        combined_text=combined_text,
        url_length=len(path) + len(query_string),
        body_length=len(body),
        num_params=num_params,
        num_headers=len(headers),
        has_cookie="cookie" in lower_headers,
        has_auth_header="authorization" in lower_headers,
        special_char_ratio=round(special_char_ratio, 4),
        digit_ratio=round(digit_ratio, 4),
        uppercase_ratio=round(uppercase_ratio, 4),
        hex_encoded_count=hex_encoded_count,
        url_encoded_count=url_encoded_count,
        null_byte_present=null_byte_present,
        long_param_value=long_param_value,
        method=method.upper(),
        path=path,
    )
