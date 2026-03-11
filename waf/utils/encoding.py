"""URL, HTML, and Base64 decoding utilities for input normalization.

Provides functions to decode various encoding schemes commonly used
in web attacks to obfuscate payloads. Handles nested and mixed encodings
by applying decodings recursively until the input stabilizes.
"""

import base64
import html
import re
import urllib.parse

_MAX_DECODE_ITERATIONS = 10


def url_decode(value: str) -> str:
    """Recursively URL-decode a string until no further decoding occurs.

    Args:
        value: The URL-encoded string to decode.

    Returns:
        The fully URL-decoded string.

    Examples:
        >>> url_decode('%3Cscript%3E')
        '<script>'
        >>> url_decode('%253Cscript%253E')
        '<script>'
    """
    previous = None
    current = value
    while current != previous:
        previous = current
        current = urllib.parse.unquote(current)
    return current


def html_decode(value: str) -> str:
    """Decode HTML entities in a string.

    Handles both named entities (e.g. &amp;) and numeric entities
    (e.g. &#60; or &#x3C;).

    Args:
        value: The HTML-encoded string to decode.

    Returns:
        The decoded string with all HTML entities resolved.

    Examples:
        >>> html_decode('&lt;script&gt;')
        '<script>'
        >>> html_decode('&#60;script&#62;')
        '<script>'
    """
    previous = None
    current = value
    while current != previous:
        previous = current
        current = html.unescape(current)
    return current


def base64_decode(value: str) -> str:
    """Safely decode a base64-encoded string.

    Returns the decoded text if the value is valid base64 and decodes
    to valid UTF-8; otherwise returns the original value unchanged.

    Args:
        value: The potentially base64-encoded string.

    Returns:
        The decoded string, or the original value if decoding fails.

    Examples:
        >>> base64_decode('PHNjcmlwdD4=')
        '<script>'
        >>> base64_decode('not-base64!!')
        'not-base64!!'
    """
    stripped = value.strip().replace('\n', '').replace('\r', '')
    if not stripped:
        return value

    if not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', stripped):
        return value

    try:
        decoded_bytes = base64.b64decode(stripped, validate=True)
        return decoded_bytes.decode('utf-8')
    except Exception:
        return value


def decode_all(value: str) -> str:
    """Apply all decodings recursively to fully normalize input.

    Repeatedly applies URL decoding, HTML entity decoding, and base64
    decoding until the value stabilizes (no further changes). This
    catches nested and mixed encoding schemes such as base64-encoded
    URL-encoded payloads.

    Args:
        value: The encoded string to normalize.

    Returns:
        The fully decoded and normalized string.

    Examples:
        >>> decode_all('%3Cscript%3E')
        '<script>'
        >>> decode_all('PHNjcmlwdD4=')
        '<script>'
    """
    previous = None
    current = value

    for _ in range(_MAX_DECODE_ITERATIONS):
        if current == previous:
            break
        previous = current
        current = url_decode(current)
        current = html_decode(current)
        current = base64_decode(current)

    return current
