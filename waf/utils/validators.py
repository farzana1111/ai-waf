"""Input validation helpers for WAF request inspection.

Provides pure functions for validating and sanitizing common HTTP
request components such as IP addresses, URLs, methods, headers,
and content types.
"""

import ipaddress
import re
import urllib.parse

_VALID_HTTP_METHODS = frozenset({
    'GET', 'HEAD', 'POST', 'PUT', 'DELETE',
    'CONNECT', 'OPTIONS', 'TRACE', 'PATCH',
})

_SAFE_CONTENT_TYPES = frozenset({
    'application/json',
    'application/x-www-form-urlencoded',
    'multipart/form-data',
    'text/plain',
    'text/html',
    'text/xml',
    'application/xml',
    'application/graphql',
    'application/octet-stream',
})

# Strip ASCII control characters except HT (\x09), LF (\x0a), CR (\x0d)
# which are permitted in HTTP header values per RFC 7230.
_DANGEROUS_HEADER_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def is_valid_ip(ip: str) -> bool:
    """Validate whether a string is a valid IPv4 or IPv6 address.

    Args:
        ip: The string to validate.

    Returns:
        True if the string is a valid IP address, False otherwise.

    Examples:
        >>> is_valid_ip('192.168.1.1')
        True
        >>> is_valid_ip('::1')
        True
        >>> is_valid_ip('999.999.999.999')
        False
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_url(url: str) -> bool:
    """Perform basic URL validation.

    Checks that the URL has a valid scheme (http or https) and a
    non-empty network location (hostname).

    Args:
        url: The URL string to validate.

    Returns:
        True if the URL has a valid scheme and hostname, False otherwise.

    Examples:
        >>> is_valid_url('https://example.com/path')
        True
        >>> is_valid_url('ftp://example.com')
        False
        >>> is_valid_url('not-a-url')
        False
    """
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.scheme in ('http', 'https') and bool(parsed.netloc)
    except Exception:
        return False


def is_valid_method(method: str) -> bool:
    """Check whether a string is a valid HTTP method.

    Comparison is case-insensitive.

    Args:
        method: The HTTP method string to validate.

    Returns:
        True if the method is a standard HTTP method, False otherwise.

    Examples:
        >>> is_valid_method('GET')
        True
        >>> is_valid_method('post')
        True
        >>> is_valid_method('HACK')
        False
    """
    return method.upper() in _VALID_HTTP_METHODS


def sanitize_header_value(value: str) -> str:
    """Strip dangerous characters from an HTTP header value.

    Removes ASCII control characters (except HT, LF, CR which are
    permitted in HTTP headers) that could be used for header injection
    or response splitting attacks.

    Args:
        value: The raw header value to sanitize.

    Returns:
        The sanitized header value with dangerous characters removed.

    Examples:
        >>> sanitize_header_value('normalvalue')
        'normalvalue'
        >>> sanitize_header_value('value\\x00with\\x01control')
        'valuewithcontrol'
    """
    return _DANGEROUS_HEADER_RE.sub('', value)


def is_safe_content_type(content_type: str) -> bool:
    """Check whether a Content-Type is in the allowed whitelist.

    Only the media type portion is checked; parameters such as charset
    or boundary are ignored.

    Args:
        content_type: The Content-Type header value to check.

    Returns:
        True if the base media type is whitelisted, False otherwise.

    Examples:
        >>> is_safe_content_type('application/json')
        True
        >>> is_safe_content_type('application/json; charset=utf-8')
        True
        >>> is_safe_content_type('application/x-evil')
        False
    """
    media_type = content_type.strip().split(';', 1)[0].strip().lower()
    return media_type in _SAFE_CONTENT_TYPES
