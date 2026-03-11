"""WAF core proxy and request handling."""

from waf.core.request_parser import ParsedRequest, parse_flask_request
from waf.core.response_handler import DetectionResult
from waf.core.proxy import create_app

__all__ = [
    "ParsedRequest",
    "parse_flask_request",
    "DetectionResult",
    "create_app",
]
