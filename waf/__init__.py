"""AI-Powered Web Application Firewall package."""

try:
    from waf.engine import WAFEngine
    from waf.waf_config import WAFConfig

    __all__ = ["WAFEngine", "WAFConfig"]
except ImportError:
    __all__ = []
