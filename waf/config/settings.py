"""Configuration loader for AI-WAF.

Reads configuration from default_config.yaml and allows overrides
via environment variables prefixed with WAF_.
"""

import os
from pathlib import Path
from typing import Any

import yaml


_DEFAULT_CONFIG_PATH = Path(__file__).parent / "default_config.yaml"


def _deep_merge(base: dict, overrides: dict) -> dict:
    """Recursively merge *overrides* into *base*, returning a new dict."""
    merged = base.copy()
    for key, value in overrides.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_yaml(path: Path) -> dict:
    """Load a YAML file and return its contents as a dictionary."""
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


class Settings:
    """Centralised configuration for the WAF.

    Resolution order (highest priority wins):
      1. Environment variables (``WAF_*``)
      2. User-supplied config YAML (``WAF_CONFIG_PATH``)
      3. ``default_config.yaml`` shipped with the package
    """

    _ENV_MAP: dict[str, tuple[str, ...]] = {
        "WAF_MODE": ("waf", "mode"),
        "WAF_BACKEND_URL": ("waf", "backend_url"),
        "WAF_LISTEN_HOST": ("waf", "listen_host"),
        "WAF_LISTEN_PORT": ("waf", "listen_port"),
        "WAF_SECRET_KEY": ("security", "secret_key"),
        "WAF_API_KEY": ("security", "api_key"),
        "WAF_LOG_LEVEL": ("logging", "level"),
        "WAF_LOG_FORMAT": ("logging", "format"),
        "WAF_LOG_FILE": ("logging", "file"),
        "WAF_MODEL_DIR": ("models", "directory"),
        "WAF_METRICS_PORT": ("metrics", "port"),
    }

    def __init__(self, config_path: str | Path | None = None) -> None:
        config_path = config_path or os.environ.get("WAF_CONFIG_PATH")
        self._data = _load_yaml(_DEFAULT_CONFIG_PATH)

        if config_path:
            user_cfg = _load_yaml(Path(config_path))
            self._data = _deep_merge(self._data, user_cfg)

        self._apply_env_overrides()

    def _apply_env_overrides(self) -> None:
        """Override config values with matching environment variables."""
        for env_var, key_path in self._ENV_MAP.items():
            value = os.environ.get(env_var)
            if value is None:
                continue
            node = self._data
            for key in key_path[:-1]:
                node = node.setdefault(key, {})
            # Coerce to int when the existing value is an int
            existing = node.get(key_path[-1])
            if isinstance(existing, int):
                try:
                    value = int(value)
                except ValueError:
                    pass
            node[key_path[-1]] = value

    def get(self, *keys: str, default: Any = None) -> Any:
        """Retrieve a nested config value by key path.

        Example::

            settings.get("detection", "sqli", "threshold")
        """
        node = self._data
        for key in keys:
            if isinstance(node, dict):
                node = node.get(key)
            else:
                return default
            if node is None:
                return default
        return node

    # -- Convenience properties -------------------------------------------

    @property
    def mode(self) -> str:
        return self.get("waf", "mode", default="detect")

    @property
    def backend_url(self) -> str:
        return self.get("waf", "backend_url", default="http://localhost:8080")

    @property
    def listen_host(self) -> str:
        return self.get("waf", "listen_host", default="0.0.0.0")

    @property
    def listen_port(self) -> int:
        return int(self.get("waf", "listen_port", default=5000))

    @property
    def secret_key(self) -> str:
        return self.get("security", "secret_key", default="change-me-in-production")

    @property
    def api_key(self) -> str:
        return self.get("security", "api_key", default="change-me")

    @property
    def log_level(self) -> str:
        return self.get("logging", "level", default="INFO")

    @property
    def log_format(self) -> str:
        return self.get("logging", "format", default="json")

    @property
    def log_file(self) -> str:
        return self.get("logging", "file", default="logs/waf.log")

    @property
    def model_dir(self) -> str:
        return self.get("models", "directory", default="models/")

    @property
    def metrics_enabled(self) -> bool:
        return bool(self.get("metrics", "enabled", default=True))

    @property
    def metrics_port(self) -> int:
        return int(self.get("metrics", "port", default=9090))

    @property
    def threat_intel_enabled(self) -> bool:
        return bool(self.get("threat_intel", "enabled", default=True))

    @property
    def sqli_detection(self) -> dict:
        return self.get("detection", "sqli", default={})

    @property
    def xss_detection(self) -> dict:
        return self.get("detection", "xss", default={})

    @property
    def anomaly_detection(self) -> dict:
        return self.get("detection", "anomaly", default={})

    @property
    def rate_limiting(self) -> dict:
        return self.get("detection", "rate_limiting", default={})

    def update(self, overrides: dict) -> None:
        """Merge *overrides* into the live configuration."""
        for key, value in overrides.items():
            if isinstance(value, dict) and isinstance(self._data.get(key), dict):
                self._data[key].update(value)
            else:
                self._data[key] = value

    def as_dict(self) -> dict:
        """Return the full resolved configuration as a dictionary."""
        return self._data.copy()
