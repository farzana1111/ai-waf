"""Configuration management for AI-WAF."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class WAFConfig(BaseSettings):
    """WAF configuration loaded from environment variables or defaults."""

    model_config = SettingsConfigDict(
        env_prefix="WAF_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Proxy / upstream ────────────────────────────────────────────────────
    upstream_url: str = Field(
        default="http://localhost:8080",
        description="Backend service URL that the WAF proxies traffic to.",
    )
    listen_host: str = Field(default="0.0.0.0", description="Host to listen on.")
    listen_port: int = Field(default=8000, description="Port to listen on.", ge=1, le=65535)

    # ── ML model ────────────────────────────────────────────────────────────
    model_path: Path = Field(
        default=Path("waf/model/threat_model.joblib"),
        description="Path to the trained scikit-learn pipeline (.joblib).",
    )
    ml_confidence_threshold: float = Field(
        default=0.70,
        description="Minimum ML confidence to flag a request as malicious.",
        ge=0.0,
        le=1.0,
    )

    # ── Rule engine ─────────────────────────────────────────────────────────
    enable_rules: bool = Field(default=True, description="Enable rule-based detection.")
    enable_ml: bool = Field(default=True, description="Enable ML-based detection.")

    # ── Rate limiting ────────────────────────────────────────────────────────
    rate_limit_enabled: bool = Field(default=True, description="Enable per-IP rate limiting.")
    rate_limit_requests: int = Field(
        default=100, description="Max requests per window.", ge=1
    )
    rate_limit_window_seconds: int = Field(
        default=60, description="Rate-limit window in seconds.", ge=1
    )

    # ── Enforcement mode ─────────────────────────────────────────────────────
    mode: Literal["block", "monitor"] = Field(
        default="block",
        description=(
            "Enforcement mode: 'block' returns 403 on detected threats; "
            "'monitor' logs threats but lets requests pass."
        ),
    )

    # ── Logging ──────────────────────────────────────────────────────────────
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO", description="Logging verbosity."
    )
    log_file: Path | None = Field(
        default=None, description="Optional file path for structured JSON logs."
    )

    @field_validator("model_path", mode="before")
    @classmethod
    def _coerce_model_path(cls, v: object) -> Path:
        return Path(str(v))

    @field_validator("log_file", mode="before")
    @classmethod
    def _coerce_log_file(cls, v: object) -> Path | None:
        if v is None or v == "":
            return None
        return Path(str(v))
