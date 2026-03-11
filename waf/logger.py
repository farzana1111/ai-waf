"""Structured logging for AI-WAF."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from waf.waf_config import WAFConfig


class _JSONFormatter(logging.Formatter):
    """Emit log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        extra_keys = set(record.__dict__) - logging.LogRecord(
            "", 0, "", 0, "", (), None
        ).__dict__.keys()
        for key in extra_keys:
            payload[key] = getattr(record, key)
        return json.dumps(payload, default=str)


def setup_logging(config: WAFConfig) -> logging.Logger:
    """Configure the root WAF logger and return it."""
    logger = logging.getLogger("ai_waf")
    logger.setLevel(config.log_level)
    logger.handlers.clear()
    logger.propagate = False

    formatter = _JSONFormatter()

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # Optional file handler
    if config.log_file is not None:
        fh = logging.FileHandler(config.log_file)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger


def get_logger() -> logging.Logger:
    """Return the shared WAF logger (call :func:`setup_logging` first)."""
    return logging.getLogger("ai_waf")


def log_threat(
    logger: logging.Logger,
    *,
    request_id: str,
    client_ip: str,
    method: str,
    path: str,
    threat_type: str,
    source: str,
    score: float,
    action: str,
    details: dict[str, Any] | None = None,
) -> None:
    """Emit a structured threat log entry."""
    logger.warning(
        "Threat detected",
        extra={
            "request_id": request_id,
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "threat_type": threat_type,
            "source": source,
            "score": round(score, 4),
            "action": action,
            "details": details or {},
        },
    )
