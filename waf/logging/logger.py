"""Structured JSON logging for the WAF.

Provides a :class:`JSONFormatter` that emits log records as single-line
JSON objects and convenience functions for creating pre-configured
loggers.
"""

import json
import logging
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Format log records as single-line JSON strings.

    Each JSON object includes ``timestamp``, ``level``, ``name``,
    ``message``, and any extra fields attached to the record.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Return a JSON-serialised representation of *record*."""
        log_entry: dict = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info and record.exc_info[1] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Merge extra fields passed via the ``extra`` kwarg
        for key, value in record.__dict__.items():
            if key not in _RESERVED_ATTRS and not key.startswith("_"):
                log_entry[key] = value

        return json.dumps(log_entry, default=str)


# Standard LogRecord attributes that should NOT be copied into the JSON body
_RESERVED_ATTRS = frozenset({
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "message",
    "module",
    "msecs",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "taskName",
    "thread",
    "threadName",
})


def setup_logger(
    name: str,
    level: str = "INFO",
    log_file: str | None = None,
) -> logging.Logger:
    """Create and configure a logger with the :class:`JSONFormatter`.

    Args:
        name:  Logger name (usually ``__name__``).
        level: Log level string (e.g. ``"DEBUG"``, ``"INFO"``).
        log_file: Optional file path.  When provided a
            :class:`~logging.FileHandler` is attached in addition to
            the stream handler.

    Returns:
        A fully configured :class:`~logging.Logger`.
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if not logger.handlers:
        formatter = JSONFormatter()

        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

        if log_file:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    return logger


_waf_logger: logging.Logger | None = None


def get_waf_logger() -> logging.Logger:
    """Return the shared WAF logger, creating it on first call."""
    global _waf_logger  # noqa: PLW0603
    if _waf_logger is None:
        _waf_logger = setup_logger("waf")
    return _waf_logger
