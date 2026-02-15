"""
Minimal logging setup for Katran control plane.

Provides console or JSON formatted logging via stdlib logging.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone


class _JsonFormatter(logging.Formatter):
    """JSON log formatter."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


_CONSOLE_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"

# Libraries to silence
_NOISY_LOGGERS = ("urllib3", "asyncio", "uvicorn.access", "httpcore", "httpx")


def setup_logging(level: str = "INFO", log_format: str = "console") -> None:
    """
    Configure root logging.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_format: "console" for human-readable, "json" for structured.
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stderr)
    if log_format.lower() == "json":
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(_CONSOLE_FORMAT))

    root.addHandler(handler)

    # Silence noisy libraries
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a named logger."""
    return logging.getLogger(name)
