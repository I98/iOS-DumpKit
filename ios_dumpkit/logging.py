"""Logging helpers with Rich, JSON, trace-file, and password redaction support."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

SENSITIVE_WORDS = ("password", "ssh_pass", "ssh-password", "token", "secret")


class RedactingFilter(logging.Filter):
    """Redact common sensitive values from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        lowered = message.lower()
        if any(word in lowered for word in SENSITIVE_WORDS):
            record.msg = "[redacted sensitive log message]"
            record.args = ()
        return True


class JsonFormatter(logging.Formatter):
    """Small structured JSON formatter for --json-log and trace files."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "stage"):
            payload["stage"] = record.stage
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"ios_dumpkit.{name}" if not name.startswith("ios_dumpkit") else name)


def configure_logging(
    *,
    verbose: bool = False,
    json_log: bool = False,
    trace_path: Path | None = None,
    console: Console | None = None,
) -> None:
    """Configure root package logging for CLI usage."""

    logger = logging.getLogger("ios_dumpkit")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False

    level = logging.DEBUG if verbose else logging.INFO
    if json_log:
        stream_handler: logging.Handler = logging.StreamHandler()
        stream_handler.setFormatter(JsonFormatter())
    else:
        stream_handler = RichHandler(
            console=console,
            rich_tracebacks=verbose,
            show_path=False,
            show_time=False,
            markup=True,
        )
        stream_handler.setFormatter(logging.Formatter("%(message)s"))
    stream_handler.setLevel(level)
    stream_handler.addFilter(RedactingFilter())
    logger.addHandler(stream_handler)

    if trace_path:
        trace_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(trace_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JsonFormatter())
        file_handler.addFilter(RedactingFilter())
        logger.addHandler(file_handler)


@contextmanager
def stage(logger: logging.Logger, name: str) -> Iterator[None]:
    """Log start/end/fail messages for a named stage."""

    logger.info("stage started: %s", name, extra={"stage": name})
    try:
        yield
    except Exception:
        logger.exception("stage failed: %s", name, extra={"stage": name})
        raise
    else:
        logger.info("stage complete: %s", name, extra={"stage": name})
