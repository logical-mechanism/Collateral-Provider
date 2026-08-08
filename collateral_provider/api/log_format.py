"""Logging formatters. The text formatter is plain stdlib logging; the JSON
one emits one JSON object per record so log aggregators (Datadog, Loki, etc.)
can index fields without regex acrobatics."""

import json
import logging
from datetime import UTC, datetime

# Standard LogRecord attributes we never want to serialize as "extra" fields.
# https://docs.python.org/3/library/logging.html#logrecord-attributes
_LOGRECORD_BUILTINS = frozenset({
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "asctime", "taskName",
})


def build_logging_config(
    *,
    log_level: str,
    log_file: str,
    log_format: str,
    log_to_console: bool,
) -> dict:
    """Build the Django logging config for exactly one output target.

    A console deployment must not instantiate a file handler at all: merely
    declaring ``RotatingFileHandler`` makes ``dictConfig`` open the path at
    startup, which defeats console-only service users without filesystem
    write access. Selecting one handler also prevents framework errors from
    appearing twice or being the only messages sent to journald.
    """
    if log_format not in {"text", "json"}:
        raise ValueError(f"Unsupported log format: {log_format!r}")

    formatter = "json" if log_format == "json" else "verbose"
    handler_name = "console" if log_to_console else "file"
    if log_to_console:
        handler = {
            "level": log_level,
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
            "formatter": formatter,
            "filters": ["request_id"],
        }
    else:
        handler = {
            "level": log_level,
            "class": "logging.handlers.RotatingFileHandler",
            "filename": log_file,
            "formatter": formatter,
            "filters": ["request_id"],
            "maxBytes": 1024 * 1024,
            "backupCount": 3,
        }

    def logger_config(level: str) -> dict:
        return {
            "handlers": [handler_name],
            "level": level,
            # Each named logger owns the selected handler. Propagating into
            # Django's preconfigured root logger would emit warning/error
            # records a second time, often to an unexpected console target.
            "propagate": False,
        }

    return {
        "version": 1,
        "disable_existing_loggers": False,
        "filters": {
            "request_id": {
                "()": "api.middleware.RequestIDLogFilter",
            },
        },
        "formatters": {
            "verbose": {
                "format": "{levelname} {asctime} [{request_id}] {module} {message}",
                "style": "{",
            },
            "json": {
                "()": "api.log_format.JsonFormatter",
            },
        },
        "handlers": {handler_name: handler},
        "loggers": {
            "django": logger_config("INFO"),
            "api": logger_config(log_level),
            "django.security.DisallowedHost": logger_config("WARNING"),
            # Django's default django.request logger routes only to
            # mail_admins and does not propagate. Give it the same selected
            # destination so unhandled 500 tracebacks remain visible.
            "django.request": logger_config("ERROR"),
        },
    }


class JsonFormatter(logging.Formatter):
    """One JSON object per record. Always includes level/time/module/message
    and request_id; serializes any extra fields the caller passed via the
    ``extra=...`` kwarg as well."""

    def format(self, record: logging.LogRecord) -> str:
        data = {
            "level": record.levelname,
            # logging.Formatter.formatTime delegates to time.strftime, which
            # does not support ``%f`` and would emit it literally. Build a
            # timezone-aware ISO-8601 value directly so JSON log consumers get
            # a real, consistently UTC timestamp with millisecond precision.
            "time": datetime.fromtimestamp(
                record.created, tz=UTC
            ).isoformat(timespec="milliseconds"),
            "logger": record.name,
            "module": record.module,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
        }
        for key, value in record.__dict__.items():
            if key not in _LOGRECORD_BUILTINS and key not in data:
                # Anything passed via logger.info(..., extra={"foo": ...})
                # ends up here. Keep keys flat — log aggregators expect that.
                data[key] = value
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        if record.stack_info:
            data["stack"] = self.formatStack(record.stack_info)
        return json.dumps(data, default=str)
