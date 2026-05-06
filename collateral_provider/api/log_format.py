"""Logging formatters. The text formatter is plain stdlib logging; the JSON
one emits one JSON object per record so log aggregators (Datadog, Loki, etc.)
can index fields without regex acrobatics."""

import json
import logging

# Standard LogRecord attributes we never want to serialize as "extra" fields.
# https://docs.python.org/3/library/logging.html#logrecord-attributes
_LOGRECORD_BUILTINS = frozenset({
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "asctime", "taskName",
})


class JsonFormatter(logging.Formatter):
    """One JSON object per record. Always includes level/time/module/message
    and request_id; serializes any extra fields the caller passed via the
    ``extra=...`` kwarg as well."""

    def format(self, record: logging.LogRecord) -> str:
        data = {
            "level": record.levelname,
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S.%f%z"),
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
