import json
import logging
import unittest
from datetime import datetime

from api.log_format import JsonFormatter
from api.middleware import RequestIDLogFilter, _request_id


def _record(msg: str = "hello", level: int = logging.INFO, **extra) -> logging.LogRecord:
    record = logging.LogRecord(
        name="api",
        level=level,
        pathname=__file__,
        lineno=1,
        msg=msg,
        args=(),
        exc_info=None,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


class TestJsonFormatter(unittest.TestCase):
    def setUp(self):
        self.formatter = JsonFormatter()

    def test_produces_valid_json(self):
        out = self.formatter.format(_record())
        # Must round-trip through json.loads — that's the whole point.
        parsed = json.loads(out)
        self.assertEqual(parsed["message"], "hello")
        self.assertEqual(parsed["level"], "INFO")
        self.assertIn("time", parsed)
        self.assertIn("module", parsed)

    def test_timestamp_is_parseable_iso_8601_with_milliseconds_and_timezone(self):
        record = _record()
        record.created = 1_700_000_000.123456

        timestamp = json.loads(self.formatter.format(record))["time"]

        parsed = datetime.fromisoformat(timestamp)
        self.assertEqual(timestamp, "2023-11-14T22:13:20.123+00:00")
        self.assertIsNotNone(parsed.tzinfo)
        self.assertNotIn("%f", timestamp)

    def test_includes_request_id_attached_by_filter(self):
        # Simulate the filter+formatter chain that runs in production.
        token = _request_id.set("abc123def456")
        try:
            record = _record()
            RequestIDLogFilter().filter(record)
            parsed = json.loads(self.formatter.format(record))
            self.assertEqual(parsed["request_id"], "abc123def456")
        finally:
            _request_id.reset(token)

    def test_request_id_dash_outside_request(self):
        record = _record()
        RequestIDLogFilter().filter(record)
        parsed = json.loads(self.formatter.format(record))
        self.assertEqual(parsed["request_id"], "-")

    def test_extra_kwargs_appear_as_top_level_keys(self):
        # Structured operational fields should serialize as top-level keys.
        record = _record(operation="witness", env="preprod")
        parsed = json.loads(self.formatter.format(record))
        self.assertEqual(parsed["operation"], "witness")
        self.assertEqual(parsed["env"], "preprod")

    def test_exception_serialized(self):
        try:
            raise ValueError("boom")
        except ValueError:
            import sys
            record = logging.LogRecord(
                name="api",
                level=logging.ERROR,
                pathname=__file__,
                lineno=1,
                msg="failed",
                args=(),
                exc_info=sys.exc_info(),
            )
        parsed = json.loads(self.formatter.format(record))
        self.assertIn("exc", parsed)
        self.assertIn("ValueError", parsed["exc"])
        self.assertIn("boom", parsed["exc"])

    def test_non_serializable_arg_falls_back_to_str(self):
        # An object without a JSON encoder shouldn't crash the formatter —
        # we use default=str so it falls back to repr/str.
        class Weird:
            def __repr__(self):
                return "<weird>"

        record = _record(thing=Weird())
        parsed = json.loads(self.formatter.format(record))
        self.assertEqual(parsed["thing"], "<weird>")
