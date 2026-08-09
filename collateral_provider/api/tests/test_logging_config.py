from django.test import SimpleTestCase

from api.log_format import build_logging_config


class TestLoggingConfig(SimpleTestCase):
    def _assert_all_loggers_use(self, config: dict, handler_name: str) -> None:
        expected = {
            "api",
            "django",
            "django.request",
            "django.security.DisallowedHost",
        }
        self.assertEqual(set(config["loggers"]), expected)
        for name, logger in config["loggers"].items():
            with self.subTest(logger=name):
                self.assertEqual(logger["handlers"], [handler_name])
                self.assertFalse(logger["propagate"])

    def test_file_mode_declares_only_rotating_file_handler(self):
        config = build_logging_config(
            log_level="INFO",
            log_file="/tmp/collateral-provider-test.log",
            log_format="text",
            log_to_console=False,
        )

        self.assertEqual(set(config["handlers"]), {"file"})
        handler = config["handlers"]["file"]
        self.assertEqual(handler["class"], "logging.handlers.RotatingFileHandler")
        self.assertEqual(handler["filename"], "/tmp/collateral-provider-test.log")
        self.assertEqual(handler["level"], "INFO")
        self.assertEqual(handler["formatter"], "verbose")
        self._assert_all_loggers_use(config, "file")

    def test_console_mode_declares_only_stderr_handler(self):
        config = build_logging_config(
            log_level="WARNING",
            log_file="/unwritable/path/that/must/not/be-opened.log",
            log_format="json",
            log_to_console=True,
        )

        self.assertEqual(set(config["handlers"]), {"console"})
        handler = config["handlers"]["console"]
        self.assertEqual(handler["class"], "logging.StreamHandler")
        self.assertEqual(handler["stream"], "ext://sys.stderr")
        self.assertEqual(handler["level"], "WARNING")
        self.assertEqual(handler["formatter"], "json")
        self.assertNotIn("filename", handler)
        self._assert_all_loggers_use(config, "console")

    def test_rejects_unknown_format(self):
        with self.assertRaisesRegex(ValueError, "Unsupported log format"):
            build_logging_config(
                log_level="INFO",
                log_file="ignored.log",
                log_format="syslog",
                log_to_console=True,
            )
