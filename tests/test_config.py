"""Tests for environment-driven application settings."""

import unittest

from sentinelshield.config import Settings
from sentinelshield.models import Severity


class SettingsTests(unittest.TestCase):
    def test_environment_overrides_defaults(self) -> None:
        settings = Settings.from_environment({
            "SS_DATABASE_PATH": "demo.db",
            "SS_BLOCK_SEVERITY": "CRITICAL",
            "SS_RATE_WINDOW_SECONDS": "30",
            "SS_REQUEST_LIMIT": "12",
            "SS_LOGIN_LIMIT": "3",
            "SS_MAX_FIELD_LENGTH": "1000",
        })
        self.assertEqual("demo.db", settings.database_path)
        self.assertEqual(Severity.CRITICAL, settings.block_severity)
        self.assertEqual(30.0, settings.rate_window_seconds)
        self.assertEqual(12, settings.request_limit)
        self.assertEqual(3, settings.login_limit)
        self.assertEqual(1000, settings.max_field_length)

    def test_invalid_severity_has_helpful_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "SS_BLOCK_SEVERITY"):
            Settings.from_environment({"SS_BLOCK_SEVERITY": "urgent"})


if __name__ == "__main__":
    unittest.main()
