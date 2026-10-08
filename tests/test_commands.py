"""Tests for the user-facing command parser."""

import unittest

from sentinelshield.__main__ import build_parser


class CommandParserTests(unittest.TestCase):
    def test_accepts_all_supported_commands(self) -> None:
        parser = build_parser()
        for command in ("demo", "simulate", "evaluate", "verify"):
            self.assertEqual(command, parser.parse_args([command]).command)

    def test_export_accepts_custom_output(self) -> None:
        arguments = build_parser().parse_args(["export", "--output", "reports/test.csv"])
        self.assertEqual("export", arguments.command)
        self.assertEqual("reports/test.csv", arguments.output)


if __name__ == "__main__":
    unittest.main()
