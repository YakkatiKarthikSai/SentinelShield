"""Tests for spreadsheet-friendly event export."""

import csv
import tempfile
import unittest
from pathlib import Path

from sentinelshield.engine import InspectionEngine
from sentinelshield.events import EventStore
from sentinelshield.models import HttpRequest
from sentinelshield.reporting import export_events_csv


class ReportingTests(unittest.TestCase):
    def test_exports_event_details_to_csv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            store = EventStore(folder / "events.db")
            request = HttpRequest("GET", "/items", query={"id": "7 OR 1=1"})
            store.record(request, InspectionEngine().inspect(request))

            output = folder / "report.csv"
            count = export_events_csv(store, output)
            with output.open(encoding="utf-8", newline="") as report_file:
                rows = list(csv.DictReader(report_file))

            self.assertEqual(1, count)
            self.assertEqual("block", rows[0]["decision"])
            self.assertEqual("SS-1001", rows[0]["rule_ids"])
            self.assertEqual("SQL injection", rows[0]["categories"])

    def test_exports_header_when_database_is_empty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            output = folder / "report.csv"
            count = export_events_csv(EventStore(folder / "events.db"), output)
            self.assertEqual(0, count)
            self.assertIn("event_id", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
