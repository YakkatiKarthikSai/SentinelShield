"""Unit test for the inspection-and-recording application workflow."""

import tempfile
import unittest
from pathlib import Path

from sentinelshield.engine import InspectionEngine
from sentinelshield.events import EventStore
from sentinelshield.models import HttpRequest
from sentinelshield.service import SentinelShieldService


class SentinelShieldServiceTests(unittest.TestCase):
    def test_inspection_result_is_saved_as_an_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = SentinelShieldService(
                InspectionEngine(), EventStore(Path(directory) / "events.db")
            )
            event_id, verdict = service.inspect_and_record(
                HttpRequest("GET", "/search", query={"q": "campus map"})
            )
            self.assertEqual("allow", verdict.decision)
            self.assertEqual(1, event_id)
            self.assertEqual("/search", service.event_store.recent_events()[0]["path"])

    def test_authentication_outcome_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = SentinelShieldService(
                InspectionEngine(), EventStore(Path(directory) / "events.db")
            )
            event_id, verdict = service.record_authentication_result("198.51.100.2", False)
            self.assertEqual(1, event_id)
            self.assertEqual("allow", verdict.decision)
            self.assertEqual("/auth/result", service.event_store.recent_events()[0]["path"])


if __name__ == "__main__":
    unittest.main()
