"""Tests for the local SQLite security-event store."""

import tempfile
import sqlite3
import unittest
from pathlib import Path

from sentinelshield import HttpRequest, InspectionEngine
from sentinelshield.events import EventStore


class EventStoreTests(unittest.TestCase):
    def test_records_and_returns_an_inspection_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "events.db"
            request = HttpRequest("GET", "/items", query={"id": "7 OR 1=1"})
            verdict = InspectionEngine().inspect(request)

            store = EventStore(database)
            event_id = store.record(request, verdict)
            events = store.recent_events()

            self.assertEqual(1, event_id)
            self.assertEqual(1, len(events))
            self.assertEqual("block", events[0]["decision"])
            self.assertEqual("/items", events[0]["path"])
            self.assertEqual("SQL injection", events[0]["findings"][0]["category"])

    def test_event_limit_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = EventStore(Path(directory) / "events.db")
            self.assertEqual([], store.recent_events(limit=999))

    def test_hash_chain_verifies_untampered_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "events.db"
            store = EventStore(database)
            engine = InspectionEngine()
            store.record(HttpRequest("GET", "/search"), engine.inspect(HttpRequest("GET", "/search")))
            store.record(HttpRequest("GET", "/items", query={"id": "7 OR 1=1"}), engine.inspect(HttpRequest("GET", "/items", query={"id": "7 OR 1=1"})))
            result = store.verify_integrity()
            self.assertTrue(result.valid)
            self.assertEqual(2, result.checked_events)

    def test_hash_chain_detects_modified_event_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "events.db"
            store = EventStore(database)
            request = HttpRequest("GET", "/search")
            store.record(request, InspectionEngine().inspect(request))
            connection = sqlite3.connect(database)
            try:
                connection.execute("UPDATE security_events SET reason = 'modified' WHERE id = 1")
                connection.commit()
            finally:
                connection.close()
            result = store.verify_integrity()
            self.assertFalse(result.valid)
            self.assertEqual(1, result.first_invalid_event_id)


if __name__ == "__main__":
    unittest.main()
