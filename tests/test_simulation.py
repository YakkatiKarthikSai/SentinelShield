"""Tests for the safe offline demonstration simulator."""

import tempfile
import unittest
from pathlib import Path

from sentinelshield.engine import InspectionEngine
from sentinelshield.events import EventStore
from sentinelshield.service import SentinelShieldService
from sentinelshield.simulation import run_simulation


class SimulationTests(unittest.TestCase):
    def test_simulation_records_expected_decisions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = EventStore(Path(directory) / "events.db")
            result = run_simulation(SentinelShieldService(InspectionEngine(), store))
            self.assertEqual(9, result.total_scenarios)
            self.assertEqual(3, result.allowed_events)
            self.assertEqual(6, result.blocked_events)
            self.assertEqual(6, result.expected_malicious_scenarios)
            self.assertEqual(9, len(store.recent_events()))


if __name__ == "__main__":
    unittest.main()
