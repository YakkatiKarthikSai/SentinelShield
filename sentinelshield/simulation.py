"""Safe, offline attack-scenario simulator for demonstrations.

The simulator processes inert request strings through SentinelShield itself. It
does not make network connections, execute commands, or target any system.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from .abuse import AbuseDetector
from .config import Settings
from .dataset import EVALUATION_DATASET
from .engine import InspectionEngine
from .events import EventStore
from .service import SentinelShieldService


@dataclass(frozen=True)
class SimulationResult:
    total_scenarios: int
    allowed_events: int
    blocked_events: int
    expected_malicious_scenarios: int


def run_simulation(service: SentinelShieldService) -> SimulationResult:
    """Run the labelled local scenarios and persist every resulting event."""

    allowed = 0
    blocked = 0
    expected_malicious = 0
    for sample in EVALUATION_DATASET:
        if sample.malicious:
            expected_malicious += 1
        _, verdict = service.inspect_and_record(sample.request)
        if verdict.decision == "block":
            blocked += 1
        else:
            allowed += 1
    return SimulationResult(len(EVALUATION_DATASET), allowed, blocked, expected_malicious)


def build_service(settings: Settings) -> SentinelShieldService:
    """Build simulation dependencies without requiring the API package."""

    engine = InspectionEngine(
        AbuseDetector(
            window_seconds=settings.rate_window_seconds,
            request_limit=settings.request_limit,
            login_limit=settings.login_limit,
        ),
        block_at_or_above=settings.block_severity,
        max_field_length=settings.max_field_length,
    )
    return SentinelShieldService(engine, EventStore(settings.database_path))


def main() -> None:
    result = run_simulation(build_service(Settings.from_environment()))
    print(json.dumps(asdict(result), indent=2))
    print("All scenarios are offline strings processed locally; no requests were sent.")


if __name__ == "__main__":
    main()
