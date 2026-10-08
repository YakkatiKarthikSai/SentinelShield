"""Run a local, safe demonstration of the SentinelShield engine."""

from __future__ import annotations

import json

from .abuse import AbuseDetector
from .config import Settings
from .engine import InspectionEngine
from .events import EventStore
from .models import HttpRequest


def main() -> None:
    settings = Settings.from_environment()
    engine = InspectionEngine(
        AbuseDetector(
            window_seconds=settings.rate_window_seconds,
            request_limit=settings.request_limit,
            login_limit=settings.login_limit,
        ),
        block_at_or_above=settings.block_severity,
        max_field_length=settings.max_field_length,
    )
    store = EventStore(settings.database_path)
    samples = (
        HttpRequest("GET", "/search", query={"q": "wireless keyboard"}, source_ip="203.0.113.10"),
        HttpRequest("GET", "/items", query={"id": "7 OR 1=1"}, source_ip="203.0.113.11"),
        HttpRequest("POST", "/feedback", body="<script>alert('demo')</script>", source_ip="203.0.113.12"),
        HttpRequest("GET", "/download", query={"file": "../../notes.txt"}, source_ip="203.0.113.13"),
    )
    for request in samples:
        result = engine.inspect(request)
        event_id = store.record(request, result)
        print(json.dumps({"event_id": event_id, "request": request.path, **result.to_dict()}, indent=2))

    print("\nRecent events saved to sentinelshield_events.db:")
    print(json.dumps(store.recent_events(limit=4), indent=2))
    print("\nAudit-chain integrity:")
    print(json.dumps(store.verify_integrity().__dict__, indent=2))


if __name__ == "__main__":
    main()
