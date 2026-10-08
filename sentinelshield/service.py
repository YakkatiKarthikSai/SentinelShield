"""Application service that joins inspection with event recording."""

from __future__ import annotations

from .engine import InspectionEngine
from .events import EventStore
from .models import Finding, HttpRequest, Verdict


class SentinelShieldService:
    """Process one request, then persist the resulting security event."""

    def __init__(self, engine: InspectionEngine, event_store: EventStore) -> None:
        self.engine = engine
        self.event_store = event_store

    def inspect_and_record(self, request: HttpRequest) -> tuple[int, Verdict]:
        verdict = self.engine.inspect(request)
        event_id = self.event_store.record(request, verdict)
        return event_id, verdict

    def record_authentication_result(self, source_ip: str, success: bool) -> tuple[int, Verdict]:
        """Save a trusted authentication outcome and any resulting abuse alert."""

        detector = self.engine.abuse_detector
        finding: Finding | None = None
        if detector:
            finding = detector.record_authentication_result(source_ip, success)
        verdict = (
            Verdict("block", (finding,), "Repeated failed authentication attempts detected.")
            if finding
            else Verdict("allow", (), "Authentication outcome recorded without an active abuse alert.")
        )
        request = HttpRequest("POST", "/auth/result", source_ip=source_ip)
        event_id = self.event_store.record(request, verdict)
        return event_id, verdict
