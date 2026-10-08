"""Factories for assembling SentinelShield application components."""

from __future__ import annotations

from .abuse import AbuseDetector
from .config import Settings
from .engine import InspectionEngine
from .events import EventStore
from .service import SentinelShieldService


def create_service(settings: Settings | None = None) -> SentinelShieldService:
    """Create a configured inspection, abuse-detection, and event-store service."""

    settings = settings or Settings.from_environment()
    return SentinelShieldService(
        InspectionEngine(
            AbuseDetector(
                window_seconds=settings.rate_window_seconds,
                request_limit=settings.request_limit,
                login_limit=settings.login_limit,
            ),
            block_at_or_above=settings.block_severity,
            max_field_length=settings.max_field_length,
        ),
        EventStore(settings.database_path),
    )
