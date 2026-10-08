"""Runtime configuration for SentinelShield.

Settings have safe defaults for local demonstrations and can be overridden with
environment variables, keeping operational values out of source-code edits.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping

from .models import Severity


@dataclass(frozen=True)
class Settings:
    database_path: str = "sentinelshield_events.db"
    block_severity: Severity = Severity.HIGH
    rate_window_seconds: float = 60.0
    request_limit: int = 20
    login_limit: int = 5
    max_field_length: int = 4096

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> "Settings":
        """Create settings from `SS_` variables, raising clear errors if invalid."""

        values = os.environ if environment is None else environment
        severity_name = values.get("SS_BLOCK_SEVERITY", "HIGH").upper()
        try:
            severity = Severity[severity_name]
        except KeyError as error:
            allowed = ", ".join(item.name for item in Severity)
            raise ValueError(f"SS_BLOCK_SEVERITY must be one of: {allowed}") from error
        try:
            return cls(
                database_path=values.get("SS_DATABASE_PATH", "sentinelshield_events.db"),
                block_severity=severity,
                rate_window_seconds=float(values.get("SS_RATE_WINDOW_SECONDS", "60")),
                request_limit=int(values.get("SS_REQUEST_LIMIT", "20")),
                login_limit=int(values.get("SS_LOGIN_LIMIT", "5")),
                max_field_length=int(values.get("SS_MAX_FIELD_LENGTH", "4096")),
            )
        except ValueError as error:
            raise ValueError("SentinelShield numeric configuration values must be valid numbers.") from error
