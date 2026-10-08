"""Local SQLite storage for SentinelShield inspection events.

This module stores only the small, explainable details needed for a classroom
demonstration. It is not a production logging or retention system.
"""

from __future__ import annotations

import json
import sqlite3
from hashlib import sha256
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .models import HttpRequest, Verdict


@dataclass(frozen=True)
class IntegrityResult:
    valid: bool
    checked_events: int
    legacy_events: int
    first_invalid_event_id: int | None = None


class EventStore:
    """Persist inspection results in a local SQLite database."""

    def __init__(self, database_path: str | Path = "sentinelshield_events.db") -> None:
        self.database_path = Path(database_path)
        self._create_table()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.database_path)

    def _create_table(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recorded_at TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL DEFAULT '',
                    event_hash TEXT NOT NULL DEFAULT ''
                )
                """
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(security_events)")}
            if "previous_hash" not in columns:
                connection.execute("ALTER TABLE security_events ADD COLUMN previous_hash TEXT NOT NULL DEFAULT ''")
            if "event_hash" not in columns:
                connection.execute("ALTER TABLE security_events ADD COLUMN event_hash TEXT NOT NULL DEFAULT ''")

    def record(self, request: HttpRequest, verdict: Verdict) -> int:
        """Save one inspection verdict and return its event ID."""

        recorded_at = datetime.now(timezone.utc).isoformat()
        findings_json = json.dumps([finding.to_dict() for finding in verdict.findings])
        with self._connect() as connection:
            previous_row = connection.execute(
                "SELECT event_hash FROM security_events WHERE event_hash != '' ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous_hash = previous_row[0] if previous_row else ""
            event_hash = self._event_hash(
                recorded_at, request.method, request.path, verdict.decision,
                verdict.reason, findings_json, previous_hash,
            )
            cursor = connection.execute(
                """
                INSERT INTO security_events
                    (recorded_at, method, path, decision, reason, findings_json, previous_hash, event_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    recorded_at, request.method, request.path, verdict.decision,
                    verdict.reason, findings_json, previous_hash, event_hash,
                ),
            )
            return int(cursor.lastrowid)

    def recent_events(self, limit: int = 10) -> list[dict[str, object]]:
        """Return newest events first; the limit is constrained defensively."""

        safe_limit = max(1, min(limit, 100))
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT id, recorded_at, method, path, decision, reason, findings_json, previous_hash, event_hash
                FROM security_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
        return [
            {
                **dict(row),
                "findings": json.loads(row["findings_json"]),
            }
            for row in rows
        ]

    def verify_integrity(self) -> IntegrityResult:
        """Verify hash links for events recorded after audit chaining was enabled."""

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, recorded_at, method, path, decision, reason, findings_json, previous_hash, event_hash
                FROM security_events ORDER BY id ASC
                """
            ).fetchall()

        previous_hash = ""
        checked = 0
        legacy = 0
        for row in rows:
            event_id, recorded_at, method, path, decision, reason, findings_json, stored_previous, stored_hash = row
            if not stored_hash:
                legacy += 1
                continue
            expected_hash = self._event_hash(
                recorded_at, method, path, decision, reason, findings_json, stored_previous,
            )
            if stored_previous != previous_hash or stored_hash != expected_hash:
                return IntegrityResult(False, checked, legacy, event_id)
            previous_hash = stored_hash
            checked += 1
        return IntegrityResult(True, checked, legacy)

    @staticmethod
    def _event_hash(
        recorded_at: str,
        method: str,
        path: str,
        decision: str,
        reason: str,
        findings_json: str,
        previous_hash: str,
    ) -> str:
        payload = json.dumps(
            {
                "recorded_at": recorded_at,
                "method": method,
                "path": path,
                "decision": decision,
                "reason": reason,
                "findings_json": findings_json,
                "previous_hash": previous_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return sha256(payload.encode("utf-8")).hexdigest()
