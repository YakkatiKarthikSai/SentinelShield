"""Export locally stored SentinelShield events for practical-report evidence."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from .config import Settings
from .events import EventStore


CSV_COLUMNS = (
    "event_id",
    "recorded_at_utc",
    "method",
    "path",
    "decision",
    "reason",
    "finding_count",
    "rule_ids",
    "categories",
    "severities",
    "event_hash",
)


def export_events_csv(event_store: EventStore, output_path: str | Path) -> int:
    """Write up to 100 stored events to a concise, spreadsheet-ready CSV file."""

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    events = event_store.recent_events(limit=100)
    with output.open("w", newline="", encoding="utf-8") as report_file:
        writer = csv.DictWriter(report_file, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for event in events:
            findings = event["findings"]
            writer.writerow({
                "event_id": event["id"],
                "recorded_at_utc": event["recorded_at"],
                "method": event["method"],
                "path": event["path"],
                "decision": event["decision"],
                "reason": event["reason"],
                "finding_count": len(findings),
                "rule_ids": "; ".join(finding["rule_id"] for finding in findings),
                "categories": "; ".join(finding["category"] for finding in findings),
                "severities": "; ".join(finding["severity"] for finding in findings),
                "event_hash": event["event_hash"],
            })
    return len(events)


def main() -> None:
    parser = argparse.ArgumentParser(description="Export SentinelShield security events to CSV.")
    parser.add_argument("--output", default="reports/sentinelshield-events.csv", help="CSV output path")
    arguments = parser.parse_args()

    settings = Settings.from_environment()
    count = export_events_csv(EventStore(settings.database_path), arguments.output)
    print(f"Exported {count} event(s) to {arguments.output}")


if __name__ == "__main__":
    main()
