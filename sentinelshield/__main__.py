"""Convenient command entry point for SentinelShield."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from .cli import main as demo_main
from .config import Settings
from .evaluation import main as evaluate_main
from .events import EventStore
from .reporting import export_events_csv
from .simulation import main as simulate_main


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m sentinelshield",
        description="SentinelShield educational WAF/IDS project commands.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("demo", help="Run the small local CLI demonstration.")
    subcommands.add_parser("simulate", help="Create safe offline demonstration events.")
    subcommands.add_parser("evaluate", help="Evaluate the controlled offline dataset.")
    export = subcommands.add_parser("export", help="Export recent events to a CSV file.")
    export.add_argument("--output", default="reports/sentinelshield-events.csv", help="CSV output path")
    subcommands.add_parser("verify", help="Verify the event audit hash chain.")
    return parser


def main() -> None:
    arguments = build_parser().parse_args()
    if arguments.command == "demo":
        demo_main()
    elif arguments.command == "simulate":
        simulate_main()
    elif arguments.command == "evaluate":
        evaluate_main()
    elif arguments.command == "export":
        count = export_events_csv(EventStore(Settings.from_environment().database_path), arguments.output)
        print(f"Exported {count} event(s) to {arguments.output}")
    elif arguments.command == "verify":
        result = EventStore(Settings.from_environment().database_path).verify_integrity()
        print(json.dumps(asdict(result), indent=2))


if __name__ == "__main__":
    main()
