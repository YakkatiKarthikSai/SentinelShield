"""Data models shared by the SentinelShield inspection engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Mapping


class Severity(IntEnum):
    """Finding impact levels, ordered from least to most serious."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class HttpRequest:
    """A deliberately small, framework-independent HTTP request model."""

    method: str
    path: str
    query: Mapping[str, str] = field(default_factory=dict)
    headers: Mapping[str, str] = field(default_factory=dict)
    body: str = ""
    source_ip: str = "unknown"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: Severity
    location: str
    evidence: str
    message: str

    def to_dict(self) -> dict[str, str]:
        data = asdict(self)
        data["severity"] = self.severity.name
        return data


@dataclass(frozen=True)
class Verdict:
    decision: str
    findings: tuple[Finding, ...]
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "findings": [finding.to_dict() for finding in self.findings],
        }
