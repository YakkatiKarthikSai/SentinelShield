"""Small, explainable signatures for classroom WAF/IDS demonstrations.

The signatures are intentionally conservative and are not comprehensive security
controls. They inspect text only and never execute or transmit request content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Finding, Severity
from .normalization import normalize_for_inspection


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: Severity
    pattern: re.Pattern[str]
    message: str

    def inspect(self, location: str, value: str) -> Finding | None:
        match = self.pattern.search(value)
        if not match:
            return None
        evidence = match.group(0)[:80]
        return Finding(
            rule_id=self.rule_id,
            category=self.category,
            severity=self.severity,
            location=location,
            evidence=evidence,
            message=self.message,
        )


RULES: tuple[Rule, ...] = (
    Rule(
        "SS-1001", "SQL injection", Severity.HIGH,
        re.compile(r"(?:\bunion\s+(?:all\s+)?select\b|\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)", re.I),
        "SQL-like boolean or UNION expression detected.",
    ),
    Rule(
        "SS-1002", "Cross-site scripting", Severity.HIGH,
        re.compile(r"<\s*script\b|\bon\w+\s*=\s*['\"]?[^\s>]+", re.I),
        "Script tag or inline event handler detected.",
    ),
    Rule(
        "SS-1003", "Directory traversal", Severity.HIGH,
        re.compile(r"(?:\.\.[\\/]){1,}"),
        "Parent-directory traversal sequence detected.",
    ),
    Rule(
        "SS-1004", "Local file inclusion", Severity.HIGH,
        re.compile(r"(?:/etc/(?:passwd|shadow)\b|[a-z]:\\(?:windows\\)?(?:system32|win\.ini)\b)", re.I),
        "Sensitive local-file reference detected.",
    ),
    Rule(
        "SS-1005", "Command injection", Severity.CRITICAL,
        re.compile(r"(?:[;&|]{1,2}\s*(?:whoami|id|cat|curl|wget|powershell)\b|\$\([^)]{1,60}\))", re.I),
        "Shell control operator or command substitution detected.",
    ),
    Rule(
        "SS-1006", "Sensitive path probing", Severity.HIGH,
        re.compile(r"(?:^|/)(?:\.env|\.git(?:/|$)|phpmyadmin(?:/|$)|wp-admin(?:/|$))", re.I),
        "Request for a commonly sensitive configuration or administration path detected.",
    ),
)


def inspect_text(location: str, value: str) -> list[Finding]:
    """Normalize then evaluate every defined rule against one request field."""

    normalized_value = normalize_for_inspection(value)
    return [finding for rule in RULES if (finding := rule.inspect(location, normalized_value))]
