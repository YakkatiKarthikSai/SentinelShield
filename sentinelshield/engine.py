"""Request inspection orchestration and transparent decision policy."""

from __future__ import annotations

from .abuse import AbuseDetector
from .models import Finding, HttpRequest, Severity, Verdict
from .rules import inspect_text


class InspectionEngine:
    """Evaluate request text against rules and return an explainable verdict."""

    def __init__(
        self,
        abuse_detector: AbuseDetector | None = None,
        block_at_or_above: Severity = Severity.HIGH,
        max_field_length: int = 4096,
    ) -> None:
        self.abuse_detector = abuse_detector
        self.block_at_or_above = block_at_or_above
        self.max_field_length = max_field_length

    def inspect(self, request: HttpRequest) -> Verdict:
        fields = [("path", request.path), ("body", request.body)]
        fields.extend((f"query.{key}", value) for key, value in request.query.items())
        fields.extend((f"header.{key}", value) for key, value in request.headers.items())

        findings: list[Finding] = []
        for location, value in fields:
            if len(value) > self.max_field_length:
                findings.append(
                    Finding(
                        "SS-3001", "Oversized input", Severity.HIGH, location,
                        f"{len(value)} characters",
                        "Request field exceeds the configured inspection-size limit.",
                    )
                )
            else:
                findings.extend(inspect_text(location, value))
        if self.abuse_detector:
            findings.extend(self.abuse_detector.inspect(request))

        # The same rule may match more than one field; keep each location because
        # it is useful for a student to explain where an alert came from.
        findings.sort(key=lambda item: int(item.severity), reverse=True)
        if findings and findings[0].severity >= self.block_at_or_above:
            return Verdict("block", tuple(findings), "High-confidence attack indicator detected.")
        if findings:
            return Verdict("allow", tuple(findings), "Only advisory findings detected.")
        return Verdict("allow", (), "No configured attack indicators detected.")
