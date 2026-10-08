"""In-memory rate and login-burst detection for classroom demonstrations.

This component detects a high volume of requests, not successful exploitation.
Login bursts are only a *brute-force indicator*: a real system must also use
authentication failure outcomes before labelling the activity a brute-force attack.
"""

from __future__ import annotations

from collections import defaultdict, deque
from time import monotonic
from typing import Callable

from .models import Finding, HttpRequest, Severity


class AbuseDetector:
    """Track recent requests per source IP using a sliding time window."""

    def __init__(
        self,
        window_seconds: float = 60,
        request_limit: int = 20,
        login_limit: int = 5,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self.window_seconds = window_seconds
        self.request_limit = request_limit
        self.login_limit = login_limit
        self.clock = clock
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._login_attempts: dict[str, deque[float]] = defaultdict(deque)
        self._failed_logins: dict[str, deque[float]] = defaultdict(deque)

    def inspect(self, request: HttpRequest) -> list[Finding]:
        """Record a request and return any volume-based security findings."""

        now = self.clock()
        source = request.source_ip
        request_count = self._record_and_count(self._requests[source], now)
        findings: list[Finding] = []

        if request_count > self.request_limit:
            findings.append(
                Finding(
                    "SS-2001", "Rate limit", Severity.HIGH, "source_ip", source,
                    "Request-rate limit exceeded for this source IP.",
                )
            )

        if request.path == "/login":
            login_count = self._record_and_count(self._login_attempts[source], now)
            if login_count > self.login_limit:
                findings.append(
                    Finding(
                        "SS-2002", "Login burst", Severity.HIGH, "source_ip", source,
                        "Repeated login attempts detected; verify authentication outcomes.",
                    )
                )
        return findings

    def record_authentication_result(self, source_ip: str, success: bool) -> Finding | None:
        """Record a trusted authentication outcome and flag repeated failures.

        Unlike the `/login` request burst indicator, this method requires the
        application to provide the actual success/failure result.
        """

        if success:
            self._failed_logins.pop(source_ip, None)
            return None
        failure_count = self._record_and_count(self._failed_logins[source_ip], self.clock())
        if failure_count > self.login_limit:
            return Finding(
                "SS-2003", "Authentication failures", Severity.HIGH, "source_ip", source_ip,
                "Repeated failed authentication attempts detected.",
            )
        return None

    def _record_and_count(self, timestamps: deque[float], now: float) -> int:
        cutoff = now - self.window_seconds
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
        timestamps.append(now)
        return len(timestamps)
