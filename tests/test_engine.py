"""Safe offline tests for SentinelShield's classroom signatures."""

import unittest

from sentinelshield import HttpRequest, InspectionEngine
from sentinelshield.abuse import AbuseDetector


class InspectionEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = InspectionEngine()

    def assert_blocked_for(self, request: HttpRequest, category: str) -> None:
        verdict = self.engine.inspect(request)
        self.assertEqual("block", verdict.decision)
        self.assertIn(category, [finding.category for finding in verdict.findings])

    def test_normal_search_is_allowed(self) -> None:
        verdict = self.engine.inspect(HttpRequest("GET", "/search", query={"q": "campus map"}))
        self.assertEqual("allow", verdict.decision)
        self.assertEqual((), verdict.findings)

    def test_sql_injection_indicator_in_query_is_blocked(self) -> None:
        self.assert_blocked_for(HttpRequest("GET", "/products", query={"id": "7 OR 1=1"}), "SQL injection")

    def test_xss_indicator_in_body_is_blocked(self) -> None:
        self.assert_blocked_for(HttpRequest("POST", "/comment", body="<script>demo()</script>"), "Cross-site scripting")

    def test_xss_event_handler_is_blocked(self) -> None:
        self.assert_blocked_for(HttpRequest("POST", "/comment", body="<img onerror=demo>"), "Cross-site scripting")

    def test_percent_encoded_xss_indicator_is_blocked(self) -> None:
        self.assert_blocked_for(
            HttpRequest("GET", "/search", query={"q": "%3Cscript%3Edemo%28%29%3C%2Fscript%3E"}),
            "Cross-site scripting",
        )

    def test_html_entity_encoded_xss_indicator_is_blocked(self) -> None:
        self.assert_blocked_for(
            HttpRequest("POST", "/comment", body="&lt;script&gt;demo()&lt;/script&gt;"),
            "Cross-site scripting",
        )

    def test_directory_traversal_is_blocked(self) -> None:
        self.assert_blocked_for(HttpRequest("GET", "/download", query={"file": "../../notes.txt"}), "Directory traversal")

    def test_percent_encoded_traversal_is_blocked(self) -> None:
        self.assert_blocked_for(
            HttpRequest("GET", "/download", query={"file": "%2e%2e%2fnotes.txt"}),
            "Directory traversal",
        )

    def test_lfi_indicator_is_blocked(self) -> None:
        self.assert_blocked_for(HttpRequest("GET", "/view", query={"page": "/etc/passwd"}), "Local file inclusion")

    def test_command_injection_indicator_is_blocked(self) -> None:
        self.assert_blocked_for(HttpRequest("GET", "/ping", query={"host": "example.test; whoami"}), "Command injection")

    def test_sensitive_path_probe_is_blocked(self) -> None:
        self.assert_blocked_for(HttpRequest("GET", "/.env"), "Sensitive path probing")

    def test_path_is_inspected(self) -> None:
        self.assert_blocked_for(HttpRequest("GET", "/files/../../private"), "Directory traversal")

    def test_oversized_body_is_blocked_without_rule_scanning(self) -> None:
        engine = InspectionEngine(max_field_length=10)
        verdict = engine.inspect(HttpRequest("POST", "/feedback", body="x" * 11))
        self.assertEqual("block", verdict.decision)
        self.assertEqual("Oversized input", verdict.findings[0].category)
        self.assertEqual("11 characters", verdict.findings[0].evidence)

    def test_header_is_inspected(self) -> None:
        self.assert_blocked_for(HttpRequest("GET", "/", headers={"X-Note": "$(id)"}), "Command injection")

    def test_rate_limit_burst_is_blocked(self) -> None:
        times = iter([0, 1, 2])
        engine = InspectionEngine(AbuseDetector(request_limit=2, clock=lambda: next(times)))
        request = HttpRequest("GET", "/search", source_ip="198.51.100.21")
        engine.inspect(request)
        engine.inspect(request)
        verdict = engine.inspect(request)
        self.assertEqual("block", verdict.decision)
        self.assertIn("Rate limit", [finding.category for finding in verdict.findings])

    def test_login_burst_is_blocked_but_not_called_a_failed_login(self) -> None:
        times = iter(range(6))
        engine = InspectionEngine(AbuseDetector(login_limit=5, clock=lambda: next(times)))
        request = HttpRequest("POST", "/login", source_ip="198.51.100.22")
        for _ in range(5):
            engine.inspect(request)
        verdict = engine.inspect(request)
        self.assertEqual("block", verdict.decision)
        self.assertIn("Login burst", [finding.category for finding in verdict.findings])

    def test_confirmed_authentication_failures_are_blocked(self) -> None:
        times = iter(range(6))
        detector = AbuseDetector(login_limit=5, clock=lambda: next(times))
        for _ in range(5):
            self.assertIsNone(detector.record_authentication_result("198.51.100.23", success=False))
        finding = detector.record_authentication_result("198.51.100.23", success=False)
        self.assertIsNotNone(finding)
        self.assertEqual("Authentication failures", finding.category)

    def test_successful_authentication_clears_failure_counter(self) -> None:
        detector = AbuseDetector(login_limit=1, clock=lambda: 1)
        detector.record_authentication_result("198.51.100.24", success=False)
        detector.record_authentication_result("198.51.100.24", success=True)
        self.assertIsNone(detector.record_authentication_result("198.51.100.24", success=False))


if __name__ == "__main__":
    unittest.main()
