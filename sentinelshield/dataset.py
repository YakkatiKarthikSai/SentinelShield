"""Small labelled offline dataset for repeatable classroom evaluation.

These requests are inert strings: they are never sent to a server or executed.
Labels describe whether the sample is deliberately attack-shaped, not whether an
actual exploit would succeed against a real application.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import HttpRequest


@dataclass(frozen=True)
class LabelledRequest:
    name: str
    request: HttpRequest
    malicious: bool


EVALUATION_DATASET: tuple[LabelledRequest, ...] = (
    LabelledRequest("normal_search", HttpRequest("GET", "/search", query={"q": "campus library"}), False),
    LabelledRequest("normal_profile", HttpRequest("GET", "/profile", query={"tab": "settings"}), False),
    LabelledRequest("normal_feedback", HttpRequest("POST", "/feedback", body="The dashboard is helpful."), False),
    LabelledRequest("sql_indicator", HttpRequest("GET", "/items", query={"id": "7 OR 1=1"}), True),
    LabelledRequest("xss_indicator", HttpRequest("POST", "/comment", body="<script>demo()</script>"), True),
    LabelledRequest("traversal_indicator", HttpRequest("GET", "/download", query={"file": "../../notes.txt"}), True),
    LabelledRequest("lfi_indicator", HttpRequest("GET", "/view", query={"page": "/etc/passwd"}), True),
    LabelledRequest("command_indicator", HttpRequest("GET", "/ping", query={"host": "example.test; whoami"}), True),
    LabelledRequest("sensitive_path_probe", HttpRequest("GET", "/.env"), True),
)
