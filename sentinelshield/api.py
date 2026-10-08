"""Local API for integrating SentinelShield with a demo web application."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .factory import create_service
from .models import HttpRequest
from .service import SentinelShieldService


class InspectionRequest(BaseModel):
    """Simplified HTTP-like request accepted by this local demo API."""

    method: str = Field(examples=["POST"])
    path: str = Field(examples=["/comment"])
    query: dict[str, str] = Field(default_factory=dict, examples=[{"id": "7 OR 1=1"}])
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = Field(default="", examples=["normal feedback text"])
    source_ip: str = Field(default="unknown", examples=["203.0.113.10"])


class AuthenticationResult(BaseModel):
    """Trusted outcome sent by an application after it checks credentials."""

    source_ip: str = Field(examples=["203.0.113.10"])
    success: bool = Field(examples=[False])


service = create_service()
app = FastAPI(
    title="SentinelShield API",
    version="0.1.0",
    description=(
        "Educational WAF/IDS prototype. Decisions indicate matches against a small rule set; "
        "they are not a guarantee that traffic is safe or malicious."
    ),
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentinelshield"}


@app.post("/inspect")
def inspect_request(request: InspectionRequest) -> dict[str, Any]:
    """Inspect an HTTP-like request and save the verdict as a local event."""

    event_id, verdict = service.inspect_and_record(HttpRequest(**request.model_dump()))
    return {"event_id": event_id, **verdict.to_dict()}


@app.post("/auth/result")
def record_authentication_result(result: AuthenticationResult) -> dict[str, Any]:
    """Record a trusted login outcome and alert after repeated failures."""

    event_id, verdict = service.record_authentication_result(result.source_ip, result.success)
    return {"event_id": event_id, **verdict.to_dict()}


@app.get("/events")
def recent_events(limit: int = 10) -> dict[str, Any]:
    return {"events": service.event_store.recent_events(limit=limit)}
