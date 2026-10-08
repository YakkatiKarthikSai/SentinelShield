"""A deliberately small local web application protected by SentinelShield.

Start with: python -m uvicorn sentinelshield.demo_app:app --reload
"""

from __future__ import annotations

from fastapi import FastAPI

from .factory import create_service
from .middleware import SentinelShieldMiddleware
from .service import SentinelShieldService


def create_app(service: SentinelShieldService | None = None) -> FastAPI:
    """Create the protected demo app; dependency injection keeps it testable."""

    app = FastAPI(
        title="SentinelShield Protected Demo",
        description="Small local demonstration of SentinelShield FastAPI middleware.",
    )
    app.add_middleware(SentinelShieldMiddleware, service=service or create_service())

    @app.get("/")
    def home() -> dict[str, str]:
        return {"message": "SentinelShield protected demo application is running."}

    @app.get("/search")
    def search(q: str = "") -> dict[str, str]:
        """Return a harmless placeholder search response after middleware inspection."""

        return {"status": "allowed", "query": q, "message": "Search request reached the demo application."}

    return app


app = create_app()
