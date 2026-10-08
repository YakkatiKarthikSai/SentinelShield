"""FastAPI middleware adapter for applying SentinelShield to real HTTP requests."""

from __future__ import annotations

from typing import Awaitable, Callable

from starlette.datastructures import QueryParams
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .models import HttpRequest
from .service import SentinelShieldService


class SentinelShieldMiddleware:
    """Inspect inbound FastAPI requests and return 403 for blocked verdicts.

    This is a local demonstration adapter. For a deployment behind a reverse
    proxy, configure trusted proxy handling before relying on client addresses.
    """

    def __init__(self, app: ASGIApp, service: SentinelShieldService) -> None:
        self.app = app
        self.service = service

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        body_parts: list[bytes] = []
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] == "http.request":
                body_parts.append(message.get("body", b""))
                if not message.get("more_body", False):
                    break

        raw_body = b"".join(body_parts)
        headers = {
            key.decode("latin-1"): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        query = dict(QueryParams(scope.get("query_string", b"").decode("latin-1")))
        client = scope.get("client")
        source_ip = client[0] if client else "unknown"
        inspection_request = HttpRequest(
            method=scope["method"],
            path=scope["path"],
            query=query,
            headers=headers,
            body=raw_body.decode("utf-8", errors="replace"),
            source_ip=source_ip,
        )
        event_id, verdict = self.service.inspect_and_record(inspection_request)
        if verdict.decision == "block":
            response = JSONResponse(
                status_code=403,
                content={"event_id": event_id, **verdict.to_dict()},
            )
            await response(scope, receive, send)
            return

        replayed = False

        async def replay_receive() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": raw_body, "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)
