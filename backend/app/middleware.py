"""Pure-ASGI middleware: request IDs + access log, body size limits, security headers."""
from __future__ import annotations

import logging
import time
import uuid

from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = logging.getLogger("pipelineguard.access")


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        rid = uuid.uuid4().hex[:16]
        scope.setdefault("state", {})["request_id"] = rid
        start = time.perf_counter()
        status = 500
        is_docs = scope["path"].startswith("/api/v1/docs") or scope["path"].startswith("/api/v1/redoc")

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = message.setdefault("headers", [])
                extra = {
                    b"x-request-id": rid.encode(),
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"cross-origin-resource-policy": b"same-origin",
                    b"permissions-policy": b"geolocation=(), microphone=(), camera=()",
                    b"cache-control": b"no-store",
                }
                if not is_docs:
                    extra[b"content-security-policy"] = b"default-src 'none'; frame-ancestors 'none'"
                headers.extend(extra.items())
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            log.info("request", extra={"request_id": rid, "method": scope["method"], "path": scope["path"], "status": status,
                                       "duration_ms": round((time.perf_counter() - start) * 1000, 1)})


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope["headers"]).get(b"content-length")
        too_big = False
        if declared is not None:
            try:
                too_big = int(declared) > self.max_bytes
            except ValueError:
                too_big = True
        if too_big:
            await self._reject(send)
            return
        total = 0

        async def limited_receive() -> Message:
            nonlocal total
            msg = await receive()
            if msg["type"] == "http.request":
                total += len(msg.get("body", b""))
                if total > self.max_bytes:
                    raise _TooLarge()
            return msg

        try:
            await self.app(scope, limited_receive, send)
        except _TooLarge:
            await self._reject(send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = b'{"error":"payload_too_large","detail":"Request body exceeds the configured limit"}'
        await send({"type": "http.response.start", "status": 413, "headers": [(b"content-type", b"application/json"),
                                                                              (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


class _TooLarge(Exception):
    pass
