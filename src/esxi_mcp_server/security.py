"""Authentication, secret handling and log redaction."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
from typing import Any

HASH_PREFIX = "sha256:"


def hash_api_key(key: str) -> str:
    """Return the storable hash (``sha256:<hex>``) of an API key."""
    return HASH_PREFIX + hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate_api_key() -> str:
    """Generate a high-entropy API key."""
    return secrets.token_urlsafe(32)


def is_valid_hash(value: str) -> bool:
    return bool(re.fullmatch(re.escape(HASH_PREFIX) + r"[0-9a-f]{64}", value))


def verify_api_key(candidate: str | None, expected_hash: str) -> bool:
    """Constant-time comparison of ``hash(candidate)`` with the stored hash."""
    if not candidate:
        return False
    return hmac.compare_digest(hash_api_key(candidate).encode(), expected_hash.encode())


def extract_api_key(headers: list[tuple[bytes, bytes]]) -> str | None:
    """Get the key from ``Authorization: Bearer`` or ``X-API-Key`` headers."""
    for name, value in headers:
        lname = name.lower()
        if lname == b"authorization":
            text = value.decode("latin-1")
            if text[:7].lower() == "bearer ":
                return text[7:].strip()
        elif lname == b"x-api-key":
            return value.decode("latin-1").strip()
    return None


class ApiKeyMiddleware:
    """Pure ASGI middleware enforcing the API key on every HTTP request.

    ``/healthz`` is answered without auth and without touching vSphere.
    """

    def __init__(self, app: Any, api_key_hash: str, exempt_paths: tuple[str, ...] = ("/healthz",)):
        self.app = app
        self.api_key_hash = api_key_hash
        self.exempt_paths = exempt_paths
        self.logger = logging.getLogger("esxi_mcp_server.auth")

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            await _respond(send, 403, {"error": "forbidden"})
            return
        if scope.get("path") in self.exempt_paths:
            await _respond(send, 200, {"status": "ok"})
            return
        if scope.get("method") == "OPTIONS":
            await _respond(send, 405, {"error": "method not allowed"})
            return
        key = extract_api_key(scope.get("headers", []))
        if not verify_api_key(key, self.api_key_hash):
            client = scope.get("client")
            self.logger.warning("Rejected request with missing/invalid API key from %s",
                                client[0] if client else "unknown")
            await _respond(send, 401, {"error": "unauthorized"},
                           [(b"www-authenticate", b"Bearer")])
            return
        await self.app(scope, receive, send)


async def _respond(send: Any, status: int, body: dict[str, str],
                   extra: list[tuple[bytes, bytes]] | None = None) -> None:
    payload = json.dumps(body).encode()
    headers = [(b"content-type", b"application/json"),
               (b"content-length", str(len(payload)).encode())] + (extra or [])
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": payload})


class RedactingFilter(logging.Filter):
    """Masks registered secrets and obvious credential patterns in log output."""

    _PATTERN = re.compile(
        r"(?i)(password|passwd|pwd|api[_-]?key|token|secret|authorization)"
        r"(\s*[=:]\s*|\s+)(bearer\s+)?([^\s,;'\"]+)"
    )

    def __init__(self, secrets_: list[str] | None = None) -> None:
        super().__init__()
        self._secrets = [s for s in (secrets_ or []) if s]

    def add_secret(self, value: str) -> None:
        if value:
            self._secrets.append(value)

    def redact(self, text: str) -> str:
        for s in self._secrets:
            text = text.replace(s, "***")
        return self._PATTERN.sub(lambda m: f"{m.group(1)}{m.group(2)}***", text)

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self.redact(record.getMessage())
        record.args = None
        return True
