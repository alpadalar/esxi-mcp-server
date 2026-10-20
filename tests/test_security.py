from __future__ import annotations

import logging

import httpx
import pytest

from esxi_mcp_server.security import (
    ApiKeyMiddleware,
    RedactingFilter,
    extract_api_key,
    generate_api_key,
    hash_api_key,
    is_valid_hash,
    verify_api_key,
)


def test_hash_roundtrip_and_format():
    key = generate_api_key()
    h = hash_api_key(key)
    assert is_valid_hash(h) and key not in h
    assert verify_api_key(key, h)
    assert not verify_api_key(key + "x", h)
    assert not verify_api_key(None, h)
    assert not verify_api_key("", h)


def test_is_valid_hash_rejects_garbage():
    assert not is_valid_hash("plaintext")
    assert not is_valid_hash("sha256:ZZ")


def test_extract_api_key():
    assert extract_api_key([(b"Authorization", b"Bearer abc")]) == "abc"
    assert extract_api_key([(b"authorization", b"bearer abc")]) == "abc"
    assert extract_api_key([(b"x-api-key", b" k ")]) == "k"
    assert extract_api_key([(b"authorization", b"Basic abc")]) is None
    assert extract_api_key([]) is None


async def _ok_app(scope, receive, send):
    if scope["type"] == "lifespan":
        return
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"inner"})


@pytest.fixture
def client():
    app = ApiKeyMiddleware(_ok_app, hash_api_key("secret-1"))
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def test_middleware_rejects_without_key(client):
    r = await client.post("/mcp")
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"


async def test_middleware_rejects_wrong_key(client):
    r = await client.post("/mcp", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


@pytest.mark.parametrize("headers", [{"Authorization": "Bearer secret-1"},
                                     {"X-API-Key": "secret-1"}])
async def test_middleware_accepts_valid_key(client, headers):
    r = await client.post("/mcp", headers=headers)
    assert r.status_code == 200 and r.text == "inner"


async def test_healthz_is_open_and_never_reaches_app(client):
    r = await client.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


async def test_options_not_allowed_without_cors(client):
    r = await client.options("/mcp", headers={"Authorization": "Bearer secret-1"})
    assert r.status_code == 405
    assert "access-control-allow-origin" not in r.headers


def test_redacting_filter_masks_secrets(caplog):
    f = RedactingFilter(["hunter2"])
    assert "hunter2" not in f.redact("login with hunter2 ok")
    assert f.redact("password=abc123 next") == "password=*** next"
    assert f.redact("Authorization: Bearer tok.en") == "Authorization: ***"
    log = logging.getLogger("redact-test")
    log.addFilter(f)
    with caplog.at_level(logging.INFO, logger="redact-test"):
        log.info("connect pwd=%s", "hunter2")
    assert "hunter2" not in caplog.text


def test_redaction_covers_tracebacks_and_keeps_plain_text(caplog):
    f = RedactingFilter(["hunter2"])
    log = logging.getLogger("redact-tb")
    log.addFilter(f)
    with caplog.at_level(logging.ERROR, logger="redact-tb"):
        try:
            raise RuntimeError("bad pwd=hunter2")
        except RuntimeError:
            log.exception("failed")
    assert "hunter2" not in caplog.text
    assert f.redact("invalid API key from 1.2.3.4") == "invalid API key from 1.2.3.4"


async def test_websocket_scope_closed_not_http_response():
    sent = []

    async def send(m):
        sent.append(m)

    mw = ApiKeyMiddleware(_ok_app, hash_api_key("k"))
    await mw({"type": "websocket", "path": "/mcp"}, None, send)
    assert sent == [{"type": "websocket.close", "code": 1008}]


@pytest.mark.parametrize("text,expected", [
    ("Authorization Bearer xyz", "Authorization ***"),
    ("api_key abc-12345678", "api_key ***"),
    ("token=short", "token=***"),
    ("token validation failed", "token validation failed"),
    ("the password was rotated", "the password was rotated"),
])
def test_redaction_space_separated_tokens(text, expected):
    assert RedactingFilter().redact(text) == expected


def test_known_value_masked_anywhere():
    f = RedactingFilter()
    f.add_secret("s3cr3tvalue")
    assert "s3cr3tvalue" not in f.redact("weird s3cr3tvalue placement")
