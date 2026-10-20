from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from esxi_mcp_server import cli
from esxi_mcp_server.server import build_server
from tests.conftest import API_KEY

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                   "clientInfo": {"name": "t", "version": "0"}}}
HDRS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


@pytest.fixture
def http_app(make_settings, fake_client):
    from esxi_mcp_server.security import hash_api_key
    s = make_settings(transport="streamable-http", api_key_hash=hash_api_key(API_KEY))
    return cli.build_http_app(s, build_server(s, fake_client))


def test_http_requires_key_end_to_end(http_app):
    with TestClient(http_app, base_url="http://localhost:8080") as c:
        assert c.get("/healthz").status_code == 200
        assert c.post("/mcp", json=INIT, headers=HDRS).status_code == 401
        bad = c.post("/mcp", json=INIT, headers={**HDRS, "Authorization": "Bearer wrong"})
        assert bad.status_code == 401
        ok = c.post("/mcp", json=INIT, headers={**HDRS, "Authorization": f"Bearer {API_KEY}"})
        assert ok.status_code == 200 and "VMware-MCP-Server" in ok.text


def test_http_no_wildcard_cors(http_app):
    with TestClient(http_app, base_url="http://localhost:8080") as c:
        r = c.post("/mcp", json=INIT, headers={**HDRS, "X-API-Key": API_KEY,
                                               "Origin": "http://evil.example"})
        assert r.headers.get("access-control-allow-origin") != "*"
        assert r.status_code in (200, 403)


def test_cli_hash_key(capsys):
    assert cli.main(["hash-key"]) == 0
    out = capsys.readouterr().out
    assert "MCP_API_KEY_HASH=sha256:" in out


def test_cli_config_error_exit_code(monkeypatch, capsys):
    for k in ("VCENTER_HOST", "VCENTER_USER", "VCENTER_PASSWORD", "MCP_CONFIG_FILE"):
        monkeypatch.delenv(k, raising=False)
    assert cli.main([]) == 2
    assert "configuration error" in capsys.readouterr().err


def test_cli_http_without_key_refuses(monkeypatch, capsys):
    monkeypatch.setenv("VCENTER_HOST", "h")
    monkeypatch.setenv("VCENTER_USER", "u")
    monkeypatch.setenv("VCENTER_PASSWORD", "p")
    monkeypatch.delenv("MCP_API_KEY_HASH", raising=False)
    monkeypatch.delenv("MCP_API_KEY", raising=False)
    assert cli.main(["--transport", "streamable-http"]) == 2
    assert "API key" in capsys.readouterr().err


def test_cli_runs_stdio_and_closes_client(monkeypatch, make_settings):
    from unittest.mock import MagicMock
    s = make_settings()
    fake_mcp = MagicMock()
    monkeypatch.setattr("esxi_mcp_server.server.build_server", lambda settings: fake_mcp)
    cli.run(s)
    fake_mcp.run.assert_called_once_with("stdio")
    fake_mcp._esxi_client.close.assert_called_once()


def test_setup_logging_redacts_password(make_settings, capsys):
    import logging
    cli.setup_logging(make_settings())
    logging.getLogger("x").info("connecting with pw-for-tests now")
    err = capsys.readouterr().err
    assert "pw-for-tests" not in err and "***" in err


def test_log_file_mode_0600_including_after_rollover(tmp_path):
    import logging
    import os
    import stat
    path = tmp_path / "app.log"
    old = os.umask(0o022)  # permissive umask must not matter
    try:
        h = cli.SecureRotatingFileHandler(str(path), maxBytes=50, backupCount=2)
        lg = logging.getLogger("rot-test")
        lg.propagate = False
        lg.addHandler(h)
        lg.setLevel(logging.INFO)
        for i in range(10):
            lg.info("line %d with some padding text", i)
        h.close()
        lg.removeHandler(h)
    finally:
        os.umask(old)
    files = list(tmp_path.glob("app.log*"))
    assert len(files) >= 2  # rollover happened
    for f in files:
        assert stat.S_IMODE(f.stat().st_mode) == 0o600, f
