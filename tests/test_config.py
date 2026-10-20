from __future__ import annotations

import pytest

from esxi_mcp_server.config import ConfigError, load_settings
from esxi_mcp_server.security import hash_api_key

BASE_ENV = {"VCENTER_HOST": "vc", "VCENTER_USER": "u", "VCENTER_PASSWORD": "pw-test"}


def test_env_only_defaults_are_secure():
    s = load_settings(env=dict(BASE_ENV))
    assert s.insecure is False and s.transport == "stdio" and s.host == "127.0.0.1"
    assert s.allow_destructive is False
    assert "pw-test" not in repr(s)  # SecretStr


def test_plaintext_password_in_file_rejected(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("vcenter_host: vc\nvcenter_user: u\nvcenter_password: oops\n")
    with pytest.raises(ConfigError, match="plaintext"):
        load_settings(str(f), env={})


def test_plaintext_api_key_in_file_rejected(tmp_path):
    f = tmp_path / "c.json"
    f.write_text('{"vcenter_host":"vc","api_key":"abc"}')
    with pytest.raises(ConfigError, match="api_key_hash"):
        load_settings(str(f), env=dict(BASE_ENV))


def test_file_plus_env_override(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("vcenter_host: from-file\nvcenter_user: u\nread_only: false\n")
    s = load_settings(str(f), env={"VCENTER_PASSWORD": "p", "MCP_READ_ONLY": "true",
                                   "VCENTER_HOST": "from-env"})
    assert s.vcenter_host == "from-env" and s.read_only is True


def test_password_from_file(tmp_path):
    pw = tmp_path / "pw"
    pw.write_text("file-secret\n")
    s = load_settings(env={"VCENTER_HOST": "h", "VCENTER_USER": "u",
                           "VCENTER_PASSWORD_FILE": str(pw)})
    assert s.vcenter_password.get_secret_value() == "file-secret"


def test_http_requires_api_key():
    with pytest.raises(ConfigError, match="API key"):
        load_settings(env={**BASE_ENV, "MCP_TRANSPORT": "streamable-http"})


def test_http_with_hash_ok():
    h = hash_api_key("k")
    s = load_settings(env={**BASE_ENV, "MCP_TRANSPORT": "streamable-http", "MCP_API_KEY_HASH": h})
    assert s.api_key_hash == h


def test_legacy_plain_api_key_env_is_hashed():
    s = load_settings(env={**BASE_ENV, "MCP_API_KEY": "legacy"})
    assert s.api_key_hash == hash_api_key("legacy")


def test_invalid_hash_rejected():
    with pytest.raises(ConfigError, match="api_key_hash"):
        load_settings(env={**BASE_ENV, "MCP_API_KEY_HASH": "plain"})


def test_validation_error_does_not_echo_secret():
    with pytest.raises(ConfigError) as ei:
        load_settings(env={**BASE_ENV, "MCP_API_KEY_HASH": "super-secret-value"})
    assert "super-secret-value" not in str(ei.value)


def test_unknown_file_key_and_bad_extension(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("vcenter_host: h\nvcenter_user: u\nbogus: 1\n")
    with pytest.raises(ConfigError):
        load_settings(str(f), env={"VCENTER_PASSWORD": "p"})
    g = tmp_path / "c.txt"
    g.write_text("x")
    with pytest.raises(ConfigError, match="unsupported"):
        load_settings(str(g), env={})
    with pytest.raises(ConfigError, match="cannot read"):
        load_settings(str(tmp_path / "missing.yaml"), env={})
