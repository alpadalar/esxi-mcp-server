"""Configuration model and loader (YAML/JSON file + environment)."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from .security import hash_api_key, is_valid_hash

logger = logging.getLogger("esxi_mcp_server.config")

FORBIDDEN_FILE_KEYS = {
    "vcenter_password": "use env VCENTER_PASSWORD or 'vcenter_password_file'",
    "password": "use env VCENTER_PASSWORD or 'vcenter_password_file'",
    "api_key": "store only 'api_key_hash' (run `esxi-mcp-server hash-key`)",
}


class ConfigError(ValueError):
    """Invalid or insecure configuration."""


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vcenter_host: str
    vcenter_user: str
    vcenter_password: SecretStr
    vcenter_port: int = Field(443, ge=1, le=65535)
    datacenter: str | None = None
    cluster: str | None = None
    datastore: str | None = None
    network: str | None = None

    # TLS: verification is ON unless explicitly disabled
    insecure: bool = False
    ca_bundle: str | None = None

    # Server
    transport: Literal["stdio", "streamable-http"] = "stdio"
    host: str = "127.0.0.1"
    port: int = Field(8080, ge=1, le=65535)
    path: str = "/mcp"
    api_key_hash: str | None = None
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_origins: list[str] = Field(default_factory=list)

    # Safety
    read_only: bool = False
    allow_destructive: bool = False
    task_timeout: int = Field(600, ge=1, le=86400)
    max_vm_cpus: int = Field(64, ge=1)
    max_vm_memory_mb: int = Field(1024 * 1024, ge=4)

    log_file: str | None = None
    log_level: str = "INFO"

    @field_validator("api_key_hash")
    @classmethod
    def _check_hash(cls, v: str | None) -> str | None:
        if v is not None and not is_valid_hash(v):
            raise ValueError("api_key_hash must look like 'sha256:<64 hex chars>'")
        return v

    @field_validator("path")
    @classmethod
    def _check_path(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("path must start with '/'")
        return v

    @field_validator("log_level")
    @classmethod
    def _check_level(cls, v: str) -> str:
        if v.upper() not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("invalid log_level")
        return v.upper()

    @model_validator(mode="after")
    def _http_needs_key(self) -> Settings:
        if self.transport == "streamable-http" and not self.api_key_hash:
            raise ValueError(
                "transport 'streamable-http' requires an API key: set MCP_API_KEY_HASH "
                "(or api_key_hash); generate one with `esxi-mcp-server hash-key`"
            )
        return self


_ENV_MAP = {
    "VCENTER_HOST": "vcenter_host",
    "VCENTER_USER": "vcenter_user",
    "VCENTER_PORT": "vcenter_port",
    "VCENTER_DATACENTER": "datacenter",
    "VCENTER_CLUSTER": "cluster",
    "VCENTER_DATASTORE": "datastore",
    "VCENTER_NETWORK": "network",
    "VCENTER_INSECURE": "insecure",
    "VCENTER_CA_BUNDLE": "ca_bundle",
    "MCP_TRANSPORT": "transport",
    "MCP_HOST": "host",
    "MCP_PORT": "port",
    "MCP_PATH": "path",
    "MCP_API_KEY_HASH": "api_key_hash",
    "MCP_READ_ONLY": "read_only",
    "MCP_ALLOW_DESTRUCTIVE": "allow_destructive",
    "MCP_TASK_TIMEOUT": "task_timeout",
    "MCP_LOG_FILE": "log_file",
    "MCP_LOG_LEVEL": "log_level",
}
_BOOL_KEYS = {"insecure", "read_only", "allow_destructive"}
_TRUE = {"1", "true", "yes", "on"}


def _read_secret_file(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ConfigError(f"cannot read secret file {path!r}: {exc.strerror}") from exc


def load_file(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path!r}: {exc.strerror}") from exc
    if p.suffix in (".yml", ".yaml"):
        data = yaml.safe_load(text)
    elif p.suffix == ".json":
        data = json.loads(text)
    else:
        raise ConfigError("unsupported config format: use .yaml, .yml or .json")
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError("config file must contain a mapping")
    return data


def load_settings(config_path: str | None = None, env: dict[str, str] | None = None) -> Settings:
    """Build :class:`Settings` from file, then environment (env wins)."""
    env = dict(os.environ) if env is None else env
    config_path = config_path or env.get("MCP_CONFIG_FILE")
    data = load_file(config_path)

    for key, hint in FORBIDDEN_FILE_KEYS.items():
        if key in data:
            raise ConfigError(
                f"'{key}' must not be stored in the config file (plaintext secret): {hint}"
            )

    password_file = data.pop("vcenter_password_file", None)
    for env_key, cfg_key in _ENV_MAP.items():
        if env_key in env and env[env_key] != "":
            val: Any = env[env_key]
            if cfg_key in _BOOL_KEYS:
                val = val.strip().lower() in _TRUE
            data[cfg_key] = val

    # Secrets: env > *_FILE > file path key
    if env.get("VCENTER_PASSWORD"):
        data["vcenter_password"] = env["VCENTER_PASSWORD"]
    elif env.get("VCENTER_PASSWORD_FILE") or password_file:
        data["vcenter_password"] = _read_secret_file(
            env.get("VCENTER_PASSWORD_FILE") or password_file
        )
    if not data.get("api_key_hash") and env.get("MCP_API_KEY_HASH_FILE"):
        data["api_key_hash"] = _read_secret_file(env["MCP_API_KEY_HASH_FILE"])
    if not data.get("api_key_hash") and env.get("MCP_API_KEY"):
        logger.warning(
            "MCP_API_KEY (plaintext) is deprecated; it was hashed in memory. "
            "Use MCP_API_KEY_HASH instead."
        )
        data["api_key_hash"] = hash_api_key(env["MCP_API_KEY"])

    try:
        settings = Settings(**data)
    except Exception as exc:  # pydantic.ValidationError -> sanitized message
        raise ConfigError(_format_validation_error(exc)) from None
    if settings.insecure:
        logger.warning("TLS certificate verification is DISABLED (insecure=true)")
    return settings


def _format_validation_error(exc: Exception) -> str:
    errors = getattr(exc, "errors", None)
    if not callable(errors):
        return str(exc)
    parts = []
    for e in errors():
        loc = ".".join(str(x) for x in e["loc"]) or "config"
        parts.append(f"{loc}: {e['msg']}")  # never echo input values (may be secrets)
    return "invalid configuration: " + "; ".join(parts)
