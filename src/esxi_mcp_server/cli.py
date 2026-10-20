"""Command line entry point."""

from __future__ import annotations

import argparse
import logging
import logging.handlers
import os
import sys
from collections.abc import Sequence

from . import __version__
from .config import ConfigError, Settings, _format_validation_error, load_settings
from .security import ApiKeyMiddleware, RedactingFilter, generate_api_key, hash_api_key


class SecureRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Rotating log handler that always creates files with mode 0600 (also after rollover)."""

    def _open(self):  # type: ignore[no-untyped-def]
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.fchmod(fd, 0o600)  # also tightens a pre-existing file
        return os.fdopen(fd, "a", encoding=self.encoding, errors=self.errors)


def setup_logging(settings: Settings) -> None:
    """Log to stderr (stdout is the MCP stdio channel) or a file, with secret redaction."""
    handler: logging.Handler
    if settings.log_file:
        handler = SecureRotatingFileHandler(
            settings.log_file, maxBytes=10_000_000, backupCount=5)
    else:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    known = [settings.vcenter_password.get_secret_value(), settings.api_key_hash or "",
             os.environ.get("MCP_API_KEY", "")]  # values are masked wherever they appear
    handler.addFilter(RedactingFilter(known))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(settings.log_level)


def build_http_app(settings: Settings, mcp: object):  # type: ignore[no-untyped-def]
    if not settings.api_key_hash:
        raise ConfigError("API key hash required for HTTP transport")
    app = mcp.streamable_http_app()  # type: ignore[attr-defined]
    return ApiKeyMiddleware(app, settings.api_key_hash)


def run(settings: Settings) -> None:
    from .server import build_server

    mcp = build_server(settings)
    client = mcp._esxi_client  # type: ignore[attr-defined]
    log = logging.getLogger("esxi_mcp_server")
    try:
        if settings.transport == "stdio":
            log.info("Starting stdio transport")
            mcp.run("stdio")
        else:
            import uvicorn

            log.info("Starting streamable-http on %s:%s%s", settings.host, settings.port,
                     settings.path)
            uvicorn.run(build_http_app(settings, mcp), host=settings.host, port=settings.port,
                        log_level=settings.log_level.lower())
    finally:
        client.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="esxi-mcp-server", description="ESXi/vCenter MCP server")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("hash-key", help="generate an API key and print it with its hash")
    parser.add_argument("--config", "-c", help="YAML/JSON config file (no plaintext secrets)")
    parser.add_argument("--transport", choices=["stdio", "streamable-http"])
    args = parser.parse_args(argv)

    if args.command == "hash-key":
        key = generate_api_key()
        print(f"API key (give to clients, shown once): {key}")
        print(f"MCP_API_KEY_HASH={hash_api_key(key)}")
        return 0

    try:
        settings = load_settings(args.config)
        if args.transport:
            settings = Settings(**{**settings.model_dump(), "transport": args.transport})
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pydantic error from CLI override
        print(f"configuration error: {_format_validation_error(exc)}", file=sys.stderr)
        return 2
    setup_logging(settings)
    run(settings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
