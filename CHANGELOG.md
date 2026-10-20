# Changelog

All notable changes to this project are documented here. Format: Keep a Changelog; versioning: SemVer.

## [0.2.0] - Unreleased

Complete rewrite of the single-file prototype (v0.0.1). The prototype's custom SSE/JSON-RPC glue
did not use a valid MCP SDK API; this release is built on the official `mcp` Python SDK (FastMCP).

### Added
- Installable package (`pyproject.toml`, `src/` layout, `uv.lock`), console script `esxi-mcp-server`, Python >= 3.10.
- Transports: `stdio` (default) and `streamable-http` (`/mcp`), `/healthz` endpoint.
- New tools: `getVMInfo`, `getVMStats`, `listHosts`, `listClusters`, `listDatastores`,
  `listNetworks`, `shutdownGuest`, `rebootGuest`, `resetVM`, `suspendVM`, `reconfigureVM`,
  `listSnapshots`, `createSnapshot`, `revertSnapshot`, `removeSnapshot`, `getServerInfo`.
- Optional parameters: `createVM.disk_gb`, `cloneVM.datastore`.
- Tool annotations (read-only / destructive hints) for MCP clients.
- Safety gates: `read_only`, `allow_destructive`, input validation, size limits.
- `esxi-mcp-server hash-key` to generate an API key and its hash.
- pytest suite (pyvmomi mocks), GitHub Actions (test, lint, security), SECURITY.md, CONTRIBUTING.md.

### Changed (BREAKING)
- Transport: legacy `/sse` + `/sse/messages` endpoints are gone; use stdio or streamable HTTP at `/mcp`.
- HTTP requires an API key, supplied per request (`Authorization: Bearer <key>` or `X-API-Key`);
  the server stores only a `sha256:` hash (`MCP_API_KEY_HASH`). The shared global "authenticated" flag
  is removed; the `authenticate` tool remains as a compatibility no-op/validator.
- Plaintext `vcenter_password` / `api_key` in config files are rejected. Use `VCENTER_PASSWORD`,
  `VCENTER_PASSWORD_FILE`, `MCP_API_KEY_HASH`. `MCP_API_KEY` (plaintext env) still works, deprecated,
  hashed in memory.
- TLS verification is on by default (`insecure: false`); use `VCENTER_CA_BUNDLE` for private CAs.
- HTTP binds `127.0.0.1` by default (was `0.0.0.0:8080`); wildcard CORS removed.
- `deleteVM`, `powerOff` (and new `resetVM`, `revertSnapshot`, `removeSnapshot`) are blocked
  unless `MCP_ALLOW_DESTRUCTIVE=true`. `deleteVM` refuses powered-on VMs.
- Config file keys unknown to the schema are rejected. `MCP_CONFIG_FILE` and `--config` unchanged.
- Docker: non-root, read-only image, compose uses secrets; `docker-entrypoint.sh`, `Makefile`,
  `config.yaml.sample`, `requirements.txt`, `README_ZH.md` and `README_DOCKER.md` removed
  (Docker docs merged into README).

### Fixed
- Busy-wait on vSphere tasks (100% CPU, no timeout) -> polling with timeout and cancel.
- Blocking pyvmomi calls no longer run on the event loop.
- VM creation now sets `files.vmPathName` (required by vSphere).
- Network counters were assigned by list position; now matched by counter name.
- Ambiguous VM names are reported instead of silently picking the first match.
- Sessions are re-established when expired; connection closed on shutdown.
