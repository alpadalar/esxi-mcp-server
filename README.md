# ESXi MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A [Model Context Protocol](https://modelcontextprotocol.io) server that lets MCP clients (Claude Desktop,
Cursor, ...) manage **VMware ESXi** and **vCenter** through [pyvmomi](https://github.com/vmware/pyvmomi).
Built on the official `mcp` Python SDK (FastMCP), secure by default.

> Status: beta. Unit-tested with mocks, not yet verified against a live ESXi/vCenter. Use a
> least-privilege vSphere role.

## Features
- Transports: **stdio** (default) and **streamable HTTP** (`/mcp`, `/healthz`)
- API key auth for HTTP (hash-only storage, constant-time compare, per request)
- TLS verification on by default (custom CA bundle supported)
- No plaintext secrets in config files; credentials redacted from logs
- Read-only mode and opt-in destructive operations
- Blocking pyvmomi calls run off the event loop; task polling with timeouts

## Tools
| Group | Tools |
|---|---|
| Inventory | `listVMs`, `listHosts`, `listClusters`, `listDatastores`, `listNetworks`, `getVMInfo`, `getVMStats` (+ resource `vmstats://{vm_name}`) |
| Lifecycle | `createVM`, `cloneVM`, `powerOn`, `reconfigureVM` |
| Snapshots | `listSnapshots`, `createSnapshot` |
| Destructive* | `deleteVM`, `powerOff`, `resetVM`, `shutdownGuest`, `rebootGuest`, `suspendVM`, `revertSnapshot`, `removeSnapshot` |
| Misc | `getServerInfo`, `authenticate` (deprecated, compatibility only) |

\* disabled unless `MCP_ALLOW_DESTRUCTIVE=true`; all non-read tools are disabled by `MCP_READ_ONLY=true`.

## Install
Requires Python >= 3.10.
```bash
uv tool install .            # or: pip install .
# from a checkout for development:
uv sync --extra dev
```

## Configure
Settings come from an optional YAML/JSON file (`--config` or `MCP_CONFIG_FILE`, see
[`config/config.example.yaml`](config/config.example.yaml)) overridden by environment variables.

| Variable | Meaning | Default |
|---|---|---|
| `VCENTER_HOST`, `VCENTER_USER` | target and account | required |
| `VCENTER_PASSWORD` / `VCENTER_PASSWORD_FILE` | password (env or secret file only) | required |
| `VCENTER_PORT`, `VCENTER_DATACENTER`, `VCENTER_CLUSTER`, `VCENTER_DATASTORE`, `VCENTER_NETWORK` | defaults for new VMs | first / most free space |
| `VCENTER_INSECURE` | `true` disables TLS verification (not recommended) | `false` |
| `VCENTER_CA_BUNDLE` | PEM file for private CAs | system CAs |
| `MCP_TRANSPORT` | `stdio` or `streamable-http` | `stdio` |
| `MCP_HOST`, `MCP_PORT`, `MCP_PATH` | HTTP bind | `127.0.0.1`, `8080`, `/mcp` |
| `MCP_API_KEY_HASH` (or `_FILE`) | `sha256:` hash of the API key, **required for HTTP** | - |
| `MCP_READ_ONLY`, `MCP_ALLOW_DESTRUCTIVE` | safety gates | `false`, `false` |
| `MCP_TASK_TIMEOUT` | seconds to wait for a vSphere task | `600` |
| `MCP_LOG_LEVEL`, `MCP_LOG_FILE` | logging (stderr by default) | `INFO` |

A plaintext `vcenter_password` or `api_key` in the config file is rejected.

### API key
```bash
esxi-mcp-server hash-key
# API key (give to clients, shown once): ...
# MCP_API_KEY_HASH=sha256:...
```
Clients send `Authorization: Bearer <key>` or `X-API-Key: <key>`.

## Run
**stdio** (Claude Desktop `claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "esxi": {
      "command": "esxi-mcp-server",
      "env": {
        "VCENTER_HOST": "vcenter.example.com",
        "VCENTER_USER": "svc-mcp@vsphere.local",
        "VCENTER_PASSWORD_FILE": "/home/me/.secrets/vcenter_password",
        "VCENTER_CA_BUNDLE": "/home/me/ca.pem"
      }
    }
  }
}
```
**HTTP**:
```bash
export MCP_API_KEY_HASH=sha256:...
esxi-mcp-server --transport streamable-http --config config/config.yaml
curl -s localhost:8080/healthz
```
Terminate TLS in a reverse proxy before exposing it beyond localhost.

## Docker
```bash
mkdir -p secrets && printf '%s' 'the-vcenter-password' > secrets/vcenter_password && chmod 600 secrets/vcenter_password
export VCENTER_HOST=vcenter.example.com VCENTER_USER=svc-mcp@vsphere.local
export MCP_API_KEY_HASH=$(docker compose run --rm esxi-mcp-server hash-key | sed -n 's/^MCP_API_KEY_HASH=//p')
docker compose up -d --build
```
The container runs as non-root with a read-only filesystem and publishes `127.0.0.1:8080` only.

## Migrating from 0.0.1
See [CHANGELOG.md](CHANGELOG.md): SSE endpoints removed, API key hashed and required for HTTP,
plaintext secrets rejected, TLS verification on, destructive tools opt-in.

## Development
```bash
uv run pytest --cov && uv run ruff check src tests && uv run mypy
```
See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). MIT licensed.
