# Security Policy

## Supported versions
Only the latest release receives security fixes.

## Reporting a vulnerability
Please do **not** open a public issue. Use GitHub's private "Report a vulnerability" (Security
Advisories) feature on this repository. Include affected version, reproduction steps and impact.
Expect an acknowledgement within 7 days.

## Security model
- This server can create, modify and delete virtual machines with the privileges of the configured
  vSphere account. **Use a dedicated least-privilege vSphere role**, never a global administrator.
- stdio transport: trust boundary is the local process that launches the server.
- HTTP transport: every request needs an API key (`Authorization: Bearer` or `X-API-Key`); only a
  SHA-256 hash is configured on the server. Keys are high-entropy random values from
  `esxi-mcp-server hash-key`. Terminate TLS in a reverse proxy; do not expose plain HTTP to untrusted networks.
- TLS to vCenter/ESXi is verified by default; `insecure` is an explicit opt-out.
- Secrets are accepted only via environment/secret files and redacted from logs.
- Destructive tools are off by default (`MCP_ALLOW_DESTRUCTIVE`); `MCP_READ_ONLY=true` disables all writes.
- Tool inputs are validated; names are never interpolated into shell commands (pyvmomi API only).

## Known limitations
- Default datastore is chosen at connect time by free space (accessibility/host mount not checked); set `datastore` explicitly.
- `authenticate` is informational; no per-IP throttling of failed keys (use the reverse proxy).
- No per-client authorization: anyone with the API key has the full privileges allowed by policy flags.
- No rate limiting built in; use the reverse proxy.
- Not verified against a live vCenter/ESXi by the maintainers of this fork at the time of 0.2.0 (see
  `.planning/HUMAN-TESTS.md`).
