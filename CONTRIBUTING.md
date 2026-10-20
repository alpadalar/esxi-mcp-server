# Contributing

```bash
uv sync --extra dev
uv run pytest --cov            # unit tests (no vCenter needed; pyvmomi is mocked)
uv run ruff check src tests && uv run mypy
uv run bandit -q -r src
```

- Keep the MCP surface stable: do not rename tools or parameters; add optional parameters only.
- New vSphere operations go in `vsphere.py` (blocking), get a validation + policy class in
  `server.py` (`READ`, `WRITE`, `DESTRUCTIVE`) and tests with mocks. Real pyvmomi types are used in
  tests (`MagicMock(spec=vim.X)`) so spec/type errors surface.
- Never log or return credentials; never add plaintext secret options to the config file.
- Conventional commits (`feat:`, `fix:`, `docs:` ...), small focused PRs, update `CHANGELOG.md`.
