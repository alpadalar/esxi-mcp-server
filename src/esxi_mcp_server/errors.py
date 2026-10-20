"""Exception hierarchy. Messages are safe to show to MCP clients."""


class EsxiMcpError(Exception):
    """Base class for expected, user-facing errors."""


class ValidationError(EsxiMcpError):
    """Invalid tool input."""


class PolicyError(EsxiMcpError):
    """Operation blocked by read_only / allow_destructive policy."""


class VSphereError(EsxiMcpError):
    """vSphere API failure, missing object or task failure."""
