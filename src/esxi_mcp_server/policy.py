"""Operation gating (read-only mode, destructive confirmation)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .errors import PolicyError


class OpClass(str, Enum):
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"


@dataclass(frozen=True)
class Policy:
    read_only: bool = False
    allow_destructive: bool = False

    def check(self, op: str, klass: OpClass) -> None:
        if klass is OpClass.READ:
            return
        if self.read_only:
            raise PolicyError(f"{op}: blocked, server runs in read-only mode (MCP_READ_ONLY)")
        if klass is OpClass.DESTRUCTIVE and not self.allow_destructive:
            raise PolicyError(
                f"{op}: destructive operation blocked; set MCP_ALLOW_DESTRUCTIVE=true to enable"
            )
