"""FastMCP server definition: tool registration, policy gating, async wrapping."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from typing import Any, TypeVar

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations

from . import __version__, validation
from .config import Settings
from .errors import EsxiMcpError
from .policy import OpClass, Policy
from .security import verify_api_key
from .vsphere import VSphereClient

logger = logging.getLogger("esxi_mcp_server.server")
T = TypeVar("T")

_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _transport_security(settings: Settings) -> TransportSecuritySettings:
    if settings.allowed_hosts or settings.allowed_origins:
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=settings.allowed_hosts, allowed_origins=settings.allowed_origins)
    if settings.host in _LOOPBACK:
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*"],
            allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"])
    # Non-loopback bind: every request must carry the API key (enforced by middleware),
    # which makes DNS-rebinding moot; configure allowed_hosts to tighten further.
    return TransportSecuritySettings(enable_dns_rebinding_protection=False)


def build_server(settings: Settings, client: VSphereClient | None = None) -> FastMCP:
    client = client or VSphereClient(settings)
    policy = Policy(settings.read_only, settings.allow_destructive)
    mcp = FastMCP(
        "VMware-MCP-Server",
        instructions="Manage VMware ESXi / vCenter virtual machines and inventory.",
        host=settings.host, port=settings.port,
        streamable_http_path=settings.path,
        log_level=settings.log_level,  # type: ignore[arg-type]
        transport_security=_transport_security(settings),
    )
    mcp._esxi_client = client  # type: ignore[attr-defined]  # exposed for cleanup/tests

    async def run(op: str, klass: OpClass, fn: Callable[..., T], *args: Any) -> T:
        """Policy check, run blocking pyvmomi code in a thread, map errors."""
        try:
            policy.check(op, klass)
            return await asyncio.to_thread(fn, *args)
        except EsxiMcpError as exc:
            raise ToolError(str(exc)) from None
        except Exception:
            logger.exception("unexpected error in %s", op)
            raise ToolError(f"{op}: internal error, see server log") from None

    def jdump(data: Any) -> str:
        return json.dumps(data, indent=2, default=str)

    R = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)
    W = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False)
    D = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False)

    # -------- legacy surface (names and parameters unchanged) --------
    @mcp.tool(name="authenticate", annotations=R,
              description="Deprecated: authentication is enforced per request on the HTTP "
                          "transport (Bearer / X-API-Key). Kept for client compatibility.")
    async def authenticate(key: str) -> str:
        if settings.api_key_hash is None:
            return "Authentication is not required on this transport."
        if not verify_api_key(key, settings.api_key_hash):
            raise ToolError("Authentication failed: invalid API key.")
        return "Authentication successful."

    @mcp.tool(name="createVM", annotations=W,
              description="Create a new virtual machine (empty thin disk, optional network).")
    async def create_vm(name: str, cpu: int, memory: int, datastore: str | None = None,
                        network: str | None = None, disk_gb: int = 10) -> str:
        def op() -> str:
            validation.vm_name(name)
            validation.int_range(cpu, "cpu", 1, settings.max_vm_cpus)
            validation.int_range(memory, "memory", 4, settings.max_vm_memory_mb)
            validation.int_range(disk_gb, "disk_gb", 1, 65536)
            if datastore:
                validation.object_name(datastore, "datastore")
            if network:
                validation.object_name(network, "network")
            return client.create_vm(name, cpu, memory, datastore, network, disk_gb)
        return await run("createVM", OpClass.WRITE, op)

    @mcp.tool(name="cloneVM", annotations=W,
              description="Clone a virtual machine from a template or existing VM.")
    async def clone_vm(template_name: str, new_name: str, datastore: str | None = None) -> str:
        def op() -> str:
            validation.vm_name(template_name, "template_name")
            validation.vm_name(new_name, "new_name")
            if datastore:
                validation.object_name(datastore, "datastore")
            return client.clone_vm(template_name, new_name, datastore)
        return await run("cloneVM", OpClass.WRITE, op)

    @mcp.tool(name="deleteVM", annotations=D,
              description="Delete a (powered-off) virtual machine. DESTRUCTIVE; requires "
                          "MCP_ALLOW_DESTRUCTIVE=true.")
    async def delete_vm(name: str) -> str:
        def op() -> str:
            validation.vm_name(name)
            return client.delete_vm(name)
        return await run("deleteVM", OpClass.DESTRUCTIVE, op)

    @mcp.tool(name="powerOn", annotations=W, description="Power on a virtual machine.")
    async def power_on(name: str) -> str:
        def op() -> str:
            validation.vm_name(name)
            return client.power_on_vm(name)
        return await run("powerOn", OpClass.WRITE, op)

    @mcp.tool(name="powerOff", annotations=D,
              description="Hard power off a virtual machine. DESTRUCTIVE; requires "
                          "MCP_ALLOW_DESTRUCTIVE=true. Prefer shutdownGuest.")
    async def power_off(name: str) -> str:
        def op() -> str:
            validation.vm_name(name)
            return client.power_off_vm(name)
        return await run("powerOff", OpClass.DESTRUCTIVE, op)

    @mcp.tool(name="listVMs", annotations=R, description="List all virtual machines.")
    async def list_vms() -> list[str]:
        return await run("listVMs", OpClass.READ, client.list_vms)

    # -------- new tools --------
    @mcp.tool(name="getVMInfo", annotations=R,
              description="Detailed information about one VM (power state, IP, host, ...).")
    async def get_vm_info(name: str) -> str:
        def op() -> str:
            validation.vm_name(name)
            return jdump(client.get_vm_info(name))
        return await run("getVMInfo", OpClass.READ, op)

    @mcp.tool(name="getVMStats", annotations=R,
              description="CPU (MHz), memory (MB), storage (GB) and network (KBps) usage of a VM.")
    async def get_vm_stats(name: str) -> str:
        def op() -> str:
            validation.vm_name(name)
            return jdump(client.get_vm_performance(name))
        return await run("getVMStats", OpClass.READ, op)

    @mcp.resource("vmstats://{vm_name}", name="vmStats", mime_type="application/json",
                  description="Get CPU, memory, storage, network usage of a VM")
    async def vm_stats_resource(vm_name: str) -> str:
        return str(await get_vm_stats(vm_name))

    for tool_name, fn, desc in (
        ("listHosts", client.list_hosts, "List ESXi hosts with state and resource usage."),
        ("listClusters", client.list_clusters, "List clusters (DRS/HA state)."),
        ("listDatastores", client.list_datastores, "List datastores with capacity and free space."),
        ("listNetworks", client.list_networks, "List networks and distributed port groups."),
    ):
        _register_inventory(mcp, run, jdump, R, tool_name, fn, desc)

    @mcp.tool(name="shutdownGuest", annotations=W,
              description="Graceful guest OS shutdown (requires VMware Tools).")
    async def shutdown_guest(name: str) -> str:
        def op() -> str:
            validation.vm_name(name)
            return client.shutdown_guest(name)
        return await run("shutdownGuest", OpClass.WRITE, op)

    @mcp.tool(name="rebootGuest", annotations=W,
              description="Graceful guest OS reboot (requires VMware Tools).")
    async def reboot_guest(name: str) -> str:
        def op() -> str:
            validation.vm_name(name)
            return client.reboot_guest(name)
        return await run("rebootGuest", OpClass.WRITE, op)

    @mcp.tool(name="resetVM", annotations=D,
              description="Hard reset a VM. DESTRUCTIVE; requires MCP_ALLOW_DESTRUCTIVE=true.")
    async def reset_vm(name: str) -> str:
        def op() -> str:
            validation.vm_name(name)
            return client.reset_vm(name)
        return await run("resetVM", OpClass.DESTRUCTIVE, op)

    @mcp.tool(name="suspendVM", annotations=W, description="Suspend a virtual machine.")
    async def suspend_vm(name: str) -> str:
        def op() -> str:
            validation.vm_name(name)
            return client.suspend_vm(name)
        return await run("suspendVM", OpClass.WRITE, op)

    @mcp.tool(name="reconfigureVM", annotations=W,
              description="Change the vCPU count and/or memory (MB) of a VM.")
    async def reconfigure_vm(name: str, cpu: int | None = None, memory: int | None = None) -> str:
        def op() -> str:
            validation.vm_name(name)
            if cpu is not None:
                validation.int_range(cpu, "cpu", 1, settings.max_vm_cpus)
            if memory is not None:
                validation.int_range(memory, "memory", 4, settings.max_vm_memory_mb)
            return client.reconfigure_vm(name, cpu, memory)
        return await run("reconfigureVM", OpClass.WRITE, op)

    @mcp.tool(name="listSnapshots", annotations=R, description="List snapshots of a VM.")
    async def list_snapshots(vm_name: str) -> str:
        def op() -> str:
            validation.vm_name(vm_name, "vm_name")
            return jdump(client.list_snapshots(vm_name))
        return await run("listSnapshots", OpClass.READ, op)

    @mcp.tool(name="createSnapshot", annotations=W, description="Create a snapshot of a VM.")
    async def create_snapshot(vm_name: str, snapshot_name: str, description: str = "",
                              memory: bool = False, quiesce: bool = False) -> str:
        def op() -> str:
            validation.vm_name(vm_name, "vm_name")
            validation.object_name(snapshot_name, "snapshot_name")
            validation.object_name(description or "-", "description")
            return client.create_snapshot(vm_name, snapshot_name, description, memory, quiesce)
        return await run("createSnapshot", OpClass.WRITE, op)

    @mcp.tool(name="revertSnapshot", annotations=D,
              description="Revert a VM to a snapshot. DESTRUCTIVE; requires "
                          "MCP_ALLOW_DESTRUCTIVE=true.")
    async def revert_snapshot(vm_name: str, snapshot_name: str) -> str:
        def op() -> str:
            validation.vm_name(vm_name, "vm_name")
            validation.object_name(snapshot_name, "snapshot_name")
            return client.revert_snapshot(vm_name, snapshot_name)
        return await run("revertSnapshot", OpClass.DESTRUCTIVE, op)

    @mcp.tool(name="removeSnapshot", annotations=D,
              description="Remove a snapshot. DESTRUCTIVE; requires MCP_ALLOW_DESTRUCTIVE=true.")
    async def remove_snapshot(vm_name: str, snapshot_name: str,
                              remove_children: bool = False) -> str:
        def op() -> str:
            validation.vm_name(vm_name, "vm_name")
            validation.object_name(snapshot_name, "snapshot_name")
            return client.remove_snapshot(vm_name, snapshot_name, remove_children)
        return await run("removeSnapshot", OpClass.DESTRUCTIVE, op)

    @mcp.tool(name="getServerInfo", annotations=R,
              description="Server version, safety mode and target vCenter/ESXi host.")
    async def get_server_info() -> str:
        return jdump({
            "version": __version__,
            "vcenter_host": settings.vcenter_host,
            "read_only": settings.read_only,
            "allow_destructive": settings.allow_destructive,
            "tls_verification": not settings.insecure,
        })

    return mcp


def _register_inventory(mcp: FastMCP, run: Any, jdump: Any, ann: ToolAnnotations,
                        name: str, fn: Callable[[], Any], desc: str) -> None:
    async def tool() -> str:
        return str(jdump(await run(name, OpClass.READ, fn)))

    mcp.tool(name=name, annotations=ann, description=desc)(tool)
