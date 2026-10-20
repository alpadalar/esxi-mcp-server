from __future__ import annotations

import json

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from esxi_mcp_server.errors import VSphereError
from esxi_mcp_server.server import build_server

LEGACY = {"authenticate", "createVM", "cloneVM", "deleteVM", "powerOn", "powerOff", "listVMs"}


async def call(mcp, name, args=None):
    content, _ = await mcp.call_tool(name, args or {})
    return content[0].text if content else ""


async def test_legacy_surface_preserved(settings, fake_client):
    mcp = build_server(settings, fake_client)
    tools = {t.name: t for t in await mcp.list_tools()}
    assert LEGACY <= set(tools)
    props = tools["createVM"].inputSchema["properties"]
    assert {"name", "cpu", "memory", "datastore", "network"} <= set(props)
    assert set(tools["createVM"].inputSchema["required"]) == {"name", "cpu", "memory"}
    assert set(tools["cloneVM"].inputSchema["required"]) == {"template_name", "new_name"}
    resources = await mcp.list_resource_templates()
    assert any(r.uriTemplate == "vmstats://{vm_name}" for r in resources)


async def test_destructive_annotations(settings, fake_client):
    mcp = build_server(settings, fake_client)
    tools = {t.name: t for t in await mcp.list_tools()}
    assert tools["deleteVM"].annotations.destructiveHint is True
    assert tools["listVMs"].annotations.readOnlyHint is True


async def test_list_vms_runs_in_thread(settings, fake_client):
    fake_client.list_vms.return_value = ["a", "b"]
    mcp = build_server(settings, fake_client)
    content, _ = await mcp.call_tool("listVMs", {})
    assert [c.text for c in content] == ["a", "b"]
    fake_client.list_vms.assert_called_once()


async def test_destructive_blocked_by_default(settings, fake_client):
    mcp = build_server(settings, fake_client)
    for name, args in [("deleteVM", {"name": "vm1"}), ("powerOff", {"name": "vm1"}),
                       ("resetVM", {"name": "vm1"}),
                       ("revertSnapshot", {"vm_name": "vm1", "snapshot_name": "s"}),
                       ("removeSnapshot", {"vm_name": "vm1", "snapshot_name": "s"})]:
        with pytest.raises(ToolError, match="destructive"):
            await call(mcp, name, args)
    fake_client.delete_vm.assert_not_called()
    fake_client.power_off_vm.assert_not_called()


async def test_destructive_allowed_when_enabled(make_settings, fake_client):
    fake_client.delete_vm.return_value = "deleted"
    mcp = build_server(make_settings(allow_destructive=True), fake_client)
    assert await call(mcp, "deleteVM", {"name": "vm1"}) == "deleted"


async def test_read_only_blocks_writes_not_reads(make_settings, fake_client):
    fake_client.list_vms.return_value = []
    mcp = build_server(make_settings(read_only=True, allow_destructive=True), fake_client)
    with pytest.raises(ToolError, match="read-only"):
        await call(mcp, "powerOn", {"name": "vm1"})
    with pytest.raises(ToolError, match="read-only"):
        await call(mcp, "deleteVM", {"name": "vm1"})
    await call(mcp, "listVMs")


async def test_input_validation_blocks_before_client(settings, fake_client):
    mcp = build_server(settings, fake_client)
    for args in [{"name": "../x", "cpu": 1, "memory": 512},
                 {"name": "ok", "cpu": 0, "memory": 512},
                 {"name": "ok", "cpu": 1, "memory": 1},
                 {"name": "ok", "cpu": 10_000, "memory": 512}]:
        with pytest.raises(ToolError):
            await call(mcp, "createVM", args)
    fake_client.create_vm.assert_not_called()


async def test_create_vm_passes_through(settings, fake_client):
    fake_client.create_vm.return_value = "VM 'n' created."
    mcp = build_server(settings, fake_client)
    out = await call(mcp, "createVM", {"name": "n", "cpu": 1, "memory": 512, "network": "VM Network"})
    assert out == "VM 'n' created."
    fake_client.create_vm.assert_called_once_with("n", 1, 512, None, "VM Network", 10)


async def test_expected_errors_surface_message_unexpected_are_masked(settings, fake_client):
    mcp = build_server(settings, fake_client)
    fake_client.power_on_vm.side_effect = VSphereError("VM 'x' not found")
    with pytest.raises(ToolError, match="not found"):
        await call(mcp, "powerOn", {"name": "x"})
    fake_client.power_on_vm.side_effect = RuntimeError("password=hunter2 stack detail")
    with pytest.raises(ToolError) as ei:
        await call(mcp, "powerOn", {"name": "x"})
    assert "hunter2" not in str(ei.value) and "internal error" in str(ei.value)


async def test_authenticate_compat(settings, make_settings, fake_client):
    from tests.conftest import API_KEY
    mcp = build_server(settings, fake_client)
    assert "successful" in await call(mcp, "authenticate", {"key": API_KEY})
    with pytest.raises(ToolError, match="invalid"):
        await call(mcp, "authenticate", {"key": "wrong"})
    stdio = build_server(make_settings(), fake_client)
    assert "not required" in await call(stdio, "authenticate", {"key": "x"})


async def test_new_tools_dispatch(settings, fake_client):
    fake_client.get_vm_info.return_value = {"name": "vm1"}
    fake_client.get_vm_performance.return_value = {"cpu_usage": 1}
    fake_client.list_hosts.return_value = [{"name": "h"}]
    fake_client.list_snapshots.return_value = []
    mcp = build_server(settings, fake_client)
    assert json.loads(await call(mcp, "getVMInfo", {"name": "vm1"}))["name"] == "vm1"
    assert json.loads(await call(mcp, "getVMStats", {"name": "vm1"}))["cpu_usage"] == 1
    assert json.loads(await call(mcp, "listHosts"))
    await call(mcp, "listSnapshots", {"vm_name": "vm1"})
    info = json.loads(await call(mcp, "getServerInfo"))
    assert info["tls_verification"] is True and "password" not in json.dumps(info).lower()
    res = await mcp.read_resource("vmstats://vm1")
    assert "cpu_usage" in list(res)[0].content


async def test_snapshot_and_guest_tools(settings, fake_client):
    for m in ("create_snapshot", "shutdown_guest", "reboot_guest", "suspend_vm", "reconfigure_vm"):
        getattr(fake_client, m).return_value = "ok"
    mcp = build_server(settings, fake_client)
    await call(mcp, "createSnapshot", {"vm_name": "vm1", "snapshot_name": "s1"})
    fake_client.create_snapshot.assert_called_once_with("vm1", "s1", "", False, False)
    await call(mcp, "shutdownGuest", {"name": "vm1"})
    await call(mcp, "rebootGuest", {"name": "vm1"})
    await call(mcp, "suspendVM", {"name": "vm1"})
    await call(mcp, "reconfigureVM", {"name": "vm1", "cpu": 2})
    fake_client.reconfigure_vm.assert_called_once_with("vm1", 2, None)
