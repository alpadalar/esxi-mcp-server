from __future__ import annotations

import ssl
from types import SimpleNamespace as NS
from unittest.mock import MagicMock, patch

import pytest
from pyVmomi import vim

from esxi_mcp_server.errors import VSphereError
from esxi_mcp_server.vsphere import VSphereClient, build_ssl_context

GB = 1024**3


def mk(spec, **attrs):
    m = MagicMock(spec=spec)
    for k, v in attrs.items():
        setattr(m, k, v)
    return m


def make_vm(name="vm1", power=vim.VirtualMachine.PowerState.poweredOff, tools="guestToolsRunning",
            snapshots=None):
    vm = mk(vim.VirtualMachine)
    vm.name = name
    vm.runtime = NS(powerState=power, host=NS(name="esx1"))
    vm.guest = NS(ipAddress="10.0.0.5", hostName="h", toolsRunningStatus=tools)
    vm.summary = NS(
        config=NS(name=name, uuid="u-1", guestFullName="Linux", numCpu=2, memorySizeMB=2048,
                  template=False),
        quickStats=NS(overallCpuUsage=120, guestMemoryUsage=512),
        storage=NS(committed=3 * GB))
    vm.datastore = [NS(name="ds1")]
    vm.network = [NS(name="VM Network")]
    vm.snapshot = NS(rootSnapshotList=snapshots) if snapshots else None
    vm.resourcePool = None
    vm.parent = mk(vim.Folder)
    return vm


def ok_task(result=None):
    t = MagicMock()
    t.info.state = vim.TaskInfo.State.success
    t.info.result = result
    return t


def err_task(msg="boom"):
    t = MagicMock()
    t.info.state = vim.TaskInfo.State.error
    t.info.error = NS(msg=msg)
    return t


@pytest.fixture
def inventory():
    ds_small = mk(vim.Datastore)
    ds_small.name = "small"
    ds_small.summary = NS(freeSpace=1 * GB, capacity=10 * GB, type="VMFS", accessible=True)
    ds_big = mk(vim.Datastore)
    ds_big.name = "big"
    ds_big.summary = NS(freeSpace=9 * GB, capacity=10 * GB, type="NFS", accessible=True)
    net = mk(vim.Network)
    net.name = "VM Network"
    dvpg = mk(vim.dvs.DistributedVirtualPortgroup)
    dvpg.name = "dvpg"
    host = mk(vim.HostSystem)
    host.name = "esx1"
    host.runtime = NS(connectionState="connected", powerState="poweredOn", inMaintenanceMode=False)
    host.config = NS(product=NS(version="8.0.3"))
    host.summary = NS(quickStats=NS(overallCpuUsage=100, overallMemoryUsage=2000),
                      hardware=NS(numCpuCores=16, memorySize=64 * GB))
    cluster = mk(vim.ClusterComputeResource)
    cluster.name = "cl1"
    cluster.host = [host]
    cluster.configuration = NS(drsConfig=NS(enabled=True), dasConfig=NS(enabled=False))
    cluster.resourcePool = mk(vim.ResourcePool)
    dc = mk(vim.Datacenter)
    dc.name = "DC1"
    dc.hostFolder = NS(childEntity=[cluster])
    dc.vmFolder = MagicMock()
    vms = [make_vm("vm1"), make_vm("vm2", power=vim.VirtualMachine.PowerState.poweredOn)]
    types = {vim.Datastore: [ds_small, ds_big], vim.Network: [net, dvpg],
             vim.HostSystem: [host], vim.ClusterComputeResource: [cluster],
             vim.VirtualMachine: vms}
    content = MagicMock()
    content.rootFolder.childEntity = [dc]

    def create_view(root, t, recursive):
        v = MagicMock()
        v.view = types[t[0]]
        return v
    content.viewManager.CreateContainerView.side_effect = create_view
    si = MagicMock()
    si.RetrieveContent.return_value = content
    si.content = content
    return NS(si=si, content=content, dc=dc, vms=vms, ds_big=ds_big, ds_small=ds_small,
              net=net, dvpg=dvpg, types=types, cluster=cluster)


@pytest.fixture
def client(make_settings, inventory):
    with patch("esxi_mcp_server.vsphere.connect") as conn:
        conn.SmartConnect.return_value = inventory.si
        c = VSphereClient(make_settings(), poll_interval=0)
        c._conn = conn
        c.ensure_connected()
        yield c


def test_connect_picks_largest_datastore_and_passes_tls_context(client):
    assert client.datastore.name == "big"
    kwargs = client._conn.SmartConnect.call_args.kwargs
    assert isinstance(kwargs["sslContext"], ssl.SSLContext)
    assert kwargs["sslContext"].verify_mode == ssl.CERT_REQUIRED
    assert kwargs["pwd"] == "pw-for-tests"


def test_ssl_context_insecure_only_when_explicit(make_settings):
    assert build_ssl_context(make_settings()).verify_mode == ssl.CERT_REQUIRED
    ctx = build_ssl_context(make_settings(insecure=True))
    assert ctx.verify_mode == ssl.CERT_NONE and ctx.check_hostname is False


def test_connect_failure_is_sanitised(make_settings):
    with patch("esxi_mcp_server.vsphere.connect") as conn:
        conn.SmartConnect.side_effect = RuntimeError("secret pw-for-tests leaked")
        with pytest.raises(VSphereError) as ei:
            VSphereClient(make_settings()).connect()
    assert "pw-for-tests" not in str(ei.value)


def test_missing_datacenter_cluster_datastore(make_settings, inventory):
    for kw, msg in [({"datacenter": "nope"}, "datacenter"), ({"cluster": "nope"}, "cluster"),
                    ({"datastore": "nope"}, "datastore"), ({"network": "nope"}, "network")]:
        with patch("esxi_mcp_server.vsphere.connect") as conn:
            conn.SmartConnect.return_value = inventory.si
            with pytest.raises(VSphereError, match=msg):
                VSphereClient(make_settings(**kw)).connect()


def test_reconnects_when_session_dead(client, inventory):
    type(inventory.content.sessionManager).currentSession = None
    client.si.content = inventory.content
    calls = client._conn.SmartConnect.call_count
    client.list_vms()
    assert client._conn.SmartConnect.call_count == calls + 1


def test_list_and_find(client):
    assert client.list_vms() == ["vm1", "vm2"]
    with pytest.raises(VSphereError, match="not found"):
        client.get_vm_info("ghost")


def test_find_vm_ambiguous(client, inventory):
    inventory.types[vim.VirtualMachine].append(make_vm("vm1"))
    with pytest.raises(VSphereError, match="ambiguous"):
        client.get_vm_info("vm1")


def test_inventory_listings(client):
    assert client.list_hosts()[0]["memory_total_mb"] == 65536
    assert client.list_clusters() == [{"name": "cl1", "hosts": 1, "drs_enabled": True,
                                       "ha_enabled": False}]
    assert {d["name"] for d in client.list_datastores()} == {"small", "big"}
    assert [n["type"] for n in client.list_networks()] == ["standard", "distributed"]


def test_vm_info_and_perf_without_counters(client, inventory):
    info = client.get_vm_info("vm1")
    assert info["ip_address"] == "10.0.0.5" and info["snapshot_count"] == 0
    inventory.content.perfManager.perfCounter = []
    perf = client.get_vm_performance("vm1")
    assert perf == {"cpu_usage": 120, "memory_usage": 512, "storage_usage": 3.0,
                    "network_transmit_KBps": None, "network_receive_KBps": None}


def test_perf_network_counters_mapped_by_name_not_order(client, inventory):
    def counter(key, name):
        return NS(key=key, groupInfo=NS(key="net"), nameInfo=NS(key=name), rollupType="average")
    # received listed before transmitted: old code mixed them up
    inventory.content.perfManager.perfCounter = [counter(2, "received"), counter(1, "transmitted")]
    inventory.content.perfManager.QueryStats.return_value = [NS(value=[
        NS(id=NS(counterId=1), value=[40]), NS(id=NS(counterId=2), value=[7])])]
    with patch("esxi_mcp_server.vsphere.vim.PerformanceManager"):
        perf = client.get_vm_performance("vm1")
    assert perf["network_transmit_KBps"] == 40.0 and perf["network_receive_KBps"] == 7.0


def test_perf_query_failure_is_best_effort(client, inventory):
    inventory.content.perfManager.perfCounter = [NS(key=1, groupInfo=NS(key="net"),
                                                    nameInfo=NS(key="transmitted"),
                                                    rollupType="average")]
    inventory.content.perfManager.QueryStats.side_effect = RuntimeError("x")
    perf = client.get_vm_performance("vm1")
    assert perf["network_transmit_KBps"] is None


def test_power_ops_idempotent_and_task_driven(client, inventory):
    vm1, vm2 = inventory.vms
    assert "already powered off" in client.power_off_vm("vm1")
    assert "already powered on" in client.power_on_vm("vm2")
    vm1.PowerOnVM_Task.return_value = ok_task()
    assert "powered on" in client.power_on_vm("vm1")
    vm1.PowerOnVM_Task.assert_called_once()
    vm2.PowerOffVM_Task.return_value = ok_task()
    assert client.power_off_vm("vm2") == "VM 'vm2' powered off."


def test_task_error_and_timeout(client, inventory):
    vm1 = inventory.vms[0]
    vm1.PowerOnVM_Task.return_value = err_task("no resources")
    with pytest.raises(VSphereError, match="no resources"):
        client.power_on_vm("vm1")
    pending = MagicMock()
    pending.info.state = vim.TaskInfo.State.running
    vm1.PowerOnVM_Task.return_value = pending
    client.settings = client.settings.model_copy(update={"task_timeout": 1})
    with patch("esxi_mcp_server.vsphere.time.monotonic", side_effect=[0, 0, 5]):
        with pytest.raises(VSphereError, match="timed out"):
            client.power_on_vm("vm1")
    pending.CancelTask.assert_called_once()


def test_delete_refuses_powered_on(client, inventory):
    with pytest.raises(VSphereError, match="powered on"):
        client.delete_vm("vm2")
    inventory.vms[0].Destroy_Task.return_value = ok_task()
    assert client.delete_vm("vm1") == "VM 'vm1' deleted."


def test_create_vm_builds_spec(client, inventory):
    inventory.dc.vmFolder.CreateVM_Task.return_value = ok_task()
    assert client.create_vm("new1", 2, 2048, network="VM Network", disk_gb=20) == "VM 'new1' created."
    spec = inventory.dc.vmFolder.CreateVM_Task.call_args.kwargs["config"]
    assert spec.name == "new1" and spec.numCPUs == 2 and spec.memoryMB == 2048
    assert spec.files.vmPathName == "[big]"
    kinds = [type(d.device).__name__ for d in spec.deviceChange]
    assert kinds == ["vim.vm.device.ParaVirtualSCSIController", "vim.vm.device.VirtualDisk",
                     "vim.vm.device.VirtualVmxnet3"]
    assert spec.deviceChange[1].device.capacityInKB == 20 * 1024 * 1024


def test_create_vm_without_network_has_no_nic_and_unknown_ds(client, inventory):
    inventory.dc.vmFolder.CreateVM_Task.return_value = ok_task()
    client.create_vm("new2", 1, 512)
    spec = inventory.dc.vmFolder.CreateVM_Task.call_args.kwargs["config"]
    assert len(spec.deviceChange) == 2
    with pytest.raises(VSphereError, match="datastore"):
        client.create_vm("new3", 1, 512, datastore="nope")


def test_clone(client, inventory):
    vm1 = inventory.vms[0]
    vm1.Clone.return_value = ok_task()
    assert "cloned" in client.clone_vm("vm1", "vm1-copy")
    kw = vm1.Clone.call_args.kwargs
    assert kw["name"] == "vm1-copy" and kw["spec"].powerOn is False


def test_guest_ops_require_tools(client, inventory):
    vm1 = inventory.vms[0]
    client.shutdown_guest("vm1")
    vm1.ShutdownGuest.assert_called_once()
    client.reboot_guest("vm1")
    vm1.RebootGuest.assert_called_once()
    vm1.guest.toolsRunningStatus = "guestToolsNotRunning"
    with pytest.raises(VSphereError, match="Tools"):
        client.shutdown_guest("vm1")


def test_reset_suspend_reconfigure(client, inventory):
    vm1 = inventory.vms[0]
    for m in (vm1.ResetVM_Task, vm1.SuspendVM_Task, vm1.ReconfigVM_Task):
        m.return_value = ok_task()
    client.reset_vm("vm1")
    client.suspend_vm("vm1")
    client.reconfigure_vm("vm1", 4, None)
    spec = vm1.ReconfigVM_Task.call_args.args[0]
    assert spec.numCPUs == 4
    with pytest.raises(VSphereError, match="nothing"):
        client.reconfigure_vm("vm1", None, None)


def test_snapshots(client, inventory):
    child = NS(name="child", description="", createTime="t", state="poweredOff",
               childSnapshotList=[], snapshot=MagicMock())
    root = NS(name="root", description="d", createTime="t", state="poweredOff",
              childSnapshotList=[child], snapshot=MagicMock())
    inventory.vms[0].snapshot = NS(rootSnapshotList=[root])
    listing = client.list_snapshots("vm1")
    assert [(s["name"], s["depth"]) for s in listing] == [("root", 0), ("child", 1)]
    assert client.list_snapshots("vm2") == []
    child.snapshot.RevertToSnapshot_Task.return_value = ok_task()
    client.revert_snapshot("vm1", "child")
    root.snapshot.RemoveSnapshot_Task.return_value = ok_task()
    client.remove_snapshot("vm1", "root", remove_children=True)
    root.snapshot.RemoveSnapshot_Task.assert_called_with(removeChildren=True)
    with pytest.raises(VSphereError, match="not found"):
        client.revert_snapshot("vm1", "ghost")
    inventory.vms[1].CreateSnapshot_Task.return_value = ok_task()
    client.create_snapshot("vm2", "s1", "desc", memory=True)
    inventory.vms[1].CreateSnapshot_Task.assert_called_with(
        name="s1", description="desc", memory=True, quiesce=False)


def test_method_fault_and_not_authenticated_mapped(client, inventory):
    vm1 = inventory.vms[0]
    fault = vim.fault.InvalidState()
    fault.msg = "bad state"
    vm1.PowerOnVM_Task.side_effect = fault
    with pytest.raises(VSphereError, match="bad state"):
        client.power_on_vm("vm1")
    vm1.PowerOnVM_Task.side_effect = vim.fault.NotAuthenticated()
    with pytest.raises(VSphereError, match="expired"):
        client.power_on_vm("vm1")
    assert client.si is None


def test_close_disconnects(client):
    client.close()
    client._conn.Disconnect.assert_called_once()
    assert client.si is None
