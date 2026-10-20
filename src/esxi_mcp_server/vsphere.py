"""pyvmomi wrapper. All methods are blocking; call them via ``asyncio.to_thread``."""

from __future__ import annotations

import logging
import ssl
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, TypeVar

from pyVim import connect
from pyVmomi import vim, vmodl

from .config import Settings
from .errors import VSphereError

logger = logging.getLogger("esxi_mcp_server.vsphere")
T = TypeVar("T")

GB = 1024**3


def build_ssl_context(settings: Settings) -> ssl.SSLContext:
    """TLS context: verification ON by default; ``insecure`` must be explicit."""
    if settings.insecure:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    ctx = ssl.create_default_context(cafile=settings.ca_bundle)
    return ctx


class VSphereClient:
    def __init__(self, settings: Settings, poll_interval: float = 1.0) -> None:
        self.settings = settings
        self.poll_interval = poll_interval
        self._lock = threading.RLock()
        self.si: Any = None
        self.content: Any = None
        self.datacenter: Any = None
        self.resource_pool: Any = None
        self.datastore: Any = None
        self.network: Any = None

    # ------------------------------------------------------------ connection
    def connect(self) -> None:
        s = self.settings
        try:
            self.si = connect.SmartConnect(
                host=s.vcenter_host,
                port=s.vcenter_port,
                user=s.vcenter_user,
                pwd=s.vcenter_password.get_secret_value(),
                sslContext=build_ssl_context(s),
                httpConnectionTimeout=30,
            )
        except ssl.SSLError as exc:
            raise VSphereError(
                "TLS verification failed for vCenter/ESXi; provide VCENTER_CA_BUNDLE or "
                f"(not recommended) VCENTER_INSECURE=true ({exc.reason})"
            ) from None
        except vim.fault.InvalidLogin:
            raise VSphereError("vCenter/ESXi rejected the credentials") from None
        except Exception as exc:
            raise VSphereError(f"cannot connect to vCenter/ESXi: {type(exc).__name__}") from exc
        try:
            self.content = self.si.RetrieveContent()
            logger.info("Connected to %s", s.vcenter_host)
            self._resolve_defaults()
        except Exception:
            self.close()  # never keep a half-initialised session
            raise

    def close(self) -> None:
        with self._lock:
            if self.si is not None:
                try:
                    connect.Disconnect(self.si)
                except Exception:  # noqa: BLE001
                    logger.debug("disconnect failed", exc_info=True)
                self.si = None

    def _session_alive(self) -> bool:
        try:
            return self.si.content.sessionManager.currentSession is not None
        except Exception:  # noqa: BLE001
            return False

    def ensure_connected(self) -> None:
        with self._lock:
            if self.si is None or not self._session_alive():
                logger.info("(re)connecting to vCenter/ESXi")
                self.close()
                self.connect()

    def _resolve_defaults(self) -> None:
        s = self.settings
        dcs = [d for d in self.content.rootFolder.childEntity if isinstance(d, vim.Datacenter)]
        if s.datacenter:
            self.datacenter = next((d for d in dcs if d.name == s.datacenter), None)
            if not self.datacenter:
                raise VSphereError(f"datacenter {s.datacenter!r} not found")
        else:
            self.datacenter = dcs[0] if dcs else None
        if not self.datacenter:
            raise VSphereError("no datacenter found")

        computes = [c for c in self.datacenter.hostFolder.childEntity
                    if isinstance(c, vim.ComputeResource)]
        if s.cluster:
            cr = next((c for c in computes
                       if isinstance(c, vim.ClusterComputeResource) and c.name == s.cluster), None)
            if not cr:
                raise VSphereError(f"cluster {s.cluster!r} not found")
        else:
            cr = computes[0] if computes else None
        if not cr:
            raise VSphereError("no compute resource (cluster or host) found")
        self.resource_pool = cr.resourcePool

        if s.datastore:
            self.datastore = self._find_datastore(s.datastore)
        else:
            stores = self._objects(vim.Datastore, self.datacenter)
            if not stores:
                raise VSphereError("no datastore found in the datacenter")
            self.datastore = max(stores, key=lambda d: d.summary.freeSpace)
        self.network = self._find_network(s.network) if s.network else None

    # --------------------------------------------------------------- helpers
    @contextmanager
    def _session(self) -> Iterator[None]:
        """Make sure the session is alive; the lock is NOT held while tasks run."""
        self.ensure_connected()
        try:
            yield
        except VSphereError:
            raise
        except vim.fault.NotAuthenticated:
            with self._lock:
                self.si = None  # force reconnect on next call
            raise VSphereError("vSphere session expired; please retry") from None
        except vmodl.MethodFault as exc:
            raise VSphereError(
                f"vSphere error: {getattr(exc, 'msg', None) or type(exc).__name__}") from None

    def _objects(self, vimtype: Any, root: Any = None) -> list[Any]:
        view = self.content.viewManager.CreateContainerView(
            root or self.content.rootFolder, [vimtype], True)
        try:
            return list(view.view)
        finally:
            view.Destroy()

    def _find_datastore(self, name: str) -> Any:
        ds = next((d for d in self._objects(vim.Datastore, self.datacenter) if d.name == name), None)
        if not ds:
            raise VSphereError(f"datastore {name!r} not found")
        return ds

    def _find_network(self, name: str) -> Any:
        net = next((n for n in self._objects(vim.Network, self.datacenter) if n.name == name), None)
        if not net:
            raise VSphereError(f"network {name!r} not found")
        return net

    def find_vm(self, name: str) -> Any:
        matches = [v for v in self._objects(vim.VirtualMachine) if v.name == name]
        if not matches:
            raise VSphereError(f"VM {name!r} not found")
        if len(matches) > 1:
            raise VSphereError(f"VM name {name!r} is ambiguous ({len(matches)} matches)")
        return matches[0]

    def wait_for_task(self, task: Any, timeout: int | None = None) -> Any:
        """Poll a vSphere task until done; never busy-loops and always times out."""
        timeout = timeout or self.settings.task_timeout
        deadline = time.monotonic() + timeout
        while True:
            state = task.info.state
            if state == vim.TaskInfo.State.success:
                return task.info.result
            if state == vim.TaskInfo.State.error:
                err = task.info.error
                detail = (getattr(err, "localizedMessage", None)
                          or getattr(getattr(err, "fault", None), "msg", None)
                          or "unknown error")
                raise VSphereError(f"task failed: {detail}")
            if time.monotonic() >= deadline:
                try:
                    task.CancelTask()
                except Exception:  # noqa: BLE001
                    logger.debug("cancel failed", exc_info=True)
                raise VSphereError(f"task timed out after {timeout}s")
            time.sleep(self.poll_interval)

    # ------------------------------------------------------------- inventory
    def list_vms(self) -> list[str]:
        with self._session():
            return sorted(v.name for v in self._objects(vim.VirtualMachine))

    def list_hosts(self) -> list[dict[str, Any]]:
        with self._session():
            out = []
            for h in self._objects(vim.HostSystem):
                qs = h.summary.quickStats
                hw = h.summary.hardware
                out.append({
                    "name": h.name,
                    "connection_state": str(h.runtime.connectionState),
                    "power_state": str(h.runtime.powerState),
                    "in_maintenance_mode": bool(h.runtime.inMaintenanceMode),
                    "version": getattr(h.config.product, "version", None) if h.config else None,
                    "cpu_cores": getattr(hw, "numCpuCores", None),
                    "cpu_usage_mhz": getattr(qs, "overallCpuUsage", None),
                    "memory_total_mb": round(hw.memorySize / 1024**2) if hw else None,
                    "memory_usage_mb": getattr(qs, "overallMemoryUsage", None),
                })
            return out

    def list_clusters(self) -> list[dict[str, Any]]:
        with self._session():
            return [{
                "name": c.name,
                "hosts": len(c.host),
                "drs_enabled": bool(c.configuration.drsConfig.enabled),
                "ha_enabled": bool(c.configuration.dasConfig.enabled),
            } for c in self._objects(vim.ClusterComputeResource)]

    def list_datastores(self) -> list[dict[str, Any]]:
        with self._session():
            out = []
            for d in self._objects(vim.Datastore):
                sm = d.summary
                out.append({
                    "name": d.name,
                    "type": sm.type,
                    "accessible": bool(sm.accessible),
                    "capacity_gb": round(sm.capacity / GB, 2),
                    "free_gb": round(sm.freeSpace / GB, 2),
                })
            return out

    def list_networks(self) -> list[dict[str, Any]]:
        with self._session():
            return [{
                "name": n.name,
                "type": "distributed" if isinstance(n, vim.dvs.DistributedVirtualPortgroup)
                else "standard",
            } for n in self._objects(vim.Network)]

    # ------------------------------------------------------------ VM details
    def get_vm_info(self, name: str) -> dict[str, Any]:
        with self._session():
            vm = self.find_vm(name)
            s = vm.summary
            cfg = s.config
            return {
                "name": cfg.name,
                "uuid": cfg.uuid,
                "power_state": str(vm.runtime.powerState),
                "guest_os": cfg.guestFullName,
                "cpus": cfg.numCpu,
                "memory_mb": cfg.memorySizeMB,
                "ip_address": getattr(vm.guest, "ipAddress", None),
                "hostname": getattr(vm.guest, "hostName", None),
                "tools_status": str(getattr(vm.guest, "toolsRunningStatus", None)),
                "host": vm.runtime.host.name if vm.runtime.host else None,
                "datastores": [d.name for d in vm.datastore],
                "networks": [n.name for n in vm.network],
                "is_template": bool(cfg.template),
                "snapshot_count": len(self._flatten_snapshots(vm)),
            }

    def get_vm_performance(self, vm_name: str) -> dict[str, Any]:
        with self._session():
            vm = self.find_vm(vm_name)
            qs = vm.summary.quickStats
            storage = vm.summary.storage
            stats: dict[str, Any] = {
                "cpu_usage": qs.overallCpuUsage,  # MHz
                "memory_usage": qs.guestMemoryUsage,  # MB
                "storage_usage": round((storage.committed if storage else 0) / GB, 2),  # GB
            }
            tx, rx = self._network_kbps(vm)
            stats["network_transmit_KBps"] = tx
            stats["network_receive_KBps"] = rx
            return stats

    def _network_kbps(self, vm: Any) -> tuple[float | None, float | None]:
        try:
            pm = self.content.perfManager
            wanted = {"net.transmitted.average": "tx", "net.received.average": "rx"}
            ids: dict[int, str] = {}
            for c in pm.perfCounter:
                full = f"{c.groupInfo.key}.{c.nameInfo.key}.{c.rollupType}"
                if full in wanted:
                    ids[c.key] = wanted[full]
            if not ids:
                return None, None
            spec = vim.PerformanceManager.QuerySpec(
                maxSample=1, entity=vm, intervalId=20,
                metricId=[vim.PerformanceManager.MetricId(counterId=k, instance="")
                          for k in ids])
            result = pm.QueryStats(querySpec=[spec])
            values: dict[str, float | None] = {"tx": None, "rx": None}
            for series in (result[0].value if result else []):
                kind = ids.get(series.id.counterId)
                if kind and series.value:
                    values[kind] = float(series.value[-1])
            return values["tx"], values["rx"]
        except vim.fault.NotAuthenticated:
            raise
        except Exception:  # noqa: BLE001 - perf data is best effort
            logger.warning("network performance data unavailable", exc_info=True)
            return None, None

    # ------------------------------------------------------------ VM actions
    def create_vm(self, name: str, cpus: int, memory_mb: int, datastore: str | None = None,
                  network: str | None = None, disk_gb: int = 10,
                  guest_id: str = "otherGuest64") -> str:
        with self._session():
            ds = self._find_datastore(datastore) if datastore else self.datastore
            net = self._find_network(network) if network else self.network
            spec = vim.vm.ConfigSpec(
                name=name, memoryMB=memory_mb, numCPUs=cpus, guestId=guest_id,
                files=vim.vm.FileInfo(vmPathName=f"[{ds.name}]"),
            )
            Op = vim.vm.device.VirtualDeviceSpec.Operation
            FileOp = vim.vm.device.VirtualDeviceSpec.FileOperation

            ctrl = vim.vm.device.VirtualDeviceSpec(operation=Op.add)
            ctrl.device = vim.vm.device.ParaVirtualSCSIController(
                key=-101, busNumber=0,
                sharedBus=vim.vm.device.VirtualSCSIController.Sharing.noSharing)

            disk = vim.vm.device.VirtualDeviceSpec(operation=Op.add, fileOperation=FileOp.create)
            disk.device = vim.vm.device.VirtualDisk(
                key=-102, capacityInKB=disk_gb * 1024 * 1024, controllerKey=-101, unitNumber=0)
            disk.device.backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo(
                diskMode="persistent", thinProvisioned=True, datastore=ds)
            devices = [ctrl, disk]

            if net is not None:
                nic = vim.vm.device.VirtualDeviceSpec(operation=Op.add)
                nic.device = vim.vm.device.VirtualVmxnet3(key=-103)
                if isinstance(net, vim.dvs.DistributedVirtualPortgroup):
                    nic.device.backing = vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo(
                        port=vim.dvs.PortConnection(
                            portgroupKey=net.key,
                            switchUuid=net.config.distributedVirtualSwitch.uuid))
                else:
                    nic.device.backing = vim.vm.device.VirtualEthernetCard.NetworkBackingInfo(
                        network=net, deviceName=net.name)
                nic.device.connectable = vim.vm.device.VirtualDevice.ConnectInfo(
                    startConnected=True, allowGuestControl=True, connected=False)
                devices.append(nic)
            spec.deviceChange = devices

            task = self.datacenter.vmFolder.CreateVM_Task(config=spec, pool=self.resource_pool)
            self.wait_for_task(task)
            logger.info("VM created: %s", name)
            return f"VM '{name}' created."

    def clone_vm(self, template_name: str, new_name: str, datastore: str | None = None) -> str:
        with self._session():
            src = self.find_vm(template_name)
            folder = src.parent if isinstance(src.parent, vim.Folder) else self.datacenter.vmFolder
            ds = self._find_datastore(datastore) if datastore else self.datastore
            reloc = vim.vm.RelocateSpec(pool=src.resourcePool or self.resource_pool, datastore=ds)
            spec = vim.vm.CloneSpec(powerOn=False, template=False, location=reloc)
            self.wait_for_task(src.Clone(folder=folder, name=new_name, spec=spec))
            logger.info("VM cloned: %s -> %s", template_name, new_name)
            return f"VM '{new_name}' cloned from '{template_name}'."

    def delete_vm(self, name: str) -> str:
        with self._session():
            vm = self.find_vm(name)
            if vm.runtime.powerState == vim.VirtualMachine.PowerState.poweredOn:
                raise VSphereError(f"VM {name!r} is powered on; power it off before deleting")
            self.wait_for_task(vm.Destroy_Task())
            logger.info("VM deleted: %s", name)
            return f"VM '{name}' deleted."

    def power_on_vm(self, name: str) -> str:
        with self._session():
            vm = self.find_vm(name)
            if vm.runtime.powerState == vim.VirtualMachine.PowerState.poweredOn:
                return f"VM '{name}' is already powered on."
            self.wait_for_task(vm.PowerOnVM_Task())
            return f"VM '{name}' powered on."

    def power_off_vm(self, name: str) -> str:
        with self._session():
            vm = self.find_vm(name)
            if vm.runtime.powerState == vim.VirtualMachine.PowerState.poweredOff:
                return f"VM '{name}' is already powered off."
            self.wait_for_task(vm.PowerOffVM_Task())
            return f"VM '{name}' powered off."

    def reset_vm(self, name: str) -> str:
        with self._session():
            self.wait_for_task(self.find_vm(name).ResetVM_Task())
            return f"VM '{name}' reset."

    def suspend_vm(self, name: str) -> str:
        with self._session():
            self.wait_for_task(self.find_vm(name).SuspendVM_Task())
            return f"VM '{name}' suspended."

    def _require_tools(self, vm: Any, name: str) -> None:
        if str(getattr(vm.guest, "toolsRunningStatus", "")) != "guestToolsRunning":
            raise VSphereError(f"VMware Tools are not running in {name!r}; guest operation impossible")

    def shutdown_guest(self, name: str) -> str:
        with self._session():
            vm = self.find_vm(name)
            self._require_tools(vm, name)
            vm.ShutdownGuest()
            return f"Guest shutdown requested for VM '{name}'."

    def reboot_guest(self, name: str) -> str:
        with self._session():
            vm = self.find_vm(name)
            self._require_tools(vm, name)
            vm.RebootGuest()
            return f"Guest reboot requested for VM '{name}'."

    def reconfigure_vm(self, name: str, cpus: int | None, memory_mb: int | None) -> str:
        if cpus is None and memory_mb is None:
            raise VSphereError("nothing to change: provide cpu and/or memory")
        with self._session():
            vm = self.find_vm(name)
            spec = vim.vm.ConfigSpec()
            if cpus is not None:
                spec.numCPUs = cpus
            if memory_mb is not None:
                spec.memoryMB = memory_mb
            self.wait_for_task(vm.ReconfigVM_Task(spec))
            return f"VM '{name}' reconfigured."

    # ------------------------------------------------------------- snapshots
    @staticmethod
    def _walk(nodes: list[Any], depth: int = 0) -> Iterator[tuple[Any, int]]:
        for n in nodes:
            yield n, depth
            yield from VSphereClient._walk(n.childSnapshotList, depth + 1)

    def _flatten_snapshots(self, vm: Any) -> list[Any]:
        if not vm.snapshot:
            return []
        return [n for n, _ in self._walk(vm.snapshot.rootSnapshotList)]

    def list_snapshots(self, vm_name: str) -> list[dict[str, Any]]:
        with self._session():
            vm = self.find_vm(vm_name)
            if not vm.snapshot:
                return []
            return [{
                "name": n.name,
                "description": n.description,
                "created": str(n.createTime),
                "state": str(n.state),
                "depth": d,
            } for n, d in self._walk(vm.snapshot.rootSnapshotList)]

    def _find_snapshot(self, vm: Any, snap_name: str) -> Any:
        matches = [n for n in self._flatten_snapshots(vm) if n.name == snap_name]
        if not matches:
            raise VSphereError(f"snapshot {snap_name!r} not found")
        if len(matches) > 1:
            raise VSphereError(f"snapshot name {snap_name!r} is ambiguous")
        return matches[0]

    def create_snapshot(self, vm_name: str, snap_name: str, description: str = "",
                        memory: bool = False, quiesce: bool = False) -> str:
        with self._session():
            vm = self.find_vm(vm_name)
            self.wait_for_task(vm.CreateSnapshot_Task(
                name=snap_name, description=description, memory=memory, quiesce=quiesce))
            return f"Snapshot '{snap_name}' created for VM '{vm_name}'."

    def revert_snapshot(self, vm_name: str, snap_name: str) -> str:
        with self._session():
            vm = self.find_vm(vm_name)
            node = self._find_snapshot(vm, snap_name)
            self.wait_for_task(node.snapshot.RevertToSnapshot_Task())
            return f"VM '{vm_name}' reverted to snapshot '{snap_name}'."

    def remove_snapshot(self, vm_name: str, snap_name: str, remove_children: bool = False) -> str:
        with self._session():
            vm = self.find_vm(vm_name)
            node = self._find_snapshot(vm, snap_name)
            self.wait_for_task(node.snapshot.RemoveSnapshot_Task(removeChildren=remove_children))
            return f"Snapshot '{snap_name}' removed from VM '{vm_name}'."



