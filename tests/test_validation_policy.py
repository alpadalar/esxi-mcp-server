from __future__ import annotations

import pytest

from esxi_mcp_server import validation as v
from esxi_mcp_server.errors import PolicyError, ValidationError
from esxi_mcp_server.policy import OpClass, Policy


@pytest.mark.parametrize("name", ["web-01", "a", "My VM 2.0", "x" * 80])
def test_vm_name_ok(name):
    assert v.vm_name(name) == name


@pytest.mark.parametrize("name", ["", " lead", "trail ", "a/b", "a\\b", "100%", "x" * 81,
                                  "bad\nname", "-start", "../etc", None, 5])
def test_vm_name_rejected(name):
    with pytest.raises(ValidationError):
        v.vm_name(name)  # type: ignore[arg-type]


def test_object_name():
    assert v.object_name("VM Network", "n") == "VM Network"
    for bad in ["", "   ", "a\x00b", "x" * 257]:
        with pytest.raises(ValidationError):
            v.object_name(bad, "n")


def test_int_range():
    assert v.int_range(2, "cpu", 1, 4) == 2
    for bad in [0, 5, True, "2", 1.5]:
        with pytest.raises(ValidationError):
            v.int_range(bad, "cpu", 1, 4)  # type: ignore[arg-type]


def test_policy_matrix():
    Policy().check("x", OpClass.READ)
    Policy().check("x", OpClass.WRITE)
    with pytest.raises(PolicyError, match="destructive"):
        Policy().check("x", OpClass.DESTRUCTIVE)
    Policy(allow_destructive=True).check("x", OpClass.DESTRUCTIVE)
    ro = Policy(read_only=True, allow_destructive=True)
    ro.check("x", OpClass.READ)
    for k in (OpClass.WRITE, OpClass.DESTRUCTIVE):
        with pytest.raises(PolicyError, match="read-only"):
            ro.check("x", k)
