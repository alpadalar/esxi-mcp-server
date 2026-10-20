from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from esxi_mcp_server.config import Settings
from esxi_mcp_server.security import hash_api_key

API_KEY = "test-key-not-a-real-secret"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        vcenter_host="vc.example.test", vcenter_user="svc@vsphere.local",
        vcenter_password="pw-for-tests", api_key_hash=hash_api_key(API_KEY),
    )


@pytest.fixture
def make_settings() -> Any:
    def _make(**kw: Any) -> Settings:
        base: dict[str, Any] = dict(vcenter_host="vc.example.test", vcenter_user="u",
                                    vcenter_password="pw-for-tests")
        base.update(kw)
        return Settings(**base)
    return _make


@pytest.fixture
def fake_client() -> MagicMock:
    from esxi_mcp_server.vsphere import VSphereClient
    return MagicMock(spec=VSphereClient)
