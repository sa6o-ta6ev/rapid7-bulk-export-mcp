"""
Unit tests for daily_sync.main()'s single-tenant filter argument.
"""

import sys

from src import daily_sync

TENANTS = [
    {"organization_id": "", "name": "DefaultOrg"},
    {"organization_id": "abc-123", "name": "boni"},
    {"organization_id": "def-456", "name": "AcmeCo"},
]


def _fake_sync_one_tenant(tenant):
    return {"organization_id": tenant["organization_id"], "name": tenant["name"], "status": "ok", "export_types": {}}


def test_filter_by_name_is_case_insensitive(tmp_path, monkeypatch):
    monkeypatch.setattr(daily_sync, "discover_tenants", lambda: TENANTS)
    monkeypatch.setattr(daily_sync, "sync_one_tenant", _fake_sync_one_tenant)
    monkeypatch.setattr(daily_sync, "REGISTRY_PATH", tmp_path / "tenant_registry.json")
    monkeypatch.setattr(sys, "argv", ["daily_sync.py", "BONI"])

    assert daily_sync.main() == 0

    payload = (tmp_path / "tenant_registry.json").read_text()
    assert '"name": "boni"' in payload
    assert "AcmeCo" not in payload
    assert "DefaultOrg" not in payload


def test_filter_by_organization_id(tmp_path, monkeypatch):
    monkeypatch.setattr(daily_sync, "discover_tenants", lambda: TENANTS)
    monkeypatch.setattr(daily_sync, "sync_one_tenant", _fake_sync_one_tenant)
    monkeypatch.setattr(daily_sync, "REGISTRY_PATH", tmp_path / "tenant_registry.json")
    monkeypatch.setattr(sys, "argv", ["daily_sync.py", "def-456"])

    assert daily_sync.main() == 0

    payload = (tmp_path / "tenant_registry.json").read_text()
    assert '"name": "AcmeCo"' in payload
    assert "boni" not in payload


def test_no_matching_tenant_returns_error(monkeypatch):
    monkeypatch.setattr(daily_sync, "discover_tenants", lambda: TENANTS)
    monkeypatch.setattr(sys, "argv", ["daily_sync.py", "does-not-exist"])

    assert daily_sync.main() == 1


def test_no_filter_syncs_all_tenants(tmp_path, monkeypatch):
    monkeypatch.setattr(daily_sync, "discover_tenants", lambda: TENANTS)
    monkeypatch.setattr(daily_sync, "sync_one_tenant", _fake_sync_one_tenant)
    monkeypatch.setattr(daily_sync, "REGISTRY_PATH", tmp_path / "tenant_registry.json")
    monkeypatch.setattr(sys, "argv", ["daily_sync.py"])

    assert daily_sync.main() == 0

    payload = (tmp_path / "tenant_registry.json").read_text()
    assert "boni" in payload
    assert "AcmeCo" in payload
    assert "DefaultOrg" in payload
