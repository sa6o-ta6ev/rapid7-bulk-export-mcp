"""
Unit tests for daily_sync.main()'s single-tenant filter argument.
"""

import json
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
    assert daily_sync.main("BONI") == 0

    payload = (tmp_path / "tenant_registry.json").read_text()
    assert '"name": "boni"' in payload
    assert "AcmeCo" not in payload
    assert "DefaultOrg" not in payload


def test_filter_by_organization_id(tmp_path, monkeypatch):
    monkeypatch.setattr(daily_sync, "discover_tenants", lambda: TENANTS)
    monkeypatch.setattr(daily_sync, "sync_one_tenant", _fake_sync_one_tenant)
    monkeypatch.setattr(daily_sync, "REGISTRY_PATH", tmp_path / "tenant_registry.json")
    assert daily_sync.main("def-456") == 0

    payload = (tmp_path / "tenant_registry.json").read_text()
    assert '"name": "AcmeCo"' in payload
    assert "boni" not in payload


def test_ambiguous_name_prefers_exact_case(tmp_path, monkeypatch):
    tenants = TENANTS + [{"organization_id": "ghi-789", "name": "Boni"}]
    monkeypatch.setattr(daily_sync, "discover_tenants", lambda: tenants)
    monkeypatch.setattr(daily_sync, "sync_one_tenant", _fake_sync_one_tenant)
    monkeypatch.setattr(daily_sync, "REGISTRY_PATH", tmp_path / "tenant_registry.json")

    assert daily_sync.main("Boni") == 0

    payload = (tmp_path / "tenant_registry.json").read_text()
    assert "ghi-789" in payload
    assert "abc-123" not in payload


def test_ambiguous_name_without_exact_case_returns_error(monkeypatch):
    tenants = TENANTS + [{"organization_id": "ghi-789", "name": "Boni"}]
    monkeypatch.setattr(daily_sync, "discover_tenants", lambda: tenants)

    assert daily_sync.main("BONI") == 1


def test_no_matching_tenant_returns_error(monkeypatch):
    monkeypatch.setattr(daily_sync, "discover_tenants", lambda: TENANTS)
    assert daily_sync.main("does-not-exist") == 1


def test_no_filter_syncs_all_tenants(tmp_path, monkeypatch):
    monkeypatch.setattr(daily_sync, "discover_tenants", lambda: TENANTS)
    monkeypatch.setattr(daily_sync, "sync_one_tenant", _fake_sync_one_tenant)
    monkeypatch.setattr(daily_sync, "REGISTRY_PATH", tmp_path / "tenant_registry.json")
    assert daily_sync.main() == 0

    payload = (tmp_path / "tenant_registry.json").read_text()
    assert "boni" in payload
    assert "AcmeCo" in payload
    assert "DefaultOrg" in payload


def test_ignores_process_argv(tmp_path, monkeypatch):
    # The scheduler calls main() inside the MCP server, whose argv[1] is the default db path.
    # That must not be treated as a tenant filter.
    monkeypatch.setattr(daily_sync, "discover_tenants", lambda: TENANTS)
    monkeypatch.setattr(daily_sync, "sync_one_tenant", _fake_sync_one_tenant)
    monkeypatch.setattr(daily_sync, "REGISTRY_PATH", tmp_path / "tenant_registry.json")
    monkeypatch.setattr(sys, "argv", ["run_server.py", "/data/rapid7_bulk_export.db"])

    assert daily_sync.main() == 0

    payload = (tmp_path / "tenant_registry.json").read_text()
    assert "boni" in payload
    assert "AcmeCo" in payload


def test_crashing_tenant_does_not_abort_run(tmp_path, monkeypatch):
    def sync(tenant):
        if tenant["name"] == "boni":
            raise OSError("cannot open db")
        return _fake_sync_one_tenant(tenant)

    monkeypatch.setattr(daily_sync, "discover_tenants", lambda: TENANTS)
    monkeypatch.setattr(daily_sync, "sync_one_tenant", sync)
    monkeypatch.setattr(daily_sync, "REGISTRY_PATH", tmp_path / "tenant_registry.json")

    assert daily_sync.main() == 1

    payload = json.loads((tmp_path / "tenant_registry.json").read_text())
    by_name = {t["name"]: t for t in payload["tenants"]}
    assert by_name["boni"]["status"] == "failed"
    assert "cannot open db" in by_name["boni"]["error"]
    assert by_name["AcmeCo"]["status"] == "ok"


def test_discover_skips_unconfigured_default_tenant(monkeypatch):
    """Multi-tenant-only deployments have no RAPID7_API_KEY; the default tenant could
    only fail there, and its name duplicated a managed org's."""

    def no_default_key(organization_id=None):
        raise ValueError("RAPID7_API_KEY environment variable is not set")

    monkeypatch.setattr(daily_sync, "load_config", no_default_key)
    monkeypatch.setattr(
        daily_sync,
        "load_parent_organization_config",
        lambda: {"api_key": "k", "region": "eu", "parent_organization_id": "p"},
    )
    monkeypatch.setattr(daily_sync, "get_managed_organizations", lambda **kw: [{"id": "abc-123", "name": "BaselineIT"}])
    monkeypatch.setattr(daily_sync, "filter_by_region", lambda orgs, region: orgs)

    assert daily_sync.discover_tenants() == [{"organization_id": "abc-123", "name": "BaselineIT"}]


def test_discover_includes_configured_default_tenant(monkeypatch):
    monkeypatch.setattr(daily_sync, "load_config", lambda organization_id=None: {"api_key": "k"})
    monkeypatch.setattr(
        daily_sync,
        "load_parent_organization_config",
        lambda: {"api_key": "k", "region": "eu", "parent_organization_id": "p"},
    )
    monkeypatch.setattr(daily_sync, "get_managed_organizations", lambda **kw: [])
    monkeypatch.setattr(daily_sync, "filter_by_region", lambda orgs, region: orgs)

    assert daily_sync.discover_tenants() == [{"organization_id": "", "name": daily_sync.DEFAULT_TENANT_NAME}]
