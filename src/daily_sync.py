"""Unattended daily sync of Rapid7 InsightVM Bulk Export data.

Run from cron (see scripts/run-daily-sync.sh), not through Claude/MCP tool
calls: no FastMCP runtime dependency, plain function calls into the same
building blocks mcp_server.py's interactive tools use
(config/export_manager/download/duckdb_loader/export_tracker/
organizations_client).

Syncs every tenant this account can see (the default/unscoped tenant plus
every Rapid7-managed organization, discovered live) across all 4 export
types (vulnerability, policy, remediation, asset_software), then writes a
tenant_registry.json that rapid7-mcp-server's web backend reads to resolve
a tenant display_name to a DuckDB file path.

Deliberately does NOT replay the interactive skill docs' documented
sequence of loading each export type with its own separate
download_and_load_export call. load_parquet_files_by_prefix deletes the
whole DuckDB file on every non-append load (vulnerability/policy/
asset_software all use append=False) and only rescues+restores the
vulnerability_remediation table across that wipe -- confirmed empirically
against the real on-disk data (every tenant today has only `assets` +
`vulnerabilities`, never `policies`/`asset_software` alongside them), that
sequence quietly destroys each previous type's tables rather than
accumulating them. Instead: download all 3 snapshot export types first,
merge their prefix->file maps into one (dropping any redundant `asset`
prefix files from policy/asset_software -- vulnerability's own `asset`
files are the sole source of truth here, mirroring the interactive
policy load's existing skip_prefixes={"asset"}), then load once per
tenant per day. Remediation stays separate (append=True, no wipe) with
its own watermark file so a daily run only pulls the incremental window
since the last successful load, instead of re-pulling (and duplicating)
the same 30-day default range every day.
"""

import json
import logging
import os
import re
import sys
import tempfile
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import load_config, load_parent_organization_config
from .download import download_all_files
from .duckdb_loader import VulnerabilityDatabase
from .export_manager import (
    build_remediation_date_chunks,
    create_asset_software_export,
    create_policy_export,
    create_remediation_export,
    create_vulnerability_export,
    get_export_status,
)
from .export_tracker import DEFAULT_ORG_ID, ExportTracker
from .organizations_client import filter_by_region, get_managed_organizations

logger = logging.getLogger("daily_sync")

_DATA_DIR: Path = Path(os.environ.get("DATA_DIR", "~/.rapid7_mcp")).expanduser().resolve()
REGISTRY_PATH = Path(os.environ.get("TENANT_REGISTRY_PATH", str(_DATA_DIR / "tenant_registry.json")))

# Must match whatever this repo's Postgres `tenants.display_name` uses for
# BaseLineIT's own row -- rapid7-mcp-server matches by name, not id, for
# this one entry (see plan's "manual data-alignment" step).
DEFAULT_TENANT_NAME = os.environ.get("DEFAULT_TENANT_NAME", "BaseLineIT")

SNAPSHOT_EXPORT_TYPES = ("vulnerability", "policy", "asset_software")
TABLE_FOR_EXPORT_TYPE = {
    "vulnerability": "vulnerabilities",
    "policy": "policies",
    "asset_software": "asset_software",
}
REMEDIATION_LOOKBACK_DAYS = 30

POLL_INTERVAL_SECONDS = int(os.environ.get("DAILY_SYNC_POLL_INTERVAL", "30"))
EXPORT_TIMEOUT_SECONDS = int(os.environ.get("DAILY_SYNC_EXPORT_TIMEOUT", "1800"))

# Duplicated from mcp_server.py's _ORG_ID_PATTERN/_org_data_dir rather than
# imported, so this script has no dependency on the FastMCP server module's
# own globals/state.
_ORG_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def _org_data_dir(organization_id: Optional[str]) -> Path:
    if not organization_id:
        return _DATA_DIR
    if not _ORG_ID_PATTERN.match(organization_id):
        raise ValueError(f"Invalid organization_id: {organization_id!r}")
    orgs_root = (_DATA_DIR / "orgs").resolve()
    org_dir = (orgs_root / organization_id).resolve()
    org_dir.relative_to(orgs_root)  # containment check
    org_dir.mkdir(parents=True, exist_ok=True)
    return org_dir


def discover_tenants() -> List[Dict[str, str]]:
    """Default/unscoped tenant plus every live-discovered managed organization in this
    account's own configured region. Filtered the same way get_organization_ids's MCP tool
    filters by default -- confirmed live that an unfiltered list includes cross-region
    duplicate entries (e.g. a "<name> - us1" org alongside the real "eu" one) that always
    401 here, since every other call in this script is pinned to RAPID7_REGION."""
    tenants = [{"organization_id": "", "name": DEFAULT_TENANT_NAME}]
    parent_cfg = load_parent_organization_config()
    orgs = get_managed_organizations(
        api_key=parent_cfg["api_key"],
        region=parent_cfg["region"],
        parent_organization_id=parent_cfg["parent_organization_id"],
    )
    orgs = filter_by_region(orgs, parent_cfg["region"])
    for org in orgs:
        tenants.append({"organization_id": org["id"], "name": org.get("name", org["id"])})
    return tenants


def _poll_until_complete_bounded(config: Dict[str, str], export_id: str) -> Dict[str, Any]:
    """Same contract as export_manager.poll_until_complete, but bounded by
    EXPORT_TIMEOUT_SECONDS so one stuck Rapid7 export can't hang an
    unattended overnight run forever. Returns the full status_info dict from
    the SAME get_export_status call that observed COMPLETE -- callers must
    build both the download URL list and the prefix map from this one dict,
    never a second get_export_status call: Rapid7's parquetFiles URLs are
    pre-signed and are not guaranteed to be byte-identical across two
    separate calls, so re-fetching status a second time to "look up" the
    prefix for a URL from the first call can silently fail to match
    anything (confirmed live: this exact mistake produced literal prefix
    'unknown' for every file, which the loader then discards entirely)."""
    deadline = time.monotonic() + EXPORT_TIMEOUT_SECONDS
    while True:
        status_info = get_export_status(config, export_id)
        current_status = status_info["status"]

        if current_status in ("COMPLETE", "SUCCEEDED"):
            return status_info
        if current_status == "FAILED":
            raise ValueError(f"Export {export_id} failed")
        if current_status not in ("PENDING", "PROCESSING", "IN_PROGRESS"):
            raise ValueError(f"Unexpected export status: {current_status}")

        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"Export {export_id} still {current_status} after {EXPORT_TIMEOUT_SECONDS}s -- giving up"
            )
        time.sleep(POLL_INTERVAL_SECONDS)


def _download_export_files(
    config: Dict[str, str], organization_id: Optional[str], export_id: str
) -> Dict[str, List[str]]:
    """Poll an export to completion, download its files to a fresh temp
    dir, return prefix -> local file paths. Caller owns temp file cleanup."""
    status_info = _poll_until_complete_bounded(config, export_id)
    parquet_urls = status_info["parquetFiles"]
    if not parquet_urls:
        return {}

    url_to_prefix: Dict[str, str] = {}
    for item in status_info.get("result") or []:
        prefix = item.get("prefix", "")
        for url in item.get("urls", []):
            url_to_prefix[url] = prefix

    file_data = download_all_files(parquet_urls, config["api_key"], organization_id=organization_id)

    temp_dir = tempfile.mkdtemp(prefix="daily_sync_")
    prefix_file_map: Dict[str, List[str]] = {}
    for i, (url, data) in enumerate(zip(parquet_urls, file_data)):
        temp_path = Path(temp_dir) / f"export_{i}.parquet"
        temp_path.write_bytes(data)
        prefix = url_to_prefix.get(url, "unknown")
        prefix_file_map.setdefault(prefix, []).append(str(temp_path))

    return prefix_file_map


def _drop_asset_prefix_files(prefix_file_map: Dict[str, List[str]]) -> None:
    """Remove (and delete on disk) any `asset`-prefixed files, including
    sub-path variants like `asset/ivm` (see duckdb_loader._normalize_prefix).
    Used for policy/asset_software downloads, whose own asset context is
    redundant with -- and would otherwise silently shadow -- vulnerability's."""
    for key in list(prefix_file_map.keys()):
        if key.split("/")[0] == "asset":
            for p in prefix_file_map.pop(key):
                Path(p).unlink(missing_ok=True)


def _cleanup_temp_files(prefix_file_map: Dict[str, List[str]]) -> None:
    dirs = set()
    for paths in prefix_file_map.values():
        for p in paths:
            path = Path(p)
            dirs.add(path.parent)
            path.unlink(missing_ok=True)
    for d in dirs:
        try:
            d.rmdir()
        except OSError:
            pass  # not empty (shared with another export's files) or already gone


def sync_snapshot_export(
    config: Dict[str, str],
    tracker: ExportTracker,
    org_key: str,
    organization_id: Optional[str],
    export_type: str,
) -> Tuple[str, Dict[str, List[str]], Optional[str]]:
    """Create (or skip, if already synced today) one snapshot export type,
    download it. Does NOT load into the db, and deliberately does NOT mark
    the tracker row COMPLETE -- caller merges prefix maps across all
    snapshot types, loads once, and only THEN marks each type COMPLETE with
    its real row count. Marking COMPLETE here (before the load actually
    happens) would leave a misleading "COMPLETE, 0 rows" tracker row if the
    process crashes/is killed between download and the merged load -- a
    same-day rerun would then wrongly treat that type as already synced
    and skip re-fetching it (confirmed live: exactly this happened to a
    tenant when a prior version of this script was interrupted mid-run).

    Returns (status, prefix_file_map, export_id). export_id is None when
    already synced today (nothing new was created this call)."""
    today_export = tracker.get_today_export(export_type=export_type, organization_id=org_key)
    if today_export:
        return "already synced today", {}, None

    creator = {
        "vulnerability": create_vulnerability_export,
        "policy": create_policy_export,
        "asset_software": create_asset_software_export,
    }[export_type]
    export_id = creator(config)
    tracker.save_export(
        export_id=export_id, status="PENDING", parquet_urls=[], export_type=export_type, organization_id=org_key
    )

    prefix_file_map = _download_export_files(config, organization_id, export_id)
    if export_type != "vulnerability":
        _drop_asset_prefix_files(prefix_file_map)

    return "ok", prefix_file_map, export_id


def _watermark_path(org_dir: Path) -> Path:
    return org_dir / "remediation_watermark.json"


def _load_remediation_watermark(org_dir: Path) -> Optional[str]:
    path = _watermark_path(org_dir)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text()).get("last_end_date")
    except (json.JSONDecodeError, OSError):
        return None


def _save_remediation_watermark(org_dir: Path, end_date: str) -> None:
    path = _watermark_path(org_dir)
    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_text(json.dumps({"last_end_date": end_date}))
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)


def sync_remediation(
    config: Dict[str, str],
    tracker: ExportTracker,
    org_key: str,
    organization_id: Optional[str],
    db: VulnerabilityDatabase,
    org_dir: Path,
) -> str:
    """Append-load remediation data for [watermark, today], advancing the
    watermark only after each chunk successfully loads -- so a crash mid-run
    retries that exact window next time instead of silently skipping it, and
    a same-day rerun (start >= end) is a no-op rather than re-pulling (and
    duplicating) the same range."""
    last_end = _load_remediation_watermark(org_dir)
    start_date = last_end or (date.today() - timedelta(days=REMEDIATION_LOOKBACK_DAYS)).isoformat()
    end_date = date.today().isoformat()

    if start_date >= end_date:
        return "up to date"

    for chunk_start, chunk_end in build_remediation_date_chunks(start_date, end_date):
        export_id = create_remediation_export(config, chunk_start, chunk_end)
        tracker.save_export(
            export_id=export_id, status="PENDING", parquet_urls=[],
            export_type="remediation", organization_id=org_key,
        )
        prefix_file_map = _download_export_files(config, organization_id, export_id)
        try:
            row_counts = db.load_parquet_files_by_prefix(prefix_file_map, append=True)
            if "vulnerability_remediation" not in row_counts:
                # Downloaded but never actually loaded (e.g. an unrecognized/mismatched
                # prefix) -- do NOT mark COMPLETE or advance the watermark, so a rerun
                # retries this exact chunk instead of silently treating it as done.
                raise ValueError(
                    f"remediation export {export_id} downloaded but vulnerability_remediation "
                    f"table was never loaded (prefixes seen: {list(prefix_file_map.keys())})"
                )
            tracker.save_export(
                export_id=export_id, status="COMPLETE", parquet_urls=[],
                row_count=row_counts["vulnerability_remediation"],
                export_type="remediation", organization_id=org_key,
            )
        finally:
            _cleanup_temp_files(prefix_file_map)
        _save_remediation_watermark(org_dir, chunk_end)

    return "ok"


def sync_one_tenant(tenant: Dict[str, str]) -> Dict[str, Any]:
    organization_id = tenant["organization_id"] or None
    org_key = organization_id or DEFAULT_ORG_ID
    org_dir = _org_data_dir(organization_id)
    db_path = str(org_dir / "rapid7_bulk_export.db")
    entry: Dict[str, Any] = {
        "organization_id": organization_id or "",
        "name": tenant["name"],
        "db_path": db_path,
        "export_types": {},
    }

    try:
        config = load_config(organization_id)
    except ValueError as e:
        logger.error("tenant=%s: config load failed: %s", tenant["name"], e)
        entry["status"] = "failed"
        entry["error"] = str(e)
        return entry

    tracker = ExportTracker(str(org_dir / "rapid7_bulk_export_tracking.db"))
    db = VulnerabilityDatabase(db_path)

    merged_prefix_map: Dict[str, List[str]] = {}
    downloaded_maps: List[Dict[str, List[str]]] = []
    export_ids: Dict[str, str] = {}
    any_failed = False

    for export_type in SNAPSHOT_EXPORT_TYPES:
        try:
            status, prefix_file_map, export_id = sync_snapshot_export(config, tracker, org_key, organization_id, export_type)
            entry["export_types"][export_type] = status
            if export_id:
                export_ids[export_type] = export_id
            if prefix_file_map:
                downloaded_maps.append(prefix_file_map)
                for prefix, files in prefix_file_map.items():
                    merged_prefix_map.setdefault(prefix, []).extend(files)
        except Exception as e:
            logger.exception("tenant=%s export_type=%s failed", tenant["name"], export_type)
            entry["export_types"][export_type] = f"error: {e}"
            any_failed = True

    if merged_prefix_map:
        try:
            row_counts = db.load_parquet_files_by_prefix(merged_prefix_map)
            for export_type, table in TABLE_FOR_EXPORT_TYPE.items():
                export_id = export_ids.get(export_type)
                if entry["export_types"].get(export_type) != "ok" or export_id is None:
                    continue
                if table in row_counts:
                    tracker.save_export(
                        export_id=export_id, status="COMPLETE", parquet_urls=[],
                        row_count=row_counts[table], export_type=export_type, organization_id=org_key,
                    )
                else:
                    # Downloaded, but its table never appeared in the load's output -- e.g. an
                    # unrecognized/mismatched prefix. Leave the tracker row PENDING (not
                    # COMPLETE) so a same-day rerun retries this type instead of skipping it.
                    logger.warning(
                        "tenant=%s export_type=%s: downloaded but table '%s' was never loaded",
                        tenant["name"], export_type, table,
                    )
                    entry["export_types"][export_type] = "downloaded but not loaded (prefix mismatch or empty export)"
                    any_failed = True
        except Exception as e:
            logger.exception("tenant=%s: merged snapshot load failed", tenant["name"])
            for export_type in SNAPSHOT_EXPORT_TYPES:
                if entry["export_types"].get(export_type) == "ok":
                    entry["export_types"][export_type] = f"downloaded but load failed: {e}"
            any_failed = True
    else:
        logger.info(
            "tenant=%s: nothing new to load this run (all snapshot types already synced today, or all failed)",
            tenant["name"],
        )

    for prefix_file_map in downloaded_maps:
        _cleanup_temp_files(prefix_file_map)

    try:
        entry["export_types"]["remediation"] = sync_remediation(config, tracker, org_key, organization_id, db, org_dir)
    except Exception as e:
        logger.exception("tenant=%s export_type=remediation failed", tenant["name"])
        entry["export_types"]["remediation"] = f"error: {e}"
        any_failed = True

    entry["status"] = "partial" if any_failed else "ok"
    entry["last_synced_at"] = datetime.now(timezone.utc).isoformat()
    return entry


def write_registry_atomically(path: Path, tenants: List[Dict[str, Any]]) -> None:
    payload = {"generated_at": datetime.now(timezone.utc).isoformat(), "tenants": tenants}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, default=str))
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    _DATA_DIR.mkdir(parents=True, exist_ok=True)

    try:
        tenants = discover_tenants()
    except Exception:
        logger.exception("Tenant discovery failed -- leaving the existing registry file untouched")
        return 1

    logger.info("Discovered %d tenant(s) (including default)", len(tenants))

    results = []
    for tenant in tenants:
        logger.info("Syncing tenant: %s (organization_id=%r)", tenant["name"], tenant["organization_id"])
        result = sync_one_tenant(tenant)
        logger.info("Tenant %s: status=%s export_types=%s", tenant["name"], result["status"], result.get("export_types"))
        results.append(result)
        # Write after every tenant, not just once at the end -- a full run across many tenants
        # can take hours, and rapid7-mcp-server's Clients tab should show each tenant's data as
        # soon as it's ready rather than nothing at all until the entire run finishes (confirmed
        # live: checking the tab mid-run found no registry file yet). Also means a mid-run crash
        # still leaves a registry reflecting whatever did complete, not nothing.
        write_registry_atomically(REGISTRY_PATH, results)

    logger.info("Registry written to %s", REGISTRY_PATH)

    return 1 if any(r["status"] == "failed" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
