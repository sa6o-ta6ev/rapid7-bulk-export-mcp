#!/usr/bin/env python3
"""
FastMCP Server for Rapid7 Vulnerability Data

This server exposes vulnerability data through the Model Context Protocol,
allowing AI assistants to query and analyze the data.
"""

import datetime as _dt
import glob
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Dict, Optional

import duckdb as _duckdb
from fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .config import load_config, load_parent_organization_config
from .db_utils import get_db_lock
from .download import download_all_files
from .duckdb_loader import VulnerabilityDatabase
from .export_manager import (
    ExportInProgressError,
    build_remediation_date_chunks,
    create_asset_software_export,
    create_policy_export,
    create_remediation_export,
    create_vulnerability_export,
    get_export_status,
    poll_until_complete,
)
from .export_tracker import DEFAULT_ORG_ID, ExportTracker
from .organizations_client import filter_by_region, get_managed_organizations

# Initialize FastMCP server
mcp = FastMCP("rapid7-bulk-export")

# Org-keyed database instances. "default" (DEFAULT_ORG_ID) is the unscoped,
# single-tenant store used when no organization_id is passed to a tool —
# this preserves today's exact behavior and paths.
_db_instances: Dict[str, VulnerabilityDatabase] = {}


# Locks guarding each tenant's database (both a background load and the read
# tools below), so a query can never run concurrently with that same tenant's
# tables being replaced mid-load. Keyed by database file via
# db_utils.get_db_lock, the same lock the loader itself takes and the
# in-process daily sync resolves to -- so a scheduled sync and an interactive
# load of one tenant serialize instead of racing. Re-entrant so a locked
# section can safely call the loader. Per-file (not global) so a background
# load for one tenant never blocks reads/loads for an unrelated tenant.
def _get_db_lock(organization_id: str = "") -> threading.RLock:
    """Get the lock guarding this tenant's database file."""
    return get_db_lock(_db_path(organization_id))


# CLI positional arg override for the default org's database path, captured
# in main() and applied lazily the first time the default db is requested.
_default_db_path_override: Optional[str] = None

# Data directory — resolved once at startup, used for all database paths.
# Precedence: explicit DATA_DIR wins (existing installs unaffected), then the
# plugin host's PLUGIN_DATA (Agent Plugins spec: per-install, writable, survives
# updates), then ~/.rapid7_mcp so relative-path writes never hit a read-only CWD.
_DATA_DIR: Path = (
    Path(os.environ.get("DATA_DIR") or os.environ.get("PLUGIN_DATA") or "~/.rapid7_mcp").expanduser().resolve()
)

VALID_EXPORT_TYPES = ("vulnerability", "policy", "remediation", "asset_software")

# Rapid7 customer/tenant org IDs are UUIDs; keep this permissive but safe for
# use as a filesystem path segment (no separators, no "..").
_ORG_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

# ---------------------------------------------------------------------------
# Background download/load job tracking
#
# Loading a full export (potentially millions of rows) can take much longer
# than an MCP client's tool-call timeout — Claude Desktop, for example,
# hard-cancels a tool call after ~4 minutes. Running the download+load
# synchronously inside a single tool call means the client gives up and
# cancels while the server keeps working, and when the server later tries
# to respond to that already-cancelled request, some MCP client/session
# implementations raise on a duplicate response and crash the whole stdio
# server process.
#
# To avoid this, download_rapid7_export() only *starts* the work in a
# background thread and returns immediately. Progress and results are
# recorded as phase transitions on the durable ExportTracker row (not an
# in-memory dict), so state is durable and inspectable after a restart and is
# reported by the existing check_rapid7_export_status() and list_rapid7_exports()
# tools — there is no separate status tool to poll. Workers do not resume across
# a restart; interrupted work is reconciled to a retryable FAILED at startup.
#
# All of this is per-tenant: each background worker carries organization_id
# through to _get_db/_tracker/_get_db_lock, so one tenant's load never blocks
# or corrupts another tenant's database.
# ---------------------------------------------------------------------------

# Local load-phase values written to the tracker's `status` column. These
# describe THIS server's download+load progress, distinct from the Rapid7
# platform-side export status returned by the API (PENDING/PROCESSING/…).
PHASE_DOWNLOADING = "DOWNLOADING"
PHASE_LOADING = "LOADING"
PHASE_COMPLETE = "COMPLETE"  # data loaded locally and queryable
PHASE_FAILED = "FAILED"

# States that mean a background load is actively touching the database, so a
# second download must not start and reads should back off.
_ACTIVE_PHASES = (PHASE_DOWNLOADING, PHASE_LOADING)

# Multi-chunk job status values (export_jobs.status). A job spans N per-chunk
# export IDs; these describe the job as a whole.
JOB_RUNNING = "RUNNING"
JOB_COMPLETE = "COMPLETE"
JOB_FAILED = "FAILED"  # at least one chunk failed; loaded chunks remain

# How long to wait between retries when the platform reports another export of
# the same type already in flight, and how long to keep retrying before giving
# up on a chunk.
_IN_PROGRESS_RETRY_SECS = 30
_IN_PROGRESS_MAX_WAIT_SECS = 20 * 60

# Runs daily_sync.main() on a schedule inside this same process/container,
# instead of relying on a separate host cron job -- keeps every write to
# DATA_DIR under this image's own uid (no separate host checkout that can
# drift to a different owner). Opt-in: off by default so `make docker-test`
# and other one-off container runs never trigger a background sync.
_ENABLE_DAILY_SYNC = os.environ.get("ENABLE_DAILY_SYNC", "").lower() in ("1", "true", "yes")
_DAILY_SYNC_HOUR_UTC = int(os.environ.get("DAILY_SYNC_HOUR_UTC", "2"))
_DAILY_SYNC_MINUTE_UTC = int(os.environ.get("DAILY_SYNC_MINUTE_UTC", "0"))

logger = logging.getLogger("mcp_server")


def _seconds_until_next_run(hour: int, minute: int, now: Optional[_dt.datetime] = None) -> float:
    now = now or _dt.datetime.now(_dt.timezone.utc)
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        target += _dt.timedelta(days=1)
    return (target - now).total_seconds()


def _daily_sync_scheduler_loop() -> None:
    """Background loop: run daily_sync.main() once every 24h, at a fixed UTC time.

    Runs forever as a daemon thread. A failed run (or one that daily_sync.main()
    itself reports as "failed") never stops the loop -- it just waits for the
    next scheduled time and tries again.
    """
    from . import daily_sync

    while True:
        sleep_seconds = _seconds_until_next_run(_DAILY_SYNC_HOUR_UTC, _DAILY_SYNC_MINUTE_UTC)
        logger.info("Daily sync scheduler: next run in %.0fs", sleep_seconds)
        time.sleep(sleep_seconds)
        try:
            exit_code = daily_sync.main()
            if exit_code:
                logger.error("Scheduled daily sync finished with errors (exit code %s)", exit_code)
            else:
                logger.info("Scheduled daily sync finished")
        except Exception:
            logger.exception("Scheduled daily sync run raised an unhandled exception")


def _org_data_dir(organization_id: Optional[str]) -> Path:
    """Return the data directory root for a given organization_id.

    None/"" returns _DATA_DIR unchanged — identical to today's single-tenant
    paths. A truthy organization_id returns an isolated per-org subdirectory
    under _DATA_DIR/orgs/, created on demand.
    """
    if not organization_id:
        return _DATA_DIR

    if not _ORG_ID_PATTERN.match(organization_id):
        raise ValueError(
            f"Invalid organization_id: {organization_id!r}. Must contain only "
            "letters, digits, hyphens, or underscores (e.g. a Rapid7 customer UUID)."
        )

    orgs_root = (_DATA_DIR / "orgs").resolve()
    org_dir = (orgs_root / organization_id).resolve()
    # Containment check, same idea as the ALLOWED_ROOT check in load_rapid7_parquet.
    org_dir.relative_to(orgs_root)
    org_dir.mkdir(parents=True, exist_ok=True)
    return org_dir


def _db_path(organization_id: str = "") -> str:
    """Database file path for one organization."""
    if not organization_id and _default_db_path_override:
        return _default_db_path_override
    return str(_org_data_dir(organization_id) / "rapid7_bulk_export.db")


def _get_db(organization_id: str = "") -> VulnerabilityDatabase:
    """Lazily get or create the VulnerabilityDatabase for one organization."""
    key = organization_id or DEFAULT_ORG_ID
    if key not in _db_instances:
        _db_instances[key] = VulnerabilityDatabase(_db_path(organization_id))
    return _db_instances[key]


def _tracker(organization_id: str = "") -> ExportTracker:
    """Open a tracker handle on the given tenant's tracking database."""
    return ExportTracker(str(_org_data_dir(organization_id) / "rapid7_bulk_export_tracking.db"))


@mcp.tool(
    annotations=ToolAnnotations(
        title="Load Rapid7 Parquet File",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def load_rapid7_parquet(parquet_path: str, organization_id: str = "") -> str:
    """Load vulnerability data from existing Parquet file(s).

    Use this if you already have Parquet files downloaded and want to skip
    the export process. This is much faster than running a full export.

    Args:
        parquet_path: Path to a Parquet file or directory containing Parquet files
        organization_id: Optional Rapid7 customer/tenant org ID. When provided,
            loads into that tenant's isolated cache under
            DATA_DIR/orgs/<organization_id>/ instead of the default store.

    Returns:
        Summary of loaded data including row count and statistics.
    """
    try:
        ALLOWED_ROOT = (_org_data_dir(organization_id) / "imports").resolve()

        # Resolve and validate path is within allowed root
        resolved = Path(parquet_path).resolve()
        try:
            resolved.relative_to(ALLOWED_ROOT)
        except ValueError:
            return (
                f"✗ Error: Path must be within {ALLOWED_ROOT}\n"
                f"Resolved path '{resolved}' is outside the allowed directory.\n"
                f"Please copy your Parquet files into {ALLOWED_ROOT} first."
            )

        # Check if path exists
        if not resolved.exists():
            return f"✗ Error: Path does not exist: {resolved}"

        # Get list of parquet files
        if resolved.is_file():
            parquet_files = [str(resolved)]
        else:
            parquet_files = glob.glob(str(resolved / "*.parquet"))

        if not parquet_files:
            return f"✗ Error: No Parquet files found at: {resolved}"

        if not _get_db_lock(organization_id).acquire(blocking=False):
            return (
                "⏳ A background download/load is currently in progress for this "
                "tenant. Try again shortly, or check "
                "check_rapid7_export_status(export_id=..., organization_id=...) for progress."
            )
        try:
            db = _get_db(organization_id)

            # Detect file types by peeking at schema and build prefix map
            prefix_file_map: dict = {}
            for pf in parquet_files:
                try:
                    cols = [
                        desc[0]
                        for desc in _duckdb.execute(
                            f"SELECT * FROM read_parquet('{pf}') LIMIT 0"  # nosec B608
                        ).description
                    ]
                    if "vulnId" in cols or "checkId" in cols:
                        prefix_file_map.setdefault("asset_vulnerability", []).append(pf)
                    else:
                        prefix_file_map.setdefault("asset", []).append(pf)
                except Exception:
                    # If we can't determine type, skip the file
                    continue

            if not prefix_file_map:
                return f"✗ Error: Could not determine schema for any Parquet files at: {resolved}"

            # Load into database
            row_counts = db.load_parquet_files_by_prefix(prefix_file_map)
            row_count = sum(row_counts.values())
            if getattr(db, "last_load_refused_tables", []):
                return (
                    "✗ Some tables could not be loaded; their previously loaded data was kept unchanged.\n\n"
                    + "\n".join(f"  {w}" for w in db.last_load_warnings)
                    + f"\n\nRows loaded into other tables: {json.dumps(row_counts)}"
                )

            # Get statistics
            stats = db.get_stats()
        finally:
            _get_db_lock(organization_id).release()

        return (
            f"✓ Successfully loaded {row_count} rows from {len(parquet_files)} file(s).\n\n"
            f"Per-table row counts: {json.dumps(row_counts, default=str)}\n\n"
            f"Statistics:\n{json.dumps(stats, indent=2, default=str)}\n\n"
            f"You can now query the data using query_rapid7, get_rapid7_schema, or get_rapid7_stats tools."
        )

    except Exception as e:
        return f"✗ Error loading Parquet files: {str(e)}"


@mcp.tool(
    annotations=ToolAnnotations(
        title="Start Rapid7 Export",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    )
)
def start_rapid7_export(
    export_type: str = "vulnerability",
    start_date: str = "",
    end_date: str = "",
    organization_id: str = "",
) -> str:
    """Start a new Rapid7 export job (non-blocking).

    This is a fast, non-blocking call that creates an export job on the
    Rapid7 platform and returns the export ID immediately. The export
    will process in the background on Rapid7's servers (typically 3-5
    minutes).

    Use check_rapid7_export_status(export_id) to monitor progress, then
    download_rapid7_export(export_id, export_type="...") once it completes.

    If an export from today already exists, returns that export's ID
    instead of creating a duplicate.

    For remediation exports, the Rapid7 API limits each request to 31 days.
    If the date range exceeds 31 days, this tool automatically splits it
    into multiple 31-day chunks and kicks off an export for each chunk.

    Args:
        export_type: Type of export to create. One of "vulnerability",
                     "policy", or "remediation".
        start_date: Start date in YYYY-MM-DD format (only for remediation exports).
                    Defaults to 30 days ago if not specified.
        end_date: End date in YYYY-MM-DD format (only for remediation exports).
                  Defaults to today if not specified.
        organization_id: Optional Rapid7 customer/tenant org ID. When provided,
            uses the Multi-Tenant API key (RAPID7_MULTI_TENANT_API_KEY) and
            sends R7-Organization-Id to scope this export to that tenant, and
            caches it under DATA_DIR/orgs/<organization_id>/ separately from
            other tenants. Omit for the default single-tenant behavior.

    Returns:
        The export ID and next steps.
    """
    if export_type not in VALID_EXPORT_TYPES:
        return f"✗ Invalid export_type: '{export_type}'. Valid values are: {', '.join(VALID_EXPORT_TYPES)}"

    try:
        config = load_config(organization_id or None)
        org_key = organization_id or DEFAULT_ORG_ID

        tracker = ExportTracker(str(_org_data_dir(organization_id) / "rapid7_bulk_export_tracking.db"))

        # Return a cached export from today unless it's remediation (which is date-range keyed)
        today_export = tracker.get_today_export(export_type=export_type, organization_id=org_key)
        if today_export and export_type != "remediation":
            tracker.close()
            eid = today_export["export_id"]
            return (
                f"♻️ A {export_type} export from today already exists.\n\n"
                f"Export ID: {eid}\n"
                f"Status: COMPLETE\n"
                f"Created: {today_export['created_at']}\n"
                f"Rows: {today_export['row_count']}\n\n"
                f"Load it with: "
                f"download_rapid7_export("
                f'export_id="{eid}", '
                f'export_type="{export_type}")'
            )

        # Create the export based on type
        if export_type == "vulnerability":
            print("Creating new vulnerability export...", file=sys.stderr)
            new_id = create_vulnerability_export(config)
            print(f"Created {export_type} export with ID: {new_id}", file=sys.stderr)
            tracker.save_export(
                export_id=new_id, status="PENDING", parquet_urls=[], export_type=export_type, organization_id=org_key
            )
            tracker.close()

            return (
                f"✓ Vulnerability export job created.\n\n"
                f"Export ID: {new_id}\n"
                f"Status: PENDING\n\n"
                f"The export is now processing on Rapid7's servers "
                f"(typically 3-5 minutes).\n"
                f'Check progress: check_rapid7_export_status(export_id="{new_id}")\n'
                f"Once COMPLETE, load with: "
                f'download_rapid7_export(export_id="{new_id}", export_type="vulnerability")'
            )

        elif export_type == "policy":
            print("Creating new policy export...", file=sys.stderr)
            new_id = create_policy_export(config)
            print(f"Created {export_type} export with ID: {new_id}", file=sys.stderr)
            tracker.save_export(
                export_id=new_id, status="PENDING", parquet_urls=[], export_type=export_type, organization_id=org_key
            )
            tracker.close()

            return (
                f"✓ Policy export job created.\n\n"
                f"Export ID: {new_id}\n"
                f"Status: PENDING\n\n"
                f"The export is now processing on Rapid7's servers "
                f"(typically 3-5 minutes).\n"
                f'Check progress: check_rapid7_export_status(export_id="{new_id}")\n'
                f"Once COMPLETE, load with: "
                f'download_rapid7_export(export_id="{new_id}", export_type="policy")'
            )

        elif export_type == "remediation":
            if not start_date:
                start_date = (_dt.date.today() - _dt.timedelta(days=30)).isoformat()
            if not end_date:
                end_date = _dt.date.today().isoformat()

            # Idempotency: this MCP tool may be retried. A remediation job
            # appends its windows, so starting a second job for the SAME range
            # would double the rows. Reuse an existing job for the exact range —
            # report progress if it's still RUNNING, or its stored result if
            # COMPLETE — and only start a fresh job when none exists or the
            # prior one FAILED (an intended retry).
            existing = tracker.find_job_by_range("remediation", start_date, end_date)
            if existing is not None and existing.get("status") in (JOB_RUNNING, JOB_COMPLETE):
                tracker.close()
                jid = existing["job_id"]
                if existing["status"] == JOB_COMPLETE:
                    return (
                        f"♻️ Remediation data for {start_date} → {end_date} is already loaded "
                        f"(job {jid}). Not re-running (that would duplicate rows).\n\n"
                        f'See results with: check_rapid7_export_status(export_id="{jid}")'
                    )
                return (
                    f"⏳ A remediation load for {start_date} → {end_date} is already in progress "
                    f"(job {jid}).\n\n"
                    f'Check progress with: check_rapid7_export_status(export_id="{jid}")'
                )

            # A remediation range may span multiple ≤31-day windows, and the
            # platform allows only one remediation export in flight at a time.
            # Hand the whole range to a single background job that creates,
            # polls, downloads, and loads each window sequentially and appends
            # them into vulnerability_remediation. The caller polls one job id.
            tracker.close()
            chunk_ranges = build_remediation_date_chunks(start_date, end_date)
            job_id = _start_remediation_job(start_date, end_date, organization_id)

            return (
                f"▶️ Started loading remediation data for {start_date} → {end_date} "
                f"in the background.\n\n"
                f"Job ID: {job_id}\n"
                f"Windows: {len(chunk_ranges)} (each ≤31 days, loaded sequentially)\n\n"
                f"The platform allows only one remediation export at a time, so windows "
                f"are processed one after another; this can take several minutes each.\n"
                f"All windows append into the same vulnerability_remediation table.\n\n"
                f"Check progress with: "
                f'check_rapid7_export_status(export_id="{job_id}")'
            )

        elif export_type == "asset_software":
            new_id = create_asset_software_export(config)
            print(f"Created asset_software export with ID: {new_id}", file=sys.stderr)
            tracker.save_export(
                export_id=new_id,
                status="PENDING",
                parquet_urls=[],
                export_type="asset_software",
                organization_id=org_key,
            )
            tracker.close()

            return (
                f"✓ Asset software export job created.\n\n"
                f"Export ID: {new_id}\n"
                f"Status: PENDING\n\n"
                f"The export is now processing on Rapid7's servers "
                f"(typically 3-5 minutes).\n"
                f'Check progress: check_rapid7_export_status(export_id="{new_id}")\n'
                f"Once COMPLETE, load with: "
                f'download_rapid7_export(export_id="{new_id}", export_type="asset_software")'
            )

    except Exception as e:
        return f"✗ Error starting {export_type} export: {str(e)}"


@mcp.tool(
    annotations=ToolAnnotations(
        title="Check Rapid7 Export Status",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    )
)
def check_rapid7_export_status(export_id: str, organization_id: str = "") -> str:
    """Check the status of a Rapid7 export, including local download/load progress.

    Fast, non-blocking call. Reports whichever stage the export is in:

      - While this server is downloading or loading the export in the
        background, reports that local phase and per-file progress — and
        skips the Rapid7 API call, since the platform-side export is
        already known to be complete.
      - Once loaded (COMPLETE) or failed (FAILED) locally, returns the
        stored summary/error so no work is repeated.
      - Otherwise queries the Rapid7 API once for the platform-side export
        status (PENDING/PROCESSING/COMPLETE/FAILED).

    Because local phase lives in the durable tracker, it is inspectable after
    a server restart (interrupted work is reconciled to a retryable FAILED at
    startup rather than resumed). Does NOT poll or wait.

    Args:
        export_id: The export ID returned by start_rapid7_export, or a
            job ID returned by a multi-window remediation load.
        organization_id: Optional Rapid7 customer/tenant org ID — pass the
            same value used in start_rapid7_export for this export, if any.

    Returns:
        Current export/load status and next steps.
    """
    try:
        # A multi-window remediation load is tracked as a job spanning N export
        # IDs; if the id names a job, report the job's progress.
        tracker = _tracker(organization_id)
        job = tracker.get_job(export_id)
        if job is not None:
            tracker.close()
            return _format_job_status(job)

        # Local load phase takes precedence: if a background download/load is
        # active or has reached a terminal state, report that and skip the
        # (now-redundant) platform-side status call.
        local = tracker.get_export_by_id(export_id)
        tracker.close()

        if local is not None:
            local_status = local.get("status")

            if local_status == PHASE_COMPLETE:
                return local.get("message") or (
                    f"✓ Data loaded and queryable.\n\nExport ID: {export_id}\nRows: {local.get('row_count')}"
                )
            if local_status == PHASE_FAILED:
                return local.get("message") or f"✗ Download/load failed.\n\nExport ID: {export_id}"
            if local_status in _ACTIVE_PHASES:
                detail = local.get("phase_detail")
                detail_line = f"\n{detail}" if detail else ""
                return (
                    f"⏳ Downloading/loading in progress locally ({local_status}).{detail_line}\n\n"
                    f"Export ID: {export_id}\n"
                    f"Last update: {local.get('updated_at') or local.get('created_at', 'unknown')}\n\n"
                    f"Check again in 30-60 seconds with: "
                    f'check_rapid7_export_status(export_id="{export_id}")'
                )
            # PENDING or any other value falls through to the platform-side check.

        config = load_config(organization_id or None)
        status_info = get_export_status(config, export_id)
        current_status = status_info["status"]
        file_count = len(status_info.get("parquetFiles", []))

        if current_status in ["COMPLETE", "SUCCEEDED"]:
            return (
                f"✓ Export is complete on Rapid7's side and ready to download.\n\n"
                f"Export ID: {export_id}\n"
                f"Status: {current_status}\n"
                f"Files ready: {file_count}\n\n"
                f"Load the data with: "
                f"download_rapid7_export("
                f'export_id="{export_id}", '
                f'export_type="...")'
            )
        elif current_status == "FAILED":
            return (
                f"✗ Export failed.\n\n"
                f"Export ID: {export_id}\n"
                f"Status: FAILED\n\n"
                f"Start a new export with: start_rapid7_export()"
            )
        else:
            return (
                f"⏳ Export still processing.\n\n"
                f"Export ID: {export_id}\n"
                f"Status: {current_status}\n\n"
                f"Check again in 30-60 seconds with: "
                f"check_rapid7_export_status("
                f'export_id="{export_id}")'
            )

    except Exception as e:
        return f"✗ Error checking export status: {str(e)}"


def _download_and_load_files(
    export_type: str,
    status_info: dict,
    api_key: str,
    organization_id: str = "",
    on_downloaded=None,
    request_organization_id: Optional[str] = None,
) -> tuple:
    """Download an export's parquet files and load them into DuckDB.

    Shared by the single-export worker and the multi-chunk remediation
    orchestrator so the download/route/load path is not forked. Acquires
    the given tenant's db lock around the load. If provided, on_downloaded()
    is called once the files are actually downloaded and before the load
    begins, so a caller can record the LOADING phase honestly. Returns
    (row_count, row_counts, stats, validation_warnings).

    organization_id selects the tenant's db; request_organization_id is the
    R7-Organization-Id header to send (load_config's "organization_id",
    which is "" for a per-org key from RAPID7_ORG_API_KEYS). Defaults to
    organization_id.
    """
    if request_organization_id is None:
        request_organization_id = organization_id
    parquet_urls = status_info["parquetFiles"]
    file_data = download_all_files(parquet_urls, api_key, organization_id=request_organization_id or None)
    if on_downloaded is not None:
        on_downloaded()

    temp_dir = tempfile.mkdtemp()
    validation_warnings: list = []
    try:
        with _get_db_lock(organization_id):
            db = _get_db(organization_id)

            result_list = status_info.get("result") or []
            url_to_prefix = {}
            for item in result_list:
                prefix = item.get("prefix", "")
                for url in item.get("urls", []):
                    url_to_prefix[url] = prefix

            prefix_file_map: dict = {}
            for i, (url, data) in enumerate(zip(parquet_urls, file_data)):
                temp_path = Path(temp_dir) / f"{export_type}_export_{i}.parquet"
                temp_path.write_bytes(data)
                prefix = url_to_prefix.get(url, "unknown")
                prefix_file_map.setdefault(prefix, []).append(str(temp_path))
                if len(data) < 100:
                    validation_warnings.append(f"File {i + 1} (prefix={prefix}): unusually small ({len(data)} bytes)")

            if export_type == "policy":
                row_counts = db.load_parquet_files_by_prefix(prefix_file_map, skip_prefixes={"asset"})
            elif export_type == "remediation":
                row_counts = db.load_parquet_files_by_prefix(prefix_file_map, append=True)
            else:
                row_counts = db.load_parquet_files_by_prefix(prefix_file_map)

            row_count = sum(row_counts.values())
            refused = getattr(db, "last_load_refused_tables", [])
            if refused:
                # Existing data was kept, but this export did NOT load. Raise so the
                # caller records FAILED rather than COMPLETE -- a COMPLETE row would
                # make today's start_rapid7_export reuse this broken export and the
                # nightly sync skip the type as "already synced today".
                raise RuntimeError(
                    f"{export_type} export did not load table(s) {', '.join(refused)}; "
                    f"previously loaded data for them was kept unchanged. "
                    f"Prefixes received: {list(prefix_file_map.keys())}. Details: " + "; ".join(db.last_load_warnings)
                )
            validation_warnings.extend(getattr(db, "last_load_warnings", []))
            if row_count == 0 and len(file_data) > 0:
                validation_warnings.append(
                    f"⚠️  {len(file_data)} file(s) downloaded but 0 rows loaded. "
                    f"Prefixes received: {list(prefix_file_map.keys())}. "
                    f"Check that prefixes match expected routing."
                )

            stats = db.get_stats()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return row_count, row_counts, stats, validation_warnings


def _run_download_and_load(export_id: str, export_type: str, organization_id: str = "") -> None:
    """Background worker: download parquet files and load them into DuckDB.

    Runs in its own thread. All progress/results are written to the
    ExportTracker row for this export_id rather than returned, since
    nothing is waiting on a function return here. Any exception is caught
    and recorded as a FAILED phase (with the error text) so the status
    tools can report it, instead of the process crashing on a late/
    duplicate response the way the synchronous version could when a client
    had already timed out and cancelled the request.
    """
    tracker = _tracker(organization_id)
    try:
        config = load_config(organization_id or None)
        status_info = get_export_status(config, export_id)
        parquet_urls = status_info["parquetFiles"]

        tracker.set_phase(
            export_id,
            PHASE_DOWNLOADING,
            phase_detail=f"downloading {len(parquet_urls)} file(s)",
        )
        print(f"Downloading {len(parquet_urls)} {export_type} files...", file=sys.stderr)

        def _mark_loading() -> None:
            tracker.set_phase(
                export_id,
                PHASE_LOADING,
                phase_detail=f"{len(parquet_urls)} file(s) downloaded, loading into database",
            )

        row_count, row_counts, stats, validation_warnings = _download_and_load_files(
            export_type,
            status_info,
            config["api_key"],
            organization_id=organization_id,
            on_downloaded=_mark_loading,
            request_organization_id=config.get("organization_id", organization_id),
        )
        row_info = f"Rows loaded: {row_count}\nPer-table row counts: {json.dumps(row_counts, default=str)}"

        warnings_section = ""
        if validation_warnings:
            warnings_section = "\nValidation Warnings:\n" + "\n".join(f"  {w}" for w in validation_warnings) + "\n"

        message = (
            f"✓ {export_type.capitalize()} data loaded successfully.\n\n"
            f"Export ID: {export_id}\n"
            f"Files processed: {len(parquet_urls)}\n"
            f"{row_info}\n"
            f"{warnings_section}\n"
            f"Statistics:\n"
            f"{json.dumps(stats, indent=2, default=str)}\n\n"
            f"Query the data with query_rapid7, get_rapid7_schema, or get_rapid7_stats."
        )
        # Record the completed load with its parquet URLs and final row count.
        tracker.save_export(
            export_id=export_id,
            status=PHASE_COMPLETE,
            parquet_urls=parquet_urls,
            row_count=row_count,
            export_type=export_type,
            organization_id=organization_id or DEFAULT_ORG_ID,
        )
        tracker.set_phase(export_id, PHASE_COMPLETE, phase_detail=None, message=message, row_count=row_count)

    except Exception as e:
        error_text = f"{e}\n{traceback.format_exc()}"
        message = (
            f"✗ Error downloading/loading {export_type}: {str(e)}\n\n"
            f"Export ID: {export_id}\n"
            f"Retry with: download_rapid7_export("
            f'export_id="{export_id}", '
            f'export_type="{export_type}")\n\n'
            f"{error_text}"
        )
        tracker.set_phase(export_id, PHASE_FAILED, phase_detail=None, message=message)
    finally:
        tracker.close()


def _create_remediation_chunk_waiting(config: dict, chunk_start: str, chunk_end: str) -> str:
    """Create one remediation chunk, waiting out any foreign in-flight export.

    The platform permits only one remediation export in flight at a time. If
    another is running (this job's previous chunk, or an unrelated export),
    create is rejected with ExportInProgressError. We must NOT adopt that
    foreign id — it may cover a different date range — so we back off and
    recreate THIS chunk's own range until the platform frees up.
    """
    deadline = time.monotonic() + _IN_PROGRESS_MAX_WAIT_SECS
    while True:
        try:
            return create_remediation_export(config, chunk_start, chunk_end)
        except ExportInProgressError:
            if time.monotonic() >= deadline:
                raise
            print(
                f"Remediation export slot busy; waiting to create {chunk_start} → {chunk_end}...",
                file=sys.stderr,
            )
            time.sleep(_IN_PROGRESS_RETRY_SECS)


def _run_remediation_job(job_id: str, chunks: list, organization_id: str = "") -> None:
    """Background worker: load a multi-window remediation range as one job.

    Processes each ≤31-day window strictly sequentially (create → poll →
    download → load append), because the platform serialises remediation
    exports anyway. Per-chunk outcome is persisted on the export_jobs row so a
    partial failure names exactly which windows loaded and which did not.
    """
    tracker = _tracker(organization_id)
    try:
        config = load_config(organization_id or None)
        total = len(chunks)
        total_rows = 0

        for i, chunk in enumerate(chunks):
            cs, ce = chunk["start"], chunk["end"]
            window = f"{cs} → {ce}"

            def _mark(state: str) -> None:
                chunks[i]["status"] = state
                tracker.update_job(
                    job_id,
                    current_index=i,
                    chunks=chunks,
                    message=f"chunk {i + 1}/{total} ({window}), {state}",
                )

            _mark("creating")
            eid = _create_remediation_chunk_waiting(config, cs, ce)
            chunks[i]["export_id"] = eid

            _mark("waiting for export")
            parquet_urls = poll_until_complete(config, eid)
            status_info = get_export_status(config, eid)
            if not parquet_urls:
                status_info["parquetFiles"] = status_info.get("parquetFiles", [])

            row_count, _, _, _ = _download_and_load_files(
                "remediation",
                status_info,
                config["api_key"],
                organization_id=organization_id,
                on_downloaded=lambda: _mark("loading"),
                request_organization_id=config.get("organization_id", organization_id),
            )
            # Mark loaded the instant the append has committed, BEFORE any
            # further tracker writes. If save_export below throws, the window
            # is already recorded loaded so the failure report can never tell
            # the user to re-run a window whose rows are already present.
            total_rows += row_count
            chunks[i]["row_count"] = row_count
            _mark("loaded")
            tracker.save_export(
                export_id=eid,
                status=PHASE_COMPLETE,
                parquet_urls=parquet_urls,
                row_count=row_count,
                export_type="remediation",
                organization_id=organization_id or DEFAULT_ORG_ID,
            )

        loaded = [f"{c['start']} → {c['end']} ({c.get('row_count', 0)} rows)" for c in chunks]
        message = (
            f"✓ Remediation data loaded for all {total} window(s).\n\n"
            f"Total rows: {total_rows}\n"
            f"Windows loaded:\n" + "\n".join(f"  {w}" for w in loaded) + "\n\n"
            "Query the data with query_rapid7, get_rapid7_schema, or get_rapid7_stats."
        )
        tracker.update_job(job_id, status=JOB_COMPLETE, current_index=total - 1, chunks=chunks, message=message)

    except Exception as e:
        error_text = f"{e}\n{traceback.format_exc()}"
        loaded = [f"{c['start']} → {c['end']}" for c in chunks if c.get("status") == "loaded"]
        missing = [f"{c['start']} → {c['end']}" for c in chunks if c.get("status") != "loaded"]
        message = (
            f"✗ Remediation load failed partway through.\n\n"
            f"Loaded windows (kept): {', '.join(loaded) or 'none'}\n"
            f"Missing windows: {', '.join(missing) or 'none'}\n\n"
            f"Re-run only the missing range with start_rapid7_export("
            f'export_type="remediation", start_date="...", end_date="...").\n\n'
            f"{error_text}"
        )
        tracker.update_job(job_id, status=JOB_FAILED, chunks=chunks, message=message)
    finally:
        tracker.close()


def _start_remediation_job(start_date: str, end_date: str, organization_id: str = "") -> str:
    """Create and launch a multi-window remediation load job. Returns the job_id."""
    chunk_ranges = build_remediation_date_chunks(start_date, end_date)
    chunks = [{"start": cs, "end": ce, "export_id": None, "status": "pending"} for cs, ce in chunk_ranges]

    job_id = f"remediation-{uuid.uuid4().hex[:12]}"
    tracker = _tracker(organization_id)
    tracker.create_job(
        job_id=job_id,
        export_type="remediation",
        start_date=start_date,
        end_date=end_date,
        chunks=chunks,
        status=JOB_RUNNING,
    )
    tracker.close()

    thread = threading.Thread(target=_run_remediation_job, args=(job_id, chunks, organization_id), daemon=True)
    thread.start()
    return job_id


def _format_job_status(job: dict) -> str:
    """Render an export_jobs row for check_rapid7_export_status."""
    status = job.get("status")
    if status == JOB_COMPLETE:
        return job.get("message") or f"✓ Remediation job {job['job_id']} complete."
    if status == JOB_FAILED:
        return job.get("message") or f"✗ Remediation job {job['job_id']} failed."

    total = len(job.get("chunks") or [])
    return (
        f"⏳ Remediation load in progress.\n\n"
        f"Job ID: {job['job_id']}\n"
        f"Range: {job.get('start_date')} → {job.get('end_date')} ({total} window(s))\n"
        f"{job.get('message', '')}\n\n"
        f"Check again in 30-60 seconds with: "
        f'check_rapid7_export_status(export_id="{job["job_id"]}")'
    )


@mcp.tool(
    annotations=ToolAnnotations(
        title="Download Rapid7 Export",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    )
)
def download_rapid7_export(export_id: str, export_type: str = "vulnerability", organization_id: str = "") -> str:
    """Start downloading a completed Rapid7 export and loading it into the database.

    Call this after check_rapid7_export_status confirms the export is COMPLETE.
    This kicks off the download and load in the background and returns
    immediately — large exports (potentially millions of rows) can take
    several minutes to load, longer than most MCP clients will wait on a
    single tool call. Poll progress with check_rapid7_export_status(export_id).

    Args:
        export_id: The export ID of a completed export.
        export_type: Type of export. One of "vulnerability", "policy",
                     "remediation", or "asset_software".
        organization_id: Optional Rapid7 customer/tenant org ID — pass the
            same value used in start_rapid7_export for this export, if any.
            Loads into that tenant's isolated cache under
            DATA_DIR/orgs/<organization_id>/.

    Returns:
        Confirmation that the background job has started, plus how to
        check on it.
    """
    if export_type not in VALID_EXPORT_TYPES:
        return f"✗ Invalid export_type: '{export_type}'. Valid values are: {', '.join(VALID_EXPORT_TYPES)}"

    try:
        config = load_config(organization_id or None)

        # Quick call — just confirms the export is ready, doesn't download anything.
        status_info = get_export_status(config, export_id)
        current_status = status_info["status"]

        if current_status not in ["COMPLETE", "SUCCEEDED"]:
            return (
                f"✗ Export is not yet complete.\n\n"
                f"Export ID: {export_id}\n"
                f"Status: {current_status}\n\n"
                f"Check again with: "
                f"check_rapid7_export_status("
                f'export_id="{export_id}")'
            )

        if not status_info["parquetFiles"]:
            return f"✗ Export complete but has no files.\n\nExport ID: {export_id}"

        # Don't start a second job for the same export if one's already running.
        tracker = _tracker(organization_id)
        existing = tracker.get_export_by_id(export_id)
        if existing is not None and existing.get("status") in _ACTIVE_PHASES:
            tracker.close()
            return (
                f"⏳ A download for this export is already in progress "
                f"(status: {existing['status']}).\n\n"
                f"Export ID: {export_id}\n"
                f'Check progress with: check_rapid7_export_status(export_id="{export_id}")'
            )

        # Record the initial phase durably. The row usually already exists at
        # PENDING (start_rapid7_export inserts it); save_export upserts so a
        # directly-supplied export_id is tracked too.
        parquet_urls = status_info["parquetFiles"]
        tracker.save_export(
            export_id=export_id,
            status=PHASE_DOWNLOADING,
            parquet_urls=parquet_urls,
            export_type=export_type,
            organization_id=organization_id or DEFAULT_ORG_ID,
        )
        tracker.set_phase(
            export_id,
            PHASE_DOWNLOADING,
            phase_detail=f"queued: {len(parquet_urls)} file(s) to download",
        )
        tracker.close()

        thread = threading.Thread(
            target=_run_download_and_load,
            args=(export_id, export_type, organization_id),
            daemon=True,
        )
        thread.start()

        return (
            f"▶️ Started downloading and loading {export_type} export in the background.\n\n"
            f"Export ID: {export_id}\n"
            f"Files: {len(parquet_urls)}\n\n"
            f"This can take several minutes for large exports. Check progress with:\n"
            f'check_rapid7_export_status(export_id="{export_id}")'
        )

    except Exception as e:
        return (
            f"✗ Error starting download for {export_type}: {str(e)}\n\n"
            f"Export ID: {export_id}\n"
            f"Retry with: download_rapid7_export("
            f'export_id="{export_id}", '
            f'export_type="{export_type}")'
        )


@mcp.tool(
    annotations=ToolAnnotations(
        title="Query Rapid7 Data",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def query_rapid7(sql: str, organization_id: str = "") -> str:
    """Execute a SQL query against the Rapid7 database.

    The database contains the following tables loaded from Rapid7 InsightVM
    Bulk Export API Parquet files:

    **assets** — Asset inventory data:
      Key fields: orgId, assetId, agentId, hostName, ip, mac, osFamily,
      osProduct, osVersion, osDescription, riskScore, sites, assetGroups, tags,
      awsInstanceId, azureResourceId, gcpObjectId

    **vulnerabilities** — Combined asset + vulnerability data:
      Key fields: orgId, assetId, vulnId, checkId, port, protocol, title,
      description, severity, severityRank, cvssScore, cvssV3Score,
      cvssV3Severity, hasExploits, epssscore, epsspercentile, riskScoreV2_0,
      cves, firstFoundTimestamp, reintroducedTimestamp, dateAdded,
      dateModified, datePublished, pciCompliant, pciSeverity

    **vulnerability_exceptions** — Vulnerability exceptions (waived/accepted risk):
      Key fields: orgId, assetId, vulnId, checkId, key, port, protocol,
      nic, proof, firstFoundTimestamp, reintroducedTimestamp, exceptionDetails

    **policies** — Policy compliance results (agent and scan based):
      Key fields: orgId, assetId, benchmarkNaturalId, profileNaturalId,
      benchmarkVersion, ruleNaturalId, ruleTitle, finalStatus, proof,
      lastAssessmentTimestamp, benchmarkTitle, profileTitle, publisher,
      fixTexts, rationales, source ('agent' or 'scan')

    **vulnerability_remediation** — Vulnerability remediation tracking:
      Key fields: orgId, assetId, cveId, vulnId, proof, firstFoundTimestamp,
      reintroducedTimestamp, lastDetected, lastRemoved, title, description,
      cvssV2Score, cvssV3Score, cvssV2Severity, cvssV3Severity,
      cvssV2AttackVector, cvssV3AttackVector, riskScoreV2_0, datePublished,
      dateAdded, dateModified, epssscore, epsspercentile

    Use this tool to query any of the above tables. You can filter, aggregate,
    join across tables, or perform any SQL-based analysis supported by DuckDB.

    Examples:
    - SELECT * FROM vulnerabilities WHERE severity = 'Critical' LIMIT 10
    - SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity
    - SELECT * FROM policies WHERE finalStatus = 'fail' LIMIT 10
    - SELECT cveId, COUNT(*) FROM vulnerability_remediation GROUP BY cveId

    Note: the `orgId` column above is Rapid7's own per-row tenant field,
    distinct from the `organization_id` parameter this tool accepts — after
    switching tenants via organization_id, `SELECT DISTINCT orgId FROM
    assets` is a good sanity check that you're looking at the expected
    tenant's data.

    Args:
        sql: SQL query to execute against the database
        organization_id: Optional Rapid7 customer/tenant org ID. When
            provided, queries that tenant's isolated cache instead of the
            default store.

    Returns:
        Query results as formatted JSON
    """
    db = _get_db(organization_id)

    # Acquire this tenant's lock BEFORE touching db at all — has_data() opens
    # its own DuckDB connection, which conflicts with a background load's
    # read-write connection. Locking first turns that into a clean busy
    # response, and never blocks an unrelated tenant's query.
    if not _get_db_lock(organization_id).acquire(blocking=False):
        return (
            "⏳ A background download/load is currently in progress for this "
            "tenant, so the database can't be safely queried right now. Try "
            "again shortly, or check "
            "check_rapid7_export_status(export_id=..., organization_id=...) for progress."
        )
    try:
        if not db.has_data():
            return "Error: No data loaded. Please run start_rapid7_export and download_rapid7_export first."
        results = db.query(sql)
        result_text = json.dumps(results, indent=2, default=str)
        return f"Query executed successfully. {len(results)} rows returned.\n\n{result_text}"
    except Exception as e:
        return f"Error executing query: {str(e)}"
    finally:
        _get_db_lock(organization_id).release()


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Rapid7 Schema",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def get_rapid7_schema(organization_id: str = "") -> str:
    """Get the schema of all database tables.

    Returns column names and data types for all existing tables:
    assets, vulnerabilities, policies, and vulnerability_remediation.
    Tables that have not been loaded yet are omitted.

    Use this to understand what data is available before writing queries.

    Args:
        organization_id: Optional Rapid7 customer/tenant org ID. When
            provided, inspects that tenant's isolated cache instead of the
            default store.

    Returns:
        Table schemas as formatted JSON, keyed by table name
    """
    db = _get_db(organization_id)

    if not _get_db_lock(organization_id).acquire(blocking=False):
        return (
            "⏳ A background download/load is currently in progress for this "
            "tenant, so the schema can't be safely read right now. Try again "
            "shortly, or check "
            "check_rapid7_export_status(export_id=..., organization_id=...) for progress."
        )
    try:
        if not db.has_data():
            return "Error: No data loaded. Please run start_rapid7_export and download_rapid7_export first."
        schema = db.get_schema()
        schema_text = json.dumps(schema, indent=2)
        return f"Database schema:\n\n{schema_text}"
    except Exception as e:
        return f"Error getting schema: {str(e)}"
    finally:
        _get_db_lock(organization_id).release()


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Rapid7 Statistics",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def get_rapid7_stats(organization_id: str = "") -> str:
    """Get summary statistics for all database tables.

    Returns row counts and relevant distributions for all existing tables:
    assets, vulnerabilities, policies, and vulnerability_remediation.
    Tables that have not been loaded yet are omitted.

    Useful for getting an overview of the data across all loaded datasets.

    Args:
        organization_id: Optional Rapid7 customer/tenant org ID. When
            provided, summarizes that tenant's isolated cache instead of the
            default store.

    Returns:
        Summary statistics as formatted JSON, keyed by table name
    """
    db = _get_db(organization_id)

    if not _get_db_lock(organization_id).acquire(blocking=False):
        return (
            "⏳ A background download/load is currently in progress for this "
            "tenant, so statistics can't be safely read right now. Try again "
            "shortly, or check "
            "check_rapid7_export_status(export_id=..., organization_id=...) for progress."
        )
    try:
        if not db.has_data():
            return "Error: No data loaded. Please run start_rapid7_export and download_rapid7_export first."
        stats = db.get_stats()
        stats_text = json.dumps(stats, indent=2, default=str)
        return f"Database statistics:\n\n{stats_text}"
    except Exception as e:
        return f"Error getting statistics: {str(e)}"
    finally:
        _get_db_lock(organization_id).release()


@mcp.tool(
    annotations=ToolAnnotations(
        title="Purge Rapid7 Data",
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def purge_rapid7_data(organization_id: str = "") -> str:
    """Permanently delete local Rapid7 data and tracking databases for one tenant.

    This removes:
    - The main vulnerability database (rapid7_bulk_export.db)
    - The export tracking database (rapid7_bulk_export_tracking.db)
    - Any associated WAL files

    Only purges the given organization_id's cache (or the default/unscoped
    store if omitted) — other tenants' data under orgs/<other_id>/ is
    untouched.

    Use this when you are done with your analysis session, before handing
    off a machine, or to free disk space. After purging, you will need to
    run a new export to query data again.

    Args:
        organization_id: Optional Rapid7 customer/tenant org ID identifying
            which tenant's cache to purge. Omit to purge only the default
            (unscoped) store.

    Returns:
        Confirmation of purged data.
    """
    # Refuse to purge while a background load holds this tenant's database —
    # dropping the file mid-load would corrupt the in-flight load and leave
    # stale tracker rows. Non-blocking to match the read tools, and scoped to
    # this tenant's own lock so purging one tenant never blocks on another's
    # in-flight load.
    if not _get_db_lock(organization_id).acquire(blocking=False):
        return (
            "⏳ A background download/load is currently in progress for this "
            "tenant, so the database can't be purged right now. Try again once "
            "it finishes (check_rapid7_export_status(export_id=..., "
            "organization_id=...) shows progress)."
        )
    try:
        # Even with the lock, a job can be between windows (downloading/polling)
        # while the lock is momentarily free. Refuse if any durable export or
        # job is still active for this tenant, so a purge can't delete data a
        # worker will then repopulate under a deleted tracker row.
        active_tracker = _tracker(organization_id)
        try:
            if active_tracker.has_active_work(
                active_export_statuses=list(_ACTIVE_PHASES),
                active_job_statuses=[JOB_RUNNING],
            ):
                return (
                    "⏳ A background download/load or multi-window remediation job "
                    "is still active for this tenant, so the database can't be "
                    "purged right now. Wait until check_rapid7_export_status("
                    "export_id=..., organization_id=...) reports it finished, then purge."
                )
        finally:
            active_tracker.close()

        # Purge main database
        db = _get_db(organization_id)
        db.purge()

        # Purge tracking database (also clears all export/phase rows)
        tracker = _tracker(organization_id)
        tracker.purge()

        scope = f"organization_id={organization_id}" if organization_id else "the default (unscoped) store"
        return (
            f"✓ Local Rapid7 data has been purged for {scope}.\n\n"
            "Deleted:\n"
            "  - Vulnerability database (rapid7_bulk_export.db)\n"
            "  - Export tracking database (rapid7_bulk_export_tracking.db)\n\n"
            "Other tenants' caches (if any) were not affected.\n\n"
            "To load new data, run start_rapid7_export() followed by download_rapid7_export()."
        )

    except Exception as e:
        return f"✗ Error purging data: {str(e)}"
    finally:
        _get_db_lock(organization_id).release()


@mcp.tool(
    annotations=ToolAnnotations(
        title="List Rapid7 Exports",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def list_rapid7_exports(limit: int = 10, organization_id: str = "") -> str:
    """List recent Rapid7 exports tracked in the system.

    Shows export metadata including export ID, date, status, type, and row counts.
    Useful for understanding what exports are available for reuse.

    Args:
        limit: Maximum number of exports to return (default: 10)
        organization_id: Optional Rapid7 customer/tenant org ID. When
            provided, lists that tenant's tracked exports instead of the
            default store's.

    Returns:
        Formatted list of recent exports
    """
    try:
        # Reads only the local tracker DB (not the shared query database), so
        # it needs no db lock guard and is safe to call during a load — that
        # is in fact how you watch a background load progress.
        tracker = _tracker(organization_id)
        exports = tracker.list_exports(limit=limit, organization_id=organization_id or DEFAULT_ORG_ID)
        tracker.close()

        if not exports:
            return "No exports found in the tracker database."

        result = f"Recent Exports (showing up to {limit}):\n\n"
        for exp in exports:
            result += f"Export ID: {exp['export_id']}\n"
            result += f"  Type: {exp.get('export_type', 'vulnerability')}\n"
            result += f"  Date: {exp['export_date']}\n"
            result += f"  Created: {exp['created_at']}\n"
            result += f"  Status: {exp['status']}\n"
            if exp.get("phase_detail"):
                result += f"  Progress: {exp['phase_detail']}\n"
            result += f"  Files: {exp['file_count']}\n"
            result += f"  Rows: {exp['row_count']}\n\n"

        return result

    except Exception as e:
        return f"✗ Error listing exports: {str(e)}"


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Organization IDs",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    )
)
def get_organization_ids(region: str = "") -> str:
    """List Rapid7-managed organizations (tenants) available to this account.

    Calls the Rapid7 Insight Account API live (via your Multi-Tenant API
    key) and returns every managed organization's name, id, and region. All
    pages are fetched automatically.

    By default, results are filtered to your configured RAPID7_REGION —
    tenants in a different region can't currently be used with the other
    tools anyway (they all require RAPID7_REGION to match the target
    tenant's region). Pass region="all" to see every managed organization
    regardless of region, or pass a specific region code (e.g. "us") to see
    only that one.

    Use the id from this list as the organization_id argument on other
    tools (start_rapid7_export, query_rapid7, purge_rapid7_data, etc.) —
    match the tenant's name here to get its id, then reuse that id across
    subsequent tool calls.

    Requires RAPID7_MULTI_TENANT_API_KEY and RAPID7_PARENT_ORG_ID
    to be set in the server's environment. RAPID7_PARENT_ORG_ID is
    your own primary/parent account's organization id — not any managed
    tenant's id — since the Rapid7 API has no endpoint to look this up
    automatically.

    Args:
        region: Optional region code to filter results to (e.g. "eu").
            Defaults to your configured RAPID7_REGION. Pass "all" to
            bypass filtering and see every managed organization.

    Returns:
        One line per managed organization in the form
        "- <name> (id: <id>, region: <region>)", or an error message if
        required environment variables are missing or the API call fails.
    """
    try:
        config = load_parent_organization_config()
        organizations = get_managed_organizations(
            api_key=config["api_key"],
            region=config["region"],
            parent_organization_id=config["parent_organization_id"],
        )

        effective_region = region or config["region"]
        if effective_region.lower() != "all":
            organizations = filter_by_region(organizations, effective_region)

        if not organizations:
            return f"No managed organizations found (region filter: {effective_region})."

        label = "all regions" if effective_region.lower() == "all" else f"region '{effective_region}'"
        lines = [f"Managed organizations in {label} ({len(organizations)}):\n"]
        for org in organizations:
            name = org.get("name", "<unknown>")
            org_id = org.get("id", "<unknown>")
            org_region = org.get("region", "<unknown>")
            lines.append(f"- {name} (id: {org_id}, region: {org_region})")

        lines.append(
            "\nUse one of the ids above as the organization_id parameter on "
            "other tools (e.g. start_rapid7_export, query_rapid7). Pass "
            'region="all" to this tool to see organizations in other regions.'
        )
        return "\n".join(lines)

    except Exception as e:
        return f"✗ Error listing managed organizations: {str(e)}"


def main():
    """Entry point for the MCP server command."""
    global _default_db_path_override

    # Handle help flag
    if len(sys.argv) > 1 and sys.argv[1] in ["--help", "-h"]:
        print("Usage: rapid7-mcp-server [database_path]")
        print()
        print("Start the MCP server for Rapid7 vulnerability data.")
        print()
        print("Arguments:")
        print("  database_path    Path to the DuckDB database file (optional, overrides DATA_DIR default)")
        print()
        print("Environment Variables:")
        print("  RAPID7_API_KEY              Your Rapid7 InsightVM API key (required)")
        print("  RAPID7_MULTI_TENANT_API_KEY Rapid7 Multi-Tenant Admin/User API key (required only")
        print("                              when calling a tool with organization_id set, or")
        print("                              when calling get_organization_ids)")
        print("  RAPID7_PARENT_ORG_ID Your primary/parent account's own org id (required")
        print("                              only for the get_organization_ids tool; not a")
        print("                              managed tenant's id)")
        print("  RAPID7_REGION               Your Rapid7 region: us, us2, us3, eu, ca, au, ap (default: us)")
        print("  DATA_DIR                    Directory for database files (takes precedence when set)")
        print("  PLUGIN_DATA                 Plugin-host data dir; used when DATA_DIR is unset (else ~/.rapid7_mcp)")
        print("  MCP_TRANSPORT               Transport protocol: 'stdio' (default) or 'http'")
        print("  MCP_HOST                    HTTP bind address (default: 0.0.0.0)")
        print("  MCP_PORT                    HTTP port (default: 8000)")
        print()
        print("Tool parameter:")
        print("  organization_id  Optional, accepted by most tools (not an env var). Scopes that")
        print("                   call's data/tracking under DATA_DIR/orgs/<organization_id>/ and")
        print("                   sends R7-Organization-Id using the Multi-Tenant API key. Omit for")
        print("                   default single-tenant behavior.")
        print()
        print("Example:")
        print("  rapid7-mcp-server /path/to/rapid7_bulk_export.db")
        print()
        print("The server communicates via stdio by default, or streamable HTTP")
        print("when MCP_TRANSPORT=http (for Docker / remote deployments).")
        print()
        print("See README.md for configuration details.")
        sys.exit(0)

    # Ensure data directory exists, including the imports/ subdir that
    # load_rapid7_parquet reads from (its allowed root), so a fresh
    # DATA_DIR/PLUGIN_DATA has the path users are told to copy files into.
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    (_DATA_DIR / "imports").mkdir(parents=True, exist_ok=True)

    if _ENABLE_DAILY_SYNC:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
        logger.info("Daily sync scheduler enabled: runs at %02d:%02d UTC", _DAILY_SYNC_HOUR_UTC, _DAILY_SYNC_MINUTE_UTC)
        threading.Thread(target=_daily_sync_scheduler_loop, name="daily-sync-scheduler", daemon=True).start()

    # Stash the CLI override for the default org's database path — applied
    # lazily the first time it's actually needed, since databases now
    # initialize per-organization on demand rather than eagerly at startup.
    if len(sys.argv) > 1:
        _default_db_path_override = sys.argv[1]
        print(f"Default database path override: {_default_db_path_override}", file=sys.stderr)

    print(
        "Rapid7 MCP server ready (multi-tenant mode: databases initialize lazily per organization_id).",
        file=sys.stderr,
    )

    # Reconcile any work left mid-flight by a previous crash/restart. Background
    # workers are daemon threads with no resume, so a stuck DOWNLOADING/LOADING
    # export or RUNNING job would otherwise block retry forever. Covers the
    # default/unscoped tenant plus every per-tenant tracker under
    # DATA_DIR/orgs/ — each tenant's tracker db is a separate file, so a
    # tenant that was mid-load at crash time must be reconciled individually
    # or its tools would incorrectly report "already in progress" forever.
    org_ids_to_reconcile = [""]
    orgs_root = _DATA_DIR / "orgs"
    if orgs_root.is_dir():
        org_ids_to_reconcile.extend(sorted(p.name for p in orgs_root.iterdir() if p.is_dir()))

    for org_id in org_ids_to_reconcile:
        try:
            recon_tracker = _tracker(org_id)
            recon_tracker.reconcile_interrupted(
                active_export_statuses=list(_ACTIVE_PHASES),
                active_job_statuses=[JOB_RUNNING],
                reason="Interrupted by a server restart before completing. Re-run the export/range to retry.",
            )
            recon_tracker.close()
        except Exception as e:
            label = org_id or "default"
            print(f"Warning: could not reconcile interrupted exports for tenant {label!r}: {e}", file=sys.stderr)

    # Determine transport mode from environment
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "http":
        host = os.environ.get("MCP_HOST", "0.0.0.0")  # nosec B104 - intentional for Docker
        port = int(os.environ.get("MCP_PORT", "8000"))
        print(f"Starting HTTP transport on {host}:{port}", file=sys.stderr)
        mcp.run(transport="http", host=host, port=port, show_banner=False)
    else:
        mcp.run(show_banner=False)


if __name__ == "__main__":
    main()
