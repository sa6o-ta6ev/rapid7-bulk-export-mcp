#!/usr/bin/env bash
# Invoked by cron once daily. Syncs Rapid7 InsightVM Bulk Export data for
# every managed tenant (see src/daily_sync.py) so rapid7-mcp-server's
# "Clients" tab always has fresh data without any Claude/MCP session
# involved.
set -euo pipefail

# cron doesn't source shell profile — load RAPID7_API_KEY,
# RAPID7_MULTI_TENANT_API_KEY, RAPID7_PARENT_ORG_ID, RAPID7_REGION (and
# DATA_DIR/DEFAULT_TENANT_NAME if overridden) explicitly, same reasoning as
# ~/rapid7-cron-sweep/run-sweep.sh's CF_ACCESS_* sourcing.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
set -a
source "$SCRIPT_DIR/.env"
set +a

# cron's PATH is minimal (typically just /usr/bin:/bin) and won't include wherever `uv` actually
# lives — confirmed live that `uv` only resolves via ~/.local/bin, added to PATH by interactive
# shell profiles cron never sources. Prepend the common install locations explicitly rather than
# assume the invoking environment's PATH is sufficient (same class of fix as sourcing .env above).
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/bin:$PATH"

mkdir -p "${DATA_DIR:-$HOME/.rapid7_mcp}/logs"

# Regenerate the vm-sync allowlist (rapid7-mcp-server's tenants.vm_org_id) right before the
# sync itself, so daily_sync.py's discover_tenants() only syncs orgs that project actually
# tracks as tenants, not every managed org under the account. Best-effort: RAPID7_MCP_SERVER_DIR
# unset, or the script itself failing, must not abort this whole cron run (set -e is
# temporarily relaxed here) -- daily_sync.py's own _load_vm_sync_allowlist falls back to an
# unfiltered sync if the allowlist file ends up missing/stale, same as before this existed.
if [ -n "${RAPID7_MCP_SERVER_DIR:-}" ]; then
  set +e
  (cd "$RAPID7_MCP_SERVER_DIR" && bun run scripts/export-vm-sync-allowlist.ts)
  if [ $? -ne 0 ]; then
    echo "warning: failed to regenerate vm sync allowlist from $RAPID7_MCP_SERVER_DIR -- continuing with existing/unfiltered list" >&2
  fi
  set -e
else
  echo "warning: RAPID7_MCP_SERVER_DIR not set -- skipping vm sync allowlist regeneration" >&2
fi

# `uv run` manages this project's own .venv from pyproject.toml/uv.lock (creating it on first
# run if needed) — portable across hosts, unlike a hardcoded path to one specific machine's venv
# (this used to point at a sibling workspace's venv on one dev machine and broke immediately on
# any other host). Requires `uv` on PATH (see above), same prerequisite the workspace README
# already states.
cd "$SCRIPT_DIR"
exec uv run python -m src.daily_sync
