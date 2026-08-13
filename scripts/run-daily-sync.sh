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

# `uv run` manages this project's own .venv from pyproject.toml/uv.lock (creating it on first
# run if needed) — portable across hosts, unlike a hardcoded path to one specific machine's venv
# (this used to point at a sibling workspace's venv on one dev machine and broke immediately on
# any other host). Requires `uv` on PATH (see above), same prerequisite the workspace README
# already states.
cd "$SCRIPT_DIR"
exec uv run python -m src.daily_sync
