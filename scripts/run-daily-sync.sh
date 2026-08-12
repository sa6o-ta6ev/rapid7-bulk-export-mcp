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

mkdir -p "${DATA_DIR:-$HOME/.rapid7_mcp}/logs"

exec /home/s460/rapid7/bulk-export-mcp/.venv/bin/python -m src.daily_sync
