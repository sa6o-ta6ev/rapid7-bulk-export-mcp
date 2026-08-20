"""
Unit tests for the in-process daily sync scheduler in src/mcp_server.py.
"""

import datetime as _dt

from src.mcp_server import _seconds_until_next_run


def test_disabled_by_default():
    """ENABLE_DAILY_SYNC must default to off so image test/one-off runs never sync."""
    import importlib

    from src import mcp_server

    importlib.reload(mcp_server)
    assert mcp_server._ENABLE_DAILY_SYNC is False


def test_seconds_until_next_run_later_today():
    now = _dt.datetime(2026, 8, 20, 1, 0, tzinfo=_dt.timezone.utc)
    seconds = _seconds_until_next_run(2, 0, now=now)
    assert seconds == 3600


def test_seconds_until_next_run_rolls_over_to_tomorrow():
    now = _dt.datetime(2026, 8, 20, 3, 0, tzinfo=_dt.timezone.utc)
    seconds = _seconds_until_next_run(2, 0, now=now)
    assert seconds == 23 * 3600


def test_seconds_until_next_run_exact_match_rolls_over():
    now = _dt.datetime(2026, 8, 20, 2, 0, tzinfo=_dt.timezone.utc)
    seconds = _seconds_until_next_run(2, 0, now=now)
    assert seconds == 24 * 3600
