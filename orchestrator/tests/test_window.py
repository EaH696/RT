"""The ROE testing-window check (parity with the Go gate; fail-closed)."""
from datetime import datetime, timezone

import pytest

from rt.scope import Scope


def _at(y, m, d):
    return datetime(y, m, d, 12, 0, 0, tzinfo=timezone.utc)


def test_within_window():
    s = Scope(engagement_id="T", allowed_cidrs=["10.0.0.0/24"],
              window_start="2026-11-01T00:00:00Z", window_end="2026-11-30T23:59:59Z")
    assert s.within_window(_at(2026, 11, 20)) is True
    assert s.within_window(_at(2026, 10, 31)) is False   # before open
    assert s.within_window(_at(2026, 12, 1)) is False     # after close


def test_no_window_is_always_open():
    s = Scope(engagement_id="T", allowed_cidrs=["10.0.0.0/24"])
    assert s.within_window(_at(2030, 1, 1)) is True


def test_malformed_window_fails_closed():
    s = Scope(engagement_id="T", allowed_cidrs=["10.0.0.0/24"], window_end="nonsense")
    assert s.within_window(_at(2026, 11, 20)) is False
