"""Pure helpers for logfile storage (DB path is verified live)."""

from __future__ import annotations

from app.logs.store import clamp, sanitize_logfiles, surplus_ids


def test_clamp_keeps_newest_tail() -> None:
    assert clamp("abcdef", 3) == "def"
    assert clamp("ab", 5) == "ab"


def test_sanitize_drops_empty_and_trims_name() -> None:
    out = sanitize_logfiles(
        [
            {"name": "system", "content": "x"},
            {"name": "", "content": "y"},  # no name → dropped
            {"name": "filter", "content": ""},  # no content → dropped
            {"name": "n" * 80, "content": "z"},  # over-long name → trimmed to 64
        ]
    )
    assert ("system", "x") in out
    assert len(out) == 2
    assert all(name and len(name) <= 64 for name, _ in out)


def test_surplus_ids_keeps_last_three() -> None:
    assert surplus_ids([5, 4, 3, 2, 1], 3) == [2, 1]
    assert surplus_ids([2, 1], 3) == []
