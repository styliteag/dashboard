"""Pure helpers for logfile storage (DB path is verified live)."""

from __future__ import annotations

from types import SimpleNamespace

from app.logs.context import build_analysis_text, build_context_text
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


def test_context_renders_telemetry() -> None:
    snap = {
        "status": {
            "interfaces": [
                {"name": "igc1", "status": "up", "address": "10.0.0.1", "err_rate": 2.0}
            ],
            "pf": {"states_current": 10, "states_limit": 100, "states_pct": 10.0},
        },
        "ipsec": {
            "tunnels": [
                {
                    "id": "t1",
                    "description": "to-hq",
                    "phase1_status": "established",
                    "phase2_up": 1,
                    "phase2_total": 2,
                    "children": [
                        {
                            "local_ts": "10.1/24",
                            "remote_ts": "10.2/24",
                            "state": "INSTALLED",
                            "bytes_in": 0,
                            "bytes_out": 0,
                            "ping_state": "fail",
                        }
                    ],
                }
            ]
        },
        "gateways": [{"name": "WAN", "status": "online", "loss": "0%", "delay": "5ms"}],
        "services": [{"name": "sshd", "running": True}, {"name": "unbound", "running": False}],
        "certificates": [{"name": "web", "days_remaining": 5}],
    }
    txt = build_context_text(snap)
    assert "SYSTEM CONTEXT" in txt
    assert "igc1" in txt and "err_rate=2.0" in txt
    assert "to-hq" in txt and "INSTALLED" in txt and "ping=fail" in txt
    assert "WAN" in txt
    assert "unbound STOPPED" in txt and "sshd STOPPED" not in txt
    assert "web expires in 5d" in txt


def test_context_empty_when_no_snapshot() -> None:
    assert build_context_text(None) == ""
    assert build_context_text({}) == ""


def test_analysis_text_state_before_logs_and_capped() -> None:
    rows = [
        SimpleNamespace(name="system", content="S" * 9000),  # verbose log → tail
        SimpleNamespace(name="rules", content="R" * 20000),  # state → head
        SimpleNamespace(name="ifconfig", content="I" * 9000),  # state → head
    ]
    txt = build_analysis_text(None, rows)
    # State snapshots come before the verbose log.
    assert txt.index("rules") < txt.index("system")
    assert txt.index("ifconfig") < txt.index("system")
    # Per-source caps applied.
    assert "R" * 12001 not in txt  # rules head capped at RULES_CHARS
    assert "I" * 4501 not in txt  # ifconfig head capped at STATE_CHARS
    assert "S" * 5001 not in txt  # system tail capped at PER_LOG_CHARS
    assert len(txt) <= 48_000
