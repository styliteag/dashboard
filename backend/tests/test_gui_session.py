"""Tests for the GUI session-cookie stash (§18).

The stash holds the firewall's WebUI session cookie between gui/open (where the
agent replays the login) and gui/handoff (where it's set on the browser). It must
be single-use and short-lived so a captured admin session can't be replayed.
"""

from __future__ import annotations

from app.agent_hub.gui_session import GuiSessionStash


def test_put_pop_roundtrip() -> None:
    s = GuiSessionStash()
    s.put("tok", [{"name": "PHPSESSID", "value": "abc"}], ttl_seconds=60)
    assert s.pop("tok") == [("PHPSESSID", "abc")]


def test_pop_is_single_use() -> None:
    s = GuiSessionStash()
    s.put("tok", [{"name": "S", "value": "v"}], ttl_seconds=60)
    assert s.pop("tok") == [("S", "v")]
    assert s.pop("tok") == []  # second pop is empty — can't be replayed


def test_pop_missing_returns_empty() -> None:
    assert GuiSessionStash().pop("nope") == []


def test_put_ignores_empty_or_nameless_cookies() -> None:
    s = GuiSessionStash()
    s.put("a", [], ttl_seconds=60)
    s.put("b", [{"value": "v"}], ttl_seconds=60)  # no name
    assert s.pop("a") == []
    assert s.pop("b") == []


def test_expired_entry_not_returned() -> None:
    s = GuiSessionStash()
    s.put("tok", [{"name": "S", "value": "v"}], ttl_seconds=-1)  # already expired
    assert s.pop("tok") == []


def test_multiple_cookies_preserved() -> None:
    s = GuiSessionStash()
    s.put(
        "tok",
        [{"name": "PHPSESSID", "value": "a"}, {"name": "extra", "value": "b"}],
        ttl_seconds=60,
    )
    assert s.pop("tok") == [("PHPSESSID", "a"), ("extra", "b")]
