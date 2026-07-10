"""Public-IP echo collector: parsing, family pinning, throttle, and stickiness."""

from __future__ import annotations

import orbit_agent as agent
import pytest


@pytest.fixture(autouse=True)
def _fresh_extip_state(monkeypatch: pytest.MonkeyPatch):
    # Each test starts with an empty cache and an unthrottled window.
    monkeypatch.setattr(agent._STATE, "extip_cache", {}, raising=False)
    monkeypatch.setattr(agent._STATE, "extip_ts", 0.0, raising=False)


def _stub_http(monkeypatch: pytest.MonkeyPatch, bodies: dict[str, bytes | Exception]):
    """Route _http_request by URL to a canned (status, headers, body) or raise."""

    def fake(url, method, headers, body, timeout, *, verify=True):
        val = bodies.get(url)
        if isinstance(val, Exception):
            raise val
        return 200, [], val

    monkeypatch.setattr(agent, "_http_request", fake)


def test_probe_returns_ip_of_expected_family(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_http(monkeypatch, {agent._EXTIP_V4_URL: b"203.0.113.7\n"})
    assert agent._probe_public_ip(agent._EXTIP_V4_URL, 4) == "203.0.113.7"


def test_probe_rejects_wrong_family(monkeypatch: pytest.MonkeyPatch) -> None:
    # A v4 answer on the v6 endpoint (or vice versa) must not be accepted.
    _stub_http(monkeypatch, {agent._EXTIP_V6_URL: b"203.0.113.7"})
    assert agent._probe_public_ip(agent._EXTIP_V6_URL, 6) is None


def test_probe_rejects_non_ip_body(monkeypatch: pytest.MonkeyPatch) -> None:
    # A captive portal / HTML error page is not an address.
    _stub_http(monkeypatch, {agent._EXTIP_V4_URL: b"<html>nope</html>"})
    assert agent._probe_public_ip(agent._EXTIP_V4_URL, 4) is None


def test_probe_swallows_transport_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_http(monkeypatch, {agent._EXTIP_V4_URL: OSError("unreachable")})
    assert agent._probe_public_ip(agent._EXTIP_V4_URL, 4) is None


def test_collect_reports_both_families(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_http(
        monkeypatch,
        {agent._EXTIP_V4_URL: b"203.0.113.7", agent._EXTIP_V6_URL: b"2001:db8::1"},
    )
    out = agent.collect_external_ip()
    assert out["ipv4"] == "203.0.113.7"
    assert out["ipv6"] == "2001:db8::1"
    assert out["checked_at"]


def test_collect_v4_only_when_no_ipv6_route(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_http(
        monkeypatch,
        {agent._EXTIP_V4_URL: b"203.0.113.7", agent._EXTIP_V6_URL: OSError("no route")},
    )
    out = agent.collect_external_ip()
    assert out["ipv4"] == "203.0.113.7"
    assert out["ipv6"] is None


def test_collect_is_throttled_and_serves_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def fake(url, method, headers, body, timeout, *, verify=True):
        calls["n"] += 1
        return 200, [], b"203.0.113.7"

    monkeypatch.setattr(agent, "_http_request", fake)
    first = agent.collect_external_ip()
    n_after_first = calls["n"]
    second = agent.collect_external_ip()  # within the throttle window
    assert second == first
    assert calls["n"] == n_after_first  # no re-probe on the throttled cycle


def test_transient_failure_keeps_last_known_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    # First cycle succeeds, then the window is forced open and the probe fails —
    # the sticky public IP must survive rather than blank out.
    _stub_http(monkeypatch, {agent._EXTIP_V4_URL: b"203.0.113.7"})
    agent.collect_external_ip()
    monkeypatch.setattr(agent._STATE, "extip_ts", 0.0)
    _stub_http(monkeypatch, {agent._EXTIP_V4_URL: OSError("blip")})
    out = agent.collect_external_ip()
    assert out["ipv4"] == "203.0.113.7"
