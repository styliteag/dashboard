"""Smoke tests for the Securepoint connector using respx for HTTP mocking.

The fixtures mirror the live ``/spcgi.cgi`` envelopes captured from a UTM 14.1.6 box.
"""

from __future__ import annotations

import json

import pytest
import respx
from httpx import Request, Response

from app.securepoint.client import SecurepointClient, SecurepointError

_BASE = "https://sp.example.test:11115"
_SID = "0123456789abcdef0123456789abcdef"

# Live-captured ipsec status: one row per Phase-2 selector, grouped by `name`.
_IPSEC_STATUS = [
    {
        "id": 1,
        "name": "bonis-test",
        "subnet_id": 1,
        "subnet": "10.21.0.0/22 - 10.1.1.0/24",
        "local_addr": "213.232.100.192",
        "remote_addr": "84.180.80.50",
        "state": "UP",
    },
    {
        "id": 1,
        "name": "bonis-test",
        "subnet_id": 2,
        "subnet": "10.21.0.0/22 - 10.2.2.0/24",
        "local_addr": "213.232.100.192",
        "remote_addr": "84.180.80.50",
        "state": "DOWN",
    },
]
_APPMGMT_STATUS = [
    {"application": "ipsec", "state": "UP", "flags": ["AUTOSTART"]},
    {"application": "openvpn", "state": "UP", "flags": ["AUTOSTART"]},
]


def _ok(content: object, *, sessionid: str | None = None) -> Response:
    body: dict[str, object] = {
        "result": {"module": "server", "code": 200, "status": "OK", "content": content},
        "version": "11.6",
    }
    if sessionid is not None:
        body["sessionid"] = sessionid
    return Response(200, json=body)


def _router(request: Request) -> Response:
    """Dispatch an spcgi.cgi POST to a canned response by module/command."""
    payload = json.loads(request.content)
    module, command = payload["module"], payload["command"]
    if (module, command) == ("auth", ["login"]):
        if payload["arguments"].get("pass") != "secret":
            return Response(
                200,
                json={"result": {"code": 401, "message": "insufficient credentials"}},
            )
        return _ok(["session opened"], sessionid=_SID)
    if (module, command) == ("auth", ["logout"]):
        return _ok(["session closed"])
    if (module, command) == ("appmgmt", ["status"]):
        return _ok(_APPMGMT_STATUS)
    if (module, command) == ("ipsec", ["status"]):
        return _ok(_IPSEC_STATUS)
    return Response(200, json={"result": {"code": 400, "message": "unknown command"}})


@pytest.mark.asyncio
async def test_ipsec_status_groups_rows_and_maps_state() -> None:
    with respx.mock(base_url=_BASE) as mock:
        mock.post("/spcgi.cgi").mock(side_effect=_router)
        async with SecurepointClient(_BASE, "admin", "secret", ssl_verify=False) as sp:
            status = await sp.ipsec_status()

    assert status.running is True
    assert len(status.tunnels) == 1  # two rows, one connection name
    t = status.tunnels[0]
    assert t.id == "bonis-test"
    assert t.phase1_status == "established"  # at least one child UP
    assert (t.phase2_up, t.phase2_total) == (1, 2)
    assert t.local == "213.232.100.192"
    assert t.remote == "84.180.80.50"
    assert {(c.local_ts, c.remote_ts, c.state) for c in t.children} == {
        ("10.21.0.0/22", "10.1.1.0/24", "INSTALLED"),
        ("10.21.0.0/22", "10.2.2.0/24", ""),
    }


@pytest.mark.asyncio
async def test_all_phase2_down_maps_to_down() -> None:
    down_rows = [{**r, "state": "DOWN"} for r in _IPSEC_STATUS]

    def router(request: Request) -> Response:
        payload = json.loads(request.content)
        if (payload["module"], payload["command"]) == ("ipsec", ["status"]):
            return _ok(down_rows)
        return _router(request)

    with respx.mock(base_url=_BASE) as mock:
        mock.post("/spcgi.cgi").mock(side_effect=router)
        async with SecurepointClient(_BASE, "admin", "secret", ssl_verify=False) as sp:
            status = await sp.ipsec_status()
    assert status.tunnels[0].phase1_status == "down"
    assert status.tunnels[0].phase2_up == 0


@pytest.mark.asyncio
async def test_ipsec_get_is_refused_to_protect_psk() -> None:
    with respx.mock(base_url=_BASE) as mock:
        mock.post("/spcgi.cgi").mock(side_effect=_router)
        async with SecurepointClient(_BASE, "admin", "secret", ssl_verify=False) as sp:
            with pytest.raises(SecurepointError, match="leaks secrets"):
                await sp._command("ipsec", ["get"])


@pytest.mark.asyncio
async def test_login_failure_raises() -> None:
    with respx.mock(base_url=_BASE) as mock:
        mock.post("/spcgi.cgi").mock(side_effect=_router)
        sp = SecurepointClient(_BASE, "admin", "wrong", ssl_verify=False)
        try:
            with pytest.raises(SecurepointError, match="login failed"):
                await sp.login()
        finally:
            await sp.aclose()


@pytest.mark.asyncio
async def test_command_before_login_raises() -> None:
    sp = SecurepointClient(_BASE, "admin", "secret", ssl_verify=False)
    try:
        with pytest.raises(SecurepointError, match="not logged in"):
            await sp.appmgmt_status()
    finally:
        await sp.aclose()
