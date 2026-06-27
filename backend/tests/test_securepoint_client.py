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
# Live-captured `system info`: live stats as {attribute, value} rows.
_SYSTEM_INFO = [
    {"attribute": "hostname", "value": "bensheim.stylite.de"},
    {"attribute": "version", "value": "14.1.6"},
    {"attribute": "Idle", "value": "  98%"},
    {"attribute": "Mem Total", "value": "3887616"},
    {"attribute": "Mem Avail", "value": "2930392"},
    {"attribute": "storage", "value": "61660659712"},
    {"attribute": "storage free", "value": "57942274048"},
    {"attribute": "Uptime", "value": "01:19:44"},
    {"attribute": "productname", "value": "RC100-G5"},
    {"attribute": "cur", "value": "14.1.6"},
    {"attribute": "new", "value": "none"},
]
_INTERFACE_ADDRS = [
    {"id": 3, "flags": ["ONLINE"], "device": "A1", "address": "10.21.0.1/22"},
    {"id": 0, "flags": ["DYNAMIC"], "device": "wan0", "address": "213.232.100.192/32"},
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
    if (module, command) == ("system", ["info"]):
        return _ok(_SYSTEM_INFO)
    if (module, command) == ("interface", ["address", "get"]):
        return _ok(_INTERFACE_ADDRS)
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
async def test_ipsec_diagnose_without_ssh_returns_hint() -> None:
    sp = SecurepointClient(_BASE, "admin", "secret", ssl_verify=False)  # no ssh=
    try:
        diag = await sp.ipsec_diagnose("bonis-test")
    finally:
        await sp.aclose()
    assert diag.tunnel_id == "bonis-test"
    assert len(diag.sections) == 1
    assert "SSH" in diag.sections[0].title


@pytest.mark.asyncio
async def test_ipsec_diagnose_with_ssh_returns_sections(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.securepoint import client as client_mod
    from app.securepoint.ssh import SSHConfig
    from app.xsense.schemas import DiagnosisSection

    async def fake_diag(host, port, user, key, host_key, tunnel_id):  # noqa: ANN001
        assert tunnel_id == "bonis-test"
        return [DiagnosisSection(title="Connection config", content="bonis-test: IKEv2")]

    monkeypatch.setattr(client_mod, "fetch_diagnosis", fake_diag)
    ssh = SSHConfig(host="sp.test", port=9922, user="root", private_key="KEY")
    sp = SecurepointClient(_BASE, "admin", "secret", ssl_verify=False, ssh=ssh)
    try:
        diag = await sp.ipsec_diagnose("bonis-test")
    finally:
        await sp.aclose()
    assert [s.title for s in diag.sections] == ["Connection config"]


@pytest.mark.asyncio
async def test_ipsec_status_uses_ssh_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.securepoint import client as client_mod
    from app.securepoint.ssh import SSHConfig
    from app.xsense.schemas import IPsecServiceStatus, IPsecTunnel

    rich = IPsecServiceStatus(
        running=True, tunnels=[IPsecTunnel(id="bonis-test", ike_init_spi="0731875234fa6144")]
    )

    async def fake_fetch(host, port, user, key, host_key, *, running):  # noqa: ANN001
        assert (host, port, user) == ("sp.test", 9922, "root")
        return rich

    monkeypatch.setattr(client_mod, "fetch_ipsec_status", fake_fetch)
    ssh = SSHConfig(host="sp.test", port=9922, user="root", private_key="KEY")
    with respx.mock(base_url=_BASE) as mock:
        mock.post("/spcgi.cgi").mock(side_effect=_router)  # serves appmgmt for the running flag
        async with SecurepointClient(_BASE, "admin", "secret", ssl_verify=False, ssh=ssh) as sp:
            status = await sp.ipsec_status()
    assert status.tunnels[0].ike_init_spi == "0731875234fa6144"  # SSH (rich) path used


@pytest.mark.asyncio
async def test_ipsec_status_falls_back_to_spcgi_when_ssh_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.securepoint import client as client_mod
    from app.securepoint.ssh import SecurepointSSHError, SSHConfig

    async def boom(*a, **k):  # noqa: ANN001, ANN002, ANN003
        raise SecurepointSSHError("connect refused")

    monkeypatch.setattr(client_mod, "fetch_ipsec_status", boom)
    ssh = SSHConfig(host="sp.test", port=9922, user="root", private_key="KEY")
    with respx.mock(base_url=_BASE) as mock:
        mock.post("/spcgi.cgi").mock(side_effect=_router)
        async with SecurepointClient(_BASE, "admin", "secret", ssl_verify=False, ssh=ssh) as sp:
            status = await sp.ipsec_status()
    # spcgi fallback: simple view, no IKE cookie
    assert status.tunnels[0].id == "bonis-test"
    assert status.tunnels[0].ike_init_spi == ""


@pytest.mark.asyncio
async def test_firmware_status_reports_version_up_to_date() -> None:
    with respx.mock(base_url=_BASE) as mock:
        mock.post("/spcgi.cgi").mock(side_effect=_router)
        async with SecurepointClient(_BASE, "admin", "secret", ssl_verify=False) as sp:
            fw = await sp.firmware_status()
    assert fw.product_version == "14.1.6"
    assert fw.product_name == "RC100-G5"
    assert fw.upgrade_available is False  # new == "none"
    assert fw.updates_available == 0


@pytest.mark.asyncio
async def test_firmware_status_reports_available_upgrade() -> None:
    sysinfo = [x for x in _SYSTEM_INFO if x["attribute"] != "new"] + [
        {"attribute": "new", "value": "14.2.0"}
    ]

    def router(request: Request) -> Response:
        payload = json.loads(request.content)
        if (payload["module"], payload["command"]) == ("system", ["info"]):
            return _ok(sysinfo)
        return _router(request)

    with respx.mock(base_url=_BASE) as mock:
        mock.post("/spcgi.cgi").mock(side_effect=router)
        async with SecurepointClient(_BASE, "admin", "secret", ssl_verify=False) as sp:
            fw = await sp.firmware_status()
    assert fw.product_version == "14.1.6"
    assert fw.product_latest == "14.2.0"
    assert fw.upgrade_available is True
    assert fw.updates_available == 1


@pytest.mark.asyncio
async def test_poll_status_maps_metrics_and_interfaces() -> None:
    with respx.mock(base_url=_BASE) as mock:
        mock.post("/spcgi.cgi").mock(side_effect=_router)
        async with SecurepointClient(_BASE, "admin", "secret", ssl_verify=False) as sp:
            status = await sp.poll_status()

    assert status.name == "bensheim.stylite.de"
    assert status.version == "14.1.6"
    assert status.uptime == "01:19:44"
    assert status.cpu.total == 2.0  # 100 - 98% idle
    assert status.memory.used_pct == round((3887616 - 2930392) / 3887616 * 100, 1)
    assert status.disks and status.disks[0].mountpoint == "/data"
    assert {(i.name, i.address, i.status) for i in status.interfaces} == {
        ("A1", "10.21.0.1/22", "up"),
        ("wan0", "213.232.100.192/32", "up"),
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
async def test_opnsense_capability_stubs_are_neutral() -> None:
    """Routes call firmware/gateway/reboot on the cached client; these must return
    neutral data (not AttributeError-500) for a Securepoint instance."""
    sp = SecurepointClient(_BASE, "admin", "secret", ssl_verify=False)
    try:
        assert (await sp.firmware_status()).product_version == ""
        assert await sp.gateway_status() == []
        assert await sp.firewall_log() == []
        assert (await sp.firmware_check()).success is False
        assert (await sp.reboot()).success is False
        assert (await sp.firmware_upgrade_status()).status == "unsupported"
        with pytest.raises(SecurepointError):
            await sp.download_config()
    finally:
        await sp.aclose()


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
async def test_lazy_login_on_first_command() -> None:
    """Registry uses the client without `async with`; first command must log in."""
    with respx.mock(base_url=_BASE) as mock:
        mock.post("/spcgi.cgi").mock(side_effect=_router)
        sp = SecurepointClient(_BASE, "admin", "secret", ssl_verify=False)
        try:
            services = await sp.appmgmt_status()  # no prior login()/async-with
            assert services["ipsec"] == "UP"
            assert sp._sessionid == _SID
        finally:
            await sp.aclose()


@pytest.mark.asyncio
async def test_relogin_once_on_session_expiry() -> None:
    """An expired session triggers exactly one re-login, then the command retries."""
    logins = {"count": 0}
    expired_once = {"done": False}

    def router(request: Request) -> Response:
        payload = json.loads(request.content)
        module, command = payload["module"], payload["command"]
        if (module, command) == ("auth", ["login"]):
            logins["count"] += 1
            return _ok(["session opened"], sessionid=_SID)
        if (module, command) == ("appmgmt", ["status"]) and not expired_once["done"]:
            expired_once["done"] = True
            return Response(200, json={"result": {"code": 401, "message": "invalid session"}})
        return _router(request)

    with respx.mock(base_url=_BASE) as mock:
        mock.post("/spcgi.cgi").mock(side_effect=router)
        sp = SecurepointClient(_BASE, "admin", "secret", ssl_verify=False)
        try:
            services = await sp.appmgmt_status()
            assert services["ipsec"] == "UP"
            assert logins["count"] == 2  # initial lazy login + one re-login
        finally:
            await sp.aclose()
