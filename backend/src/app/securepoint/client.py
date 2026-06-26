"""Async Securepoint UTM client (PoC).

Wraps ``httpx.AsyncClient`` around the appliance ``/spcgi.cgi`` JSON endpoint:

- Session auth: ``auth login`` returns a top-level ``sessionid`` that every later
  request must carry; ``auth logout`` invalidates it.
- Request envelope: ``{"module", "command": [...], "arguments": {...}, "sessionid"}``.
- Response envelope: ``{"sessionid", "result": {"code", "status", "content": [...]}, ...}``
  — the payload lives in ``result.content``; ``code >= 400`` means error.

Maps tunnel/service status onto the shared DTOs in ``app.xsense.schemas`` so a
Securepoint box slots into the same poller path as OPNsense.

Security: this client deliberately never calls ``ipsec get`` — that command returns
the IPsec pre-shared key (``local_secret``) in plaintext. Only ``ipsec status`` (no
secret) is used in the read path.
"""

from __future__ import annotations

import contextlib
import ssl
from typing import Any

import httpx

from app.xsense.schemas import (
    ActionResult,
    FirmwareStatus,
    FirmwareUpgradeStatus,
    GatewayStatus,
    IPsecChild,
    IPsecServiceStatus,
    IPsecTunnel,
    SystemStatus,
)

_SPCGI_PATH = "/spcgi.cgi"
# Securepoint connector is read-only; state-change IPsec actions are not supported.
_READ_ONLY = "not supported on Securepoint (read-only)"
# Securepoint reports per-tunnel/Phase-2 state as this literal.
_STATE_UP = "UP"
# Phase-1 status string the rest of Orbit recognises as "up" (see checks/evaluate.py
# `_IPSEC_UP`, ipsec/history.py `_is_up`, frontend `isUp`). Map UP → this.
_PHASE1_UP = "established"
_PHASE1_DOWN = "down"
# Forbidden in the read path — leaks the PSK. Guard against accidental use.
_FORBIDDEN_COMMANDS = {("ipsec", "get")}


class SecurepointError(RuntimeError):
    def __init__(self, message: str, *, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


class SecurepointClient:
    def __init__(
        self,
        base_url: str,
        user: str,
        password: str,
        ca_bundle_pem: str | None = None,
        ssl_verify: bool = True,
        timeout: float = 10.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._user = user
        self._password = password
        self._sessionid: str | None = None

        verify: ssl.SSLContext | bool
        if not ssl_verify:
            verify = False
        elif ca_bundle_pem:
            verify = ssl.create_default_context(cadata=ca_bundle_pem)
        else:
            verify = True

        self._http = httpx.AsyncClient(
            base_url=self._base_url,
            verify=verify,
            timeout=httpx.Timeout(timeout, connect=5.0),
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> SecurepointClient:
        await self.login()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        with contextlib.suppress(SecurepointError):
            await self.logout()
        await self.aclose()

    # ----- low-level ------------------------------------------------------

    async def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            resp = await self._http.post(_SPCGI_PATH, json=payload)
        except httpx.HTTPError as exc:
            raise SecurepointError(f"POST {_SPCGI_PATH}: {exc}") from exc
        if resp.status_code >= 400:
            raise SecurepointError(
                f"POST {_SPCGI_PATH}: HTTP {resp.status_code}", code=resp.status_code
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise SecurepointError(f"POST {_SPCGI_PATH}: invalid JSON: {exc}") from exc

    async def _run(self, module: str, command: list[str], arguments: dict[str, Any] | None) -> Any:
        payload = {
            "module": module,
            "command": command,
            "arguments": arguments or {},
            "sessionid": self._sessionid,
        }
        return self._unwrap(await self._post(payload), f"{module} {' '.join(command)}")

    async def _command(
        self,
        module: str,
        command: list[str],
        arguments: dict[str, Any] | None = None,
    ) -> Any:
        """Run a spcgi command and return ``result.content``.

        Ensures a live session (lazy login), and re-logs in once if the session
        has expired — the registry caches this client and calls it without the
        ``async with`` context manager, so auth must be self-managed.
        """
        if (module, command[0]) in _FORBIDDEN_COMMANDS:
            raise SecurepointError(
                f"refusing to call '{module} {' '.join(command)}': leaks secrets"
            )
        await self._ensure_session()
        try:
            return await self._run(module, command, arguments)
        except SecurepointError as exc:
            if not self._is_session_expired(exc):
                raise
            self._sessionid = None
            await self.login()
            return await self._run(module, command, arguments)

    async def _ensure_session(self) -> None:
        if self._sessionid is None:
            await self.login()

    @staticmethod
    def _is_session_expired(exc: SecurepointError) -> bool:
        if exc.code == 401:
            return True
        msg = str(exc).lower()
        return "invalid session" in msg or "missing sessionid" in msg

    @staticmethod
    def _unwrap(data: dict[str, Any], what: str) -> Any:
        result = data.get("result", {})
        code = int(result.get("code", 0))
        if code >= 400:
            msg = result.get("message", result.get("status", "error"))
            raise SecurepointError(f"{what}: {code} {msg}", code=code)
        return result.get("content", [])

    # ----- session -------------------------------------------------------

    async def login(self) -> None:
        """Open a session; stores the returned ``sessionid`` for later calls."""
        data = await self._post(
            {
                "module": "auth",
                "command": ["login"],
                "arguments": {"user": self._user, "pass": self._password},
            }
        )
        result = data.get("result", {})
        if int(result.get("code", 0)) >= 400:
            raise SecurepointError(f"login failed: {result.get('message', 'unauthorized')}")
        sid = data.get("sessionid")
        if not sid:
            raise SecurepointError("login succeeded but no sessionid returned")
        self._sessionid = str(sid)

    async def logout(self) -> None:
        if self._sessionid is None:
            return
        payload = {"module": "auth", "command": ["logout"], "sessionid": self._sessionid}
        with contextlib.suppress(SecurepointError):
            await self._post(payload)
        self._sessionid = None

    # ----- status --------------------------------------------------------

    async def appmgmt_status(self) -> dict[str, str]:
        """Service health map, e.g. ``{"ipsec": "UP", "openvpn": "UP", ...}``."""
        rows = await self._command("appmgmt", ["status"])
        out: dict[str, str] = {}
        for row in rows if isinstance(rows, list) else []:
            app = str(row.get("application", ""))
            if app:
                out[app] = str(row.get("state", ""))
        return out

    async def openvpn_status(self) -> list[dict[str, Any]]:
        """Raw OpenVPN server/client rows (id, name, state, tun_addr, addr, time).

        No shared Orbit DTO exists for OpenVPN yet — returned as-is for the PoC.
        """
        rows = await self._command("openvpn", ["status"])
        return list(rows) if isinstance(rows, list) else []

    async def ipsec_status(self) -> IPsecServiceStatus:
        """IPsec service state + tunnel list mapped onto the shared Orbit DTOs.

        Securepoint ``ipsec status`` returns one row per Phase-2 selector
        (``subnet_id``) — verified live against a 2-selector tunnel. Rows are
        grouped by connection ``name`` into a single ``IPsecTunnel`` carrying one
        ``IPsecChild`` per row. ``bytes_in/out`` and ``seconds_established`` are
        not exposed by this endpoint → left at 0.
        """
        services = await self.appmgmt_status()
        running = services.get("ipsec", "").upper() == _STATE_UP

        rows = await self._command("ipsec", ["status"])
        grouped: dict[str, list[dict[str, Any]]] = {}
        for row in rows if isinstance(rows, list) else []:
            grouped.setdefault(str(row.get("name", "")), []).append(row)

        tunnels = [self._build_tunnel(name, group) for name, group in grouped.items()]
        return IPsecServiceStatus(running=running, tunnels=tunnels)

    @staticmethod
    def _build_tunnel(name: str, group: list[dict[str, Any]]) -> IPsecTunnel:
        children: list[IPsecChild] = []
        up = 0
        for row in group:
            is_up = str(row.get("state", "")).upper() == _STATE_UP
            up += is_up
            local_ts, _, remote_ts = str(row.get("subnet", "")).partition(" - ")
            children.append(
                IPsecChild(
                    name=str(row.get("subnet_id", "")),
                    local_ts=local_ts.strip(),
                    remote_ts=remote_ts.strip(),
                    state="INSTALLED" if is_up else "",
                )
            )
        first = group[0] if group else {}
        return IPsecTunnel(
            id=name,
            description=name,
            phase1_status=_PHASE1_UP if up > 0 else _PHASE1_DOWN,
            local=str(first.get("local_addr", "")),
            remote=str(first.get("remote_addr", "")),
            phase2_up=up,
            phase2_total=len(group),
            children=children,
        )

    # ----- IPsec actions (read-only no-ops) ------------------------------

    async def ipsec_connect(self, tunnel_id: str) -> ActionResult:
        return ActionResult(success=False, message=_READ_ONLY)

    async def ipsec_disconnect(self, tunnel_id: str) -> ActionResult:
        return ActionResult(success=False, message=_READ_ONLY)

    async def ipsec_restart(self) -> ActionResult:
        return ActionResult(success=False, message=_READ_ONLY)

    # ----- DeviceClient protocol -----------------------------------------

    async def system_info(self) -> dict[str, str]:
        """``system info`` flattened to an attribute map.

        The endpoint returns a list of ``{"attribute": k, "value": v}`` rows
        (hostname, version, productname, serialnumber, …) — collapsed to ``{k: v}``.
        """
        content = await self._command("system", ["info"])
        info: dict[str, str] = {}
        for item in content if isinstance(content, list) else []:
            if isinstance(item, dict) and "attribute" in item:
                info[str(item["attribute"])] = str(item.get("value", ""))
        return info

    async def poll_status(self) -> SystemStatus:
        """Best-effort snapshot satisfying the ``DeviceClient`` protocol.

        PoC fills hostname + product version; the full metrics surface
        (cpu/mem/disk/interfaces) is left for the integration step.
        """
        name = ""
        version: str | None = None
        with contextlib.suppress(SecurepointError):
            info = await self.system_info()
            name = str(info.get("hostname") or info.get("productname") or "")
            version = info.get("version") or info.get("productversion") or None
        return SystemStatus(name=name, version=version)

    # ----- OPNsense-capability stubs (unsupported, neutral) ---------------
    # The poller and several routes call these on the cached device client.
    # Securepoint doesn't manage firmware/gateways/config-backup here, so return
    # neutral/empty data (status reads) or a not-supported result (actions),
    # rather than 500ing. These are why a Securepoint instance renders cleanly.

    async def firmware_status(self) -> FirmwareStatus:
        return FirmwareStatus(status_msg=_READ_ONLY)

    async def firmware_check(self) -> ActionResult:
        return ActionResult(success=False, message=_READ_ONLY)

    async def firmware_update(self) -> ActionResult:
        return ActionResult(success=False, message=_READ_ONLY)

    async def firmware_upgrade_status(self) -> FirmwareUpgradeStatus:
        return FirmwareUpgradeStatus(status="unsupported")

    async def gateway_status(self) -> list[GatewayStatus]:
        return []

    async def firewall_log(self, limit: int = 50) -> list[dict]:
        return []

    async def reboot(self) -> ActionResult:
        return ActionResult(success=False, message=_READ_ONLY)

    async def download_config(self) -> str:
        raise SecurepointError(_READ_ONLY)
