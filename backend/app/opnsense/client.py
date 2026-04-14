"""Async OPNsense REST client.

Wraps ``httpx.AsyncClient`` with:
- Basic auth (API key + secret)
- Per-instance pinned CA bundle (no blanket ``verify=False``)
- Sane timeouts and a small connection pool
"""
from __future__ import annotations

import ssl
from typing import Any

import httpx

from app.opnsense.schemas import (
    ActionResult,
    CpuUsage,
    DiskUsage,
    FirmwareStatus,
    FirmwareUpgradeStatus,
    InterfaceStats,
    IPsecServiceStatus,
    IPsecTunnel,
    MemoryUsage,
    SystemInformation,
    SystemStatus,
)


class OPNsenseError(RuntimeError):
    pass


class OPNsenseClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        api_secret: str,
        ca_bundle_pem: str | None = None,
        ssl_verify: bool = True,
        timeout: float = 10.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")

        verify: ssl.SSLContext | bool
        if not ssl_verify:
            verify = False
        elif ca_bundle_pem:
            ctx = ssl.create_default_context(cadata=ca_bundle_pem)
            verify = ctx
        else:
            verify = True

        self._http = httpx.AsyncClient(
            base_url=self._base_url,
            auth=(api_key, api_secret),
            verify=verify,
            timeout=httpx.Timeout(timeout, connect=5.0),
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
            headers={"Accept": "application/json"},
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> OPNsenseClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    # ----- low-level ------------------------------------------------------

    async def _get(self, path: str) -> Any:
        try:
            resp = await self._http.get(path)
        except httpx.HTTPError as exc:
            raise OPNsenseError(f"GET {path}: {exc}") from exc
        if resp.status_code >= 400:
            raise OPNsenseError(f"GET {path}: HTTP {resp.status_code}")
        return resp.json()

    async def _post(self, path: str, body: dict | None = None) -> Any:
        try:
            resp = await self._http.post(path, json=body or {})
        except httpx.HTTPError as exc:
            raise OPNsenseError(f"POST {path}: {exc}") from exc
        if resp.status_code >= 400:
            raise OPNsenseError(f"POST {path}: HTTP {resp.status_code}")
        return resp.json()

    # ----- diagnostics ----------------------------------------------------

    async def system_information(self) -> SystemInformation:
        data = await self._get("/api/diagnostics/system/system_information")
        return SystemInformation.model_validate(data)

    async def _system_resources(self) -> dict:
        """Fetch /api/diagnostics/system/systemResources (cached per poll cycle)."""
        return await self._get("/api/diagnostics/system/systemResources")

    async def cpu_usage(self) -> CpuUsage:
        """Parse CPU usage.

        Primary source: systemResources (if it has a cpu section).
        Fallback: activity endpoint headers contain a line like:
          "CPU: 11.1% user,  0.0% nice,  3.9% system,  0.0% interrupt, 85.0% idle"
        We compute total = 100 - idle.
        """
        # Try systemResources first
        try:
            data = await self._system_resources()
            cpu_raw = data.get("cpu", {})
            if cpu_raw and "used" in cpu_raw:
                return CpuUsage(total=float(cpu_raw["used"]))
        except (OPNsenseError, ValueError, TypeError, KeyError):
            pass

        # Fallback: parse activity headers
        try:
            data = await self._get("/api/diagnostics/activity/getActivity")
            headers = data.get("headers", []) if isinstance(data, dict) else []
            for line in headers:
                if "idle" in str(line).lower():
                    # Parse "85.0% idle" → idle=85.0 → total=15.0
                    import re
                    match = re.search(r"([\d.]+)%\s*idle", str(line))
                    if match:
                        idle = float(match.group(1))
                        return CpuUsage(total=round(100.0 - idle, 1))
        except (OPNsenseError, ValueError, TypeError, KeyError):
            pass
        return CpuUsage(total=0.0)

    async def memory_usage(self) -> MemoryUsage:
        """Parse memory from systemResources.

        OPNsense returns:
          {"memory": {"total": "4248293376", "used": 1870169729, "total_frmt": "4051", "used_frmt": "1783", ...}}
        total/used are in BYTES, *_frmt are in MB.
        """
        try:
            data = await self._system_resources()
            mem = data.get("memory", {})
            # Use the _frmt fields (in MB) if available, else convert from bytes
            total_mb = float(mem.get("total_frmt", 0)) or (float(mem.get("total", 0)) / 1024 / 1024)
            used_mb = float(mem.get("used_frmt", 0)) or (float(mem.get("used", 0)) / 1024 / 1024)
            used_pct = (used_mb / total_mb * 100) if total_mb > 0 else 0.0
            return MemoryUsage(used_pct=round(used_pct, 1), total_mb=round(total_mb, 1), used_mb=round(used_mb, 1))
        except (ValueError, TypeError, KeyError):
            return MemoryUsage()

    async def disk_usage(self) -> list[DiskUsage]:
        """Parse disk info from systemDisk.

        OPNsense returns:
          {"devices": [{"device": "zroot/ROOT/default", "used_pct": 42, "mountpoint": "/", ...}]}
        The used_pct field is already a number (not a string with %).
        """
        try:
            data = await self._get("/api/diagnostics/system/systemDisk")
            devices = data if isinstance(data, list) else data.get("devices", [])
            result: list[DiskUsage] = []
            for d in devices:
                # used_pct can be int/float directly, or a string like "42%"
                raw = d.get("used_pct", d.get("capacity", 0))
                if isinstance(raw, str):
                    raw = raw.rstrip("%")
                result.append(
                    DiskUsage(
                        device=d.get("device", ""),
                        mountpoint=d.get("mountpoint", d.get("type", "")),
                        used_pct=float(raw) if raw else 0.0,
                    )
                )
            return result
        except (ValueError, TypeError, KeyError):
            return []

    async def interface_statistics(self) -> list[InterfaceStats]:
        """Parse interface statistics.

        OPNsense returns:
          {"statistics": {"[LAN] (vmx0) / 00:50:56:be:dd:5b": {"name": "vmx0", "flags": "0x8843", ...}}}
        The outer key is a human-readable label; the inner "name" has the short BSD name.
        We deduplicate by short name (same iface appears multiple times for each address).
        """
        try:
            data = await self._get(
                "/api/diagnostics/interface/getInterfaceStatistics"
            )
            stats = data.get("statistics", data) if isinstance(data, dict) else data
            # Deduplicate: keep the first entry per short interface name
            seen: dict[str, InterfaceStats] = {}
            if isinstance(stats, dict):
                for label, info in stats.items():
                    short_name = info.get("name", label[:60])
                    if short_name in seen:
                        continue
                    # Extract the zone/role from the label, e.g. "[LAN]" from "[LAN] (vmx0) / ..."
                    zone = ""
                    if label.startswith("["):
                        zone = label.split("]")[0] + "]"
                    display_name = f"{zone} {short_name}".strip() if zone else short_name
                    seen[short_name] = InterfaceStats(
                        name=display_name,
                        status=info.get("status", info.get("flags", "")),
                        address=info.get("address"),
                        bytes_received=int(info.get("received-bytes", info.get("bytes received", 0))),
                        bytes_transmitted=int(info.get("sent-bytes", info.get("bytes transmitted", 0))),
                    )
            return list(seen.values())
        except (ValueError, TypeError, KeyError):
            return []

    # ----- combined poll --------------------------------------------------

    async def _parse_uptime(self) -> str | None:
        """Extract uptime from the activity endpoint header.

        Header line: "last pid: 80943;  load averages:  0.45,  0.33,  0.26  up 1+18:18:17    10:16:21"
        """
        try:
            import re

            data = await self._get("/api/diagnostics/activity/getActivity")
            headers = data.get("headers", []) if isinstance(data, dict) else []
            for line in headers:
                match = re.search(r"up\s+([\d+:]+)", str(line))
                if match:
                    raw = match.group(1)
                    # "1+18:18:17" → "1d 18h 18m" or just return raw
                    if "+" in raw:
                        days, rest = raw.split("+", 1)
                        parts = rest.split(":")
                        return f"{days}d {parts[0]}h {parts[1]}m"
                    else:
                        parts = raw.split(":")
                        if len(parts) == 3:
                            return f"{parts[0]}h {parts[1]}m"
                        return raw
        except (OPNsenseError, ValueError, TypeError, KeyError):
            pass
        return None

    async def poll_status(self) -> SystemStatus:
        """Gather all diagnostics in one call. Individual failures are swallowed
        so a single broken endpoint doesn't invalidate the whole poll."""
        info = SystemInformation()
        cpu = CpuUsage()
        mem = MemoryUsage()
        disks: list[DiskUsage] = []
        ifaces: list[InterfaceStats] = []
        uptime: str | None = None

        try:
            info = await self.system_information()
        except OPNsenseError:
            pass

        try:
            cpu = await self.cpu_usage()
        except OPNsenseError:
            pass

        try:
            mem = await self.memory_usage()
        except OPNsenseError:
            pass

        try:
            disks = await self.disk_usage()
        except OPNsenseError:
            pass

        try:
            ifaces = await self.interface_statistics()
        except OPNsenseError:
            pass

        try:
            uptime = await self._parse_uptime()
        except OPNsenseError:
            pass

        return SystemStatus(
            name=info.name,
            version=(info.versions[0] if info.versions else None),
            uptime=uptime,
            cpu=cpu,
            memory=mem,
            disks=disks,
            interfaces=ifaces,
        )

    # ----- IPsec --------------------------------------------------------------

    async def ipsec_status(self) -> IPsecServiceStatus:
        """Get IPsec service status and tunnel list."""
        try:
            data = await self._get("/api/ipsec/service/status")
            running = str(data.get("status", "")).lower() in ("running", "1", "true")
        except OPNsenseError:
            running = False

        tunnels: list[IPsecTunnel] = []
        try:
            ph1 = await self._get("/api/ipsec/sessions/searchPhase1")
            rows = ph1.get("rows", []) if isinstance(ph1, dict) else []
            for row in rows:
                tunnels.append(
                    IPsecTunnel(
                        id=str(row.get("id", row.get("ikeid", ""))),
                        description=row.get("description", row.get("phase1desc", "")),
                        phase1_status=row.get("connected", row.get("status", "unknown")),
                        phase2_status="",
                        remote=row.get("remote-host", row.get("remote_host", "")),
                        local=row.get("local-host", row.get("local_host", "")),
                        bytes_in=int(row.get("bytes-in", row.get("bytes_in", 0))),
                        bytes_out=int(row.get("bytes-out", row.get("bytes_out", 0))),
                        established=row.get("established"),
                    )
                )
        except OPNsenseError:
            pass

        return IPsecServiceStatus(running=running, tunnels=tunnels)

    async def ipsec_connect(self, tunnel_id: str) -> ActionResult:
        data = await self._post(f"/api/ipsec/sessions/connect/{tunnel_id}")
        return ActionResult(
            success="ok" in str(data).lower() or data.get("status", "") == "ok",
            message=str(data.get("message", data.get("status", ""))),
        )

    async def ipsec_disconnect(self, tunnel_id: str) -> ActionResult:
        data = await self._post(f"/api/ipsec/sessions/disconnect/{tunnel_id}")
        return ActionResult(
            success="ok" in str(data).lower() or data.get("status", "") == "ok",
            message=str(data.get("message", data.get("status", ""))),
        )

    async def ipsec_restart(self) -> ActionResult:
        data = await self._post("/api/ipsec/service/restart")
        return ActionResult(
            success="ok" in str(data).lower(),
            message=str(data.get("message", data.get("response", ""))),
        )

    # ----- Firmware -----------------------------------------------------------

    async def firmware_status(self) -> FirmwareStatus:
        data = await self._get("/api/core/firmware/status")

        # Collect updateable items from multiple sources
        upgrade_sets = data.get("upgrade_sets", [])
        upgrade_pkgs = data.get("upgrade_packages", [])
        new_pkgs = data.get("new_packages", [])
        all_updates: list[dict] = []
        for s in upgrade_sets:
            all_updates.append({
                "name": s.get("name", ""),
                "current": s.get("current_version", ""),
                "new": s.get("new_version", ""),
                "size": s.get("size", ""),
            })
        for p in upgrade_pkgs + new_pkgs:
            all_updates.append({
                "name": p.get("name", ""),
                "current": p.get("current_version", p.get("installed", "")),
                "new": p.get("new_version", p.get("provided", "")),
            })

        # Determine latest version from sets or product_latest
        product_latest = data.get("product_latest", "")
        if not product_latest and upgrade_sets:
            product_latest = upgrade_sets[0].get("new_version", "")

        status_val = data.get("status", "")
        needs_reboot = data.get("needs_reboot", "0")
        upgrade_needs_reboot = data.get("upgrade_needs_reboot", "0")

        return FirmwareStatus(
            product_name=data.get("product_name", data.get("product_id", "")),
            product_version=data.get("product_version", ""),
            product_latest=product_latest,
            needs_reboot=str(needs_reboot) not in ("0", "", "false", "False"),
            upgrade_available=status_val in ("upgrade", "update") or bool(all_updates),
            updates_available=len(all_updates),
            packages=all_updates,
            status_msg=data.get("status_msg", ""),
            download_size=data.get("download_size", ""),
            last_check=data.get("last_check", ""),
        )

    async def firmware_check(self) -> ActionResult:
        data = await self._post("/api/core/firmware/check")
        return ActionResult(
            success=True,
            message=str(data.get("status", "check triggered")),
        )

    async def firmware_update(self) -> ActionResult:
        data = await self._post("/api/core/firmware/update")
        return ActionResult(
            success="ok" in str(data).lower() or data.get("status", "") == "ok",
            message=str(data.get("msg", data.get("status", ""))),
        )

    async def firmware_upgrade_status(self) -> FirmwareUpgradeStatus:
        data = await self._get("/api/core/firmware/upgradestatus")
        log_lines = data.get("log", "").splitlines() if isinstance(data.get("log"), str) else []
        return FirmwareUpgradeStatus(
            status=data.get("status", "unknown"),
            log=log_lines,
        )
