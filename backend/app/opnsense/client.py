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
    CpuUsage,
    DiskUsage,
    InterfaceStats,
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
        timeout: float = 10.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")

        verify: ssl.SSLContext | bool
        if ca_bundle_pem:
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

    # ----- diagnostics ----------------------------------------------------

    async def system_information(self) -> SystemInformation:
        data = await self._get("/api/diagnostics/system/system_information")
        return SystemInformation.model_validate(data)

    async def cpu_usage(self) -> CpuUsage:
        """Parse CPU usage from systemResources or activity endpoint."""
        try:
            data = await self._get("/api/diagnostics/system/systemResources")
            # OPNsense systemResources returns {"cpu": {"used": "12", ...}, ...}
            cpu_raw = data.get("cpu", {})
            total = float(cpu_raw.get("used", 0))
            return CpuUsage(total=total)
        except (ValueError, TypeError, KeyError):
            return CpuUsage(total=0.0)

    async def memory_usage(self) -> MemoryUsage:
        """Parse memory from systemResources."""
        try:
            data = await self._get("/api/diagnostics/system/systemResources")
            mem = data.get("memory", {})
            used_pct = float(mem.get("used", 0))
            # OPNsense may report total/used in various units; normalize to MB.
            total = float(mem.get("total", 0))
            used = float(mem.get("used_raw", total * used_pct / 100 if total else 0))
            return MemoryUsage(used_pct=used_pct, total_mb=total, used_mb=used)
        except (ValueError, TypeError, KeyError):
            return MemoryUsage()

    async def disk_usage(self) -> list[DiskUsage]:
        """Parse disk info from systemDisk."""
        try:
            data = await self._get("/api/diagnostics/system/systemDisk")
            devices = data if isinstance(data, list) else data.get("devices", [])
            result: list[DiskUsage] = []
            for d in devices:
                used_str = str(d.get("capacity", "0")).rstrip("%")
                result.append(
                    DiskUsage(
                        device=d.get("device", ""),
                        mountpoint=d.get("mountpoint", d.get("type", "")),
                        used_pct=float(used_str) if used_str else 0.0,
                    )
                )
            return result
        except (ValueError, TypeError, KeyError):
            return []

    async def interface_statistics(self) -> list[InterfaceStats]:
        """Parse interface statistics."""
        try:
            data = await self._get(
                "/api/diagnostics/interface/getInterfaceStatistics"
            )
            stats = data.get("statistics", data) if isinstance(data, dict) else data
            result: list[InterfaceStats] = []
            if isinstance(stats, dict):
                for iface_name, info in stats.items():
                    result.append(
                        InterfaceStats(
                            name=iface_name,
                            status=info.get("status", info.get("flags", "")),
                            address=info.get("address"),
                            bytes_received=int(info.get("bytes received", 0)),
                            bytes_transmitted=int(info.get("bytes transmitted", 0)),
                        )
                    )
            return result
        except (ValueError, TypeError, KeyError):
            return []

    # ----- combined poll --------------------------------------------------

    async def poll_status(self) -> SystemStatus:
        """Gather all diagnostics in one call. Individual failures are swallowed
        so a single broken endpoint doesn't invalidate the whole poll."""
        info = SystemInformation()
        cpu = CpuUsage()
        mem = MemoryUsage()
        disks: list[DiskUsage] = []
        ifaces: list[InterfaceStats] = []

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

        return SystemStatus(
            name=info.name,
            version=(info.versions[0] if info.versions else None),
            uptime=info.model_extra.get("uptime") if info.model_extra else None,
            cpu=cpu,
            memory=mem,
            disks=disks,
            interfaces=ifaces,
        )
