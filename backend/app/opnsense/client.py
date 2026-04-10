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

from app.opnsense.schemas import SystemInformation


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
            # httpx wants a path or SSLContext. Build a context that trusts only the pinned bundle.
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

    # ----- high-level -----------------------------------------------------

    async def system_information(self) -> SystemInformation:
        data = await self._get("/api/diagnostics/system/system_information")
        return SystemInformation.model_validate(data)
