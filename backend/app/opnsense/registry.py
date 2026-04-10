"""Per-instance OPNsense client cache.

Reusing the underlying ``httpx.AsyncClient`` keeps the TCP/TLS connection pool
warm. The registry is invalidated when an Instance row is updated or deleted.
"""
from __future__ import annotations

import asyncio

from app.crypto.secrets import decrypt
from app.db.models import Instance
from app.opnsense.client import OPNsenseClient


class ClientRegistry:
    def __init__(self) -> None:
        self._clients: dict[int, OPNsenseClient] = {}
        self._lock = asyncio.Lock()

    async def get(self, instance: Instance) -> OPNsenseClient:
        async with self._lock:
            client = self._clients.get(instance.id)
            if client is None:
                client = OPNsenseClient(
                    base_url=instance.base_url,
                    api_key=decrypt(instance.api_key_enc),
                    api_secret=decrypt(instance.api_secret_enc),
                    ca_bundle_pem=instance.ca_bundle,
                )
                self._clients[instance.id] = client
            return client

    async def invalidate(self, instance_id: int) -> None:
        async with self._lock:
            client = self._clients.pop(instance_id, None)
        if client is not None:
            await client.aclose()

    async def close_all(self) -> None:
        async with self._lock:
            clients = list(self._clients.values())
            self._clients.clear()
        for c in clients:
            await c.aclose()


registry = ClientRegistry()
