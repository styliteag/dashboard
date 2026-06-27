"""Per-instance device client cache.

Reusing the underlying ``httpx.AsyncClient`` keeps the TCP/TLS connection pool
warm. The registry is invalidated when an Instance row is updated or deleted.
"""

from __future__ import annotations

import asyncio

from app.crypto.secrets import decrypt
from app.db.models import Instance
from app.devices.protocol import DeviceClient
from app.devices.types import DeviceType
from app.securepoint.client import SecurepointClient
from app.securepoint.ssh import SSHConfig
from app.xsense.client import OPNsenseClient


class ClientRegistry:
    # Producer of direct-API clients. Branches on Instance.device_type; OPNsense
    # and Securepoint are the two direct clients today. Returns DeviceClient — the
    # poller only needs poll_status(); ipsec routes narrow via SupportsIPsec.
    def __init__(self) -> None:
        self._clients: dict[int, DeviceClient] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _ssh_config(instance: Instance) -> SSHConfig | None:
        """Build SSH enrichment config from the instance, or None when not usable."""
        if not (instance.ssh_enabled and instance.ssh_key_enc):
            return None
        return SSHConfig(
            host=instance.ssh_host,
            port=instance.ssh_port,
            user=instance.ssh_user,
            private_key=decrypt(instance.ssh_key_enc),
            host_key=instance.ssh_host_key,
        )

    @classmethod
    def _build(cls, instance: Instance) -> DeviceClient:
        if instance.device_type == DeviceType.SECUREPOINT.value:
            return SecurepointClient(
                base_url=instance.primary_base_url,
                user=decrypt(instance.api_key_enc),
                password=decrypt(instance.api_secret_enc),
                ca_bundle_pem=instance.ca_bundle,
                ssl_verify=instance.ssl_verify,
                ssh=cls._ssh_config(instance),
            )
        return OPNsenseClient(
            base_url=instance.primary_base_url,
            api_key=decrypt(instance.api_key_enc),
            api_secret=decrypt(instance.api_secret_enc),
            ca_bundle_pem=instance.ca_bundle,
            ssl_verify=instance.ssl_verify,
        )

    async def get(self, instance: Instance) -> DeviceClient:
        async with self._lock:
            client = self._clients.get(instance.id)
            if client is None:
                client = self._build(instance)
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
