"""The client registry builds the right device client per device_type."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from app.db.models import Instance
from app.securepoint.client import SecurepointClient
from app.xsense.client import OPNsenseClient
from app.xsense.registry import ClientRegistry


@pytest.fixture(autouse=True)
def _set_master_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DASH_MASTER_KEY", Fernet.generate_key().decode())
    from app.crypto import secrets as crypto_secrets

    crypto_secrets._fernet.cache_clear()  # type: ignore[attr-defined]
    from app.config import get_settings

    get_settings.cache_clear()  # type: ignore[attr-defined]


def _instance(device_type: str) -> Instance:
    from app.crypto.secrets import encrypt

    return Instance(
        id=1,
        base_url="https://fw.example.test:11115",
        device_type=device_type,
        ssl_verify=False,
        api_key_enc=encrypt("admin"),
        api_secret_enc=encrypt("pw"),
    )


@pytest.mark.asyncio
async def test_registry_builds_securepoint_client() -> None:
    reg = ClientRegistry()
    client = await reg.get(_instance("securepoint"))
    try:
        assert isinstance(client, SecurepointClient)
    finally:
        await reg.close_all()


@pytest.mark.asyncio
async def test_registry_builds_opnsense_client_for_default() -> None:
    reg = ClientRegistry()
    client = await reg.get(_instance("opnsense"))
    try:
        assert isinstance(client, OPNsenseClient)
    finally:
        await reg.close_all()
