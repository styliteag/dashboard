"""Instance CRUD with encrypted secrets."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.crypto.secrets import encrypt
from app.db.models import Instance
from app.instances.schemas import InstanceCreate, InstanceUpdate
from app.opnsense.client import OPNsenseClient, OPNsenseError
from app.opnsense.registry import registry


async def list_instances(session: AsyncSession) -> list[Instance]:
    rows = (
        await session.execute(
            select(Instance).where(Instance.deleted_at.is_(None)).order_by(Instance.name)
        )
    ).scalars().all()
    return list(rows)


async def get_instance(session: AsyncSession, instance_id: int) -> Instance | None:
    inst = await session.get(Instance, instance_id)
    if inst is None or inst.deleted_at is not None:
        return None
    return inst


async def create_instance(session: AsyncSession, payload: InstanceCreate) -> Instance:
    # In agent mode, API key/secret are not needed (agent collects data locally).
    # Store a placeholder so the NOT NULL constraint is satisfied.
    api_key = payload.api_key or ""
    api_secret = payload.api_secret or ""
    placeholder = encrypt("agent-mode-no-key") if not api_key else encrypt(api_key)
    placeholder_secret = encrypt("agent-mode-no-secret") if not api_secret else encrypt(api_secret)

    inst = Instance(
        name=payload.name,
        base_url=str(payload.base_url),
        api_key_enc=placeholder,
        api_secret_enc=placeholder_secret,
        ca_bundle=payload.ca_bundle,
        ssl_verify=payload.ssl_verify,
        agent_mode=payload.agent_mode,
        location=payload.location,
        notes=payload.notes,
        tags=payload.tags,
    )
    session.add(inst)
    await session.flush()
    return inst


async def update_instance(
    session: AsyncSession, inst: Instance, payload: InstanceUpdate
) -> Instance:
    if payload.name is not None:
        inst.name = payload.name
    if payload.base_url is not None:
        inst.base_url = str(payload.base_url)
    if payload.api_key:
        inst.api_key_enc = encrypt(payload.api_key)
    if payload.api_secret:
        inst.api_secret_enc = encrypt(payload.api_secret)
    if payload.ca_bundle is not None:
        inst.ca_bundle = payload.ca_bundle or None
    if payload.ssl_verify is not None:
        inst.ssl_verify = payload.ssl_verify
    if payload.location is not None:
        inst.location = payload.location or None
    if payload.notes is not None:
        inst.notes = payload.notes or None
    if payload.tags is not None:
        inst.tags = payload.tags or None
    await session.flush()
    # Drop the cached client so the next call rebuilds with new credentials/URL.
    await registry.invalidate(inst.id)
    return inst


async def soft_delete_instance(session: AsyncSession, inst: Instance) -> None:
    inst.deleted_at = datetime.now(timezone.utc)
    await session.flush()
    await registry.invalidate(inst.id)


async def test_connection(inst: Instance) -> tuple[bool, int | None, int | None, str | None]:
    """Open a *fresh* client (not the cached one) and call system_information."""
    from app.crypto.secrets import decrypt

    client = OPNsenseClient(
        base_url=inst.base_url,
        api_key=decrypt(inst.api_key_enc),
        api_secret=decrypt(inst.api_secret_enc),
        ca_bundle_pem=inst.ca_bundle,
        ssl_verify=inst.ssl_verify,
        timeout=10.0,
    )
    start = time.monotonic()
    try:
        await client.system_information()
        elapsed = int((time.monotonic() - start) * 1000)
        return True, 200, elapsed, None
    except OPNsenseError as exc:
        elapsed = int((time.monotonic() - start) * 1000)
        return False, None, elapsed, str(exc)
    except Exception as exc:  # noqa: BLE001 — surface anything to the operator
        elapsed = int((time.monotonic() - start) * 1000)
        return False, None, elapsed, f"{type(exc).__name__}: {exc}"
    finally:
        await client.aclose()
