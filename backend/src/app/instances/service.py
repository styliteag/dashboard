"""Instance CRUD with encrypted secrets."""

from __future__ import annotations

import time
from datetime import UTC, datetime

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.crypto.secrets import decrypt, encrypt
from app.db.models import Instance
from app.devices.types import DeviceType, Transport
from app.instances.schemas import InstanceCreate, InstanceUpdate
from app.instances.slug import MAX_SLUG_LEN, is_valid_slug, slugify_name
from app.securepoint.client import SecurepointClient, SecurepointError
from app.securepoint.ssh import probe_host_key
from app.xsense.client import OPNsenseClient, OPNsenseError
from app.xsense.registry import registry

log = structlog.get_logger("app.instances")


async def _maybe_pin_host_key(inst: Instance) -> None:
    """Best-effort trust-on-first-use capture of the box's SSH host key.

    Runs only when SSH enrichment is enabled with a key but nothing is pinned yet.
    On any failure (box unreachable, bad key) the key stays unpinned — enrichment
    then fails closed and falls back to the spcgi API, and a later save retries.
    TOFU caveat: pinning while an active MITM is on the path pins the attacker's key.
    """
    if not (inst.ssh_enabled and inst.ssh_key_enc and inst.ssh_host_key is None):
        return
    try:
        inst.ssh_host_key = await probe_host_key(
            inst.ssh_host, inst.ssh_port, inst.ssh_user, decrypt(inst.ssh_key_enc)
        )
        log.info("instance.ssh_host_key_pinned", instance_id=inst.id, host=inst.ssh_host)
    except Exception as exc:  # noqa: BLE001 — best-effort; unpinned → spcgi fallback
        log.warning("instance.ssh_host_key_pin_failed", instance_id=inst.id, error=str(exc))


class SlugConflictError(ValueError):
    """An explicitly requested slug is already in use by another instance."""


async def _slug_taken(session: AsyncSession, slug: str, exclude_id: int | None) -> bool:
    # Only *active* instances reserve a slug (soft-deleted rows free it — mirrors the
    # name_active_key generated-column constraint).
    query = select(Instance.id).where(Instance.slug == slug, Instance.deleted_at.is_(None))
    if exclude_id is not None:
        query = query.where(Instance.id != exclude_id)
    return (await session.execute(query.limit(1))).first() is not None


async def _resolve_slug(
    session: AsyncSession,
    desired: str,
    *,
    exclude_id: int | None = None,
    auto_suffix: bool,
) -> str:
    """Return a free, valid slug. ``auto_suffix`` appends -2/-3… instead of conflicting.

    Used with ``auto_suffix=True`` for name-derived slugs (must always succeed) and
    ``auto_suffix=False`` for an explicit user slug (a clash is an error, not a rename).
    """
    base = desired if is_valid_slug(desired) else slugify_name(desired)
    if not auto_suffix:
        if await _slug_taken(session, base, exclude_id):
            raise SlugConflictError(f"slug {base!r} is already in use")
        return base
    candidate, n = base, 2
    while await _slug_taken(session, candidate, exclude_id):
        suffix = f"-{n}"
        candidate = f"{base[: MAX_SLUG_LEN - len(suffix)].rstrip('-')}{suffix}"
        n += 1
    return candidate


async def list_instances(session: AsyncSession) -> list[Instance]:
    rows = (
        (
            await session.execute(
                select(Instance).where(Instance.deleted_at.is_(None)).order_by(Instance.name)
            )
        )
        .scalars()
        .all()
    )
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

    # transport is the source of truth; fall back to the agent_mode flag when omitted.
    transport = payload.transport or (Transport.PUSH if payload.agent_mode else Transport.DIRECT)

    # Explicit slug must be free (conflict surfaces); a name-derived one auto-suffixes.
    slug = await _resolve_slug(
        session, payload.slug or payload.name, auto_suffix=payload.slug is None
    )

    inst = Instance(
        name=payload.name,
        slug=slug,
        base_url=payload.base_url,
        api_key_enc=placeholder,
        api_secret_enc=placeholder_secret,
        ca_bundle=payload.ca_bundle,
        ssl_verify=payload.ssl_verify,
        poll_interval_seconds=payload.poll_interval_seconds,
        push_interval_seconds=payload.push_interval_seconds,
        transport=transport.value,
        device_type=payload.device_type.value,
        ssh_enabled=payload.ssh_enabled,
        ssh_port=payload.ssh_port,
        ssh_user=payload.ssh_user,
        ssh_key_enc=encrypt(payload.ssh_key) if payload.ssh_key else None,
        location=payload.location,
        notes=payload.notes,
        tags=payload.tags,
    )
    session.add(inst)
    await session.flush()
    await _maybe_pin_host_key(inst)
    return inst


async def update_instance(
    session: AsyncSession, inst: Instance, payload: InstanceUpdate
) -> Instance:
    if payload.name is not None:
        inst.name = payload.name  # slug stays put → the GUI URL is persistent
    if payload.slug is not None and payload.slug != inst.slug:
        inst.slug = await _resolve_slug(
            session, payload.slug, exclude_id=inst.id, auto_suffix=False
        )
    if payload.base_url is not None:
        inst.base_url = payload.base_url
    if payload.api_key:
        inst.api_key_enc = encrypt(payload.api_key)
    if payload.api_secret:
        inst.api_secret_enc = encrypt(payload.api_secret)
    if payload.ca_bundle is not None:
        inst.ca_bundle = payload.ca_bundle or None
    if payload.ssl_verify is not None:
        inst.ssl_verify = payload.ssl_verify
    if payload.gui_login_enabled is not None:
        inst.gui_login_enabled = payload.gui_login_enabled
    # Interval overrides: presence in model_fields_set (not None-ness) drives intent
    # — an explicit null clears the override back to the global default.
    fields_set = payload.model_fields_set
    if "poll_interval_seconds" in fields_set:
        inst.poll_interval_seconds = payload.poll_interval_seconds
    if "push_interval_seconds" in fields_set:
        inst.push_interval_seconds = payload.push_interval_seconds
    if payload.ssh_enabled is not None:
        inst.ssh_enabled = payload.ssh_enabled
    if payload.ssh_port is not None:
        inst.ssh_port = payload.ssh_port
    if payload.ssh_user is not None:
        inst.ssh_user = payload.ssh_user
    if payload.ssh_key:
        inst.ssh_key_enc = encrypt(payload.ssh_key)
        inst.ssh_host_key = None  # re-pin against the new key/identity
    if payload.location is not None:
        inst.location = payload.location or None
    if payload.notes is not None:
        inst.notes = payload.notes or None
    if payload.tags is not None:
        inst.tags = payload.tags or None
    # Capture the box's SSH host key (TOFU) when enrichment is on but unpinned —
    # e.g. right after a new key was uploaded above (which reset ssh_host_key).
    await _maybe_pin_host_key(inst)
    await session.flush()
    # Drop the cached client so the next call rebuilds with new credentials/URL.
    await registry.invalidate(inst.id)
    return inst


async def soft_delete_instance(session: AsyncSession, inst: Instance) -> None:
    inst.deleted_at = datetime.now(UTC)
    # The slug_active_key generated column auto-NULLs on soft-delete, so the slug
    # (and its GUI URL) is freed for reuse without mutating the stored value.
    await session.flush()
    await registry.invalidate(inst.id)


async def _test_securepoint(inst: Instance) -> tuple[bool, int | None, int | None, str | None]:
    """Probe a Securepoint box: login + system_info on a fresh session client."""
    from app.crypto.secrets import decrypt

    client = SecurepointClient(
        base_url=inst.primary_base_url,
        user=decrypt(inst.api_key_enc),
        password=decrypt(inst.api_secret_enc),
        ca_bundle_pem=inst.ca_bundle,
        ssl_verify=inst.ssl_verify,
        timeout=10.0,
    )
    start = time.monotonic()
    try:
        await client.login()
        await client.system_info()
        return True, 200, int((time.monotonic() - start) * 1000), None
    except SecurepointError as exc:
        return False, None, int((time.monotonic() - start) * 1000), str(exc)
    except Exception as exc:  # noqa: BLE001 — surface anything to the operator
        return False, None, int((time.monotonic() - start) * 1000), f"{type(exc).__name__}: {exc}"
    finally:
        await client.logout()
        await client.aclose()


async def test_connection(inst: Instance) -> tuple[bool, int | None, int | None, str | None]:
    """Open a *fresh* client (not the cached one) and probe reachability."""
    from app.crypto.secrets import decrypt

    if inst.device_type == DeviceType.SECUREPOINT.value:
        return await _test_securepoint(inst)

    client = OPNsenseClient(
        base_url=inst.primary_base_url,
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
