"""Signed auto-redeploy of the vendored Checkmk script to linux nodes (§25).

DB-free: maybe_deploy_checkmk gets a fake connected agent; the vendored file
comes from a tmp AGENT_DIR.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.agent_hub.routes import update as update_routes

_SCRIPT = b"#!/bin/bash\necho '<<<check_mk>>>'\n"


def _fake_agent(platform: str = "linux", sha: str = "stale") -> SimpleNamespace:
    agent = SimpleNamespace(
        platform=platform,
        checkmk_sha256=sha,
        instance_id=6,
        calls=[],
    )

    async def send_command(action: str, params: dict, timeout: float = 30) -> dict:
        agent.calls.append((action, params))
        return {"success": True, "output": "deployed"}

    agent.send_command = send_command
    return agent


@pytest.fixture()
def vendor_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "check_mk_agent.linux").write_bytes(_SCRIPT)
    (vendor / "check_mk_agent.linux.sig").write_text("c2ln\n")
    monkeypatch.setattr(update_routes, "_AGENT_DIR", tmp_path)
    return vendor


@pytest.mark.asyncio
async def test_deploy_pushes_signed_script_on_sha_mismatch(vendor_dir: Path) -> None:
    agent = _fake_agent()
    await update_routes.maybe_deploy_checkmk(agent)
    assert len(agent.calls) == 1
    action, params = agent.calls[0]
    assert action == "checkmk.update"
    assert params["sha256"] == hashlib.sha256(_SCRIPT).hexdigest()
    assert base64.b64decode(params["code"]) == _SCRIPT
    assert params["signature"] == "c2ln"
    # Success pins the served sha so a reconnect doesn't re-push.
    assert agent.checkmk_sha256 == params["sha256"]


@pytest.mark.asyncio
async def test_deploy_skips_matching_sha_and_non_linux(vendor_dir: Path) -> None:
    current = _fake_agent(sha=hashlib.sha256(_SCRIPT).hexdigest())
    await update_routes.maybe_deploy_checkmk(current)
    assert current.calls == []

    firewall = _fake_agent(platform="opnsense")
    await update_routes.maybe_deploy_checkmk(firewall)
    assert firewall.calls == []


@pytest.mark.asyncio
async def test_deploy_without_vendor_file_is_a_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(update_routes, "_AGENT_DIR", tmp_path)  # no vendor/ inside
    agent = _fake_agent()
    await update_routes.maybe_deploy_checkmk(agent)
    assert agent.calls == []


@pytest.mark.asyncio
async def test_rejected_deploy_does_not_pin_sha(vendor_dir: Path) -> None:
    agent = _fake_agent()

    async def refuse(action: str, params: dict, timeout: float = 30) -> dict:
        agent.calls.append((action, params))
        return {"success": False, "output": "signature verification failed"}

    agent.send_command = refuse
    await update_routes.maybe_deploy_checkmk(agent)
    assert agent.checkmk_sha256 == "stale"  # retried on next reconnect


def test_checkmk_update_is_not_reachable_via_generic_passthrough() -> None:
    from app.agent_hub.routes.management import _INTERNAL_AGENT_ACTIONS

    assert "checkmk.update" in _INTERNAL_AGENT_ACTIONS
