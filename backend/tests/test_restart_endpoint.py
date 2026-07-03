"""Tests for the admin backend-restart endpoint (POST /api/settings/restart)."""

from __future__ import annotations

import asyncio
import signal
from types import SimpleNamespace

import pytest
from fastapi import Request

import app.settings.routes as routes


class _Session:
    def __init__(self) -> None:
        self.committed = False

    async def commit(self) -> None:
        self.committed = True


def _post_request() -> Request:
    return Request({"type": "http", "method": "POST", "headers": []})


@pytest.mark.asyncio
async def test_restart_commits_audit_then_schedules_terminate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: list[str] = []
    monkeypatch.setattr(routes, "_schedule_self_terminate", lambda: order.append("terminate"))

    audits: list[dict] = []

    async def fake_audit(session, **kw):
        audits.append(kw)

    monkeypatch.setattr(routes, "write_audit", fake_audit)

    session = _Session()
    orig_commit = session.commit

    async def commit_tracking() -> None:
        order.append("commit")
        await orig_commit()

    session.commit = commit_tracking  # type: ignore[method-assign]

    out = await routes.restart_backend(
        _post_request(),
        session=session,  # type: ignore[arg-type]
        admin=SimpleNamespace(id=1),  # type: ignore[arg-type]
    )
    assert out == {"status": "restarting"}
    assert session.committed
    # Audit must be durable before the process starts dying.
    assert order == ["commit", "terminate"]
    assert audits[0]["action"] == "settings.restart"


@pytest.mark.asyncio
async def test_schedule_self_terminate_sigterms_target_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kills: list[tuple[int, int]] = []
    monkeypatch.setattr(routes.os, "kill", lambda pid, sig: kills.append((pid, sig)))
    monkeypatch.setattr(routes, "_RESTART_DELAY_SECONDS", 0)
    monkeypatch.setattr(routes, "_restart_target_pid", lambda: 4242)

    routes._schedule_self_terminate()
    assert kills == []  # deferred, not immediate — the HTTP response must flush first
    await asyncio.sleep(0.05)
    assert kills == [(4242, signal.SIGTERM)]


def test_restart_target_is_pid1_when_pid1_is_uvicorn(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    # Dev --reload supervisor / bare-uvicorn container: the worker's death is not
    # resupervised, so the whole PID-1 uvicorn must die (container restart policy).
    cmdline = tmp_path / "cmdline"
    cmdline.write_bytes(b"/usr/bin/python\x00/usr/bin/uvicorn\x00app.main:app\x00--reload\x00")
    monkeypatch.setattr(routes, "_PID1_CMDLINE", str(cmdline))
    assert routes._restart_target_pid() == 1


def test_restart_target_is_self_when_pid1_is_not_uvicorn(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    # Combined prod container: PID 1 is nginx; the start.sh supervisor loop
    # restarts uvicorn, so only our own process dies.
    cmdline = tmp_path / "cmdline"
    cmdline.write_bytes(b"nginx: master process nginx -g daemon off;\x00")
    monkeypatch.setattr(routes, "_PID1_CMDLINE", str(cmdline))
    assert routes._restart_target_pid() == routes.os.getpid()


def test_restart_target_is_self_without_proc(monkeypatch: pytest.MonkeyPatch) -> None:
    # No /proc (macOS `just backend-run`): fall back to plain self-terminate.
    monkeypatch.setattr(routes, "_PID1_CMDLINE", "/nonexistent/cmdline")
    assert routes._restart_target_pid() == routes.os.getpid()
