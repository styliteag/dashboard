"""Global interval-defaults endpoint.

A 200 (not 422) also proves ``/instances/defaults`` is matched before the
``/instances/{instance_id}`` int route — i.e. it is not shadowed.
"""

from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.main as main_mod
import app.poller.scheduler as sched_mod
from app.auth.deps import current_user


def test_defaults_endpoint_returns_global_intervals(monkeypatch) -> None:
    monkeypatch.setattr(sched_mod, "start_scheduler", lambda: None)
    monkeypatch.setattr(main_mod, "ensure_admin", lambda *a, **k: None)
    app = main_mod.create_app()
    app.dependency_overrides[current_user] = lambda: SimpleNamespace(id=1)
    with TestClient(app) as c:
        r = c.get("/api/instances/defaults")
    assert r.status_code == 200
    body = r.json()
    assert body["poll_interval_seconds"] == 30
    assert body["push_interval_seconds"] == 30
    assert body["poll_tick_seconds"] == 10
