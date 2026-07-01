"""Checkmk export blackout: when checkmk_blackout is on the export returns no
instances, so the special agent emits nothing and every service goes stale/gone."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.checks import routes as checks_routes


@pytest.mark.asyncio
async def test_checkmk_blackout_returns_no_instances(monkeypatch) -> None:
    # Blackout short-circuits at the top of the handler — before the DB query and
    # the (potentially slow) live polls — so session/principal are never touched.
    monkeypatch.setattr(
        checks_routes, "effective_settings", lambda: SimpleNamespace(checkmk_blackout=True)
    )
    result = await checks_routes.export_checkmk(session=None, _principal=None)
    assert result == {"version": 1, "instances": []}
