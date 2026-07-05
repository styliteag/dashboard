"""Prometheus export: text-format rendering and the /export/prometheus route."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.checks.models import CheckState, PerfMetric, ServiceCheck
from app.checks.prometheus import CONTENT_TYPE, render_prometheus


def _inst(id: int = 1, name: str = "opn1", device_type: str = "opnsense", agent_mode: bool = True):
    return SimpleNamespace(id=id, name=name, device_type=device_type, agent_mode=agent_mode)


def _check(key: str, state: CheckState, metrics: list[PerfMetric] | None = None) -> ServiceCheck:
    return ServiceCheck(key=key, state=int(state), summary=key, metrics=metrics or [])


def test_render_empty_fleet_is_empty() -> None:
    assert render_prometheus([]) == ""


def test_render_instance_info_and_states() -> None:
    checks = [
        _check("memory", CheckState.OK),
        _check("gateway:WAN", CheckState.CRIT),
    ]
    out = render_prometheus([(_inst(), checks)])
    assert "# HELP orbit_check_state" in out
    assert "# TYPE orbit_check_state gauge" in out
    assert (
        'orbit_instance_info{instance_id="1",instance_name="opn1",'
        'device_type="opnsense",mode="push"} 1' in out
    )
    assert 'orbit_check_state{instance_id="1",instance_name="opn1",key="memory"} 0' in out
    assert 'orbit_check_state{instance_id="1",instance_name="opn1",key="gateway:WAN"} 2' in out


def test_render_poll_mode_and_multiple_instances() -> None:
    out = render_prometheus(
        [
            (_inst(), [_check("memory", CheckState.OK)]),
            (_inst(id=2, name="sp1", device_type="securepoint", agent_mode=False), []),
        ]
    )
    assert 'instance_id="2",instance_name="sp1",device_type="securepoint",mode="poll"' in out


def test_render_perfdata_with_thresholds() -> None:
    metrics = [PerfMetric(name="mem_used_pct", value=42.5, warn=80.0, crit=90.0, unit="%")]
    out = render_prometheus([(_inst(), [_check("memory", CheckState.OK, metrics)])])
    labels = 'instance_id="1",instance_name="opn1",key="memory",metric="mem_used_pct",unit="%"'
    assert f"orbit_check_metric{{{labels}}} 42.5" in out
    assert f"orbit_check_metric_warn{{{labels}}} 80" in out
    assert f"orbit_check_metric_crit{{{labels}}} 90" in out


def test_render_omits_absent_thresholds_and_empty_families() -> None:
    metrics = [PerfMetric(name="uptime", value=123456789.0)]
    out = render_prometheus([(_inst(), [_check("uptime", CheckState.OK, metrics)])])
    assert "orbit_check_metric{" in out
    assert "orbit_check_metric_warn" not in out
    assert "orbit_check_metric_crit" not in out
    # Large integers must not lose precision to scientific notation.
    assert "} 123456789" in out


def test_render_escapes_label_values() -> None:
    inst = _inst(name='a"b\\c')
    out = render_prometheus([(inst, [_check("svc:new\nline", CheckState.OK)])])
    assert 'instance_name="a\\"b\\\\c"' in out
    assert 'key="svc:new\\nline"' in out


@pytest.mark.asyncio
async def test_export_prometheus_route(monkeypatch) -> None:
    from app.checks import routes as checks_routes

    inst = _inst()

    async def fake_gather_many(rows):
        assert rows == [inst]
        return [(inst, (None, None, None, None, None, None, None))]

    async def fake_list_instances(session, principal):
        return [inst]

    monkeypatch.setattr(checks_routes, "list_instances", fake_list_instances)
    monkeypatch.setattr(checks_routes, "gather_many", fake_gather_many)
    monkeypatch.setattr(checks_routes, "effective_settings", lambda: SimpleNamespace())
    monkeypatch.setattr(checks_routes, "evaluate_checks", lambda *aspects: [])
    monkeypatch.setattr(
        checks_routes,
        "overlay_checks",
        lambda inst_, base, settings, now: [ServiceCheck(key="memory", state=1, summary="high")],
    )

    resp = await checks_routes.export_prometheus(session=None, principal=None)
    assert resp.headers["content-type"] == CONTENT_TYPE
    body = resp.body.decode()
    assert 'orbit_check_state{instance_id="1",instance_name="opn1",key="memory"} 1' in body
