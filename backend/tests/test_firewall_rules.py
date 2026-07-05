from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.firewall_rules import routes
from app.firewall_rules.schemas import FirewallRuleMutation


def test_normalize_rule_marks_mvc_rule_editable() -> None:
    rule = routes.normalize_rule(
        {
            "uuid": "abc",
            "enabled": "1",
            "log": "0",
            "action": "pass",
            "interface": "lan",
            "source_net": "lan",
            "destination_net": "any",
            "description": "Allow LAN",
        }
    )

    assert rule.uuid == "abc"
    assert rule.editable is True
    assert rule.enabled is True
    assert rule.action == "pass"
    assert rule.interfaces == "lan"
    assert rule.source == "lan"
    assert rule.destination == "any"


def test_normalize_rule_marks_legacy_rule_read_only() -> None:
    rule = routes.normalize_rule({"uuid": "legacy-1", "legacy": "1", "action": "block"})

    assert rule.editable is False
    assert rule.legacy is True


def test_normalize_rule_renders_selected_gateway_object() -> None:
    rule = routes.normalize_rule(
        {
            "uuid": "abc",
            "gateway": {"WAN_DHCP": {"selected": "1", "value": "WAN_DHCP", "label": "WAN DHCP"}},
        }
    )

    assert rule.gateway == "WAN_DHCP"


@pytest.mark.asyncio
async def test_search_rules_maps_dashboard_filters_to_opnsense(monkeypatch) -> None:
    inst = SimpleNamespace(id=7, device_type="opnsense", transport="direct")
    calls: list[tuple[str, str, str, dict | None]] = []

    async def fake_get_instance(_session, _instance_id, _user):
        return inst

    async def fake_opnsense_json(instance, method, path, body=None):
        calls.append((instance.transport, method, path, body))
        return {
            "total": 1,
            "rowCount": 200,
            "current": 1,
            "rows": [{"uuid": "abc", "enabled": "1", "action": "pass"}],
        }

    monkeypatch.setattr(routes.inst_service, "get_instance", fake_get_instance)
    monkeypatch.setattr(routes, "_opnsense_json", fake_opnsense_json)

    result = await routes.search_rules(
        instance_id=7,
        interface="lan",
        category=["cat-a"],
        search="web",
        show_all=True,
        current=1,
        row_count=200,
        session=object(),
        user=object(),
    )

    assert result.total == 1
    assert result.rows[0].uuid == "abc"
    _, method, path, body = calls[0]
    assert method == "POST"
    assert path == "/api/firewall/filter/search_rule?show_all=1&interface=lan&category=cat-a"
    assert body == {"current": 1, "rowCount": 200, "sort": {}, "searchPhrase": "web"}


@pytest.mark.asyncio
async def test_search_rules_uses_empty_interface_for_floating(monkeypatch) -> None:
    inst = SimpleNamespace(id=7, device_type="opnsense", transport="direct")
    paths: list[str] = []

    async def fake_get_instance(_session, _instance_id, _user):
        return inst

    async def fake_opnsense_json(_instance, _method, path, _body=None):
        paths.append(path)
        return {"rows": []}

    monkeypatch.setattr(routes.inst_service, "get_instance", fake_get_instance)
    monkeypatch.setattr(routes, "_opnsense_json", fake_opnsense_json)

    await routes.search_rules(
        instance_id=7,
        interface="__floating",
        category=[],
        search="",
        show_all=False,
        current=1,
        row_count=200,
        session=object(),
        user=object(),
    )

    assert paths[0] == "/api/firewall/filter/search_rule?interface="


@pytest.mark.asyncio
async def test_add_rule_posts_opnsense_rule_wrapper(monkeypatch) -> None:
    inst = SimpleNamespace(id=7, device_type="opnsense", transport="direct")
    calls: list[tuple[str, str, dict | None]] = []
    audits: list[tuple[str, str | None]] = []

    async def fake_get_instance(_session, _instance_id, _user):
        return inst

    async def fake_opnsense_json(_instance, method, path, body=None):
        calls.append((method, path, body))
        return {"result": "saved", "uuid": "abc"}

    async def fake_audit(_session, _request, _user, action, _instance_id, result, uuid=None):
        audits.append((action, uuid or result.uuid))

    monkeypatch.setattr(routes.inst_service, "get_instance", fake_get_instance)
    monkeypatch.setattr(routes, "_opnsense_json", fake_opnsense_json)
    monkeypatch.setattr(routes, "_audit_rule_write", fake_audit)

    result = await routes.add_rule(
        instance_id=7,
        payload=FirewallRuleMutation(rule={"action": "pass"}),
        request=object(),
        session=object(),
        user=object(),
    )

    assert result.result == "saved"
    assert result.uuid == "abc"
    assert calls == [
        ("POST", "/api/firewall/filter/add_rule", {"rule": {"action": "pass"}}),
    ]
    assert audits == [("firewall.rule.add", "abc")]


@pytest.mark.asyncio
async def test_set_rule_posts_to_uuid_endpoint(monkeypatch) -> None:
    inst = SimpleNamespace(id=7, device_type="opnsense", transport="direct")
    calls: list[tuple[str, str, dict | None]] = []

    async def fake_get_instance(_session, _instance_id, _user):
        return inst

    async def fake_opnsense_json(_instance, method, path, body=None):
        calls.append((method, path, body))
        return {"result": "saved"}

    async def fake_audit(*_args, **_kwargs):
        return None

    monkeypatch.setattr(routes.inst_service, "get_instance", fake_get_instance)
    monkeypatch.setattr(routes, "_opnsense_json", fake_opnsense_json)
    monkeypatch.setattr(routes, "_audit_rule_write", fake_audit)

    result = await routes.set_rule(
        instance_id=7,
        rule_uuid="abc",
        payload=FirewallRuleMutation(rule={"description": "updated"}),
        request=object(),
        session=object(),
        user=object(),
    )

    assert result.result == "saved"
    assert calls == [
        (
            "POST",
            "/api/firewall/filter/set_rule/abc",
            {"rule": {"description": "updated"}},
        ),
    ]


@pytest.mark.asyncio
async def test_apply_rules_calls_filter_base_apply(monkeypatch) -> None:
    inst = SimpleNamespace(id=7, device_type="opnsense", transport="direct")
    paths: list[str] = []

    async def fake_get_instance(_session, _instance_id, _user):
        return inst

    async def fake_opnsense_json(_instance, _method, path, _body=None):
        paths.append(path)
        return {"status": "OK"}

    async def fake_audit(*_args, **_kwargs):
        return None

    monkeypatch.setattr(routes.inst_service, "get_instance", fake_get_instance)
    monkeypatch.setattr(routes, "_opnsense_json", fake_opnsense_json)
    monkeypatch.setattr(routes, "_audit_rule_write", fake_audit)

    result = await routes.apply_rules(
        instance_id=7,
        request=object(),
        session=object(),
        user=object(),
    )

    assert result.status == "OK"
    assert paths == ["/api/firewall/filter_base/apply"]
