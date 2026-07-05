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
async def test_apply_rules_calls_filter_apply(monkeypatch) -> None:
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
    assert paths == ["/api/firewall/filter/apply"]


def test_alias_from_row_maps_name_and_content() -> None:
    assert routes._alias_from_row({"name": "webservers", "content": "10.0.0.1\n10.0.0.2"}) == {
        "name": "webservers",
        "address": "10.0.0.1, 10.0.0.2",
    }
    # External/URL tables (bogons) carry no content → address stays None.
    assert routes._alias_from_row({"name": "bogons", "content": ""}) == {
        "name": "bogons",
        "address": None,
    }
    assert routes._alias_from_row({"name": ""}) is None
    assert routes._alias_from_row("nope") is None
    # OPNsense internal __<if>_network aliases are dropped (networks cover them).
    assert routes._alias_from_row({"name": "__lan_network", "content": ""}) is None


@pytest.mark.asyncio
async def test_rule_options_uses_filter_controller_paths(monkeypatch) -> None:
    # filter_base is the abstract base controller and is not routable — every
    # select-options call must go through the concrete `filter` controller.
    inst = SimpleNamespace(id=7, device_type="opnsense", transport="direct")
    paths: list[str] = []

    async def fake_get_instance(_session, _instance_id, _user):
        return inst

    async def fake_opnsense_json(_instance, _method, path, _body=None):
        paths.append(path)
        return {}

    monkeypatch.setattr(routes.inst_service, "get_instance", fake_get_instance)
    monkeypatch.setattr(routes, "_opnsense_json", fake_opnsense_json)

    await routes.rule_options(instance_id=7, session=object(), user=object())

    assert not any("filter_base" in p for p in paths)
    assert "/api/firewall/filter/list_network_select_options" in paths
    assert "/api/firewall/filter/list_port_select_options" in paths
    assert "/api/firewall/filter/list_categories" in paths


@pytest.mark.asyncio
async def test_get_aliases_opnsense_uses_search_item(monkeypatch) -> None:
    inst = SimpleNamespace(id=7, device_type="opnsense", transport="direct")
    paths: list[str] = []

    async def fake_get_instance(_session, _instance_id, _user):
        return inst

    async def fake_opnsense_json(_instance, _method, path, _body=None):
        paths.append(path)
        return {"rows": [{"name": "webservers", "content": "10.0.0.1"}]}

    monkeypatch.setattr(routes.inst_service, "get_instance", fake_get_instance)
    monkeypatch.setattr(routes, "_opnsense_json", fake_opnsense_json)
    monkeypatch.setattr(routes.hub, "get", lambda _id: None)

    result = await routes.get_aliases(instance_id=7, session=object(), user=object())

    assert result == {"aliases": [{"name": "webservers", "address": "10.0.0.1"}]}
    assert paths[0].startswith("/api/firewall/alias/search_item")


@pytest.mark.asyncio
async def test_get_aliases_empty_agent_reply_does_not_mask_api(monkeypatch) -> None:
    # A push agent that answers get_aliases with an empty list must not suppress
    # the OPNsense alias API (regression: empty-but-successful reply short-circuited).
    inst = SimpleNamespace(id=7, device_type="opnsense", transport="push")

    async def fake_get_instance(_session, _instance_id, _user):
        return inst

    async def fake_opnsense_json(_instance, _method, _path, _body=None):
        return {"rows": [{"name": "lan_hosts", "content": "192.168.1.0/24"}]}

    class FakeAgent:
        async def send_command(self, _cmd, _params):
            return {"success": True, "aliases": []}

    monkeypatch.setattr(routes.inst_service, "get_instance", fake_get_instance)
    monkeypatch.setattr(routes, "_opnsense_json", fake_opnsense_json)
    monkeypatch.setattr(routes.hub, "get", lambda _id: FakeAgent())

    result = await routes.get_aliases(instance_id=7, session=object(), user=object())

    assert result == {"aliases": [{"name": "lan_hosts", "address": "192.168.1.0/24"}]}


@pytest.mark.asyncio
async def test_get_aliases_pfsense_uses_agent(monkeypatch) -> None:
    inst = SimpleNamespace(id=8, device_type="pfsense", transport="push")

    async def fake_get_instance(_session, _instance_id, _user):
        return inst

    class FakeAgent:
        async def send_command(self, _cmd, _params):
            return {"success": True, "aliases": [{"name": "vpn_net", "address": "10.8.0.0/24"}]}

    monkeypatch.setattr(routes.inst_service, "get_instance", fake_get_instance)
    monkeypatch.setattr(routes.hub, "get", lambda _id: FakeAgent())

    result = await routes.get_aliases(instance_id=8, session=object(), user=object())

    assert result == {"aliases": [{"name": "vpn_net", "address": "10.8.0.0/24"}]}
