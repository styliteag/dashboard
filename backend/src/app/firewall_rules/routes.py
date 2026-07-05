"""OPNsense firewall rule editor endpoints."""

from __future__ import annotations

import base64
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import hub
from app.audit.log import write_audit
from app.auth.deps import current_user, require_write
from app.db.base import get_session
from app.db.models import Instance, User
from app.devices.types import DeviceType, Transport
from app.firewall_rules.schemas import (
    FirewallActionResult,
    FirewallRule,
    FirewallRuleDetail,
    FirewallRuleMove,
    FirewallRuleMutation,
    FirewallRuleOptions,
    FirewallRuleSearchResponse,
)
from app.instances import service as inst_service
from app.net import client_ip
from app.xsense.client import OPNsenseClient, OPNsenseError
from app.xsense.registry import registry

router = APIRouter(prefix="/instances/{instance_id}/firewall", tags=["firewall-rules"])


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on", "enabled"}


def _field_text(value: Any) -> str:
    """Render OPNsense form/list field values without leaking object reprs.

    Several MVC select fields arrive as nested option objects depending on API
    endpoint and OPNsense version. The UI needs the selected value/label, not
    Python's ``{'...': ...}`` representation.
    """
    if value is None:
        return ""
    if isinstance(value, str | int | float | bool):
        return str(value)
    if isinstance(value, list):
        return ", ".join(part for part in (_field_text(item) for item in value) if part)
    if isinstance(value, dict):
        for key in ("selected", "value", "label", "text", "__text"):
            if key in value and not isinstance(value[key], dict | list):
                return str(value[key])
        for key, item in value.items():
            if isinstance(item, dict) and _truthy(item.get("selected")):
                return _field_text(item.get("value") or item.get("label") or key)
        truthy_keys = [str(key) for key, item in value.items() if _truthy(item)]
        if truthy_keys:
            return ", ".join(truthy_keys)
    return str(value)


def normalize_rule(row: dict[str, Any]) -> FirewallRule:
    uuid = str(row.get("uuid") or row.get("@uuid") or "")
    legacy = _truthy(row.get("legacy")) or _truthy(row.get("internal"))
    disabled = _truthy(row.get("disabled"))
    enabled = _truthy(row.get("enabled")) if "enabled" in row else not disabled
    editable = bool(uuid) and not legacy
    return FirewallRule(
        uuid=uuid,
        editable=editable,
        enabled=enabled,
        log=_truthy(row.get("log")),
        action=_field_text(row.get("action") or row.get("%action")),
        direction=_field_text(row.get("direction") or row.get("%direction")),
        ip_protocol=_field_text(row.get("ipprotocol") or row.get("%ipprotocol")),
        protocol=_field_text(row.get("protocol")),
        interfaces=_field_text(row.get("interface")),
        source=_field_text(row.get("source_net") or row.get("source")),
        source_port=_field_text(row.get("source_port")),
        destination=_field_text(row.get("destination_net") or row.get("destination")),
        destination_port=_field_text(row.get("destination_port")),
        gateway=_field_text(row.get("gateway")),
        categories=_field_text(row.get("categories") or row.get("category")),
        description=_field_text(row.get("description")),
        sequence=_field_text(row.get("sequence")),
        sort_order=_field_text(row.get("sort_order")),
        prio_group=_field_text(row.get("prio_group")),
        legacy=legacy,
        raw=row,
    )


def _query_path(path: str, params: dict[str, Any]) -> str:
    clean = {k: v for k, v in params.items() if v not in (None, [])}
    return f"{path}?{urlencode(clean, doseq=True)}" if clean else path


async def _relay_json(instance_id: int, method: str, path: str, body: dict | None = None) -> Any:
    agent = hub.get(instance_id)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="agent not connected"
        )
    raw_body = b""
    if body is not None:
        import json

        raw_body = json.dumps(body).encode()
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    result = await agent.send_command(
        "http.relay",
        {
            "method": method,
            "path": path.lstrip("/"),
            "headers": headers,
            "body": base64.b64encode(raw_body).decode(),
        },
        timeout=30,
    )
    if not result or result.get("status", 0) == 0:
        detail = result.get("output", "relay failed") if result else "relay failed"
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=detail)
    status_code = int(result.get("status") or 0)
    if status_code >= 400:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"HTTP {status_code}")
    try:
        import json

        data = base64.b64decode(result.get("body") or "")
        return json.loads(data.decode() or "{}")
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="invalid JSON response"
        ) from exc


async def _opnsense_json(inst: Instance, method: str, path: str, body: dict | None = None) -> Any:
    if inst.transport in {Transport.PUSH.value, Transport.RELAY.value}:
        return await _relay_json(inst.id, method, path, body)

    client = await registry.get(inst)
    if not isinstance(client, OPNsenseClient):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="firewall rules are only supported for OPNsense instances",
        )
    try:
        if method == "GET":
            return await client.api_get(path)
        return await client.api_post(path, body)
    except OPNsenseError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc


def _action_result(data: Any) -> FirewallActionResult:
    if not isinstance(data, dict):
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="invalid API response")
    return FirewallActionResult(
        result=str(data.get("result") or ""),
        status=str(data.get("status") or ""),
        uuid=str(data["uuid"]) if data.get("uuid") else None,
        changed=bool(data["changed"]) if "changed" in data else None,
        validations=data.get("validations"),
        raw=data,
    )


def _action_ok(result: FirewallActionResult) -> bool:
    token = (result.result or result.status).lower()
    return token in {"saved", "deleted", "enabled", "disabled", "ok", "ok\n", "done"}


async def _audit_rule_write(
    session: AsyncSession,
    request: Request,
    user: User,
    action: str,
    instance_id: int,
    result: FirewallActionResult,
    uuid: str | None = None,
) -> None:
    await write_audit(
        session,
        action=action,
        result="ok" if _action_ok(result) else "error",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=client_ip(request),
        detail={"uuid": uuid or result.uuid, "upstream": result.raw},
    )
    await session.commit()


async def _get_opnsense_instance(session: AsyncSession, instance_id: int, user: User) -> Instance:
    inst = await inst_service.get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    if inst.device_type != DeviceType.OPNSENSE.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="firewall rules are only supported for OPNsense instances",
        )
    return inst


@router.get("/rules", response_model=FirewallRuleSearchResponse)
async def search_rules(
    instance_id: int,
    interface: str | None = Query(default=None),
    category: list[str] = Query(default_factory=list),
    search: str = "",
    show_all: bool = True,
    current: int = 1,
    row_count: int = 200,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> FirewallRuleSearchResponse:
    inst = await _get_opnsense_instance(session, instance_id, user)

    params: dict[str, Any] = {"show_all": "1" if show_all else None}
    if interface == "__floating":
        params["interface"] = ""
    elif interface and interface != "__any":
        params["interface"] = interface
    if category:
        params["category"] = category

    path = _query_path("/api/firewall/filter/search_rule", params)
    data = await _opnsense_json(
        inst,
        "POST",
        path,
        {
            "current": current,
            "rowCount": row_count,
            "sort": {},
            "searchPhrase": search,
        },
    )
    rows = [normalize_rule(row) for row in data.get("rows", []) if isinstance(row, dict)]
    return FirewallRuleSearchResponse(
        total=int(data.get("total") or len(rows)),
        row_count=int(data.get("rowCount") or len(rows)),
        current=int(data.get("current") or current),
        rows=rows,
    )


@router.get("/rules/options", response_model=FirewallRuleOptions)
async def rule_options(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> FirewallRuleOptions:
    inst = await _get_opnsense_instance(session, instance_id, user)

    async def get(path: str) -> dict[str, Any]:
        try:
            data = await _opnsense_json(inst, "GET", path)
            return data if isinstance(data, dict) else {}
        except HTTPException:
            return {}

    return FirewallRuleOptions(
        interfaces=await get("/api/firewall/filter/get_interface_list"),
        networks=await get("/api/firewall/filter_base/list_network_select_options"),
        ports=await get("/api/firewall/filter_base/list_port_select_options"),
        categories=await get("/api/firewall/filter_base/list_categories"),
    )


@router.get("/rules/template", response_model=FirewallRuleDetail)
async def rule_template(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> FirewallRuleDetail:
    inst = await _get_opnsense_instance(session, instance_id, user)
    data = await _opnsense_json(inst, "GET", "/api/firewall/filter/get_rule")
    rule = data.get("rule", {}) if isinstance(data, dict) else {}
    return FirewallRuleDetail(rule=rule if isinstance(rule, dict) else {})


@router.get("/rules/{rule_uuid}", response_model=FirewallRuleDetail)
async def get_rule(
    instance_id: int,
    rule_uuid: str,
    copy: bool = False,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> FirewallRuleDetail:
    inst = await _get_opnsense_instance(session, instance_id, user)
    path = f"/api/firewall/filter/get_rule/{rule_uuid}"
    if copy:
        path += "?fetchmode=copy"
    data = await _opnsense_json(inst, "GET", path)
    rule = data.get("rule", {}) if isinstance(data, dict) else {}
    return FirewallRuleDetail(uuid=rule_uuid, rule=rule if isinstance(rule, dict) else {})


@router.post("/rules", response_model=FirewallActionResult)
async def add_rule(
    instance_id: int,
    payload: FirewallRuleMutation,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> FirewallActionResult:
    inst = await _get_opnsense_instance(session, instance_id, user)
    result = _action_result(
        await _opnsense_json(inst, "POST", "/api/firewall/filter/add_rule", {"rule": payload.rule})
    )
    await _audit_rule_write(session, request, user, "firewall.rule.add", instance_id, result)
    return result


@router.put("/rules/{rule_uuid}", response_model=FirewallActionResult)
async def set_rule(
    instance_id: int,
    rule_uuid: str,
    payload: FirewallRuleMutation,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> FirewallActionResult:
    inst = await _get_opnsense_instance(session, instance_id, user)
    result = _action_result(
        await _opnsense_json(
            inst, "POST", f"/api/firewall/filter/set_rule/{rule_uuid}", {"rule": payload.rule}
        )
    )
    await _audit_rule_write(
        session, request, user, "firewall.rule.set", instance_id, result, rule_uuid
    )
    return result


@router.delete("/rules/{rule_uuid}", response_model=FirewallActionResult)
async def delete_rule(
    instance_id: int,
    rule_uuid: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> FirewallActionResult:
    inst = await _get_opnsense_instance(session, instance_id, user)
    result = _action_result(
        await _opnsense_json(inst, "POST", f"/api/firewall/filter/del_rule/{rule_uuid}")
    )
    await _audit_rule_write(
        session, request, user, "firewall.rule.delete", instance_id, result, rule_uuid
    )
    return result


@router.post("/rules/{rule_uuid}/toggle", response_model=FirewallActionResult)
async def toggle_rule(
    instance_id: int,
    rule_uuid: str,
    request: Request,
    enabled: bool | None = None,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> FirewallActionResult:
    inst = await _get_opnsense_instance(session, instance_id, user)
    suffix = "" if enabled is None else f"/{1 if enabled else 0}"
    result = _action_result(
        await _opnsense_json(inst, "POST", f"/api/firewall/filter/toggle_rule/{rule_uuid}{suffix}")
    )
    await _audit_rule_write(
        session, request, user, "firewall.rule.toggle", instance_id, result, rule_uuid
    )
    return result


@router.post("/rules/{rule_uuid}/toggle-log", response_model=FirewallActionResult)
async def toggle_rule_log(
    instance_id: int,
    rule_uuid: str,
    request: Request,
    log: bool,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> FirewallActionResult:
    inst = await _get_opnsense_instance(session, instance_id, user)
    result = _action_result(
        await _opnsense_json(
            inst, "POST", f"/api/firewall/filter/toggle_rule_log/{rule_uuid}/{1 if log else 0}"
        )
    )
    await _audit_rule_write(
        session, request, user, "firewall.rule.toggle_log", instance_id, result, rule_uuid
    )
    return result


@router.post("/rules/move", response_model=FirewallActionResult)
async def move_rule(
    instance_id: int,
    payload: FirewallRuleMove,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> FirewallActionResult:
    inst = await _get_opnsense_instance(session, instance_id, user)
    result = _action_result(
        await _opnsense_json(
            inst,
            "POST",
            f"/api/firewall/filter/move_rule_before/{payload.selected_uuid}/{payload.target_uuid}",
        )
    )
    await _audit_rule_write(
        session, request, user, "firewall.rule.move", instance_id, result, payload.selected_uuid
    )
    return result


@router.post("/rules/apply", response_model=FirewallActionResult)
async def apply_rules(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> FirewallActionResult:
    inst = await _get_opnsense_instance(session, instance_id, user)
    result = _action_result(await _opnsense_json(inst, "POST", "/api/firewall/filter_base/apply"))
    await _audit_rule_write(session, request, user, "firewall.rule.apply", instance_id, result)
    return result


@router.get("/aliases", response_model=dict)
async def get_aliases(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> dict:
    """Return alias names for address/alias completion (used by packet viewer etc).

    Tries OPNsense API first, falls back to agent command "get_aliases".
    """
    inst = await inst_service.get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    # Try OPNsense style via the options endpoint
    if inst.device_type == DeviceType.OPNSENSE.value:
        try:
            data = await _opnsense_json(
                inst, "GET", "/api/firewall/filter_base/list_network_select_options"
            )
            aliases: list[str] = []
            if isinstance(data, dict):
                for section in data.values():
                    if isinstance(section, dict) and isinstance(section.get("items"), dict):
                        for k in section["items"]:
                            low = k.lower()
                            if k and not any(g in low for g in ("any", "lan", "wan", "loopback")):
                                aliases.append(k)
            if aliases:
                return {"aliases": sorted(set(aliases))}
        except Exception:
            pass

    # Fallback to agent (works for pfSense too)
    agent = hub.get(instance_id)
    if agent:
        try:
            res = await agent.send_command("get_aliases", {})
            if res.get("success") and isinstance(res.get("aliases"), list):
                names = []
                for a in res["aliases"]:
                    if isinstance(a, str):
                        names.append(a)
                    elif isinstance(a, dict) and a.get("name"):
                        names.append(a["name"])
                return {"aliases": sorted(set(names))}
        except Exception:
            pass

    return {"aliases": []}
