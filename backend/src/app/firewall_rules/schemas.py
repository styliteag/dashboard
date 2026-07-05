"""Schemas for the dashboard firewall rule editor."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FirewallRule(BaseModel):
    uuid: str
    editable: bool = False
    enabled: bool = True
    log: bool = False
    action: str = ""
    direction: str = ""
    ip_protocol: str = ""
    protocol: str = ""
    interfaces: str = ""
    source: str = ""
    source_port: str = ""
    destination: str = ""
    destination_port: str = ""
    gateway: str = ""
    categories: str = ""
    description: str = ""
    sequence: str = ""
    sort_order: str = ""
    prio_group: str = ""
    legacy: bool = False
    raw: dict[str, Any] = Field(default_factory=dict)


class FirewallRuleSearchResponse(BaseModel):
    total: int = 0
    row_count: int = Field(default=0, serialization_alias="rowCount")
    current: int = 1
    rows: list[FirewallRule] = Field(default_factory=list)


class FirewallRuleOptions(BaseModel):
    interfaces: dict[str, Any] = Field(default_factory=dict)
    networks: dict[str, Any] = Field(default_factory=dict)
    ports: dict[str, Any] = Field(default_factory=dict)
    categories: dict[str, Any] = Field(default_factory=dict)


class FirewallRuleDetail(BaseModel):
    uuid: str | None = None
    rule: dict[str, Any] = Field(default_factory=dict)


class FirewallRuleMutation(BaseModel):
    rule: dict[str, Any]


class FirewallRuleMove(BaseModel):
    selected_uuid: str
    target_uuid: str


class FirewallActionResult(BaseModel):
    result: str = ""
    status: str = ""
    uuid: str | None = None
    changed: bool | None = None
    validations: dict[str, Any] | list[Any] | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
