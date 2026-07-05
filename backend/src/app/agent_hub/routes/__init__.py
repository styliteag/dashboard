"""Agent WebSocket endpoint + REST routes for agent management.

Split by concern: ws (agent + tunnel WebSockets), management (enable/disable/
status/token/command), update (self-update push + script downloads), relay
(local firewall API proxy), gui (GUI-proxy auth gate), enroll (uninstall +
enrollment), stats (hub self-monitoring). This package aggregates their
routers into the single `router` that main.py includes.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.agent_hub.routes import enroll, gui, management, relay, stats, update, ws

router = APIRouter(tags=["agent"])
for _sub in (ws, management, update, relay, gui, enroll, stats):
    router.include_router(_sub.router)
