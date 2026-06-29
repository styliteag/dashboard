"""Out-of-band reachability probe (ICMP + HTTP), independent of the agent.

A push agent going silent tells us telemetry stopped — not whether the box is
down. An admin-supplied ``ping_url`` lets the dashboard check the box directly:
ICMP echo (is it on the network?) and an HTTP GET (is the management service
answering?). Together with agent freshness this distinguishes "box up, agent
dead" from "box down" (the confidence model in ``app.checks.confidence``).

Stdlib only for ICMP (no iputils / no raw subprocess); httpx for HTTP.
"""

from app.probe.runner import ProbeResult, run_probe

__all__ = ["ProbeResult", "run_probe"]
