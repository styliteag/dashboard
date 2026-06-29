"""In-memory probe state with flap debounce.

A single dropped packet must not flip a box red (and page someone) — so each axis
(ICMP, HTTP) only transitions to *down* after ``threshold`` consecutive failures;
recovery is immediate on the first success. The reducer (:func:`reduce_axis`) is
pure and unit-tested; :class:`ProbeRegistry` is the process-wide singleton the
scheduler writes and the check routes read (mirrors ``agent_hub.hub``).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.probe.runner import ProbeResult


@dataclass(frozen=True)
class AxisState:
    """Debounced state of one probe axis: the stable up/down and the fail streak."""

    up: bool | None = None  # None = undecided (never up, not yet past threshold)
    fail_streak: int = 0


def reduce_axis(prev: AxisState, raw_up: bool | None, threshold: int) -> AxisState:
    """Fold one raw measurement into the debounced axis state.

    ``raw_up`` is None when the axis doesn't apply to this target (e.g. a bare-host
    ping_url has no HTTP axis) — a structural property of the ping_url, not a
    transient, so the axis resets to "no signal". A success resets to up
    immediately; failures accrue and only flip to down once ``threshold``
    consecutive ones land — until then the previous stable value holds.
    """
    if raw_up is None:
        return AxisState()
    if raw_up:
        return AxisState(up=True, fail_streak=0)
    streak = prev.fail_streak + 1
    up = False if streak >= max(1, threshold) else prev.up
    return AxisState(up=up, fail_streak=streak)


@dataclass
class _Entry:
    icmp: AxisState = field(default_factory=AxisState)
    http: AxisState = field(default_factory=AxisState)
    last: ProbeResult = field(default_factory=ProbeResult)


class ProbeRegistry:
    """Per-instance debounced probe results (process-wide singleton)."""

    def __init__(self) -> None:
        self._by_id: dict[int, _Entry] = {}

    def update(self, instance_id: int, raw: ProbeResult, threshold: int) -> None:
        prev = self._by_id.get(instance_id, _Entry())
        self._by_id[instance_id] = _Entry(
            icmp=reduce_axis(prev.icmp, raw.icmp_up, threshold),
            http=reduce_axis(prev.http, raw.http_up, threshold),
            last=raw,
        )

    def get(self, instance_id: int) -> ProbeResult | None:
        """The debounced view, or None if this instance has never been probed."""
        e = self._by_id.get(instance_id)
        if e is None:
            return None
        return ProbeResult(
            icmp_up=e.icmp.up,
            http_up=e.http.up,
            rtt_ms=e.last.rtt_ms,
            http_status=e.last.http_status,
        )

    def forget(self, instance_id: int) -> None:
        """Drop state (ping_url cleared or instance deleted)."""
        self._by_id.pop(instance_id, None)

    def prune(self, keep: set[int]) -> None:
        """Drop state for any instance not in ``keep`` (no longer has a ping target)."""
        for instance_id in list(self._by_id):
            if instance_id not in keep:
                del self._by_id[instance_id]


# Process-wide singleton, mirroring agent_hub.hub.
probe_registry = ProbeRegistry()
