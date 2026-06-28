"""Pure logic for Checkmk export exclusions — DB-free and unit-testable.

A *rule* is ``(instance_id | None, target)``:
  * ``instance_id`` ``None`` applies the rule to every instance.
  * ``target`` is either a **category** token (the part before the first ``:`` in
    a check key — ``cpu``, ``gateway``, ``ipsec.tunnel_ping`` …) or a **full**
    check key (``gateway:WAN``).

A check is excluded from the export when some rule matches its instance (or is
global) AND matches its full key OR its category.
"""

from __future__ import annotations

from collections.abc import Iterable

# The export categories = the prefix (before the first ":") of every key emitted
# by ``evaluate_checks``. Order is the display order in the Settings UI. INVARIANT:
# keep this in lock-step with the keys ``evaluate_checks`` can produce — a new
# check family that isn't listed here can't be toggled off in the Settings UI
# (only via a full-key rule). The frontend ``CATEGORY_LABELS`` mirror must grow too.
CATEGORIES: tuple[str, ...] = (
    "memory",
    "cpu",
    "load",
    "swap",
    "disk",
    "gateway",
    "pf_states",
    "ntp",
    "ipsec.service",
    "ipsec.tunnel",
    "ipsec.tunnel_ping",
    "service",
    "cert",
    "iface_errors",
    "firmware",
)

# A rule as loaded from ``checkmk_export_exclusions``.
Rule = tuple[int | None, str]


def category(check_key: str) -> str:
    """Category token: the part before the first ``:``.

    Keys without a ``:`` (``memory``, ``cpu``, ``ipsec.service``, ``firmware``)
    are their own category. ``split(":", 1)`` keeps IPv6 selectors intact (only
    the first colon splits).
    """
    return check_key.split(":", 1)[0]


def excluded_reason(check_key: str, instance_id: int, rules: Iterable[Rule]) -> str | None:
    """Return ``"category"`` / ``"specific"`` if excluded, else ``None``.

    A category-level rule (target == the check's category) reports ``"category"``;
    a full-key rule reports ``"specific"``. Category rules win when both match.
    """
    cat = category(check_key)
    specific = False
    for rule_instance, target in rules:
        if rule_instance is not None and rule_instance != instance_id:
            continue
        if target == cat:
            return "category"
        if target == check_key:
            specific = True
    return "specific" if specific else None


def is_excluded(check_key: str, instance_id: int, rules: Iterable[Rule]) -> bool:
    """True when the check is hidden from the Checkmk export for this instance."""
    return excluded_reason(check_key, instance_id, rules) is not None
