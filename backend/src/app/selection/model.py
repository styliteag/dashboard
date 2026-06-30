"""Pure logic for service selection — DB-free and unit-testable.

One model drives both the Checkmk export *and* the notification channels
(Mattermost / Telegram / Email). Each is a *consumer*; a consumer is interested
in a set of (instance, service) pairs.

A *rule* is ``(consumer, instance_id | None, selector, mode)``:
  * ``consumer`` — ``checkmk`` or a notification channel.
  * ``instance_id`` ``None`` applies the rule to every instance (global); a value
    scopes it to one instance.
  * ``selector`` — either a **category** token (the part before the first ``:`` in
    a check key — ``cpu``, ``gateway``, ``ipsec.tunnel_ping`` …) or a **full**
    check key (``gateway:WAN``).
  * ``mode`` — ``include`` (turn on) or ``exclude`` (turn off / override).

**The base default is OFF for every consumer** — nothing is selected until a rule
includes it. Bidirectional: ``include`` adds, ``exclude`` mutes (an override under
an included category). Resolution is by precedence, *most specific wins*:

  1. instance + full key
  2. instance + category
  3. global + full key
  4. global + category
  5. base default (off)

The first matching level decides via its ``mode``. So a globally-included category
with a per-service ``exclude`` mutes that one service; a per-service ``include``
adds a single service that nothing else turned on. ``UNIQUE(consumer, instance_id,
selector)`` guarantees at most one rule per level — no ties.
"""

from __future__ import annotations

from collections.abc import Iterable

# The check categories = the prefix (before the first ":") of every key emitted by
# ``evaluate_checks``. Order is the display order in the Settings UI. INVARIANT:
# keep this in lock-step with the keys ``evaluate_checks`` can produce — a new check
# family that isn't listed here can't be toggled as a category in the Settings UI
# (only via a full-key rule). The frontend ``CATEGORY_LABELS`` mirror must grow too.
CHECK_CATEGORIES: tuple[str, ...] = (
    "agent",  # agent-staleness service (push mode)
    "maintenance",  # maintenance-mode banner (alerts capped at WARN)
    "ping",  # out-of-band ICMP reachability probe
    "http",  # out-of-band HTTP reachability probe
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
    "connectivity",  # standalone (tunnel-independent) ping monitors
    "service",
    "cert",
    "iface_errors",
    "firmware",
)

# Instance/agent offline & recovered events — not a service check, its own bucket.
# Notification-only: the Checkmk export never emits it (Checkmk does host up/down
# on its side), so it is offered only to the channel consumers.
AVAILABILITY = "availability"

# The consumers. ``checkmk`` is the export; the rest are notification channels.
CHECKMK = "checkmk"
CHANNELS: tuple[str, ...] = ("mattermost", "telegram", "email")
CONSUMERS: tuple[str, ...] = (CHECKMK, *CHANNELS)

INCLUDE = "include"
EXCLUDE = "exclude"
MODES: tuple[str, ...] = (INCLUDE, EXCLUDE)

# A rule as loaded from ``selection_rules``.
Rule = tuple[str, int | None, str, str]  # (consumer, instance_id, selector, mode)


def categories_for(consumer: str) -> tuple[str, ...]:
    """Selectable categories for a consumer. Channels also get ``availability``
    (instance up/down); the Checkmk export does not (it isn't exported)."""
    if consumer == CHECKMK:
        return CHECK_CATEGORIES
    return (AVAILABILITY, *CHECK_CATEGORIES)


def category(check_key: str) -> str:
    """Category token: the part before the first ``:``.

    Keys without a ``:`` (``memory``, ``cpu``, ``ipsec.service``, ``firmware``,
    ``availability``) are their own category. ``split(":", 1)`` keeps IPv6
    selectors intact (only the first colon splits).
    """
    return check_key.split(":", 1)[0]


# Precedence ranks (higher wins). Encodes "instance beats global" as the primary
# key and "specific beats category" as the secondary.
_RANK_INSTANCE_SPECIFIC = 4
_RANK_INSTANCE_CATEGORY = 3
_RANK_GLOBAL_SPECIFIC = 2
_RANK_GLOBAL_CATEGORY = 1
_RANK_REASON = {
    _RANK_INSTANCE_SPECIFIC: "instance",
    _RANK_INSTANCE_CATEGORY: "instance_category",
    _RANK_GLOBAL_SPECIFIC: "global",
    _RANK_GLOBAL_CATEGORY: "global_category",
}


def resolve(
    consumer: str, check_key: str, instance_id: int, rules: Iterable[Rule]
) -> tuple[bool, str]:
    """Return ``(on, reason)`` for one (consumer, instance, check).

    ``on`` is whether the consumer is interested in this check. ``reason`` is the
    level that decided: ``instance`` / ``instance_category`` / ``global`` /
    ``global_category`` (when a rule matched) or ``default`` (base default off).
    The base default is OFF for every consumer.
    """
    cat = category(check_key)
    best_rank = 0
    best_mode = ""
    for r_consumer, r_instance, r_selector, r_mode in rules:
        if r_consumer != consumer:
            continue
        is_instance = r_instance == instance_id
        if not (is_instance or r_instance is None):
            continue
        if r_selector == check_key:
            rank = _RANK_INSTANCE_SPECIFIC if is_instance else _RANK_GLOBAL_SPECIFIC
        elif r_selector == cat:
            rank = _RANK_INSTANCE_CATEGORY if is_instance else _RANK_GLOBAL_CATEGORY
        else:
            continue
        if rank > best_rank:
            best_rank = rank
            best_mode = r_mode
    if best_rank == 0:
        return (False, "default")
    return (best_mode == INCLUDE, _RANK_REASON[best_rank])


def is_on(consumer: str, check_key: str, instance_id: int, rules: Iterable[Rule]) -> bool:
    """True when the consumer is interested in this check for this instance."""
    return resolve(consumer, check_key, instance_id, rules)[0]


def valid_consumer(consumer: str) -> bool:
    return consumer in CONSUMERS


def valid_mode(mode: str) -> bool:
    return mode in MODES


def valid_selector(consumer: str, selector: str) -> bool:
    """A selector is valid when its category is one this consumer offers. This
    accepts both a bare category token and a full check key (its prefix must be a
    known category) — so garbage like ``foo:bar`` is rejected."""
    return category(selector) in categories_for(consumer)
