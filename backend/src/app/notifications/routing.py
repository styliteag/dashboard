"""Per-channel notification routing — which alert categories each channel gets.

A *route* is ``(instance_id, channel, category, enabled)``: its presence wires a
channel to a category. ``instance_id`` ``None`` is a **global** route (applies to
every instance); a non-NULL value scopes it to one instance.

Matching is **override (precedence)**: a per-instance route for the firewall in
question wins outright over the global route — its ``enabled`` flag decides. So a
globally-on category can be switched **off** for a single box (and a globally-off
one switched on). With no per-instance route, the global route's presence decides.
Global routes are pure presence (always ``enabled``); "off for all" is the absence
of the global route, never a disabled one.

This is **opt-in**: a service-check transition fires on many categories, so a fresh
install stays quiet until an admin subscribes a channel to a category.
``availability`` (instance offline/recovered) is seeded on globally for every
channel by the table migration, so up/down alerts work out of the box. (Unlike the
Checkmk export exclusions — opt-out, Union — this routing is opt-in with per-box
override; the two no longer share a resolution model.)

Pure + DB-free.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.checkmk.exclusions import CATEGORIES as _CHECK_CATEGORIES

# Channels with a per-category routing UI. (The env-only webhook/ntfy channels
# were dropped; these three are all configurable in the Settings UI.)
CHANNELS: tuple[str, ...] = ("mattermost", "telegram", "email")

# Instance/agent offline & recovered events — not a service check, its own bucket.
AVAILABILITY = "availability"

# The selectable categories: availability + the Checkmk check categories one-to-one,
# so a check transition's ``category(check_key)`` lands in the same bucket the admin
# toggles. Order is the display order in the Settings UI.
CATEGORIES: tuple[str, ...] = (AVAILABILITY, *_CHECK_CATEGORIES)

Route = tuple[int | None, str, str, bool]  # (instance_id, channel, category, enabled)


def is_subscribed(channel: str, category: str, instance_id: int, routes: Iterable[Route]) -> bool:
    """True when ``channel`` receives alerts of ``category`` for ``instance_id``.

    Override match: a per-instance route for this instance wins over the global
    route — its ``enabled`` decides (so a global-on category can be switched off for
    one box, a global-off one switched on). With no per-instance route, the global
    route's presence decides. Global routes are always ``enabled`` by construction.
    """
    global_on = False
    for r_instance, r_channel, r_category, r_enabled in routes:
        if r_channel != channel or r_category != category:
            continue
        if r_instance == instance_id:
            return r_enabled  # per-instance override wins outright
        if r_instance is None:
            global_on = r_enabled
    return global_on


def valid_channel(channel: str) -> bool:
    return channel in CHANNELS


def valid_category(category: str) -> bool:
    return category in CATEGORIES
