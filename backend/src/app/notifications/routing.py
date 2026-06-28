"""Per-channel notification routing — which alert categories each channel gets.

A *route* is ``(channel, category)``: its presence means that channel receives
alerts of that category. Absence means it does not. This is the **opt-in** inverse
of the Checkmk export exclusions (which are opt-out): a service-check transition
fires on many categories, so a fresh install stays quiet until an admin subscribes
a channel to a category. ``availability`` (instance offline/recovered) is seeded on
for every channel by the table migration, so up/down alerts work out of the box.

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

Route = tuple[str, str]  # (channel, category)


def is_subscribed(channel: str, category: str, routes: Iterable[Route]) -> bool:
    """True when ``channel`` is subscribed to alerts of ``category``."""
    return (channel, category) in (routes if isinstance(routes, set) else set(routes))


def valid_channel(channel: str) -> bool:
    return channel in CHANNELS


def valid_category(category: str) -> bool:
    return category in CATEGORIES
