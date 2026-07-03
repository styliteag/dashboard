"""Per-group notification-channel config: field spec + settings adapter.

Single source of truth shared by the channels API (validation/masking, see
app.groups.channels) and the dispatcher (app.notifications.notifier). A group
channel's config is stored as one Fernet-encrypted JSON blob
(``group_channels.config_enc``); the field names here are the JSON keys, each
mapped to the ``notify_*`` attribute name the (unchanged) senders read.
"""

from __future__ import annotations

from dataclasses import dataclass

CHANNELS = ("mattermost", "telegram", "email")

# Placeholder returned instead of secret values (and accepted back as
# "keep the stored value") — mirrors the Settings API convention.
MASK = "••••••"


@dataclass(frozen=True)
class ChannelField:
    name: str  # JSON key in config_enc
    attr: str  # notify_* attribute the senders getattr()
    secret: bool = False
    required: bool = False
    options: tuple[str, ...] | None = None  # enum values, if constrained


CHANNEL_FIELDS: dict[str, tuple[ChannelField, ...]] = {
    "mattermost": (ChannelField("url", "notify_mattermost_url", secret=True, required=True),),
    "telegram": (
        ChannelField("token", "notify_telegram_token", secret=True, required=True),
        ChannelField("chat_id", "notify_telegram_chat_id", required=True),
    ),
    "email": (
        ChannelField("smtp_host", "notify_email_smtp_host", required=True),
        ChannelField("smtp_port", "notify_email_smtp_port"),
        ChannelField("security", "notify_email_security", options=("starttls", "ssl", "none")),
        ChannelField("from", "notify_email_from", required=True),
        ChannelField("to", "notify_email_to", required=True),
        ChannelField("username", "notify_email_username"),
        ChannelField("password", "notify_email_password", secret=True),
    ),
}


class GroupChannelSettings:
    """Settings-like overlay for ONE group channel.

    The channel's ``notify_*`` attributes come from the group's decrypted
    config; every other attribute (incl. the ``notify_*_muted`` flags and the
    other channels' fields) delegates to the global effective settings — so
    the unchanged senders read this object exactly like the global one.
    """

    def __init__(self, base, channel: str, config: dict) -> None:  # noqa: ANN001
        self._base = base
        self._attr_map = {f.attr: config.get(f.name, "") for f in CHANNEL_FIELDS.get(channel, ())}

    def __getattr__(self, name: str):  # noqa: ANN204
        if name in self._attr_map:
            return self._attr_map[name]
        return getattr(self._base, name)
