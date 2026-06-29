"""key the IPsec ping-monitor uniqueness on the selector pair, not child_name.

strongSwan splits a single configured Phase-2 child with several local subnets
into one CHILD_SA per subnet, and every split SA shares the configured child
name. The old unique key ``(instance_id, tunnel_id, child_name)`` therefore
rejected a second monitor for the same tunnel+child even when it pinned a
different subnet (the "a ping monitor for this Phase 2 already exists" 409 on
the BadVilbel tunnel). The selector pair is the unambiguous Phase-2 identity, so
the key becomes ``(instance_id, tunnel_id, local_ts, remote_ts)``.

Revision ID: 023
Revises: 022
Create Date: 2026-06-29
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "023"
down_revision: str | None = "022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "ipsec_ping_monitors"
_NAME = "uq_ipsec_ping_monitor"


def upgrade() -> None:
    op.drop_constraint(_NAME, _TABLE, type_="unique")
    op.create_unique_constraint(
        _NAME, _TABLE, ["instance_id", "tunnel_id", "local_ts", "remote_ts"]
    )


def downgrade() -> None:
    op.drop_constraint(_NAME, _TABLE, type_="unique")
    op.create_unique_constraint(_NAME, _TABLE, ["instance_id", "tunnel_id", "child_name"])
