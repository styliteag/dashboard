"""groups, user memberships and the superadmin flag.

Introduces the group-based permission model: every instance belongs to exactly
one group (``instances.group_id``), users are members of any number of groups
(``user_groups``) and only see instances of their groups. ``users.is_superadmin``
marks the rights managers (groups/users/memberships — nothing else).

Data migration: group 1 "default" is seeded, all existing instances move into it
and every existing user becomes a member — visibility is unchanged by the
upgrade; operators prune memberships afterwards.

Revision ID: 028
Revises: 027
Create Date: 2026-07-03
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "028"
down_revision: str | None = "027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "groups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.execute("INSERT INTO groups (id, name) VALUES (1, 'default')")

    op.create_table(
        "user_groups",
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "group_id",
            sa.Integer(),
            sa.ForeignKey("groups.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )
    # Every existing user keeps seeing everything: member of "default".
    op.execute("INSERT INTO user_groups (user_id, group_id) SELECT id, 1 FROM users")

    # Nullable add → backfill → NOT NULL → FK; MariaDB can't add a NOT NULL FK
    # column with existing rows in one step.
    op.add_column("instances", sa.Column("group_id", sa.Integer(), nullable=True))
    op.execute("UPDATE instances SET group_id = 1")
    op.alter_column("instances", "group_id", existing_type=sa.Integer(), nullable=False)
    op.create_foreign_key(
        "fk_instances_group_id_groups",
        "instances",
        "groups",
        ["group_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index("ix_instances_group_id", "instances", ["group_id"])

    op.add_column(
        "users",
        sa.Column("is_superadmin", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("users", "is_superadmin")
    op.drop_index("ix_instances_group_id", table_name="instances")
    op.drop_constraint("fk_instances_group_id_groups", "instances", type_="foreignkey")
    op.drop_column("instances", "group_id")
    op.drop_table("user_groups")
    op.drop_table("groups")
