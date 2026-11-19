"""Correspondances logicielles, actions calculées et suivi.

Revision ID: 004
Revises: 003
Create Date: 2026-11-19

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "software_mappings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("glpi_name", sa.String(length=255), nullable=False),
        sa.Column("product_slug", sa.String(length=80), nullable=False),
        sa.Column("manual", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint("glpi_name", name="uq_software_mappings_name"),
    )
    op.create_table(
        "computed_actions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("check_run_id", sa.Integer(), nullable=False),
        sa.Column("glpi_computer_id", sa.Integer(), nullable=False),
        sa.Column("product_slug", sa.String(length=80), nullable=False, server_default=""),
        sa.Column("action_key", sa.String(length=200), nullable=False),
        sa.Column("kind", sa.String(length=40), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        sa.Column("installed_version", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("target_version", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("cves_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("source_url", sa.Text(), nullable=False, server_default=""),
        sa.ForeignKeyConstraint(["check_run_id"], ["check_runs.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_computed_actions_check", "computed_actions", ["check_run_id"])
    op.create_index("ix_computed_actions_computer", "computed_actions", ["glpi_computer_id"])
    op.create_index("ix_computed_actions_key", "computed_actions", ["action_key"])
    op.create_table(
        "action_follow_ups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("action_key", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="a_faire"),
        sa.Column("technician", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("followed_on", sa.DateTime(), nullable=True),
        sa.Column("comment", sa.Text(), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("action_key", name="uq_action_follow_ups_key"),
    )


def downgrade() -> None:
    op.drop_table("action_follow_ups")
    op.drop_index("ix_computed_actions_key", table_name="computed_actions")
    op.drop_index("ix_computed_actions_computer", table_name="computed_actions")
    op.drop_index("ix_computed_actions_check", table_name="computed_actions")
    op.drop_table("computed_actions")
    op.drop_table("software_mappings")
