"""Inventaire GLPI et historique des vérifications.

Revision ID: 002
Revises: 001
Create Date: 2026-11-19

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "check_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("origin", sa.String(length=20), nullable=False),
        sa.Column("computer_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("summary_json", sa.Text(), nullable=False, server_default="{}"),
    )
    op.create_table(
        "computer_records",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("check_run_id", sa.Integer(), nullable=False),
        sa.Column("glpi_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("group_name", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("location", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("computer_type", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("os_name", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("os_version", sa.String(length=80), nullable=False, server_default=""),
        sa.Column("os_build", sa.String(length=80), nullable=False, server_default=""),
        sa.Column("last_inventory_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["check_run_id"], ["check_runs.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_computer_records_check_run_id", "computer_records", ["check_run_id"])
    op.create_index("ix_computer_records_glpi_id", "computer_records", ["glpi_id"])
    op.create_table(
        "software_installs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("computer_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("publisher", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("version", sa.String(length=120), nullable=False, server_default=""),
        sa.ForeignKeyConstraint(["computer_id"], ["computer_records.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_software_installs_computer_id", "software_installs", ["computer_id"])
    op.create_table(
        "agent_records",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("computer_id", sa.Integer(), nullable=False),
        sa.Column("glpi_id", sa.Integer(), nullable=True),
        sa.Column("last_contact", sa.DateTime(), nullable=True),
        sa.Column("version", sa.String(length=80), nullable=False, server_default=""),
        sa.Column("itemtype", sa.String(length=40), nullable=False, server_default="Agent"),
        sa.ForeignKeyConstraint(["computer_id"], ["computer_records.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("computer_id", name="uq_agent_records_computer"),
    )


def downgrade() -> None:
    op.drop_table("agent_records")
    op.drop_index("ix_software_installs_computer_id", table_name="software_installs")
    op.drop_table("software_installs")
    op.drop_index("ix_computer_records_glpi_id", table_name="computer_records")
    op.drop_index("ix_computer_records_check_run_id", table_name="computer_records")
    op.drop_table("computer_records")
    op.drop_table("check_runs")
