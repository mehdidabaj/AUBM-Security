"""Historique des mises à jour et suivis d'avis hors parc.

Revision ID: 007
Revises: 006
Create Date: 2026-11-24

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "software_changes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("glpi_computer_id", sa.Integer(), nullable=False),
        sa.Column("computer_name", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("software_key", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("software_name", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("previous_version", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("new_version", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("origin", sa.String(length=20), nullable=False, server_default="automatique"),
        sa.Column("actor", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("detected_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_software_changes_glpi_computer_id", "software_changes", ["glpi_computer_id"])
    op.create_table(
        "security_watches",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("subject_key", sa.String(length=160), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("kind", sa.String(length=20), nullable=False, server_default="logiciel"),
        sa.Column("created_by", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("subject_key", name="uq_security_watch_subject"),
    )


def downgrade() -> None:
    op.drop_table("security_watches")
    op.drop_index("ix_software_changes_glpi_computer_id", table_name="software_changes")
    op.drop_table("software_changes")
