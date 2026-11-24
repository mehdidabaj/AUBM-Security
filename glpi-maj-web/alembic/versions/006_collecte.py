"""Annulation, et un poste unique par vérification.

Revision ID: 006
Revises: 005
Create Date: 2026-11-23

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "check_runs",
        sa.Column("cancel_requested", sa.Integer(), nullable=False, server_default="0"),
    )
    op.execute(
        """
        DELETE FROM software_installs
        WHERE computer_id IN (
            SELECT id FROM computer_records
            WHERE id NOT IN (
                SELECT MIN(id) FROM computer_records GROUP BY check_run_id, glpi_id
            )
        )
        """
    )
    op.execute(
        """
        DELETE FROM agent_records
        WHERE computer_id IN (
            SELECT id FROM computer_records
            WHERE id NOT IN (
                SELECT MIN(id) FROM computer_records GROUP BY check_run_id, glpi_id
            )
        )
        """
    )
    op.execute(
        """
        DELETE FROM computer_records
        WHERE id NOT IN (
            SELECT MIN(id) FROM computer_records GROUP BY check_run_id, glpi_id
        )
        """
    )
    with op.batch_alter_table("computer_records") as batch:
        batch.create_unique_constraint("uq_computer_run_glpi", ["check_run_id", "glpi_id"])


def downgrade() -> None:
    with op.batch_alter_table("computer_records") as batch:
        batch.drop_constraint("uq_computer_run_glpi", type_="unique")
    op.drop_column("check_runs", "cancel_requested")
