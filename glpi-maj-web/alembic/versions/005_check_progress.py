"""Progression de la vérification du parc.

Revision ID: 005
Revises: 004
Create Date: 2026-11-19

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("check_runs", sa.Column("progress_current", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("check_runs", sa.Column("progress_total", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("check_runs", sa.Column("message", sa.Text(), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("check_runs", "message")
    op.drop_column("check_runs", "progress_total")
    op.drop_column("check_runs", "progress_current")
