"""Dernier bulletin retenu pour chaque sujet suivi.

Revision ID: 008
Revises: 007
Create Date: 2026-11-24

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "008"
down_revision: Union[str, None] = "007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("security_watches", sa.Column("current_reference", sa.String(length=80), nullable=False, server_default=""))
    op.add_column("security_watches", sa.Column("current_title", sa.String(length=500), nullable=False, server_default=""))
    op.add_column("security_watches", sa.Column("current_url", sa.String(length=255), nullable=False, server_default=""))
    op.add_column("security_watches", sa.Column("current_revised", sa.String(length=20), nullable=False, server_default=""))
    op.add_column("security_watches", sa.Column("current_alert", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("security_watches", sa.Column("current_closed", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    op.drop_column("security_watches", "current_closed")
    op.drop_column("security_watches", "current_alert")
    op.drop_column("security_watches", "current_revised")
    op.drop_column("security_watches", "current_url")
    op.drop_column("security_watches", "current_title")
    op.drop_column("security_watches", "current_reference")
