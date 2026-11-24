"""Cache des sources externes et journal de collecte.

Revision ID: 003
Revises: 002
Create Date: 2026-11-19

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "source_cache",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("cache_key", sa.String(length=120), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("etag", sa.String(length=200), nullable=True),
        sa.Column("fetched_at", sa.DateTime(), nullable=True),
        sa.Column("checked_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("origin", sa.String(length=20), nullable=False, server_default="live"),
        sa.UniqueConstraint("source", "cache_key", name="uq_source_cache_key"),
    )
    op.create_index("ix_source_cache_source", "source_cache", ["source"])
    op.create_table(
        "source_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("items_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("progress_current", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("progress_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("message", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_source_runs_source", "source_runs", ["source"])


def downgrade() -> None:
    op.drop_index("ix_source_runs_source", table_name="source_runs")
    op.drop_table("source_runs")
    op.drop_index("ix_source_cache_source", table_name="source_cache")
    op.drop_table("source_cache")
