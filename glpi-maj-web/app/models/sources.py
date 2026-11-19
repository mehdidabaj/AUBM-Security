from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SourceCache(Base):
    __tablename__ = "source_cache"
    __table_args__ = (UniqueConstraint("source", "cache_key", name="uq_source_cache_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    cache_key: Mapped[str] = mapped_column(String(120), nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    etag: Mapped[str | None] = mapped_column(String(200), nullable=True)
    fetched_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    origin: Mapped[str] = mapped_column(String(20), nullable=False, default="live")


class SourceRun(Base):
    __tablename__ = "source_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    items_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress_current: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    progress_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    message: Mapped[str] = mapped_column(Text, nullable=False, default="")
