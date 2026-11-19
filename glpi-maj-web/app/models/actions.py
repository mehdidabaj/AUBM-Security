from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.timeutils import utcnow


class SoftwareMapping(Base):
    __tablename__ = "software_mappings"
    __table_args__ = (UniqueConstraint("glpi_name", name="uq_software_mappings_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    glpi_name: Mapped[str] = mapped_column(String(255), nullable=False)
    product_slug: Mapped[str] = mapped_column(String(80), nullable=False)
    manual: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class ComputedAction(Base):
    __tablename__ = "computed_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    check_run_id: Mapped[int] = mapped_column(ForeignKey("check_runs.id", ondelete="CASCADE"), index=True)
    glpi_computer_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    product_slug: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    action_key: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    installed_version: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    target_version: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    cves_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    source_url: Mapped[str] = mapped_column(Text, nullable=False, default="")


class ActionFollowUp(Base):
    __tablename__ = "action_follow_ups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    action_key: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="a_faire")
    technician: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    followed_on: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    comment: Mapped[str] = mapped_column(Text, nullable=False, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
