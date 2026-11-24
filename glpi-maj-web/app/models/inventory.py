from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class CheckRun(Base):
    __tablename__ = "check_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    origin: Mapped[str] = mapped_column(String(20), nullable=False)
    computer_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    progress_current: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    progress_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    message: Mapped[str] = mapped_column(Text, nullable=False, default="")
    cancel_requested: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    computers: Mapped[list["ComputerRecord"]] = relationship(
        back_populates="check_run",
        cascade="all, delete-orphan",
        order_by="ComputerRecord.glpi_id",
    )


class ComputerRecord(Base):
    __tablename__ = "computer_records"
    __table_args__ = (UniqueConstraint("check_run_id", "glpi_id", name="uq_computer_run_glpi"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    check_run_id: Mapped[int] = mapped_column(ForeignKey("check_runs.id", ondelete="CASCADE"), index=True)
    glpi_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    group_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    location: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    computer_type: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    os_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    os_version: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    os_build: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    last_inventory_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    check_run: Mapped[CheckRun] = relationship(back_populates="computers")
    software: Mapped[list["SoftwareInstall"]] = relationship(
        back_populates="computer",
        cascade="all, delete-orphan",
    )
    agent: Mapped["AgentRecord | None"] = relationship(
        back_populates="computer",
        cascade="all, delete-orphan",
        uselist=False,
    )


class SoftwareInstall(Base):
    __tablename__ = "software_installs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    computer_id: Mapped[int] = mapped_column(ForeignKey("computer_records.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    publisher: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    version: Mapped[str] = mapped_column(String(120), nullable=False, default="")

    computer: Mapped[ComputerRecord] = relationship(back_populates="software")


class AgentRecord(Base):
    __tablename__ = "agent_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    computer_id: Mapped[int] = mapped_column(ForeignKey("computer_records.id", ondelete="CASCADE"), unique=True)
    glpi_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_contact: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    version: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    itemtype: Mapped[str] = mapped_column(String(40), nullable=False, default="Agent")

    computer: Mapped[ComputerRecord] = relationship(back_populates="agent")
