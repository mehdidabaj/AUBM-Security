from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.timeutils import utcnow


class SoftwareChange(Base):
    """Mise à jour constatée sur un poste. Survit à l'effacement des anciennes vérifications."""

    __tablename__ = "software_changes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    glpi_computer_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    computer_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    software_key: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    software_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    previous_version: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    new_version: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    origin: Mapped[str] = mapped_column(String(20), nullable=False, default="automatique")
    actor: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    detected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)


class SecurityWatch(Base):
    """Sujet d'avis suivi même s'il n'est pas installé sur le parc."""

    __tablename__ = "security_watches"
    __table_args__ = (UniqueConstraint("subject_key", name="uq_security_watch_subject"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject_key: Mapped[str] = mapped_column(String(160), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(20), nullable=False, default="logiciel")
    created_by: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    current_reference: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    current_title: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    current_url: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    current_revised: Mapped[str] = mapped_column(String(20), nullable=False, default="")
    current_alert: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    current_closed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
