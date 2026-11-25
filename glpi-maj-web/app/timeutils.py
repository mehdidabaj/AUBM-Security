from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Horodatage UTC naïf, stable avec SQLite."""
    return datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None)


def format_gmt(value: datetime | None) -> str:
    """Affiche l'heure GMT enregistrée, sans la décaler."""
    if value is None:
        return "—"
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.strftime("%d/%m/%Y %H:%M")
