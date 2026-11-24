from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Horodatage UTC naïf, stable avec SQLite."""
    return datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None)
