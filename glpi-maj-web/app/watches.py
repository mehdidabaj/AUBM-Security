from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.history import SecurityWatch
from app.security_topics import watch_subjects
from app.timeutils import utcnow


def watched_keys(db: Session) -> set[str]:
    return set(db.scalars(select(SecurityWatch.subject_key)))


def follows(title: str, keys: set[str]) -> bool:
    return any(key in keys for key, _label, _kind in watch_subjects(title))


def toggle_watch(db: Session, title: str, actor: str) -> bool:
    """Ajoute le suivi des sujets de ce bulletin, ou le retire s'il est déjà complet."""
    subjects = watch_subjects(title)
    keys = [key for key, _label, _kind in subjects]
    existing = list(db.scalars(select(SecurityWatch).where(SecurityWatch.subject_key.in_(keys)))) if keys else []
    if existing and len(existing) >= len(keys):
        for row in existing:
            db.delete(row)
        db.commit()
        return False
    have = {row.subject_key for row in existing}
    moment = utcnow()
    for key, label, kind in subjects:
        if key in have:
            continue
        db.add(
            SecurityWatch(
                subject_key=key,
                label=label,
                kind=kind,
                created_by=actor.strip(),
                created_at=moment,
            )
        )
    db.commit()
    return True
