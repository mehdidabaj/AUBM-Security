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


def remove_subject(db: Session, subject_key: str) -> bool:
    row = db.scalar(select(SecurityWatch).where(SecurityWatch.subject_key == subject_key))
    if row is None:
        return False
    db.delete(row)
    db.commit()
    return True


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
    sync_from_cache(db)
    return True


def choose_latest(rows: list[dict], keys: set[str]) -> dict[str, dict]:
    """Le bulletin le plus récent de chaque sujet suivi."""
    best: dict[str, dict] = {}
    for row in rows:
        revised = str(row.get("revised") or "")
        if not row.get("reference") or not revised:
            continue
        for key, _label, _kind in watch_subjects(str(row.get("title") or "")):
            if key not in keys:
                continue
            current = best.get(key)
            if current is None or _newer(row, current):
                best[key] = row
    return best


def apply_latest(db: Session, rows: list[dict]) -> int:
    """Remplace le bulletin retenu s'il est plus ancien, ou note qu'il est clôturé."""
    watches = list(db.scalars(select(SecurityWatch)))
    if not watches:
        return 0
    chosen = choose_latest(rows, {watch.subject_key for watch in watches})
    changed = 0
    for watch in watches:
        row = chosen.get(watch.subject_key)
        if row is None:
            continue
        closed = bool(row.get("closed"))
        alert = bool(row.get("alert"))
        reference = str(row.get("reference") or "")
        title = str(row.get("title") or "")
        url = str(row.get("url") or "")
        revised = str(row.get("revised") or "")
        if (
            watch.current_reference == reference
            and watch.current_title == title
            and watch.current_url == url
            and watch.current_revised == revised
            and watch.current_alert == alert
            and watch.current_closed == closed
        ):
            continue
        watch.current_reference = reference
        watch.current_title = title
        watch.current_url = url
        watch.current_revised = revised
        watch.current_alert = alert
        watch.current_closed = closed
        changed += 1
    if changed:
        db.commit()
    return changed


def sync_from_cache(db: Session) -> int:
    """Aligne les suivis sur les bulletins déjà enregistrés."""
    from app.sources.cache import get_cache, payload_of

    payload = payload_of(get_cache(db, "certfr", "bulletins"))
    raw = payload.get("items") or []
    rows = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "reference": str(item.get("reference") or ""),
                "title": str(item.get("title") or ""),
                "url": str(item.get("url") or ""),
                "revised": str(item.get("revised") or ""),
                "alert": bool(item.get("alert")),
                "closed": bool(item.get("closed")),
            }
        )
    return apply_latest(db, rows)


def _newer(candidate: dict, current: dict) -> bool:
    revised = str(candidate.get("revised") or "")
    previous = str(current.get("revised") or "")
    if revised != previous:
        return revised > previous
    return bool(candidate.get("alert")) and not current.get("alert")
