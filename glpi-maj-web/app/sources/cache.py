from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.actions.versions import compare_versions
from app.models.sources import SourceCache
from app.sources.catalog import PRODUCTS, SOURCE_LABELS
from app.timeutils import utcnow

STALE_DAYS = 3


def get_cache(db: Session, source: str, cache_key: str) -> SourceCache | None:
    return db.scalar(select(SourceCache).where(SourceCache.source == source, SourceCache.cache_key == cache_key))


def payload_of(row: SourceCache | None) -> dict:
    if row is None or not row.payload_json:
        return {}
    return json.loads(row.payload_json)


def put_cache(
    db: Session,
    source: str,
    cache_key: str,
    payload: dict,
    *,
    etag: str | None = None,
    origin: str = "live",
    now: datetime | None = None,
    checked: bool = True,
) -> SourceCache:
    moment = now or utcnow()
    row = get_cache(db, source, cache_key)
    if row is None:
        row = SourceCache(source=source, cache_key=cache_key, payload_json="{}")
        db.add(row)
    row.payload_json = json.dumps(payload, ensure_ascii=False)
    row.etag = etag if etag is not None else row.etag
    row.origin = origin
    row.last_error = None
    row.fetched_at = moment
    if checked:
        row.checked_at = moment
    db.info.pop("source_payloads", None)
    db.info.pop("certfr_cves", None)
    db.commit()
    return row


def mark_checked(db: Session, row: SourceCache, now: datetime | None = None) -> None:
    row.checked_at = now or utcnow()
    row.last_error = None
    db.commit()


def mark_error(db: Session, source: str, cache_key: str, message: str) -> None:
    row = get_cache(db, source, cache_key)
    if row is None:
        row = SourceCache(source=source, cache_key=cache_key, payload_json="{}", origin="live")
        db.add(row)
    row.last_error = message
    db.info.pop("source_payloads", None)
    db.info.pop("certfr_cves", None)
    db.commit()


def remember_version(
    db: Session,
    source: str,
    cache_key: str,
    version: str,
    *,
    url: str | None = None,
    mode: str = "ge",
    now: datetime | None = None,
) -> None:
    put_cache(
        db,
        source,
        cache_key,
        {"version": version, "url": url, "mode": mode},
        origin="live",
        now=now,
    )


def _source_payloads(db: Session) -> dict[tuple[str, str], dict]:
    """Charge une fois les versions mises en cache pour toute la requête."""
    cached = db.info.get("source_payloads")
    if cached is None:
        cached = {}
        rows = db.scalars(select(SourceCache).where(SourceCache.source.in_(("msrc", "github", "winget", "fallback"))))
        for row in rows:
            cached[(row.source, row.cache_key)] = payload_of(row)
        db.info["source_payloads"] = cached
    return cached


def version_target(db: Session, slug: str) -> dict | None:
    """Version à atteindre : donnée vivante, sinon plancher du référentiel de secours."""
    product = PRODUCTS.get(slug)
    payloads = _source_payloads(db)
    live = None
    live_source = None
    for source in ("msrc", "github", "winget"):
        data = payloads.get((source, slug)) or {}
        if data.get("version"):
            live = data
            live_source = source
            break
    floor = payloads.get(("fallback", slug)) or {}
    if live and floor.get("version") and product is not None and product.version_mode == "gt":
        compared = compare_versions(live["version"], floor["version"])
        if compared is None or compared <= 0:
            return {**floor, "source": "fallback", "mode": floor.get("mode", product.version_mode)}
    if live:
        return {**live, "source": live_source, "mode": "ge"}
    if floor.get("version"):
        return {**floor, "source": "fallback", "mode": floor.get("mode", "ge")}
    return None


def is_end_of_life(db: Session, slug: str) -> bool:
    return bool((_source_payloads(db).get(("fallback", slug)) or {}).get("eol"))


def source_overview(db: Session, now: datetime | None = None) -> list[dict[str, Any]]:
    from app.models.sources import SourceRun

    moment = now or utcnow()
    horizon = moment - timedelta(days=STALE_DAYS)
    rows = []
    for key, label in SOURCE_LABELS:
        run = db.scalar(select(SourceRun).where(SourceRun.source == key).order_by(SourceRun.id.desc()))
        caches = list(db.scalars(select(SourceCache).where(SourceCache.source == key)))
        live = [item for item in caches if item.origin == "live" and item.checked_at]
        latest = max((item.checked_at for item in live), default=None)
        error = run.error if run is not None and run.status == "error" else None
        if latest is None:
            state = "secours"
        elif latest < horizon:
            state = "alerte"
        elif error:
            state = "conserve"
        else:
            state = "ok"
        rows.append(
            {
                "source": key,
                "libelle": label,
                "etat": state,
                "derniere_donnee": latest.isoformat(sep=" ") if latest else None,
                "erreur": error,
                "elements": run.items_count if run is not None else 0,
                "journal": run.message if run is not None else "",
            }
        )
    return rows
