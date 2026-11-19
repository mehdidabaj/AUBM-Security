from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta
from pathlib import Path

import httpx
from sqlalchemy.orm import Session

from app.config import Settings
from app.models.sources import SourceRun
from app.settings_store import get_setting
from app.sources.cache import get_cache, mark_checked, mark_error, payload_of, put_cache, remember_version
from app.sources.catalog import (
    ENDOLIFE_URL,
    FEEDS,
    GITHUB_RELEASE,
    KEV_URL,
    MSRC_UPDATES,
    NVD_URL,
    SOURCE_LABELS,
    USER_AGENT,
    Product,
    match_products,
)
from app.sources.http import get_with_retries, make_client
from app.sources.limiter import RateLimiter
from app.sources.parsers import parse_endoflife, parse_feed, parse_github_release, parse_kev, parse_msrc, parse_nvd
from app.sources.winget import update_winget
from app.timeutils import utcnow

FALLBACK_PATH = Path(__file__).resolve().parents[1] / "referentiel" / "secours.json"
NVD_RETRY = {403, 429, 503}


def load_fallback_if_needed(db: Session, path: Path | None = None) -> int:
    raw = json.loads((path or FALLBACK_PATH).read_text(encoding="utf-8"))
    created = 0
    for item in raw["versions"]:
        if get_cache(db, "fallback", item["slug"]) is None:
            put_cache(
                db,
                "fallback",
                item["slug"],
                {"version": item["version"], "mode": item.get("mode", "ge")},
                origin="fallback",
                checked=False,
            )
            created += 1
    for slug in raw["eol"]:
        if get_cache(db, "fallback", slug) is None and get_cache(db, "endoflife", slug) is None:
            put_cache(db, "fallback", slug, {"eol": True}, origin="fallback", checked=False)
            created += 1
    return created


def enabled_sources(db: Session) -> set[str]:
    stored = get_setting(db, "sources_enabled", None)
    if not isinstance(stored, dict):
        return {key for key, _label in SOURCE_LABELS}
    return {key for key, enabled in stored.items() if enabled}


def names_from_inventory(db: Session) -> list[str]:
    from app.glpi.service import latest_successful

    run = latest_successful(db)
    if run is None:
        return []
    names: list[str] = []
    for computer in run.computers:
        names.append(f"{computer.os_name} {computer.os_version}".strip())
        names.extend(software.name for software in computer.software)
    return names


def update_sources(
    db: Session,
    settings: Settings,
    *,
    names: list[str] | None = None,
    http: httpx.Client | None = None,
    sleep=None,
    clock=None,
    limiter: RateLimiter | None = None,
    git_runner=None,
    now: datetime | None = None,
) -> SourceRun:
    import time

    moment = now or utcnow()
    sleeper = sleep or time.sleep
    selected = match_products(names if names is not None else names_from_inventory(db))
    enabled = enabled_sources(db)
    steps = [key for key, _label in SOURCE_LABELS if key in enabled]
    parent = SourceRun(
        source="toutes",
        started_at=moment,
        status="running",
        progress_total=len(steps),
        message="Démarrage de la collecte",
    )
    db.add(parent)
    db.commit()
    interval = 0.6 if settings.nvd_api_key else 6.5
    limiter = limiter or RateLimiter(interval=interval, sleep=sleeper, clock=clock or time.monotonic)
    runner = git_runner or _subprocess_runner
    own_client = http is None
    client = http or make_client()
    failures = 0
    try:
        for index, key in enumerate(steps, start=1):
            parent.progress_current = index
            parent.message = f"Collecte de {key}"
            db.commit()
            ok = _execute(db, settings, client, key, selected, sleeper, limiter, runner, moment)
            if not ok:
                failures += 1
        if not steps:
            parent.status = "success"
        elif failures == 0:
            parent.status = "success"
        elif failures == len(steps):
            parent.status = "error"
        else:
            parent.status = "partial"
        parent.message = f"Collecte terminée ({parent.status})."
    finally:
        parent.finished_at = utcnow()
        db.commit()
        if own_client:
            client.close()
    return parent


def launch_source_update(app) -> None:
    """Collecte en arrière-plan, puis nouvelle vérification du parc."""

    def worker() -> None:
        db = app.state.SessionLocal()
        try:
            update_sources(db, app.state.settings)
            from app.glpi.service import run_verification
            from app.notify import notify_changes

            run_verification(db, app.state.settings)
            notify_changes(db, app.state.settings)
        finally:
            db.close()

    threading.Thread(target=worker, name="glpi-maj-sources", daemon=True).start()


def _execute(db, settings, client, key, products: list[Product], sleep, limiter, runner, now) -> bool:
    started = utcnow()
    run = SourceRun(source=key, started_at=started, status="running", message=f"Début {started:%Y-%m-%d %H:%M:%S}")
    db.add(run)
    db.commit()
    try:
        count = _dispatch(db, settings, client, key, products, sleep, limiter, runner, now)
    except Exception as exc:
        message = str(exc)
        run.status = "error"
        run.error = message
        run.items_count = 0
        _mark_source_error(db, key, products, message)
        ok = False
    else:
        run.status = "success"
        run.items_count = count
        run.error = None
        ok = True
    run.finished_at = utcnow()
    run.message = (
        f"Début {run.started_at:%Y-%m-%d %H:%M:%S}, fin {run.finished_at:%Y-%m-%d %H:%M:%S}, "
        f"{run.items_count} élément(s)."
    )
    if run.error:
        run.message += f" Erreur : {run.error}"
    db.commit()
    return ok


def _dispatch(db, settings, client, key, products, sleep, limiter, runner, now) -> int:
    if key == "winget":
        return _collect_winget(db, settings, products, runner, now)
    if key == "github":
        return _collect_github(db, settings, client, products, sleep, now)
    if key == "endoflife":
        return _collect_endoflife(db, client, products, sleep, now)
    if key == "msrc":
        return _collect_msrc(db, client, products, sleep, now)
    if key == "nvd":
        return _collect_nvd(db, settings, client, products, sleep, limiter, now)
    if key == "kev":
        return _collect_kev(db, client, products, sleep, now)
    if key == "feeds":
        return _collect_feeds(db, client, products, sleep, now)
    return 0


def _wanted(products: list[Product], predicate) -> list[Product]:
    return [product for product in products if predicate(product)]


def _collect_winget(db, settings, products, runner, now) -> int:
    wanted = _wanted(products, lambda product: product.winget_id)
    if not wanted:
        return 0
    dest = Path(settings.data_dir) / "sources" / "winget"
    versions = update_winget(dest, [product.winget_id for product in wanted if product.winget_id], runner)
    by_id = {product.winget_id: product for product in wanted}
    count = 0
    for package_id, version in versions.items():
        product = by_id.get(package_id)
        if product is None:
            continue
        remember_version(db, "winget", product.slug, version, url=f"https://github.com/microsoft/winget-pkgs", now=now)
        count += 1
    return count


def _collect_github(db, settings, client, products, sleep, now) -> int:
    count = 0
    for product in _wanted(products, lambda item: item.github):
        cached = get_cache(db, "github", product.slug)
        if cached and cached.checked_at and cached.checked_at.date() == now.date() and not cached.last_error:
            count += 1
            continue
        headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"
        if cached and cached.etag:
            headers["If-None-Match"] = cached.etag
        response = get_with_retries(
            client,
            GITHUB_RELEASE.format(repo=product.github),
            headers=headers,
            sleep=sleep,
        )
        if response.status_code == 304 and cached is not None:
            mark_checked(db, cached, now)
            count += 1
            continue
        if response.status_code >= 400:
            mark_error(db, "github", product.slug, f"GitHub a répondu HTTP {response.status_code} pour {product.github}.")
            raise RuntimeError(f"GitHub a répondu HTTP {response.status_code} pour {product.github}.")
        parsed = parse_github_release(response.json())
        put_cache(
            db,
            "github",
            product.slug,
            parsed,
            etag=response.headers.get("etag"),
            origin="live",
            now=now,
        )
        count += 1
    return count


def _collect_endoflife(db, client, products, sleep, now) -> int:
    families = sorted({product.endoflife for product in products if product.endoflife})
    wanted = {product.slug for product in products}
    count = 0
    for family in families:
        response = get_with_retries(client, ENDOLIFE_URL.format(product=family), sleep=sleep)
        if response.status_code >= 400:
            raise RuntimeError(f"endoflife.date a répondu HTTP {response.status_code} pour {family}.")
        cycles = parse_endoflife(response.json(), now)
        for slug, summary in _assign_cycles(family, cycles, wanted).items():
            put_cache(db, "endoflife", slug, summary, origin="live", now=now)
            count += 1
    return count


def _assign_cycles(family: str, cycles: list[dict], wanted: set[str]) -> dict[str, dict]:
    groups: dict[str, list[dict]] = {}
    for cycle in cycles:
        slug = _slug_for_cycle(family, cycle["cycle"], wanted)
        if slug:
            groups.setdefault(slug, []).append(cycle)
    assigned = {}
    for slug, rows in groups.items():
        assigned[slug] = {
            "eol": all(row["eol"] for row in rows),
            "cycles": rows,
            "latest": next((row["latest"] for row in rows if row.get("latest")), ""),
        }
    return assigned


def _slug_for_cycle(family: str, cycle: str, wanted: set[str]) -> str | None:
    text = cycle.lower()
    if family == "windows":
        if text.startswith("10") and "windows-10" in wanted:
            return "windows-10"
        if text.startswith("11") and "windows-11" in wanted:
            return "windows-11"
    if family == "office":
        for year in ("2013", "2016", "2019", "2021"):
            slug = f"office-{year}"
            if year in text and slug in wanted:
                return slug
    if family == "java" and text.startswith("8") and "java8" in wanted:
        return "java8"
    if family == "powershell" and "powershell" in wanted and (text.startswith("7")):
        return "powershell"
    return None


def _collect_msrc(db, client, products, sleep, now) -> int:
    if not any(product.triggers_msrc for product in products):
        return 0
    listing = get_with_retries(client, MSRC_UPDATES, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}, sleep=sleep)
    if listing.status_code >= 400:
        raise RuntimeError(f"MSRC a répondu HTTP {listing.status_code}.")
    body = listing.json()
    updates = body.get("value") if isinstance(body, dict) else body
    if not updates:
        raise RuntimeError("MSRC n'a renvoyé aucune mise à jour.")
    latest = max(updates, key=lambda item: item.get("CurrentReleaseDate") or "")
    identifier = latest.get("ID") or latest.get("Alias")
    document = get_with_retries(
        client,
        f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{identifier}",
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        sleep=sleep,
    )
    if document.status_code >= 400:
        raise RuntimeError(f"MSRC a répondu HTTP {document.status_code} pour {identifier}.")
    parsed = parse_msrc(document.json())
    parsed["release_date"] = latest.get("CurrentReleaseDate") or ""
    parsed["url"] = f"https://msrc.microsoft.com/update-guide/releaseNote/{identifier}"
    put_cache(db, "msrc", "catalog", parsed, origin="live", now=now)
    count = 1
    for feature, build in (parsed.get("windows") or {}).items():
        key = f"windows-{feature.lower()}"
        remember_version(db, "msrc", key, build, url=parsed["url"], now=now)
        count += 1
    if parsed.get("m365"):
        remember_version(db, "msrc", "m365", parsed["m365"], url=parsed["url"], now=now)
        count += 1
    return count


def _collect_nvd(db, settings, client, products, sleep, limiter: RateLimiter, now) -> int:
    wanted = _wanted(products, lambda product: product.cpe)
    count = 0
    for product in wanted:
        previous = payload_of(get_cache(db, "nvd", product.slug))
        params = {"cpeName": product.cpe, "resultsPerPage": 50}
        if previous.get("last_mod_end"):
            end = now
            start = datetime.fromisoformat(previous["last_mod_end"])
            if end - start > timedelta(days=120):
                start = end - timedelta(days=120)
            params["lastModStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")
            params["lastModEndDate"] = end.strftime("%Y-%m-%dT%H:%M:%S.000")
        response = _nvd_get(client, params, settings.nvd_api_key, limiter, sleep)
        parsed = parse_nvd(response.json())
        merged = {item["id"]: item for item in previous.get("cves", [])}
        for item in parsed:
            merged[item["id"]] = item
        put_cache(
            db,
            "nvd",
            product.slug,
            {"cves": list(merged.values()), "last_mod_end": now.strftime("%Y-%m-%dT%H:%M:%S")},
            origin="live",
            now=now,
        )
        count += len(merged)
    return count


def _nvd_get(client, params, api_key: str, limiter: RateLimiter, sleep) -> httpx.Response:
    headers = {"User-Agent": USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key
    attempt = 0
    while True:
        limiter.wait()
        response = client.get(NVD_URL, params=params, headers=headers)
        if response.status_code in NVD_RETRY and attempt < 3:
            attempt += 1
            sleep(10 * (2 ** (attempt - 1)))
            continue
        if response.status_code >= 400:
            raise RuntimeError(f"NVD a répondu HTTP {response.status_code}.")
        return response


def _collect_kev(db, client, products, sleep, now) -> int:
    if not products:
        return 0
    cached = get_cache(db, "kev", "catalog")
    if cached and cached.checked_at and cached.checked_at.date() == now.date() and not cached.last_error:
        return len((payload_of(cached).get("cves") or {}))
    response = get_with_retries(client, KEV_URL, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}, sleep=sleep)
    if response.status_code >= 400:
        raise RuntimeError(f"CISA KEV a répondu HTTP {response.status_code}.")
    parsed = parse_kev(response.json())
    put_cache(db, "kev", "catalog", parsed, origin="live", now=now)
    return len(parsed["cves"])


def _collect_feeds(db, client, products, sleep, now) -> int:
    feed_ids = sorted({product.feed for product in products if product.feed})
    count = 0
    for feed_id in feed_ids:
        response = get_with_retries(client, FEEDS[feed_id], headers={"User-Agent": USER_AGENT}, sleep=sleep)
        if response.status_code >= 400:
            mark_error(db, "feeds", feed_id, f"Le flux {feed_id} a répondu HTTP {response.status_code}.")
            raise RuntimeError(f"Le flux {feed_id} a répondu HTTP {response.status_code}.")
        entries = parse_feed(response.text)
        put_cache(db, "feeds", feed_id, {"entries": entries}, origin="live", now=now)
        count += len(entries)
    return count


def _mark_source_error(db, key: str, products: list[Product], message: str) -> None:
    if key == "kev":
        mark_error(db, "kev", "catalog", message)
        return
    if key == "msrc":
        mark_error(db, "msrc", "catalog", message)
        return
    if key == "feeds":
        for feed_id in {product.feed for product in products if product.feed}:
            mark_error(db, "feeds", feed_id, message)
        return
    for product in products:
        relevant = (
            (key == "winget" and product.winget_id)
            or (key == "github" and product.github)
            or (key == "nvd" and product.cpe)
            or (key == "endoflife" and product.endoflife)
        )
        if relevant:
            mark_error(db, key, product.slug, message)


def _subprocess_runner(command: list[str]) -> int:
    import subprocess

    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    return completed.returncode
