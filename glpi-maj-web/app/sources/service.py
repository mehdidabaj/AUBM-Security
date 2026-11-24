from __future__ import annotations

import json
import logging
import re
import threading
from datetime import datetime, timedelta
from pathlib import Path

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models.sources import SourceRun
from app.settings_store import get_setting, set_setting
from app.sources.cache import get_cache, mark_checked, mark_error, payload_of, put_cache, remember_version
from app.sources.catalog import (
    CERTFR_ALERTE_URL,
    CERTFR_AVIS_URL,
    CERTFR_SITE,
    CVE_RECORD_URL,
    ENDOLIFE_URL,
    FEEDS,
    GITHUB_RELEASE,
    KEV_URL,
    MSRC_UPDATES,
    NVD_URL,
    RETIRED_SOURCES,
    SOURCE_LABELS,
    USER_AGENT,
    Product,
    match_key,
    match_products,
)
from app.sources.http import get_with_retries, make_client
from app.sources.limiter import RateLimiter
from app.sources.parsers import (
    parse_certfr,
    parse_cve_score,
    parse_endoflife,
    parse_feed,
    parse_github_release,
    parse_kev,
    parse_msrc,
    parse_nvd,
    severity_name,
)
from app.sources.winget import update_winget
from app.timeutils import utcnow

logger = logging.getLogger(__name__)
FALLBACK_PATH = Path(__file__).resolve().parents[1] / "referentiel" / "secours.json"
NVD_RETRY = {403, 429, 503}
VULN_RECENT_DAYS = 120


class SourceWarning(Exception):
    """Une source a lu une partie des éléments. Le compte est conservé."""

    def __init__(self, count: int, detail: str) -> None:
        self.count = count
        super().__init__(detail)


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


def enable_new_sources(db: Session) -> None:
    """Coche les sources ajoutées et retire celles qui ne sont plus proposées."""
    stored = get_setting(db, "sources_enabled", None)
    if not isinstance(stored, dict):
        return
    kept = {key: value for key, value in stored.items() if key not in RETIRED_SOURCES}
    missing = {key: True for key, _label in SOURCE_LABELS if key not in kept}
    if missing or kept != stored:
        set_setting(db, "sources_enabled", {**kept, **missing})


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


def probe_source(settings: Settings, key: str, http: httpx.Client | None = None) -> dict:
    """Vérifie qu'une source répond, sans lancer une collecte complète."""
    from app.sources.catalog import CERTFR_AVIS_URL, MSRC_UPDATES

    targets = {
        "winget": "https://github.com/microsoft/winget-pkgs",
        "github": "https://api.github.com/rate_limit",
        "msrc": MSRC_UPDATES,
        "certfr": CERTFR_AVIS_URL,
    }
    url = targets.get(key)
    if not url:
        return {"ok": False, "message": "Source inconnue."}
    own = http is None
    client = http or make_client()
    try:
        headers = {"User-Agent": USER_AGENT}
        if key == "github" and settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"
        request = client.build_request("GET", url, headers=headers)
        response = client.send(request, stream=True, timeout=20)
        try:
            if response.status_code < 400:
                return {"ok": True, "message": f"{key} répond (HTTP {response.status_code})."}
            return {"ok": False, "message": f"{key} a répondu HTTP {response.status_code}."}
        finally:
            response.close()
    except Exception as exc:
        return {"ok": False, "message": f"{key} est injoignable : {exc}"}
    finally:
        if own:
            client.close()


def launch_source_update(app) -> None:
    """Collecte en arrière-plan, puis nouvelle vérification du parc."""

    def worker() -> None:
        db = app.state.SessionLocal()
        try:
            try:
                update_sources(db, app.state.settings)
            except Exception:
                logger.exception("La mise à jour des sources a échoué")
                return
            from app.glpi.service import run_verification

            try:
                run_verification(db, app.state.settings)
            except Exception:
                logger.exception("La vérification après les sources a échoué")
        finally:
            db.close()

    threading.Thread(target=worker, name="glpi-maj-sources", daemon=True).start()


def _execute(db, settings, client, key, products: list[Product], sleep, limiter, runner, now) -> bool:
    started = utcnow()
    run = SourceRun(source=key, started_at=started, status="running", message=f"Début {started:%Y-%m-%d %H:%M:%S}")
    db.add(run)
    db.commit()
    warning = ""
    try:
        count = _dispatch(db, settings, client, key, products, sleep, limiter, runner, now)
    except SourceWarning as exc:
        count = exc.count
        warning = str(exc)
        ok = count > 0
        run.status = "success" if ok else "error"
        run.items_count = count
        run.error = None if ok else warning
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
    if warning and ok:
        run.message += f" Incomplet : {warning}"
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
    if key == "certfr":
        return _collect_certfr(db, client, products, sleep, now)
    if key == "feeds":
        return _collect_feeds(db, client, products, sleep, now)
    return 0


def _wanted(products: list[Product], predicate) -> list[Product]:
    return [product for product in products if predicate(product)]


def _fresh_today(db, source: str, cache_key: str, now: datetime) -> bool:
    cached = get_cache(db, source, cache_key)
    return bool(
        cached
        and cached.checked_at
        and cached.checked_at.date() == now.date()
        and not cached.last_error
        and payload_of(cached)
    )


def _collect_winget(db, settings, products, runner, now) -> int:
    wanted = _wanted(products, lambda product: product.winget_id)
    if not wanted:
        return 0
    if all(_fresh_today(db, "winget", product.slug, now) for product in wanted):
        return len(wanted)
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
    failures: list[str] = []
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
        try:
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
                raise RuntimeError(f"GitHub a répondu HTTP {response.status_code} pour {product.github}.")
            parsed = parse_github_release(response.json())
        except Exception as exc:
            mark_error(db, "github", product.slug, str(exc))
            failures.append(f"{product.label} : {exc}")
            continue
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
    if failures:
        raise SourceWarning(count, " ; ".join(failures))
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
    if _fresh_today(db, "msrc", "catalog", now):
        return 1
    listing = get_with_retries(
        client,
        MSRC_UPDATES,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        timeout=120,
        sleep=sleep,
    )
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
        timeout=120,
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
    horizon = now - timedelta(days=VULN_RECENT_DAYS)
    for product in wanted:
        previous = payload_of(get_cache(db, "nvd", product.slug))
        start, end = _nvd_window(now, previous.get("last_mod_end"), horizon)
        params = {
            "cpeName": product.cpe,
            "resultsPerPage": 50,
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        }
        response = _nvd_get(client, params, settings.nvd_api_key, limiter, sleep)
        parsed = parse_nvd(response.json())
        merged = {
            item["id"]: item
            for item in previous.get("cves", [])
            if _recent_stamp(item.get("modified"), horizon)
        }
        for item in parsed:
            if not item.get("modified"):
                item["modified"] = now.strftime("%Y-%m-%dT%H:%M:%S")
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


def _nvd_window(now: datetime, previous_end: object, horizon: datetime) -> tuple[datetime, datetime]:
    """Fenêtre NVD d'au plus 120 jours, en reprenant après la dernière lecture."""
    end = now
    start = horizon + timedelta(seconds=1)
    if previous_end:
        try:
            parsed = datetime.fromisoformat(str(previous_end))
        except ValueError:
            parsed = None
        if parsed is not None and start < parsed < end:
            start = parsed
    return start, end


def _recent_stamp(value: object, horizon: datetime) -> bool:
    text = str(value or "")[:19]
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return False
    return moment >= horizon


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
    horizon = now - timedelta(days=VULN_RECENT_DAYS)
    recent = {
        cve_id: row
        for cve_id, row in (parsed.get("cves") or {}).items()
        if _recent_stamp(row.get("date_added"), horizon)
    }
    parsed["cves"] = recent
    put_cache(db, "kev", "catalog", parsed, origin="live", now=now)
    return len(recent)


def _collect_certfr(db, client, products, sleep, now) -> int:
    listed = get_cache(db, "certfr", "bulletins")
    listed_items = payload_of(listed).get("items") or []
    catalog = get_cache(db, "certfr", "catalog")
    lists_ready = (
        listed is not None
        and listed.checked_at
        and listed.checked_at.date() == now.date()
        and not listed.last_error
        and listed_items
    )
    catalog_ready = (
        catalog is not None
        and catalog.checked_at
        and catalog.checked_at.date() == now.date()
        and not catalog.last_error
    )
    if lists_ready and catalog_ready:
        _refresh_security_watches(db, client, sleep)
        return len(listed_items)
    _dire(db, "Téléchargement des avis CERT-FR")
    avis = _certfr_index(client, CERTFR_AVIS_URL, sleep)
    alertes = _certfr_index(client, CERTFR_ALERTE_URL, sleep)
    bulletins = _recent_bulletins(avis, alertes, products, now)
    put_cache(db, "certfr", "bulletins", {"items": bulletins}, origin="live", now=now)
    _refresh_security_watches(db, client, sleep, avis=avis, alertes=alertes)
    _dire(db, f"Avis CERT-FR enregistrés ({len(bulletins)}). Lecture des fiches.")
    latest = _certfr_latest_rows(avis, alertes, products)
    chosen = {slug: str(row.get("reference") or "") for slug, row in latest.items()}
    cves: dict[str, dict] = {}
    seen_refs: set[str] = set()
    for item in latest.values():
        reference = str(item.get("reference") or "")
        if not reference or reference in seen_refs:
            continue
        seen_refs.add(reference)
        try:
            response = get_with_retries(
                client,
                _certfr_detail_url(item),
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                sleep=sleep,
            )
            if response.status_code >= 400:
                continue
            parsed = parse_certfr(response.json(), kind=item["kind"])
        except Exception:
            continue
        parsed["revised"] = str(item.get("last_revision_date") or "")
        owned = [slug for slug in _certfr_slugs(parsed, products) if chosen.get(slug) == reference]
        cve = _newest_cve(parsed["cves"])
        if not owned or cve is None:
            continue
        score = _cve_score(client, cve["id"], sleep)
        parsed["cvss"] = score.get("cvss")
        parsed["severite"] = severity_name(parsed["cvss"], alert=parsed["alert"], cvss_label=score.get("cvss_label") or "")
        _remember_certfr(cves, parsed, cve["id"], owned)
    put_cache(db, "certfr", "catalog", {"cves": cves}, origin="live", now=now)
    return len(bulletins)


def _refresh_security_watches(db, client, sleep, avis: list | None = None, alertes: list | None = None) -> None:
    """Relit le dernier bulletin de chaque sujet suivi, et le remplace s'il est ancien ou clôturé."""
    from app.models.history import SecurityWatch
    from app.watches import apply_latest, choose_latest

    watches = list(db.scalars(select(SecurityWatch)))
    if not watches:
        return
    if avis is None or alertes is None:
        try:
            avis = _certfr_index(client, CERTFR_AVIS_URL, sleep)
            alertes = _certfr_index(client, CERTFR_ALERTE_URL, sleep)
        except Exception:
            logger.exception("La relecture des suivis CERT-FR a échoué")
            return
    rows = _index_bulletins(avis, alertes)
    chosen = choose_latest(rows, {watch.subject_key for watch in watches})
    for row in chosen.values():
        _mark_closed(client, row, sleep)
    apply_latest(db, rows)


def _index_bulletins(avis: list, alertes: list) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    for kind, items in (("alerte", alertes), ("avis", avis)):
        for row in items:
            if not isinstance(row, dict):
                continue
            revised = _certfr_date(row.get("last_revision_date"))
            reference = str(row.get("reference") or "").strip()
            if revised is None or not reference or reference in seen or "/" in reference or ".." in reference:
                continue
            seen.add(reference)
            rows.append(
                {
                    "reference": reference,
                    "title": str(row.get("title") or "").strip(),
                    "url": f"{CERTFR_SITE}/{kind}/{reference}/",
                    "revised": revised.date().isoformat(),
                    "alert": kind == "alerte",
                    "closed": False,
                    "json_url": str(row.get("json_url") or ""),
                    "kind": kind,
                }
            )
    return rows


def _mark_closed(client, row: dict, sleep) -> None:
    try:
        response = get_with_retries(
            client,
            _certfr_detail_url(row),
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            sleep=sleep,
        )
    except Exception:
        logger.warning("La fiche %s n'a pas pu être lue pour savoir si elle est clôturée.", row.get("reference"))
        return
    if response.status_code >= 400:
        return
    try:
        payload = response.json()
    except Exception:
        return
    if isinstance(payload, dict):
        row["closed"] = bool(payload.get("closed_at"))
        if payload.get("title"):
            row["title"] = str(payload["title"]).strip()


def _dire(db, texte: str) -> None:
    parent = db.scalar(
        select(SourceRun).where(SourceRun.source == "toutes", SourceRun.status == "running").order_by(SourceRun.id.desc())
    )
    if parent is None:
        return
    parent.message = texte
    db.commit()


def _recent_bulletins(avis: list, alertes: list, products: list[Product], now: datetime) -> list[dict]:
    """Avis et alertes des derniers mois, même sans logiciel du parc."""
    horizon = (now - timedelta(days=VULN_RECENT_DAYS)).date()
    matcher = _SlugMatcher(products)
    rows: list[dict] = []
    seen: set[str] = set()
    for kind, items in (("alerte", alertes), ("avis", avis)):
        for row in items:
            if not isinstance(row, dict):
                continue
            revised = _certfr_date(row.get("last_revision_date"))
            reference = str(row.get("reference") or "").strip()
            if revised is None or revised.date() < horizon or not reference or reference in seen:
                continue
            if "/" in reference or ".." in reference:
                continue
            seen.add(reference)
            title = str(row.get("title") or "").strip()
            rows.append(
                {
                    "reference": reference,
                    "title": title,
                    "kind": kind,
                    "alert": kind == "alerte",
                    "revised": revised.date().isoformat(),
                    "url": f"{CERTFR_SITE}/{kind}/{reference}/",
                    "products": sorted(matcher.slugs(title, families=False)),
                }
            )
    rows.sort(key=lambda item: (item["revised"], item["alert"]), reverse=True)
    return rows


def _cve_score(client, cve_id: str, sleep) -> dict:
    """Lit la note CVSS. Une fiche inaccessible ne bloque pas le bulletin."""
    if not re.fullmatch(r"CVE-\d{4}-\d+", cve_id):
        return {}
    try:
        response = get_with_retries(
            client,
            CVE_RECORD_URL.format(cve=cve_id),
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            sleep=sleep,
        )
    except Exception:
        return {}
    if response.status_code >= 400:
        return {}
    try:
        return parse_cve_score(response.json())
    except Exception:
        return {}


def _certfr_index(client, url: str, sleep) -> list:
    response = get_with_retries(
        client,
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        timeout=90,
        sleep=sleep,
    )
    if response.status_code >= 400:
        raise RuntimeError(f"CERT-FR a répondu HTTP {response.status_code}.")
    payload = response.json()
    if not isinstance(payload, list):
        raise RuntimeError("L'index CERT-FR n'est pas une liste.")
    return payload


def _certfr_latest_rows(avis: list, alertes: list, products: list[Product]) -> dict[str, dict]:
    """Le bulletin le plus récent de chaque logiciel suivi."""
    newest: dict[str, dict] = {}
    matcher = _SlugMatcher(products)
    for kind, rows in (("avis", avis), ("alerte", alertes)):
        for row in rows:
            if not isinstance(row, dict):
                continue
            revised = _certfr_date(row.get("last_revision_date"))
            if revised is None:
                continue
            slugs = matcher.slugs(str(row.get("title") or ""))
            if not slugs:
                continue
            stamped = {**row, "kind": kind, "revised": revised}
            for slug in slugs:
                current = newest.get(slug)
                if current is None or _certfr_is_newer(stamped, current):
                    newest[slug] = stamped
    return newest


def _certfr_is_newer(candidate: dict, current: dict) -> bool:
    if candidate["revised"] != current["revised"]:
        return candidate["revised"] > current["revised"]
    return candidate["kind"] == "alerte" and current["kind"] != "alerte"


def _newest_cve(cves: list[dict]) -> dict | None:
    ranked = [item for item in cves if item.get("id")]
    if not ranked:
        return None
    return max(ranked, key=lambda item: _cve_rank(str(item["id"])))


def _cve_rank(cve_id: str) -> tuple[int, int, str]:
    match = re.search(r"CVE-(\d+)-(\d+)", cve_id.upper())
    if not match:
        return (0, 0, cve_id)
    return (int(match.group(1)), int(match.group(2)), cve_id)


def _certfr_date(value: object) -> datetime | None:
    text = str(value or "")[:10]
    try:
        return datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        return None


def _certfr_detail_url(row: dict) -> str:
    path = str(row.get("json_url") or "")
    if path.startswith(f"{CERTFR_SITE}/") and ".." not in path:
        return path
    if path.startswith(("/avis/", "/alerte/")) and ".." not in path:
        return CERTFR_SITE + path
    reference = str(row.get("reference") or "")
    kind = "alerte" if row.get("kind") == "alerte" or "-ALE-" in reference else "avis"
    if not reference or "/" in reference or ".." in reference:
        raise RuntimeError("Référence CERT-FR inattendue.")
    return f"{CERTFR_SITE}/{kind}/{reference}/json/"


def _certfr_slugs(parsed: dict, products: list[Product]) -> list[str]:
    texts = [parsed.get("title") or "", parsed.get("summary") or ""]
    for system in parsed.get("systems") or []:
        texts.append(f"{system.get('vendor', '')} {system.get('product', '')}")
        texts.append(system.get("description") or "")
    found: set[str] = set()
    for text in texts:
        found |= _slugs_in(text, products, families=False)
    blob = " ".join(texts)
    if not any(slug.startswith("windows") for slug in found):
        found |= _family_slugs(blob, products, "windows")
    if not any(slug.startswith("office") or slug == "m365" for slug in found):
        found |= _family_slugs(blob, products, "office")
    if "java8" not in found:
        found |= _family_slugs(blob, products, "java")
    return sorted(found)


class _SlugMatcher:
    """Expressions compilées une fois pour les 18 000 titres de l'index CERT-FR."""

    def __init__(self, products: list[Product]) -> None:
        self._compiled: list[tuple[str, list[re.Pattern[str]]]] = []
        for product in products:
            patterns = [re.compile(rf"(?<![\w+]){re.escape(alias)}(?![\w+])") for alias in product.aliases]
            self._compiled.append((product.slug, patterns))
        self._windows = re.compile(r"(?<![\w+])windows(?![\w+])")
        self._office = re.compile(r"(?<![\w+])(?:office|microsoft 365)(?![\w+])")
        self._java = re.compile(r"(?<![\w+])java(?![\w+])")
        self._windows_slugs = {product.slug for product in products if product.slug.startswith("windows")}
        self._office_slugs = {product.slug for product in products if product.slug.startswith("office") or product.slug == "m365"}
        self._java_slugs = {product.slug for product in products if product.slug == "java8"}

    def slugs(self, text: str, *, families: bool = True) -> set[str]:
        key = match_key(text)
        if not key:
            return set()
        found: set[str] = set()
        for slug, patterns in self._compiled:
            for pattern in patterns:
                if pattern.search(key):
                    found.add(slug)
                    break
        if not families:
            return found
        if not any(slug.startswith("windows") for slug in found) and self._windows.search(key):
            found |= self._windows_slugs
        if not any(slug.startswith("office") or slug == "m365" for slug in found) and self._office.search(key):
            found |= self._office_slugs
        if "java8" not in found and self._java.search(key):
            found |= self._java_slugs
        return found


def _slugs_in(text: str, products: list[Product], *, families: bool = True) -> set[str]:
    key = match_key(text)
    if not key:
        return set()
    found: set[str] = set()
    for product in products:
        for alias in product.aliases:
            if re.search(rf"(?<![\w+]){re.escape(alias)}(?![\w+])", key):
                found.add(product.slug)
                break
    if not families:
        return found
    found |= _family_slugs(key, products, "windows", already=found)
    found |= _family_slugs(key, products, "office", already=found)
    found |= _family_slugs(key, products, "java", already=found)
    return found


def _family_slugs(text: str, products: list[Product], family: str, already: set[str] | None = None) -> set[str]:
    known = already or set()
    key = match_key(text)
    if family == "windows":
        if any(slug.startswith("windows") for slug in known):
            return set()
        if not re.search(r"(?<![\w+])windows(?![\w+])", key):
            return set()
        return {product.slug for product in products if product.slug.startswith("windows")}
    if family == "office":
        if any(slug.startswith("office") or slug == "m365" for slug in known):
            return set()
        if not re.search(r"(?<![\w+])(?:office|microsoft 365)(?![\w+])", key):
            return set()
        return {product.slug for product in products if product.slug.startswith("office") or product.slug == "m365"}
    if any(slug == "java8" for slug in known) or not re.search(r"(?<![\w+])java(?![\w+])", key):
        return set()
    return {product.slug for product in products if product.slug == "java8"}


def _remember_certfr(cves: dict, parsed: dict, cve_id: str, slugs: list[str]) -> None:
    previous = cves.get(cve_id)
    products = list(slugs)
    alert = bool(parsed["alert"])
    url = parsed["url"]
    title = parsed["title"]
    summary = parsed["summary"]
    reference = parsed["reference"]
    if previous:
        products = sorted(set(previous["products"]) | set(products))
        if previous["alert"] and not alert:
            url = previous["url"]
            title = previous["title"]
            summary = previous["summary"]
            reference = previous["reference"]
        alert = previous["alert"] or alert
    cves[cve_id] = {
        "id": cve_id,
        "url": url,
        "title": title,
        "summary": summary,
        "alert": alert,
        "cvss": parsed.get("cvss"),
        "severite": parsed.get("severite") or "",
        "reference": reference,
        "revised": parsed.get("revised") or "",
        "products": products,
    }


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
    if key == "certfr":
        mark_error(db, "certfr", "catalog", message)
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

    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=300)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("git a dépassé 5 minutes : " + " ".join(command)) from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        tail = detail[-1][:240] if detail else f"code {completed.returncode}"
        raise RuntimeError(f"git a échoué ({tail})")
    return 0
