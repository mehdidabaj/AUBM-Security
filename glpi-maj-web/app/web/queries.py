from __future__ import annotations

import json
import re
from collections import Counter, defaultdict

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.actions.engine import follow_up_for, is_up_to_date, priority_of
from app.actions.mapping import resolve_slug, unmatched_names
from app.actions.rules import include_low
from app.actions.versions import is_outdated, parse_version
from app.glpi.service import glpi_computer_url, latest_successful, visible_run
from app.models.actions import ComputedAction
from app.models.history import SoftwareChange
from app.models.inventory import CheckRun, ComputerRecord
from app.models.sources import SourceRun
from app.security_topics import KIND_LABELS, bulletin_kind
from app.watches import follows, watched_keys
from app.sources.cache import get_cache, payload_of, source_overview, version_target
from app.sources.catalog import PRODUCTS, match_key
from app.sources.service import VULN_RECENT_DAYS
from app.config import Settings

SEVERITY_LABELS = {
    "critique": "Critique",
    "important": "Important",
    "faible": "Faible",
    "a_jour": "À jour",
    "autre": "Autre",
    "lecture": "Lecture",
}
STATUS_LABELS = {"a_faire": "À faire", "en_cours": "En cours", "fait": "Fait"}


def actions_by_computer(db: Session, run: CheckRun) -> dict[int, list[ComputedAction]]:
    grouped: dict[int, list[ComputedAction]] = defaultdict(list)
    for action in db.scalars(select(ComputedAction).where(ComputedAction.check_run_id == run.id)):
        grouped[action.glpi_computer_id].append(action)
    return grouped


def _computers(db: Session, run: CheckRun) -> list[ComputerRecord]:
    return list(
        db.scalars(
            select(ComputerRecord)
            .where(ComputerRecord.check_run_id == run.id)
            .options(selectinload(ComputerRecord.software), selectinload(ComputerRecord.agent))
            .order_by(ComputerRecord.glpi_id)
        )
    )


def computer_views(db: Session, settings: Settings, params: dict) -> dict:
    run = visible_run(db)
    if run is None:
        return {"run": None, "en_cours": False, "lus": 0, "installations": 0, "rows": [], "services": [], "logiciels": []}
    grouped = actions_by_computer(db, run)
    count_low = include_low(db)
    en_cours = run.status == "running"
    rows = []
    services = set()
    logiciels = set()
    lus = 0
    installations = 0
    for computer in _computers(db, run):
        lus += 1
        installations += len(computer.software)
        actions = grouped.get(computer.glpi_id, [])
        if en_cours and not actions:
            priority = "lecture"
            up_to_date = False
        else:
            priority = priority_of(actions)
            up_to_date = is_up_to_date(actions, count_low)
        names = sorted({item.name for item in computer.software})
        services.add(computer.group_name)
        logiciels.update(names)
        if params.get("service") and computer.group_name != params["service"]:
            continue
        if params.get("priorite") and priority != params["priorite"]:
            continue
        if params.get("a_jour") == "oui" and not up_to_date:
            continue
        if params.get("a_jour") == "non" and up_to_date:
            continue
        if params.get("logiciel") and params["logiciel"] not in names:
            continue
        query = (params.get("q") or "").strip().lower()
        if query and query not in computer.name.lower() and query not in " ".join(names).lower():
            continue
        rows.append(
            {
                "glpi_id": computer.glpi_id,
                "nom": computer.name,
                "service": computer.group_name,
                "priorite": priority,
                "priorite_libelle": SEVERITY_LABELS.get(priority, priority),
                "a_jour": up_to_date,
                "actions": len([item for item in actions if item.severity != "autre"]),
                "logiciels": names,
                "lien": glpi_computer_url(settings, computer.glpi_id),
            }
        )
    sort = params.get("tri") or "nom"
    reverse = params.get("sens") == "desc"

    def key(row):
        if sort == "priorite":
            order = {"critique": 0, "important": 1, "faible": 2, "lecture": 3, "a_jour": 4}
            return order.get(row["priorite"], 9)
        value = row.get(sort, row["nom"])
        if isinstance(value, str):
            return value.lower()
        return value

    rows.sort(key=key, reverse=reverse)
    return {
        "run": run,
        "en_cours": en_cours,
        "lus": lus,
        "installations": installations,
        "rows": rows,
        "services": sorted(item for item in services if item),
        "logiciels": sorted(logiciels),
    }


def dashboard(db: Session, settings: Settings) -> dict:
    run = latest_successful(db)
    if run is None:
        return {"run": None, "sources": source_overview(db), "evolution": [], "par_logiciel": []}
    grouped = actions_by_computer(db, run)
    count_low = include_low(db)
    analysed = len(run.computers)
    up = 0
    critical = 0
    action_count = 0
    silent = []
    per_product: Counter[str] = Counter()
    for computer in run.computers:
        actions = grouped.get(computer.glpi_id, [])
        if is_up_to_date(actions, count_low):
            up += 1
        if priority_of(actions) == "critique":
            critical += 1
        for action in actions:
            if action.severity != "autre":
                action_count += 1
                label = PRODUCTS[action.product_slug].label if action.product_slug in PRODUCTS else action.title
                per_product[label] += 1
            if action.kind == "agent_silencieux":
                silent.append(computer.name)
    evolution = []
    runs = list(db.scalars(select(CheckRun).where(CheckRun.status == "success").order_by(CheckRun.id)))
    totals: dict[int, int] = {}
    run_ids = [item.id for item in runs]
    if run_ids:
        for run_id, total in db.execute(
            select(ComputedAction.check_run_id, func.count())
            .where(ComputedAction.check_run_id.in_(run_ids), ComputedAction.severity != "autre")
            .group_by(ComputedAction.check_run_id)
        ):
            totals[int(run_id)] = int(total)
    for item in runs:
        evolution.append(
            {
                "label": item.finished_at.strftime("%d/%m %H:%M") if item.finished_at else str(item.id),
                "actions": totals.get(item.id, 0),
            }
        )
    summary = json.loads(run.summary_json or "{}")
    return {
        "run": run,
        "analyses": analysed,
        "a_jour": up,
        "a_mettre_a_jour": analysed - up,
        "critiques": critical,
        "actions": action_count,
        "silencieux": silent,
        "resume": summary,
        "sources": source_overview(db),
        "par_logiciel": per_product.most_common(12),
        "evolution": evolution,
    }


def computer_detail(db: Session, settings: Settings, glpi_id: int) -> dict | None:
    run = visible_run(db)
    if run is None:
        return None
    computer = db.scalar(
        select(ComputerRecord)
        .where(ComputerRecord.check_run_id == run.id, ComputerRecord.glpi_id == glpi_id)
        .options(selectinload(ComputerRecord.software), selectinload(ComputerRecord.agent))
    )
    if computer is None:
        return None
    actions = actions_by_computer(db, run).get(glpi_id, [])
    detailed = []
    for action in actions:
        follow = follow_up_for(db, action.action_key)
        detailed.append(
            {
                "action": action,
                "cves": json.loads(action.cves_json or "[]"),
                "suivi": follow,
            }
        )
    en_cours = run.status == "running" and not actions
    return {
        "computer": computer,
        "actions": detailed,
        "priorite": "lecture" if en_cours else priority_of(actions),
        "a_jour": False if en_cours else is_up_to_date(actions, include_low(db)),
        "en_cours": run.status == "running",
        "lien": glpi_computer_url(settings, glpi_id),
        "historique": list(
            db.scalars(
                select(SoftwareChange)
                .where(SoftwareChange.glpi_computer_id == glpi_id)
                .order_by(SoftwareChange.detected_at.desc(), SoftwareChange.id.desc())
                .limit(30)
            )
        ),
    }


def software_rows(db: Session) -> list[dict]:
    run = visible_run(db)
    if run is None:
        return []
    presence: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for computer in _computers(db, run):
        by_slug: dict[str, list[str]] = defaultdict(list)
        for software in computer.software:
            from app.actions.mapping import resolve_slug

            slug = resolve_slug(db, software.name)
            if slug and parse_version(software.version):
                by_slug[slug].append(software.version)
        for slug, versions in by_slug.items():
            from app.actions.versions import highest_version

            best = highest_version(versions)
            if best:
                presence[slug].append((computer.glpi_id, best))
    rows = []
    for slug, installs in sorted(presence.items(), key=lambda item: PRODUCTS[item[0]].label if item[0] in PRODUCTS else item[0]):
        counter = Counter(version for _computer, version in installs)
        common = counter.most_common(1)[0][0]
        target = version_target(db, slug)
        behind = 0
        up = 0
        for _computer, version in installs:
            if target and is_outdated(version, target["version"], target.get("mode") or "ge"):
                behind += 1
            else:
                up += 1
        from app.actions.engine import _cves_for

        cves = _cves_for(db, slug)
        faille = cves[0] if cves else {}
        rows.append(
            {
                "slug": slug,
                "nom": PRODUCTS[slug].label if slug in PRODUCTS else slug,
                "courante": common,
                "publiee": (target or {}).get("version") or "—",
                "a_jour": up,
                "en_retard": behind,
                "cves": cves,
                "severite": faille.get("severite") or "",
                "cvss": faille.get("cvss"),
            }
        )
    return rows


def unknown_software(db: Session) -> list[dict]:
    """Logiciels lus qui ne correspondent à aucun produit suivi."""
    from app.actions.mapping import resolve_slug

    run = visible_run(db)
    if run is None:
        return []
    counts: Counter[str] = Counter()
    for computer in _computers(db, run):
        seen: set[str] = set()
        for software in computer.software:
            slug = resolve_slug(db, software.name)
            if slug and parse_version(software.version):
                continue
            name = (software.name or "").strip()
            if name and name not in seen:
                seen.add(name)
                counts[name] += 1
    return [{"nom": name, "postes": count} for name, count in counts.most_common()]


def journal(db: Session, limit: int = 30) -> list[SourceRun]:
    return list(db.scalars(select(SourceRun).order_by(SourceRun.id.desc()).limit(limit)))


_SECURITY_MODES = {"", "parc", "logiciel", "materiel", "ransomware", "suivis"}
_KIND_RANK = {"ransomware": 0, "materiel": 1, "logiciel": 2}


def security_bulletins(db: Session, *, mode: str = "") -> dict:
    """Avis et alertes CERT-FR récents, filtrés par parc, type ou suivi."""
    if mode not in _SECURITY_MODES:
        mode = ""
    payload = payload_of(get_cache(db, "certfr", "bulletins"))
    raw = payload.get("items")
    if not raw:
        raw = payload_of(get_cache(db, "certfr", "catalog")).get("bulletins") or []
    installed = _installed_slugs(db)
    followed = watched_keys(db)
    alertes: list[dict] = []
    avis: list[dict] = []
    lus = 0
    for row in raw:
        if not isinstance(row, dict):
            continue
        lus += 1
        title = str(row.get("title") or "")
        kind = bulletin_kind(title)
        logiciels = [PRODUCTS[slug].label for slug in _cited_on_park(title, installed)]
        item = {
            "reference": str(row.get("reference") or ""),
            "title": title,
            "url": str(row.get("url") or ""),
            "revised": str(row.get("revised") or ""),
            "lie": bool(logiciels),
            "logiciels": logiciels,
            "type": kind,
            "type_label": KIND_LABELS.get(kind, "Logiciel"),
            "suivi": follows(title, followed),
        }
        if mode == "parc" and not item["lie"]:
            continue
        if mode in {"logiciel", "materiel", "ransomware"} and item["type"] != mode:
            continue
        if mode == "suivis" and not item["suivi"]:
            continue
        if row.get("alert"):
            alertes.append(item)
        else:
            avis.append(item)
    for bucket in (alertes, avis):
        bucket.sort(key=lambda item: item["revised"], reverse=True)
        if mode == "":
            bucket.sort(key=lambda item: _KIND_RANK.get(item["type"], 9))
    run = db.scalar(select(SourceRun).where(SourceRun.source == "toutes").order_by(SourceRun.id.desc()))
    en_cours = run is not None and run.status == "running" and run.finished_at is None
    certfr = db.scalar(select(SourceRun).where(SourceRun.source == "certfr").order_by(SourceRun.id.desc()))
    erreur = ""
    if not alertes and not avis and certfr is not None and certfr.status == "error" and mode == "":
        erreur = certfr.error or certfr.message
    return {
        "alertes": alertes,
        "avis": avis,
        "jours": VULN_RECENT_DAYS,
        "lien": mode,
        "lies_seulement": mode == "parc",
        "en_cours": en_cours,
        "erreur": erreur,
        "lus": lus,
    }


def bulletin_title(db: Session, reference: str) -> str:
    payload = payload_of(get_cache(db, "certfr", "bulletins"))
    raw = payload.get("items")
    if not raw:
        raw = payload_of(get_cache(db, "certfr", "catalog")).get("bulletins") or []
    for row in raw:
        if isinstance(row, dict) and str(row.get("reference") or "") == reference:
            return str(row.get("title") or "")
    return ""


def _installed_slugs(db: Session) -> set[str]:
    """Systèmes et logiciels réellement présents sur le parc visible."""
    run = visible_run(db)
    if run is None:
        return set()
    found: set[str] = set()
    for computer in _computers(db, run):
        for label in (computer.os_name, f"{computer.os_name} {computer.os_version}".strip()):
            slug = resolve_slug(db, label)
            if slug:
                found.add(slug)
        for software in computer.software:
            slug = resolve_slug(db, software.name)
            if slug:
                found.add(slug)
    return found


def _cited_on_park(title: str, installed: set[str]) -> list[str]:
    """Produits du parc cités nommément. « Windows » seul ne retient pas Windows 10 ni Windows 11."""
    key = match_key(title)
    if not key or not installed:
        return []
    found: list[str] = []
    for slug in installed:
        product = PRODUCTS.get(slug)
        if product is None:
            continue
        if any(re.search(rf"(?<![\w+]){re.escape(alias)}(?![\w+])", key) for alias in product.aliases):
            found.append(slug)
    found.sort(key=lambda slug: PRODUCTS[slug].label.lower())
    return found
