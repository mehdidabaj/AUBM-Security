from __future__ import annotations

import json
from collections import Counter, defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.actions.engine import follow_up_for, is_up_to_date, priority_of
from app.actions.mapping import unmatched_names
from app.actions.rules import include_low
from app.actions.versions import is_outdated, parse_version
from app.glpi.service import glpi_computer_url, latest_successful
from app.models.actions import ComputedAction
from app.models.inventory import CheckRun
from app.models.sources import SourceRun
from app.sources.cache import source_overview, version_target
from app.sources.catalog import PRODUCTS
from app.config import Settings

SEVERITY_LABELS = {
    "critique": "Critique",
    "important": "Important",
    "faible": "Faible",
    "a_jour": "À jour",
    "autre": "Autre",
}
STATUS_LABELS = {"a_faire": "À faire", "en_cours": "En cours", "fait": "Fait"}


def actions_by_computer(db: Session, run: CheckRun) -> dict[int, list[ComputedAction]]:
    grouped: dict[int, list[ComputedAction]] = defaultdict(list)
    for action in db.scalars(select(ComputedAction).where(ComputedAction.check_run_id == run.id)):
        grouped[action.glpi_computer_id].append(action)
    return grouped


def computer_views(db: Session, settings: Settings, params: dict) -> dict:
    run = latest_successful(db)
    if run is None:
        return {"run": None, "rows": [], "services": [], "lieux": [], "logiciels": []}
    grouped = actions_by_computer(db, run)
    count_low = include_low(db)
    rows = []
    services = set()
    lieux = set()
    logiciels = set()
    for computer in run.computers:
        actions = grouped.get(computer.glpi_id, [])
        priority = priority_of(actions)
        up_to_date = is_up_to_date(actions, count_low)
        names = sorted({item.name for item in computer.software})
        services.add(computer.group_name)
        lieux.add(computer.location)
        logiciels.update(names)
        if params.get("service") and computer.group_name != params["service"]:
            continue
        if params.get("lieu") and computer.location != params["lieu"]:
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
                "lieu": computer.location,
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
            order = {"critique": 0, "important": 1, "faible": 2, "a_jour": 3}
            return order.get(row["priorite"], 9)
        value = row.get(sort, row["nom"])
        if isinstance(value, str):
            return value.lower()
        return value

    rows.sort(key=key, reverse=reverse)
    return {
        "run": run,
        "rows": rows,
        "services": sorted(item for item in services if item),
        "lieux": sorted(item for item in lieux if item),
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
    for item in runs:
        total = len(
            [
                action
                for action in db.scalars(select(ComputedAction).where(ComputedAction.check_run_id == item.id))
                if action.severity != "autre"
            ]
        )
        evolution.append({"label": item.finished_at.strftime("%d/%m %H:%M") if item.finished_at else str(item.id), "actions": total})
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
    run = latest_successful(db)
    if run is None:
        return None
    computer = next((item for item in run.computers if item.glpi_id == glpi_id), None)
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
    return {
        "computer": computer,
        "actions": detailed,
        "priorite": priority_of(actions),
        "a_jour": is_up_to_date(actions, include_low(db)),
        "lien": glpi_computer_url(settings, glpi_id),
    }


def software_rows(db: Session) -> list[dict]:
    run = latest_successful(db)
    if run is None:
        return []
    presence: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for computer in run.computers:
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

        rows.append(
            {
                "slug": slug,
                "nom": PRODUCTS[slug].label if slug in PRODUCTS else slug,
                "courante": common,
                "publiee": (target or {}).get("version") or "—",
                "a_jour": up,
                "en_retard": behind,
                "cves": _cves_for(db, slug),
            }
        )
    return rows


def journal(db: Session, limit: int = 30) -> list[SourceRun]:
    return list(db.scalars(select(SourceRun).order_by(SourceRun.id.desc()).limit(limit)))
