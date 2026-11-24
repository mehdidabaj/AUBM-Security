from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session

from app.actions.engine import is_up_to_date, priority_of
from app.actions.mapping import resolve_slug
from app.actions.rules import include_low
from app.actions.versions import highest_version, parse_version
from app.config import Settings
from app.glpi.service import glpi_computer_url, latest_successful
from app.sources.catalog import PRODUCTS
from app.web.queries import SEVERITY_LABELS, _computers, actions_by_computer, dashboard, software_rows
from app.sources.cache import source_overview

PARIS = ZoneInfo("Europe/Paris")


def paris(value: datetime | None) -> str:
    if value is None:
        return "—"
    aware = value.replace(tzinfo=timezone.utc)
    return aware.astimezone(PARIS).strftime("%d/%m/%Y %H:%M")


def now_paris() -> str:
    return datetime.now(PARIS).strftime("%d/%m/%Y %H:%M")


def build_model(db: Session, settings: Settings) -> dict:
    """Données communes à l'Excel et au PDF."""
    board = dashboard(db, settings)
    run = latest_successful(db)
    produits: dict[str, str] = {}
    postes = []
    vigilance = []
    if run is not None:
        grouped = actions_by_computer(db, run)
        count_low = include_low(db)
        for computer in _computers(db, run):
            actions = grouped.get(computer.glpi_id, [])
            cellules = _cells(db, computer, actions, produits)
            autres = [item.title for item in actions if item.severity == "autre"]
            priority = priority_of(actions)
            postes.append(
                {
                    "nom": computer.name,
                    "service": computer.group_name or "—",
                    "inventaire": paris(computer.last_inventory_at),
                    "a_jour": "Oui" if is_up_to_date(actions, count_low) else "Non",
                    "priorite": priority,
                    "priorite_libelle": SEVERITY_LABELS.get(priority, priority),
                    "nombre": len([item for item in actions if item.severity != "autre"]),
                    "autres": " ; ".join(autres),
                    "lien": glpi_computer_url(settings, computer.glpi_id),
                    "cellules": cellules,
                    "actions": [
                        {
                            "titre": item.title,
                            "detail": item.detail,
                            "severite": item.severity,
                            "url": item.source_url,
                            "cves": item.cves_json,
                        }
                        for item in actions
                    ],
                }
            )
        critiques = [item["nom"] for item in postes if item["priorite"] == "critique"]
        if critiques:
            vigilance.append("Postes critiques : " + ", ".join(critiques))
    for source in source_overview(db):
        if source["etat"] != "ok":
            vigilance.append(f"{source['libelle']} : {source['etat']}")
    if not vigilance:
        vigilance.append("Aucun point de vigilance.")
    ordre = sorted(produits, key=lambda slug: produits[slug].lower())
    return {
        "date": now_paris(),
        "chiffres": {
            "analyses": board.get("analyses", 0),
            "a_jour": board.get("a_jour", 0),
            "a_mettre_a_jour": board.get("a_mettre_a_jour", 0),
            "critiques": board.get("critiques", 0),
            "actions": board.get("actions", 0),
        },
        "logiciels": software_rows(db),
        "vigilance": vigilance,
        "postes": postes,
        "produits": [{"slug": slug, "label": produits[slug]} for slug in ordre],
    }


def _cells(db: Session, computer, actions, produits: dict[str, str]) -> dict[str, dict]:
    installed: dict[str, list[str]] = {}
    for software in computer.software:
        slug = resolve_slug(db, software.name)
        if not slug or not parse_version(software.version):
            continue
        installed.setdefault(slug, []).append(software.version)
        produits.setdefault(slug, PRODUCTS[slug].label if slug in PRODUCTS else slug)
    by_slug = {}
    rank = {"a_jour": 0, "faible": 1, "important": 2, "critique": 3}
    for action in actions:
        if not action.product_slug or action.severity == "autre":
            continue
        current = by_slug.get(action.product_slug)
        if current is None or rank.get(action.severity, 0) >= rank.get(current.severity, 0):
            by_slug[action.product_slug] = action
        produits.setdefault(
            action.product_slug,
            PRODUCTS[action.product_slug].label if action.product_slug in PRODUCTS else action.title,
        )
    cells = {}
    for slug in set(installed) | set(by_slug):
        action = by_slug.get(slug)
        current = highest_version(installed.get(slug, [])) or (action.installed_version if action else "")
        target = action.target_version if action else ""
        if current and target:
            texte = f"{current} → {target}"
        else:
            texte = current or target
        if not texte:
            continue
        cells[slug] = {
            "texte": texte,
            "url": action.source_url if action else "",
            "severite": action.severity if action else "a_jour",
        }
    return cells
