from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.actions.mapping import resolve_slug, seed_mappings
from app.actions.rules import (
    OFFICE_SLUGS,
    SEVERITY_RANK,
    fixed_rules,
    include_low,
    threshold,
)
from app.actions.versions import highest_version, is_outdated, parse_version
from app.models.actions import ActionFollowUp, ComputedAction
from app.models.inventory import CheckRun, ComputerRecord
from app.sources.cache import is_end_of_life, payload_of, version_target
from app.sources.cache import get_cache
from app.sources.catalog import PRODUCTS
from app.sources.parsers import severity_name
from app.timeutils import utcnow

WINDOWS_GUIDE = "https://learn.microsoft.com/windows/release-health/windows11-release-information"
OFFICE_GUIDE = "https://learn.microsoft.com/lifecycle/products/?products=office"
MSRC_GUIDE = "https://msrc.microsoft.com/update-guide"
BUILD_FEATURES = {
    26300: "26H2",
    26200: "25H2",
    26100: "24H2",
    22631: "23H2",
    22621: "22H2",
    22000: "21H2",
}


def compute_check(db: Session, run: CheckRun, previous: CheckRun | None = None) -> list[ComputedAction]:
    seed_mappings(db)
    rules = fixed_rules(db)
    critical = threshold(db, "severity_critical", 9)
    important = threshold(db, "severity_important", 7)
    db.execute(delete(ComputedAction).where(ComputedAction.check_run_id == run.id))
    from sqlalchemy.orm import selectinload

    computers = db.scalars(
        select(ComputerRecord)
        .where(ComputerRecord.check_run_id == run.id)
        .options(selectinload(ComputerRecord.software), selectinload(ComputerRecord.agent))
        .order_by(ComputerRecord.glpi_id)
    ).all()
    created: list[ComputedAction] = []
    for computer in computers:
        created.extend(_computer_actions(db, run, computer, rules, critical, important))
    db.add_all(created)
    db.flush()
    _update_summary(db, run, previous, created)
    db.commit()
    return created


def compute_computers(db: Session, run: CheckRun, glpi_ids: set[int]) -> None:
    """Recalcule les actions des postes indiqués, sans clôturer la vérification."""
    if not glpi_ids:
        return
    from sqlalchemy.orm import selectinload

    seed_mappings(db)
    rules = fixed_rules(db)
    critical = threshold(db, "severity_critical", 9)
    important = threshold(db, "severity_important", 7)
    db.execute(
        delete(ComputedAction).where(
            ComputedAction.check_run_id == run.id,
            ComputedAction.glpi_computer_id.in_(glpi_ids),
        )
    )
    records = db.scalars(
        select(ComputerRecord)
        .where(ComputerRecord.check_run_id == run.id, ComputerRecord.glpi_id.in_(glpi_ids))
        .options(selectinload(ComputerRecord.software), selectinload(ComputerRecord.agent))
    ).all()
    created: list[ComputedAction] = []
    for computer in records:
        created.extend(_computer_actions(db, run, computer, rules, critical, important))
    if created:
        db.add_all(created)
    db.flush()


def set_follow_up(
    db: Session,
    action_key: str,
    *,
    status: str,
    technician: str = "",
    comment: str = "",
    followed_on: datetime | None = None,
) -> ActionFollowUp:
    if status not in {"a_faire", "en_cours", "fait"}:
        raise ValueError("État de suivi inconnu.")
    row = db.scalar(select(ActionFollowUp).where(ActionFollowUp.action_key == action_key))
    if row is None:
        row = ActionFollowUp(action_key=action_key)
        db.add(row)
        changed = True
    else:
        changed = (
            row.status != status
            or row.technician != technician
            or row.comment != comment
            or row.followed_on != followed_on
        )
    row.status = status
    row.technician = technician
    row.comment = comment
    row.followed_on = followed_on
    row.updated_at = utcnow()
    if changed and (status in {"en_cours", "fait"} or comment.strip()):
        from app.history import record_manual_change

        record_manual_change(db, action_key, status=status, technician=technician, comment=comment)
    db.commit()
    return row


def follow_up_for(db: Session, action_key: str) -> ActionFollowUp | None:
    return db.scalar(select(ActionFollowUp).where(ActionFollowUp.action_key == action_key))


def done_action_keys(db: Session) -> set[str]:
    """Actions déjà faites, à la main. Elles ne restent pas dans la liste à traiter."""
    return set(db.scalars(select(ActionFollowUp.action_key).where(ActionFollowUp.status == "fait")))


def priority_of(actions: list[ComputedAction]) -> str:
    rank = 0
    label = "a_jour"
    for action in actions:
        if action.severity == "autre":
            continue
        current = SEVERITY_RANK.get(action.severity, 0)
        if current > rank:
            rank = current
            label = action.severity
    return label


def is_up_to_date(actions: list[ComputedAction], count_low: bool) -> bool:
    blocking = {"critique", "important"}
    if count_low:
        blocking.add("faible")
    return not any(action.severity in blocking for action in actions)


def _computer_actions(db, run, computer, rules, critical, important) -> list[ComputedAction]:
    actions: list[ComputedAction] = []
    actions.extend(_windows_actions(db, run, computer, rules))
    grouped: dict[str, list] = defaultdict(list)
    for software in computer.software:
        slug = resolve_slug(db, software.name)
        if slug:
            grouped[slug].append(software)
    for slug, installs in grouped.items():
        if slug == "advanced-ip":
            actions.append(_fixed_software(run, computer, slug, installs, "advanced_ip", rules["advanced_ip_title"], rules["advanced_ip_severity"], ""))
            continue
        if slug in OFFICE_SLUGS:
            actions.append(
                _fixed_software(run, computer, slug, installs, "office_migration", rules["office_title"], rules["office_severity"], OFFICE_GUIDE)
            )
            continue
        if slug in {"windows-10", "windows-11"}:
            continue
        version_action = _version_action(db, run, computer, slug, installs, critical, important)
        if version_action is not None:
            actions.append(version_action)
    actions.extend(_other_actions(run, computer))
    return actions


def _windows_actions(db, run, computer, rules) -> list[ComputedAction]:
    feature = windows_feature(computer.os_name, computer.os_version, computer.os_build)
    if feature is None:
        return []
    actions = []
    required = rules["required_feature"]
    installed = " ".join(part for part in (computer.os_name, computer.os_version, computer.os_build) if part)
    if feature == "10" or _is_windows_10(computer.os_name, feature):
        actions.append(
            _make(
                run,
                computer,
                "windows-10",
                "windows_migration",
                rules["windows_10_severity"],
                rules["windows_10_title"],
                installed,
                f"Windows 11 {required}",
                [],
                WINDOWS_GUIDE,
            )
        )
        return actions
    if feature != required:
        actions.append(
            _make(
                run,
                computer,
                f"windows-{feature.lower()}",
                "windows_upgrade",
                rules["windows_upgrade_severity"],
                rules["windows_upgrade_title"],
                installed,
                f"Windows 11 {required}",
                [],
                WINDOWS_GUIDE,
            )
        )
    target = version_target(db, f"windows-{feature.lower()}")
    if target and computer.os_build and is_outdated(computer.os_build, target["version"], "ge"):
        actions.append(
            _make(
                run,
                computer,
                f"windows-{feature.lower()}",
                "windows_update",
                rules["windows_update_severity"],
                rules["windows_update_title"],
                computer.os_build,
                target["version"],
                [],
                target.get("url") or MSRC_GUIDE,
            )
        )
    return actions


def _version_action(db, run, computer, slug, installs, critical, important) -> ComputedAction | None:
    versions = [item.version for item in installs if parse_version(item.version)]
    if not versions:
        return None
    installed = highest_version(versions)
    target = version_target(db, slug)
    if installed is None or target is None:
        return None
    outdated = is_outdated(installed, target["version"], target.get("mode") or "ge")
    if not outdated:
        return None
    cves = _cves_for(db, slug)
    eol = is_end_of_life(db, slug)
    severity = _severity(cves, eol, critical, important)
    product = PRODUCTS.get(slug)
    title = f"Mettre à jour {product.label if product else slug}"
    url = _best_url(cves, target.get("url") or "")
    return _make(run, computer, slug, "version", severity, title, installed, _display_target(target), cves, url)


def _other_actions(run, computer) -> list[ComputedAction]:
    actions = []
    linux = _linux_server(computer)
    if linux:
        actions.append(
            _make(run, computer, "", "linux", "autre", "Appliquer les mises à jour Debian", computer.os_name, "", [], "")
        )
    elif not computer.software:
        actions.append(_make(run, computer, "", "sans_logiciel", "autre", "Poste sans logiciel remonté", "", "", [], ""))
    return actions


def _fixed_software(run, computer, slug, installs, kind, title, severity, url) -> ComputedAction:
    versions = [item.version for item in installs if parse_version(item.version)]
    installed = highest_version(versions) if versions else (installs[0].version if installs else "")
    target = "Microsoft 365 Apps" if kind == "office_migration" else "Désinstallation"
    return _make(run, computer, slug, kind, severity, title, installed or "", target, [], url)


def _make(run, computer, slug, kind, severity, title, installed, target, cves, url) -> ComputedAction:
    shown_target = target
    if kind == "version" and str(target).startswith(">"):
        detail = f"{installed} → version supérieure à {str(target).lstrip('>').strip()}"
    else:
        detail = f"{installed} → {shown_target}".strip(" →") if installed or shown_target else title
    return ComputedAction(
        check_run_id=run.id,
        glpi_computer_id=computer.glpi_id,
        product_slug=slug,
        action_key=f"{computer.glpi_id}:{kind}:{slug or '-'}",
        kind=kind,
        severity=severity,
        title=title,
        detail=detail,
        installed_version=installed or "",
        target_version=shown_target or "",
        cves_json=json.dumps(cves, ensure_ascii=False),
        source_url=url or "",
    )


def _display_target(target: dict) -> str:
    version = str(target.get("version") or "")
    if target.get("mode") == "gt":
        return f">{version}"
    return version


def _severity(cves: list[dict], eol: bool, critical: float, important: float) -> str:
    scores = [float(item["cvss"]) for item in cves if isinstance(item.get("cvss"), (int, float))]
    highest = max(scores) if scores else None
    if eol or any(item.get("kev") or item.get("certfr_alert") for item in cves) or (highest is not None and highest >= critical):
        return "critique"
    if highest is not None and highest >= important:
        return "important"
    return "faible"


def _cves_for(db: Session, slug: str) -> list[dict]:
    certfr = db.info.get("certfr_cves")
    if certfr is None:
        certfr = payload_of(get_cache(db, "certfr", "catalog")).get("cves") or {}
        db.info["certfr_cves"] = certfr
    if not isinstance(certfr, dict):
        return []
    found = []
    oldest = utcnow().year - 1
    for cve_id, row in certfr.items():
        if not isinstance(row, dict) or slug not in (row.get("products") or []):
            continue
        year = _bulletin_year(row)
        if year and year < oldest:
            continue
        alert = bool(row.get("alert"))
        cvss = row.get("cvss")
        found.append(
            {
                "id": cve_id,
                "cvss": cvss if isinstance(cvss, (int, float)) else None,
                "summary": row.get("summary") or row.get("title") or "",
                "url": row.get("url") or "",
                "certfr": True,
                "certfr_alert": alert,
                "certfr_url": row.get("url") or "",
                "severite": row.get("severite") or severity_name(cvss, alert=alert),
            }
        )
    return found


def _bulletin_year(row: dict) -> int:
    blob = " ".join(str(row.get(key) or "") for key in ("reference", "url", "certfr_url"))
    match = re.search(r"CERTFR-(\d{4})-", blob.upper())
    return int(match.group(1)) if match else 0


def _best_url(cves: list[dict], fallback: str) -> str:
    for item in cves:
        if item.get("kev") and item.get("url"):
            return item["url"]
    for item in cves:
        if item.get("certfr_alert") and item.get("certfr_url"):
            return item["certfr_url"]
    for item in cves:
        if item.get("url"):
            return item["url"]
    return fallback


def _update_summary(db, run, previous, created) -> None:
    summary = json.loads(run.summary_json or "{}")
    previous_actions = []
    if previous is not None:
        previous_actions = list(db.scalars(select(ComputedAction).where(ComputedAction.check_run_id == previous.id)))
    previous_blocking = {item.glpi_computer_id for item in previous_actions if item.severity in {"critique", "important"}}
    current_blocking = {item.glpi_computer_id for item in created if item.severity in {"critique", "important"}}
    present = {computer.glpi_id for computer in run.computers}
    summary["postes_corriges"] = sorted((previous_blocking - current_blocking) & present)
    previous_keys = {item.action_key for item in previous_actions}
    summary["nouvelles_actions"] = sorted(item.action_key for item in created if item.action_key not in previous_keys)
    run.summary_json = json.dumps(summary, ensure_ascii=False)


def windows_feature(os_name: str, os_version: str, os_build: str) -> str | None:
    blob = f"{os_name} {os_version}".lower()
    if "windows" not in blob and "debian" not in blob and not os_build:
        return None
    if "windows" not in blob:
        return None
    if "windows 10" in blob:
        return "10"
    for feature in ("26H2", "25H2", "24H2", "23H2", "22H2", "21H2"):
        if feature.lower() in blob:
            return feature
    if "windows 10" in blob:
        return "10"
    parsed = parse_version(os_build)
    if not parsed:
        return "10" if "windows 10" in blob else None
    major = parsed[0]
    if major < 20000:
        return "10"
    return BUILD_FEATURES.get(major)


def _is_windows_10(os_name: str, feature: str) -> bool:
    return feature == "10" or "windows 10" in os_name.lower()


def _linux_server(computer) -> bool:
    os_name = computer.os_name.lower()
    kind = computer.computer_type.lower()
    name = computer.name.lower()
    linux = any(token in os_name for token in ("linux", "debian", "ubuntu"))
    if not linux:
        return False
    if not kind:
        return True
    return "serveur" in kind or name.startswith("srv")
