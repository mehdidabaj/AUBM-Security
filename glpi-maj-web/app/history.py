from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.actions.mapping import resolve_slug
from app.actions.versions import compare_versions, highest_version
from app.glpi.normalize import normalize_name
from app.models.actions import ComputedAction
from app.models.history import SoftwareChange
from app.models.inventory import CheckRun, ComputerRecord
from app.sources.catalog import PRODUCTS
from app.timeutils import utcnow

_STATUS = {"a_faire": "À faire", "en_cours": "En cours", "fait": "Fait"}


def record_collection_changes(db: Session, run: CheckRun, previous: CheckRun | None) -> int:
    """Compare les versions lues à la vérification précédente et garde les écarts.

    La première lecture d'un logiciel ne compte pas comme une mise à jour.
    Une version identique, y compris 157 et 157.0, est ignorée.
    """
    if previous is None or previous.id == run.id:
        return 0
    before = _snapshots(db, previous.id)
    after = _snapshots(db, run.id)
    created = 0
    moment = utcnow()
    for glpi_id, current in after.items():
        prior = before.get(glpi_id)
        if prior is None:
            continue
        computer_name = str(current.get("__name__", ""))
        for key, value in current.items():
            if key == "__name__":
                continue
            name, new_version = value
            old = prior.get(key)
            if old is None:
                continue
            _old_name, old_version = old
            if _unchanged(old_version, new_version):
                continue
            compared = compare_versions(new_version, old_version)
            if compared == 0:
                continue
            if compared is not None and compared < 0:
                note = "Version inférieure à la précédente"
            elif compared is None:
                note = "Version modifiée"
            else:
                note = "Mise à jour"
            db.add(
                SoftwareChange(
                    glpi_computer_id=glpi_id,
                    computer_name=str(computer_name),
                    software_key=key,
                    software_name=name,
                    previous_version=old_version,
                    new_version=new_version,
                    origin="automatique",
                    actor="",
                    note=note,
                    detected_at=moment,
                )
            )
            created += 1
    if created:
        db.flush()
    return created


def record_manual_change(
    db: Session,
    action_key: str,
    *,
    status: str,
    technician: str,
    comment: str,
) -> None:
    """Garde la décision de l'administrateur, même si la version du poste n'a pas encore bougé."""
    parts = action_key.split(":")
    if len(parts) < 3:
        return
    try:
        glpi_id = int(parts[0])
    except ValueError:
        return
    slug = parts[-1]
    if slug in {"", "-"}:
        return
    action = db.scalar(
        select(ComputedAction).where(ComputedAction.action_key == action_key).order_by(ComputedAction.id.desc())
    )
    if slug in PRODUCTS:
        name = PRODUCTS[slug].label
    elif action is not None and action.title:
        name = action.title
    else:
        name = slug
    previous = action.installed_version if action is not None else ""
    new_version = action.target_version if action is not None and status == "fait" else previous
    label = _STATUS.get(status, status)
    note = f"Suivi : {label}"
    if comment.strip():
        note = f"{note}. {comment.strip()}"
    computer_name = ""
    if action is not None:
        computer_name = db.scalar(
            select(ComputerRecord.name).where(
                ComputerRecord.check_run_id == action.check_run_id,
                ComputerRecord.glpi_id == glpi_id,
            )
        ) or ""
    db.add(
        SoftwareChange(
            glpi_computer_id=glpi_id,
            computer_name=computer_name,
            software_key=slug,
            software_name=name,
            previous_version=previous,
            new_version=new_version,
            origin="manuel",
            actor=technician.strip(),
            note=note,
            detected_at=utcnow(),
        )
    )


def _snapshots(db: Session, run_id: int) -> dict[int, dict]:
    records = db.scalars(
        select(ComputerRecord)
        .where(ComputerRecord.check_run_id == run_id)
        .options(selectinload(ComputerRecord.software))
    ).all()
    found: dict[int, dict] = {}
    for record in records:
        versions: dict[str, list[str]] = defaultdict(list)
        names: dict[str, str] = {}
        for software in record.software:
            version = normalize_name(software.version)
            if not version:
                continue
            slug = resolve_slug(db, software.name)
            key = slug or normalize_name(software.name).lower()
            if not key:
                continue
            versions[key].append(version)
            names.setdefault(key, PRODUCTS[slug].label if slug in PRODUCTS else software.name)
        snapshot: dict = {"__name__": record.name}
        for key, values in versions.items():
            best = highest_version(values) or values[0]
            snapshot[key] = (names[key], best)
        system = " ".join(part for part in (record.os_name, record.os_version, record.os_build) if part).strip()
        if system:
            snapshot["systeme"] = (record.os_name or "Système", system)
        found[record.glpi_id] = snapshot
    return found


def _unchanged(previous: str, current: str) -> bool:
    return normalize_name(previous).lower() == normalize_name(current).lower()
