from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timedelta

import httpx
from sqlalchemy import delete, func, insert, literal, select
from sqlalchemy.orm import Session, aliased, selectinload

from app.actions.engine import done_action_keys, priority_of
from app.actions.rules import SEVERITY_RANK
from app.config import Settings
from app.glpi.client import GlpiClient, _software_item, assemble
from app.glpi.errors import GlpiError
from app.glpi.normalize import extract_build, label, linked_id, normalize_name
from app.glpi.types import ComputerItem
from app.models.actions import ComputedAction
from app.models.inventory import AgentRecord, CheckRun, ComputerRecord, SoftwareInstall
from app.timeutils import utcnow

logger = logging.getLogger(__name__)
_VERIFICATION_LOCK = threading.Lock()
_STALE_RUN = timedelta(hours=6)
_HISTORY_KEEP = 10
_METER_STEPS = {"ordinateurs", "postes", "versions", "logiciels", "installations"}


def _nom_systeme_illisible(name: str) -> bool:
    """Un nom réduit à un entier est l'identifiant GLPI, pas le libellé du système."""
    return bool(name) and name.isdigit()


def latest_successful(db: Session) -> CheckRun | None:
    return db.scalar(select(CheckRun).where(CheckRun.status == "success").order_by(CheckRun.id.desc()))


def visible_run(db: Session) -> CheckRun | None:
    """Vérification affichée : celle en cours, sinon la dernière réussie, sinon une annulation partielle."""
    current = db.scalar(select(CheckRun).order_by(CheckRun.id.desc()))
    if current is not None and current.status == "running" and current.finished_at is None:
        return current
    success = latest_successful(db)
    if success is not None:
        return success
    if current is not None and current.status == "annulee":
        return current
    return None


def build_summary(previous: CheckRun | None, computers: list[ComputerItem]) -> dict:
    current_ids = {computer.glpi_id for computer in computers}
    previous_ids = {record.glpi_id for record in previous.computers} if previous is not None else set()
    return {
        "postes_ajoutes": sorted(current_ids - previous_ids),
        "postes_retires": sorted(previous_ids - current_ids),
        "postes_corriges": [],
        "nouvelles_actions": [],
    }


def collection_percent(index: int, total_steps: int, read: int, total: int | None) -> int:
    """Pourcentage de la lecture, réservé à 95. L'enregistrement occupe les 5 restants."""
    if total_steps <= 0:
        return 0
    part = 95 / total_steps
    if total is None:
        fraction = 0.0 if read <= 0 else 0.5
    elif total <= 0:
        fraction = 1.0
    else:
        fraction = min(1.0, read / total)
    return min(95, int(index * part + fraction * part))


class VerificationCancelled(Exception):
    """La vérification a été arrêtée depuis l'interface."""


class ProgressMeter:
    """Pourcentage pondéré par le nombre de lignes annoncées, sans retour en arrière."""

    def __init__(self, planned: int) -> None:
        self.planned = max(planned, 1)
        self.order: list[str] = []
        self.totals: dict[str, int] = {}
        self.reads: dict[str, int] = {}
        self.floor = 0

    def update(self, step: str, read: int, total: int | None) -> int:
        if step not in self.reads:
            self.order.append(step)
        self.reads[step] = max(0, read)
        if total is not None and total >= 0:
            self.totals[step] = total
        known = [value for value in self.totals.values() if value > 0]
        average = (sum(known) / len(known)) if known else 1.0
        done = 0.0
        weight = 0.0
        for name in self.order:
            step_total = self.totals.get(name, 0)
            step_read = self.reads.get(name, 0)
            if step_total > 0:
                step_weight = float(step_total)
                fraction = min(1.0, step_read / step_total)
            else:
                step_weight = average
                fraction = 1.0 if step_read > 0 else 0.0
            weight += step_weight
            done += step_weight * fraction
        weight += max(0, self.planned - len(self.order)) * average
        percent = 0 if weight <= 0 else min(95, int(95 * done / weight))
        if percent < self.floor:
            return self.floor
        self.floor = percent
        return percent


def _postes(count: int) -> str:
    return "1 poste" if count == 1 else f"{count} postes"


def _publish(db: Session, run: CheckRun, pourcent: int, message: str) -> None:
    run.progress_current = pourcent
    run.progress_total = 100
    run.message = message
    db.commit()


def _open_run(db: Session, origin: str) -> CheckRun:
    run = CheckRun(
        started_at=utcnow(),
        finished_at=None,
        status="running",
        origin=origin,
        computer_count=0,
        error=None,
        summary_json="{}",
        progress_current=0,
        progress_total=100,
        message="Démarrage de la lecture",
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _expire_if_stale(db: Session, run: CheckRun) -> CheckRun:
    if run.status == "running" and run.started_at < utcnow() - _STALE_RUN:
        run.status = "error"
        run.error = "La vérification a été interrompue."
        run.message = "La vérification a été interrompue."
        run.finished_at = utcnow()
        db.commit()
    return run


def save_check(
    db: Session,
    computers: list[ComputerItem],
    origin: str,
    error: str | None = None,
    run: CheckRun | None = None,
) -> CheckRun:
    now = utcnow()
    previous = None if error else latest_successful(db)
    if run is None:
        run = CheckRun(
            started_at=now,
            finished_at=now,
            status="error" if error else "success",
            origin=origin,
            computer_count=0 if error else len(computers),
            error=error,
            summary_json="{}",
            progress_current=0 if error else 100,
            progress_total=100,
            message=error or f"Collecte terminée : {_postes(len(computers))}.",
        )
        db.add(run)
        db.flush()
    else:
        run.origin = origin
        run.error = error
        run.progress_total = 100
        if error:
            run.status = "error"
            run.finished_at = now
            run.computer_count = 0
            run.message = error or "La lecture GLPI a échoué."
            db.flush()
        else:
            run.progress_current = 98
            run.message = "Enregistrement du parc"
            db.commit()
    if not error:
        computer_ids = list(
            db.scalars(select(ComputerRecord.id).where(ComputerRecord.check_run_id == run.id))
        )
        if computer_ids:
            db.execute(delete(SoftwareInstall).where(SoftwareInstall.computer_id.in_(computer_ids)))
            db.execute(delete(AgentRecord).where(AgentRecord.computer_id.in_(computer_ids)))
            db.execute(delete(ComputerRecord).where(ComputerRecord.id.in_(computer_ids)))
        db.expire_all()
        for computer in computers:
            record = ComputerRecord(
                check_run_id=run.id,
                glpi_id=computer.glpi_id,
                name=computer.name,
                group_name=computer.group_name,
                location=computer.location,
                computer_type=computer.computer_type,
                os_name=computer.os_name,
                os_version=computer.os_version,
                os_build=computer.os_build,
                last_inventory_at=computer.last_inventory_at,
            )
            db.add(record)
            db.flush()
            for software in computer.software:
                db.add(
                    SoftwareInstall(
                        computer_id=record.id,
                        name=software.name,
                        publisher=software.publisher,
                        version=software.version,
                    )
                )
            if computer.agent is not None:
                db.add(
                    AgentRecord(
                        computer_id=record.id,
                        glpi_id=computer.agent.glpi_id,
                        last_contact=computer.agent.last_contact,
                        version=computer.agent.version,
                        itemtype=computer.agent.itemtype,
                    )
                )
        db.flush()
        db.refresh(run)
        run.status = "success"
        run.finished_at = now
        run.computer_count = len(computers)
        run.progress_current = 100
        run.progress_total = 100
        run.message = f"Collecte terminée : {_postes(len(computers))}."
        run.summary_json = json.dumps(build_summary(previous, computers), ensure_ascii=False)
        from app.history import record_collection_changes

        record_collection_changes(db, run, previous)
    else:
        run.summary_json = json.dumps(
            {
                "erreur": error,
                "postes_ajoutes": [],
                "postes_retires": [],
                "postes_corriges": [],
                "nouvelles_actions": [],
            },
            ensure_ascii=False,
        )
    db.commit()
    db.refresh(run)
    if not error:
        from app.actions.engine import compute_check

        compute_check(db, run, previous)
        db.refresh(run)
    prune_history(db)
    db.refresh(run)
    return run


class _LiveCatalog:
    def __init__(self) -> None:
        self.software_by_id: dict[int, dict] = {}
        self.version_by_id: dict[int, dict] = {}
        self.records: dict[int, ComputerRecord] = {}


def noter_page(db: Session, run: CheckRun, live: _LiveCatalog, step: str, chunk: list) -> None:
    """Enregistre une page GLPI pour qu'elle soit visible avant la fin de la collecte."""
    if not chunk:
        return
    if step == "logiciels":
        for row in chunk:
            if "id" in row:
                live.software_by_id[int(row["id"])] = row
        return
    if step == "versions":
        for row in chunk:
            if "id" in row:
                live.version_by_id[int(row["id"])] = row
        return
    if step == "ordinateurs":
        _memoriser_postes(db, run, assemble(chunk, [], [], [], []), details=False)
        return
    if step == "systèmes":
        _appliquer_systemes(db, run, live, chunk)
        return
    if step == "installations":
        _appliquer_installations(db, run, live, chunk)


def _memoriser_postes(db: Session, run: CheckRun, items: list[ComputerItem], *, details: bool) -> None:
    if not items:
        return
    page_ids = [item.glpi_id for item in items]
    known = {
        row.glpi_id: row
        for row in db.scalars(
            select(ComputerRecord).where(
                ComputerRecord.check_run_id == run.id,
                ComputerRecord.glpi_id.in_(page_ids),
            )
        )
    }
    for item in items:
        row = known.get(item.glpi_id)
        if row is None:
            row = ComputerRecord(
                check_run_id=run.id,
                glpi_id=item.glpi_id,
                name="",
                group_name="",
                location="",
                computer_type="",
                os_name="",
                os_version="",
                os_build="",
            )
            db.add(row)
            known[item.glpi_id] = row
        row.name = item.name
        row.group_name = item.group_name
        row.location = item.location
        row.computer_type = item.computer_type
        row.os_name = item.os_name
        row.os_version = item.os_version
        row.os_build = item.os_build
        row.last_inventory_at = item.last_inventory_at
        if details:
            db.flush()
            _remplacer_details(db, row, item)
    db.flush()
    run.computer_count = int(
        db.scalar(select(func.count()).select_from(ComputerRecord).where(ComputerRecord.check_run_id == run.id)) or 0
    )


def _remplacer_details(db: Session, row: ComputerRecord, item: ComputerItem) -> None:
    db.execute(delete(SoftwareInstall).where(SoftwareInstall.computer_id == row.id))
    db.execute(delete(AgentRecord).where(AgentRecord.computer_id == row.id))
    db.flush()
    for software in item.software:
        db.add(
            SoftwareInstall(
                computer_id=row.id,
                name=software.name,
                publisher=software.publisher,
                version=software.version,
            )
        )
    if item.agent is not None:
        db.add(
            AgentRecord(
                computer_id=row.id,
                glpi_id=item.agent.glpi_id,
                last_contact=item.agent.last_contact,
                version=item.agent.version,
                itemtype=item.agent.itemtype,
            )
        )


def _records(db: Session, run: CheckRun, live: _LiveCatalog, glpi_ids: set[int]) -> dict[int, ComputerRecord]:
    missing = [glpi_id for glpi_id in glpi_ids if glpi_id not in live.records]
    if missing:
        for row in db.scalars(
            select(ComputerRecord).where(
                ComputerRecord.check_run_id == run.id,
                ComputerRecord.glpi_id.in_(missing),
            )
        ):
            live.records[row.glpi_id] = row
    return live.records


def _appliquer_systemes(db: Session, run: CheckRun, live: _LiveCatalog, chunk: list) -> None:
    by_item: dict[int, dict] = {}
    for row in chunk:
        if row.get("itemtype") not in (None, "", "Computer"):
            continue
        glpi_id = linked_id(row.get("items_id"))
        if glpi_id is None:
            continue
        by_item[glpi_id] = row
    found = _records(db, run, live, set(by_item))
    for glpi_id, system in by_item.items():
        record = found.get(glpi_id)
        if record is None:
            continue
        record.os_name = label(system.get("operatingsystems_id"))
        record.os_version = label(system.get("operatingsystemversions_id"))
        record.os_build = extract_build(system.get("operatingsystemkernelversions_id"))
    db.flush()


def _appliquer_installations(db: Session, run: CheckRun, live: _LiveCatalog, chunk: list) -> None:
    pending: dict[int, list] = {}
    for row in chunk:
        if row.get("itemtype") not in (None, "", "Computer"):
            continue
        glpi_id = linked_id(row.get("items_id"))
        if glpi_id is None:
            continue
        item = _software_item(row.get("softwareversions_id"), live.version_by_id, live.software_by_id)
        if item is None or not item.name:
            continue
        pending.setdefault(glpi_id, []).append(item)
    found = _records(db, run, live, set(pending))
    for glpi_id, items in pending.items():
        record = found.get(glpi_id)
        if record is None:
            continue
        for item in items:
            db.add(
                SoftwareInstall(
                    computer_id=record.id,
                    name=item.name,
                    publisher=item.publisher,
                    version=item.version,
                )
            )
    db.flush()


def _annulation_demandee(db: Session, run_id: int) -> bool:
    value = db.scalar(select(CheckRun.cancel_requested).where(CheckRun.id == run_id))
    return bool(value)


def _copier_inchanges(db: Session, run: CheckRun, previous: CheckRun | None, rows: list) -> None:
    """Reprend en base les postes inchangés, sans relire leurs logiciels."""
    if previous is None or not rows:
        return
    ids: list[int] = []
    for row in rows:
        try:
            ids.append(int(row["id"]))
        except (KeyError, TypeError, ValueError):
            continue
    if not ids:
        return
    for offset in range(0, len(ids), 400):
        part = ids[offset : offset + 400]
        present = set(
            db.scalars(
                select(ComputerRecord.glpi_id).where(
                    ComputerRecord.check_run_id == run.id,
                    ComputerRecord.glpi_id.in_(part),
                )
            )
        )
        _copier_lot(db, run, previous.id, [glpi_id for glpi_id in part if glpi_id not in present])
        _completer_existants(db, run, previous.id, [glpi_id for glpi_id in part if glpi_id in present])
    run.computer_count = int(
        db.scalar(select(func.count()).select_from(ComputerRecord).where(ComputerRecord.check_run_id == run.id)) or 0
    )


def _completer_existants(db: Session, run: CheckRun, previous_id: int, glpi_ids: list[int]) -> None:
    """La liste complète a déjà créé le poste : on y reporte le système et les logiciels connus."""
    if not glpi_ids:
        return
    sources = {
        record.glpi_id: record
        for record in db.scalars(
            select(ComputerRecord).where(
                ComputerRecord.check_run_id == previous_id,
                ComputerRecord.glpi_id.in_(glpi_ids),
            )
        )
    }
    targets = {
        record.glpi_id: record
        for record in db.scalars(
            select(ComputerRecord).where(
                ComputerRecord.check_run_id == run.id,
                ComputerRecord.glpi_id.in_(glpi_ids),
            )
        )
    }
    for glpi_id, target in targets.items():
        source = sources.get(glpi_id)
        if source is None:
            continue
        target.os_name = source.os_name
        target.os_version = source.os_version
        target.os_build = source.os_build
        target.last_inventory_at = source.last_inventory_at
        target.location = ""
        target.computer_type = ""
    db.flush()
    target_ids = [record.id for record in targets.values()]
    if target_ids:
        db.execute(delete(SoftwareInstall).where(SoftwareInstall.computer_id.in_(target_ids)))
        db.execute(delete(AgentRecord).where(AgentRecord.computer_id.in_(target_ids)))
    _copier_logiciels(db, run.id, previous_id, glpi_ids)


def _copier_lot(db: Session, run: CheckRun, previous_id: int, glpi_ids: list[int]) -> None:
    if not glpi_ids:
        return
    source = aliased(ComputerRecord)
    db.execute(
        insert(ComputerRecord).from_select(
            [
                "check_run_id",
                "glpi_id",
                "name",
                "group_name",
                "location",
                "computer_type",
                "os_name",
                "os_version",
                "os_build",
                "last_inventory_at",
            ],
            select(
                literal(run.id),
                source.glpi_id,
                source.name,
                source.group_name,
                literal(""),
                literal(""),
                source.os_name,
                source.os_version,
                source.os_build,
                source.last_inventory_at,
            ).where(source.check_run_id == previous_id, source.glpi_id.in_(glpi_ids)),
        )
    )
    db.flush()
    _copier_logiciels(db, run.id, previous_id, glpi_ids)


def _copier_logiciels(db: Session, run_id: int, previous_id: int, glpi_ids: list[int]) -> None:
    if not glpi_ids:
        return
    copied = aliased(ComputerRecord)
    origin = aliased(ComputerRecord)
    installed = aliased(SoftwareInstall)
    db.execute(
        insert(SoftwareInstall).from_select(
            ["computer_id", "name", "publisher", "version"],
            select(copied.id, installed.name, installed.publisher, installed.version)
            .select_from(installed)
            .join(origin, installed.computer_id == origin.id)
            .join(copied, (copied.glpi_id == origin.glpi_id) & (copied.check_run_id == run_id))
            .where(origin.check_run_id == previous_id, origin.glpi_id.in_(glpi_ids)),
        )
    )
    db.flush()


def finalize_run(db: Session, run: CheckRun, reprise: int = 0, relus: int = 0) -> CheckRun:
    """Clôture la vérification déjà écrite, sans la réécrire."""
    now = utcnow()
    previous = latest_successful(db)
    records = list(db.scalars(select(ComputerRecord).where(ComputerRecord.check_run_id == run.id)))
    current_ids = {record.glpi_id for record in records}
    previous_ids = {record.glpi_id for record in previous.computers} if previous is not None else set()
    run.status = "success"
    run.finished_at = now
    run.computer_count = len(records)
    run.progress_current = 100
    run.progress_total = 100
    removed = previous_ids - current_ids
    if relus == 0 and reprise and not removed:
        run.message = f"Aucune modification récente : {_postes(len(records))} repris sans relecture."
    elif reprise:
        run.message = (
            f"Collecte terminée : {_postes(len(records))}, "
            f"dont {_postes(reprise)} repris et {_postes(relus)} relus."
        )
    else:
        run.message = f"Collecte terminée : {_postes(len(records))}."
    run.summary_json = json.dumps(
        {
            "postes_ajoutes": sorted(current_ids - previous_ids),
            "postes_retires": sorted(previous_ids - current_ids),
            "postes_corriges": [],
            "nouvelles_actions": [],
        },
        ensure_ascii=False,
    )
    from app.history import record_collection_changes

    record_collection_changes(db, run, previous)
    db.commit()
    db.refresh(run)
    from app.actions.engine import compute_check

    compute_check(db, run, previous)
    prune_history(db)
    db.refresh(run)
    return run


def prune_history(db: Session, keep: int | None = None) -> None:
    """Ne conserve que les dernières vérifications terminées."""
    if keep is None:
        from app.settings_store import get_setting

        try:
            keep = int(get_setting(db, "history_limit", _HISTORY_KEEP) or _HISTORY_KEEP)
        except (TypeError, ValueError):
            keep = _HISTORY_KEEP
    keep = max(1, keep)
    finished = list(db.scalars(select(CheckRun).where(CheckRun.status != "running").order_by(CheckRun.id.desc())))
    for old in finished[keep:]:
        _delete_run(db, old.id)
    db.commit()


def _delete_run(db: Session, run_id: int) -> None:
    computer_ids = list(db.scalars(select(ComputerRecord.id).where(ComputerRecord.check_run_id == run_id)))
    db.execute(delete(ComputedAction).where(ComputedAction.check_run_id == run_id))
    if computer_ids:
        db.execute(delete(SoftwareInstall).where(SoftwareInstall.computer_id.in_(computer_ids)))
        db.execute(delete(AgentRecord).where(AgentRecord.computer_id.in_(computer_ids)))
        db.execute(delete(ComputerRecord).where(ComputerRecord.id.in_(computer_ids)))
    db.execute(delete(CheckRun).where(CheckRun.id == run_id))


def abandon_running(db: Session) -> int:
    """Un redémarrage tue le fil de collecte : ces vérifications ne tournent plus."""
    rows = list(db.scalars(select(CheckRun).where(CheckRun.status == "running")))
    for run in rows:
        run.status = "error"
        run.error = "La vérification a été interrompue par un redémarrage."
        run.message = "La vérification a été interrompue par un redémarrage."
        run.finished_at = utcnow()
    if rows:
        db.commit()
    return len(rows)


def cancel_verification(db: Session) -> CheckRun | None:
    run = db.scalar(select(CheckRun).where(CheckRun.status == "running").order_by(CheckRun.id.desc()))
    if run is None:
        return None
    run.cancel_requested = 1
    run.status = "annulee"
    run.finished_at = utcnow()
    run.message = "Vérification annulée."
    db.commit()
    db.refresh(run)
    return run


def _cloturer_annulation(db: Session, run_id: int) -> CheckRun | None:
    db.rollback()
    current = db.get(CheckRun, run_id)
    if current is None:
        return None
    current.cancel_requested = 1
    current.status = "annulee"
    current.finished_at = current.finished_at or utcnow()
    current.message = "Vérification annulée."
    db.commit()
    if current.computer_count:
        from app.actions.engine import compute_check

        try:
            compute_check(db, current, latest_successful(db))
        except Exception:
            logger.exception("Le calcul après annulation a échoué")
            db.rollback()
    prune_history(db)
    db.refresh(current)
    return current


def run_verification(
    db: Session,
    settings: Settings,
    http: httpx.Client | None = None,
    run_id: int | None = None,
) -> CheckRun:
    if run_id is None:
        run = _open_run(db, "demo" if settings.demo_active else "glpi")
    else:
        run = db.get(CheckRun, run_id)
        if run is None:
            raise RuntimeError("Vérification introuvable.")
    try:
        if settings.demo_active:
            from app.demo.loader import load_catalog

            computers = load_catalog().current
            total = max(len(computers), 1)
            for index, computer in enumerate(computers, start=1):
                if _annulation_demandee(db, run.id):
                    raise VerificationCancelled()
                _memoriser_postes(db, run, [computer], details=True)
                db.commit()
                _publish(db, run, min(95, int(index * 95 / total)), f"Lecture du parc d'exemple : {index} / {len(computers)}")
        else:
            live = _LiveCatalog()
            meter = ProgressMeter(5)
            previous = latest_successful(db)
            known: dict[int, datetime | None] = {}
            if previous is not None:
                loaded = db.scalars(select(ComputerRecord).where(ComputerRecord.check_run_id == previous.id)).all()
                known = {
                    record.glpi_id: record.last_inventory_at
                    for record in loaded
                    if not _nom_systeme_illisible(record.os_name)
                }
            reprise = {"count": 0}
            relus = {"count": 0}

            def on_progress(index: int, total_steps: int, step: str, read: int, total: int | None, chunk=None) -> None:
                if _annulation_demandee(db, run.id):
                    raise VerificationCancelled()
                rows = chunk or []
                if step == "repérage":
                    pourcent = meter.update("ordinateurs", read, total)
                    _publish(db, run, pourcent, f"Repérage de {_postes(read)} : seules les modifications seront lues.")
                    return
                if step == "reprise":
                    _copier_inchanges(db, run, previous, rows)
                    reprise["count"] = len(rows)
                    _publish(db, run, meter.floor, f"Reprise de {_postes(len(rows))} inchangés, sans relecture.")
                    return
                if step == "ordinateurs" and rows:
                    relus["count"] += len(rows)
                noter_page(db, run, live, step, rows)
                if step not in _METER_STEPS:
                    return
                pourcent = meter.update(step, read, total)
                detail = str(read) if total is None else f"{read} / {total}"
                _publish(db, run, pourcent, f"Lecture des {step} : {detail}")

            with GlpiClient(settings, http=http) as client:
                client.collect(on_progress=on_progress, known=known or None)
        if _annulation_demandee(db, run.id):
            raise VerificationCancelled()
    except VerificationCancelled:
        return _cloturer_annulation(db, run.id) or run
    except GlpiError as exc:
        save_check(db, [], run.origin, error=exc.message, run=run)
        raise
    except Exception as exc:
        logger.exception("La lecture GLPI a échoué")
        detail = normalize_name(exc)[:180]
        message = "La lecture GLPI a échoué." if not detail else f"La lecture GLPI a échoué : {detail}"
        save_check(db, [], run.origin, error=message, run=run)
        raise
    return finalize_run(
        db,
        run,
        reprise=reprise["count"] if not settings.demo_active else 0,
        relus=relus["count"] if not settings.demo_active else 0,
    )


def _spawn_verification(app, run_id: int) -> None:
    def worker() -> None:
        db = app.state.SessionLocal()
        try:
            run_verification(db, app.state.settings, run_id=run_id)
        except Exception:
            logger.exception("La vérification a échoué")
            db.rollback()
            run = db.get(CheckRun, run_id)
            if run is not None and run.status == "running":
                run.status = "error"
                run.error = "La vérification a échoué."
                run.message = "La vérification a échoué."
                run.finished_at = utcnow()
                db.commit()
        finally:
            db.close()

    threading.Thread(target=worker, name="glpi-maj-verification", daemon=True).start()


def start_verification(app, db: Session) -> CheckRun:
    """Démarre une vérification si aucune n'est déjà en cours, et la renvoie."""
    with _VERIFICATION_LOCK:
        current = db.scalar(select(CheckRun).order_by(CheckRun.id.desc()))
        if current is not None and current.status == "running":
            current = _expire_if_stale(db, current)
        if current is not None and current.status == "running":
            return current
        origin = "demo" if app.state.settings.demo_active else "glpi"
        run = _open_run(db, origin)
        _spawn_verification(app, run.id)
        return run


_RESULTATS = {
    "critique": "Critique",
    "important": "Important",
    "faible": "Faible",
    "a_jour": "À jour",
    "autre": "Autre",
    "lecture": "Lecture",
}


def inventory_counts(db: Session, run: CheckRun | None) -> tuple[int, int]:
    if run is None:
        return 0, 0
    lus = int(
        db.scalar(select(func.count()).select_from(ComputerRecord).where(ComputerRecord.check_run_id == run.id)) or 0
    )
    logiciels = int(
        db.scalar(
            select(func.count())
            .select_from(SoftwareInstall)
            .join(ComputerRecord, SoftwareInstall.computer_id == ComputerRecord.id)
            .where(ComputerRecord.check_run_id == run.id)
        )
        or 0
    )
    return lus, logiciels


def verification_view(
    db: Session,
    *,
    suivre: bool = False,
    settings: Settings | None = None,
    avec_postes: bool = True,
) -> dict:
    db.expire_all()
    run = db.scalar(select(CheckRun).order_by(CheckRun.id.desc()))
    if run is None:
        return _progress_idle()
    if run.status == "running":
        run = _expire_if_stale(db, run)
    visible = run.status in {"running", "error", "annulee"} or (
        suivre and run.finished_at is not None and run.finished_at >= utcnow() - timedelta(minutes=2)
    )
    if visible and avec_postes:
        postes, lus = _postes_deja_lus(db, run, settings)
        logiciels = inventory_counts(db, run)[1]
    elif visible:
        postes = []
        lus, logiciels = inventory_counts(db, run)
    else:
        postes, lus, logiciels = [], 0, 0
    if run.status == "running":
        return _vue(
            en_cours=True,
            pourcent=min(100, int(run.progress_current or 0)),
            texte=run.message or "Lecture du parc",
            recharger=False,
            erreur=False,
            postes=postes,
            lus=lus,
            logiciels=logiciels,
            etat="cours",
        )
    recent = run.finished_at is not None and run.finished_at >= utcnow() - timedelta(minutes=2)
    if suivre and recent and run.status == "success":
        return _vue(
            en_cours=False,
            pourcent=100,
            texte=run.message or "Collecte terminée.",
            recharger=True,
            erreur=False,
            postes=postes,
            lus=lus,
            logiciels=logiciels,
            etat="fini",
        )
    if suivre and recent and run.status in {"error", "annulee"}:
        return _vue(
            en_cours=False,
            pourcent=min(100, int(run.progress_current or 0)),
            texte=run.message or run.error or "La vérification a échoué.",
            recharger=False,
            erreur=True,
            postes=postes,
            lus=lus,
            logiciels=logiciels,
            etat="erreur",
        )
    return _progress_idle()


def _postes_deja_lus(db: Session, run: CheckRun, settings: Settings | None) -> tuple[list[dict], int]:
    total = int(
        db.scalar(select(func.count()).select_from(ComputerRecord).where(ComputerRecord.check_run_id == run.id)) or 0
    )
    records = list(
        db.scalars(
            select(ComputerRecord)
            .where(ComputerRecord.check_run_id == run.id)
            .order_by(ComputerRecord.id.desc())
            .limit(80)
            .options(selectinload(ComputerRecord.software))
        )
    )
    done = done_action_keys(db)
    grouped: dict[int, list[ComputedAction]] = {}
    for action in db.scalars(select(ComputedAction).where(ComputedAction.check_run_id == run.id)):
        if action.action_key in done:
            continue
        grouped.setdefault(action.glpi_computer_id, []).append(action)
    postes = []
    for record in records:
        own = grouped.get(record.glpi_id, [])
        if own:
            classe = priority_of(own)
            detail = max(own, key=lambda action: SEVERITY_RANK.get(action.severity, 0)).title
        else:
            classe = "lecture"
            detail = "Lecture en cours"
        names = [f"{item.name} {item.version}".strip() for item in record.software if item.name]
        shown = ", ".join(names[:3])
        extra = len(names) - 3
        if extra > 0:
            shown = f"{shown} +{extra}"
        postes.append(
            {
                "nom": record.name or f"Poste {record.glpi_id}",
                "service": record.group_name,
                "systeme": " ".join(part for part in (record.os_name, record.os_version) if part),
                "logiciels": shown,
                "resultat": _RESULTATS.get(classe, classe),
                "classe": classe,
                "detail": detail,
                "lien": glpi_computer_url(settings, record.glpi_id) if settings is not None else "",
            }
        )
    return postes, total


def _vue(
    *,
    en_cours: bool,
    pourcent: int,
    texte: str,
    recharger: bool,
    erreur: bool,
    postes: list,
    lus: int,
    logiciels: int = 0,
    etat: str = "idle",
) -> dict:
    return {
        "en_cours": en_cours,
        "pourcent": pourcent,
        "texte": texte,
        "recharger": recharger,
        "erreur": erreur,
        "postes": postes,
        "lus": lus,
        "logiciels": logiciels,
        "etat": etat,
    }


def _progress_idle() -> dict:
    return _vue(en_cours=False, pourcent=0, texte="", recharger=False, erreur=False, postes=[], lus=0, logiciels=0, etat="idle")


def connection_report(settings: Settings, http: httpx.Client | None = None) -> dict:
    if settings.demo_active:
        from app.demo.loader import load_catalog

        current = load_catalog().current
        return {"mode": "demo", "ordinateurs": len(current)}
    with GlpiClient(settings, http=http) as client:
        computers = client.list_computers()
    return {"mode": "glpi", "ordinateurs": len(computers)}


def glpi_computer_url(settings: Settings, glpi_id: int) -> str:
    return f"{settings.glpi_base_url}/front/computer.form.php?id={glpi_id}"
