from __future__ import annotations

import json
import logging
import threading
from datetime import timedelta

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, selectinload

from app.actions.engine import compute_computers, priority_of
from app.actions.rules import SEVERITY_RANK
from app.config import Settings
from app.glpi.client import GlpiClient, _software_item, assemble
from app.glpi.errors import GlpiError
from app.glpi.normalize import extract_build, label, normalize_name, parse_glpi_datetime
from app.glpi.types import AgentItem, ComputerItem
from app.models.actions import ComputedAction
from app.models.inventory import AgentRecord, CheckRun, ComputerRecord, SoftwareInstall
from app.timeutils import utcnow

logger = logging.getLogger(__name__)
_VERIFICATION_LOCK = threading.Lock()
_STALE_RUN = timedelta(hours=2)


def latest_successful(db: Session) -> CheckRun | None:
    return db.scalar(select(CheckRun).where(CheckRun.status == "success").order_by(CheckRun.id.desc()))


def visible_run(db: Session) -> CheckRun | None:
    """Vérification affichée : celle en cours s'il y en a une, sinon la dernière réussie."""
    current = db.scalar(select(CheckRun).order_by(CheckRun.id.desc()))
    if current is not None and current.status == "running" and current.finished_at is None:
        return current
    return latest_successful(db)


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
        _memoriser_postes(db, run, assemble(chunk, [], [], [], [], []), details=False)
        return
    if step == "systèmes":
        _appliquer_systemes(db, run, live, chunk)
        return
    if step == "installations":
        _appliquer_installations(db, run, live, chunk)
        return
    if step == "agents":
        _appliquer_agents(db, run, live, chunk)


def _memoriser_postes(db: Session, run: CheckRun, items: list[ComputerItem], *, details: bool) -> None:
    if not items:
        return
    known = {
        row.glpi_id: row
        for row in db.scalars(select(ComputerRecord).where(ComputerRecord.check_run_id == run.id))
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
    run.computer_count = len(known)
    db.flush()


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
        try:
            by_item[int(row["items_id"])] = row
        except (KeyError, TypeError, ValueError):
            continue
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
        try:
            glpi_id = int(row["items_id"])
        except (KeyError, TypeError, ValueError):
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
    compute_computers(db, run, set(pending))


def _appliquer_agents(db: Session, run: CheckRun, live: _LiveCatalog, chunk: list) -> None:
    by_item: dict[int, AgentItem] = {}
    for row in chunk:
        if row.get("itemtype") not in (None, "", "Computer"):
            continue
        try:
            glpi_id = int(row["items_id"])
        except (KeyError, TypeError, ValueError):
            continue
        by_item[glpi_id] = AgentItem(
            glpi_id=int(row["id"]) if row.get("id") is not None else None,
            last_contact=parse_glpi_datetime(row.get("last_contact")),
            version=normalize_name(row.get("version")),
            itemtype=normalize_name(row.get("itemtype") or "Agent") or "Agent",
        )
    found = _records(db, run, live, set(by_item))
    touched: set[int] = set()
    for glpi_id, agent in by_item.items():
        record = found.get(glpi_id)
        if record is None:
            continue
        db.execute(delete(AgentRecord).where(AgentRecord.computer_id == record.id))
        db.flush()
        db.add(
            AgentRecord(
                computer_id=record.id,
                glpi_id=agent.glpi_id,
                last_contact=agent.last_contact,
                version=agent.version,
                itemtype=agent.itemtype,
            )
        )
        touched.add(glpi_id)
    db.flush()
    compute_computers(db, run, touched)


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
                _memoriser_postes(db, run, [computer], details=True)
                compute_computers(db, run, {computer.glpi_id})
                db.commit()
                _publish(db, run, min(95, int(index * 95 / total)), f"Lecture du parc d'exemple : {index} / {len(computers)}")
        else:
            live = _LiveCatalog()

            def on_progress(index: int, total_steps: int, step: str, read: int, total: int | None, chunk=None) -> None:
                pourcent = collection_percent(index, total_steps, read, total)
                detail = str(read) if total is None else f"{read} / {total}"
                noter_page(db, run, live, step, chunk or [])
                _publish(db, run, pourcent, f"Lecture des {step} : {detail}")

            with GlpiClient(settings, http=http) as client:
                computers = client.collect(on_progress=on_progress)
    except GlpiError as exc:
        save_check(db, [], run.origin, error=exc.message, run=run)
        raise
    except Exception:
        logger.exception("La lecture GLPI a échoué")
        save_check(db, [], run.origin, error="La lecture GLPI a échoué.", run=run)
        raise
    return save_check(db, computers, run.origin, run=run)


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


def verification_view(db: Session, *, suivre: bool = False, settings: Settings | None = None) -> dict:
    db.expire_all()
    run = db.scalar(select(CheckRun).order_by(CheckRun.id.desc()))
    if run is None:
        return _progress_idle()
    if run.status == "running":
        run = _expire_if_stale(db, run)
    visible = run.status in {"running", "error"} or (
        suivre and run.finished_at is not None and run.finished_at >= utcnow() - timedelta(minutes=2)
    )
    postes, lus = _postes_deja_lus(db, run, settings) if visible else ([], 0)
    if run.status == "running":
        return _vue(
            en_cours=True,
            pourcent=min(100, int(run.progress_current or 0)),
            texte=run.message or "Lecture du parc",
            recharger=False,
            erreur=False,
            postes=postes,
            lus=lus,
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
        )
    if suivre and recent and run.status == "error":
        return _vue(
            en_cours=False,
            pourcent=min(100, int(run.progress_current or 0)),
            texte=run.message or run.error or "La vérification a échoué.",
            recharger=False,
            erreur=True,
            postes=postes,
            lus=lus,
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
    grouped: dict[int, list[ComputedAction]] = {}
    for action in db.scalars(select(ComputedAction).where(ComputedAction.check_run_id == run.id)):
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


def _vue(*, en_cours: bool, pourcent: int, texte: str, recharger: bool, erreur: bool, postes: list, lus: int) -> dict:
    return {
        "en_cours": en_cours,
        "pourcent": pourcent,
        "texte": texte,
        "recharger": recharger,
        "erreur": erreur,
        "postes": postes,
        "lus": lus,
    }


def _progress_idle() -> dict:
    return _vue(en_cours=False, pourcent=0, texte="", recharger=False, erreur=False, postes=[], lus=0)


def connection_report(settings: Settings, http: httpx.Client | None = None) -> dict:
    if settings.demo_active:
        from app.demo.loader import load_catalog

        current = load_catalog().current
        return {
            "mode": "demo",
            "ordinateurs": len(current),
            "agents": sum(1 for computer in current if computer.agent is not None),
        }
    with GlpiClient(settings, http=http) as client:
        computers = client.list_computers()
        agents = [row for row in client.list_agents() if row.get("itemtype") in (None, "", "Computer")]
    return {"mode": "glpi", "ordinateurs": len(computers), "agents": len(agents)}


def glpi_computer_url(settings: Settings, glpi_id: int) -> str:
    return f"{settings.glpi_base_url}/front/computer.form.php?id={glpi_id}"
