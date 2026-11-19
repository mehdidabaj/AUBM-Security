from __future__ import annotations

import json
import logging
import threading
from datetime import timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.glpi.client import GlpiClient
from app.glpi.errors import GlpiError
from app.glpi.types import ComputerItem
from app.models.inventory import AgentRecord, CheckRun, ComputerRecord, SoftwareInstall
from app.timeutils import utcnow

logger = logging.getLogger(__name__)
_VERIFICATION_LOCK = threading.Lock()
_STALE_RUN = timedelta(hours=2)


def latest_successful(db: Session) -> CheckRun | None:
    return db.scalar(select(CheckRun).where(CheckRun.status == "success").order_by(CheckRun.id.desc()))


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

            _publish(db, run, 50, "Lecture du parc d'exemple")
            computers = load_catalog().current
        else:

            def on_progress(index: int, total_steps: int, label: str, read: int, total: int | None) -> None:
                pourcent = collection_percent(index, total_steps, read, total)
                detail = str(read) if total is None else f"{read} / {total}"
                _publish(db, run, pourcent, f"Lecture des {label} : {detail}")

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


def verification_view(db: Session, *, suivre: bool = False) -> dict:
    db.expire_all()
    run = db.scalar(select(CheckRun).order_by(CheckRun.id.desc()))
    if run is None:
        return _progress_idle()
    if run.status == "running":
        run = _expire_if_stale(db, run)
    if run.status == "running":
        return {
            "en_cours": True,
            "pourcent": min(100, int(run.progress_current or 0)),
            "texte": run.message or "Lecture du parc",
            "recharger": False,
            "erreur": False,
        }
    recent = run.finished_at is not None and run.finished_at >= utcnow() - timedelta(minutes=2)
    if suivre and recent and run.status == "success":
        return {
            "en_cours": False,
            "pourcent": 100,
            "texte": run.message or "Collecte terminée.",
            "recharger": True,
            "erreur": False,
        }
    if suivre and recent and run.status == "error":
        return {
            "en_cours": False,
            "pourcent": min(100, int(run.progress_current or 0)),
            "texte": run.message or run.error or "La vérification a échoué.",
            "recharger": False,
            "erreur": True,
        }
    return _progress_idle()


def _progress_idle() -> dict:
    return {"en_cours": False, "pourcent": 0, "texte": "", "recharger": False, "erreur": False}


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
