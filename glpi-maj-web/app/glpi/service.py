from __future__ import annotations

import json

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.glpi.client import GlpiClient
from app.glpi.errors import GlpiError
from app.glpi.types import ComputerItem
from app.models.inventory import AgentRecord, CheckRun, ComputerRecord, SoftwareInstall
from app.timeutils import utcnow


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


def save_check(
    db: Session,
    computers: list[ComputerItem],
    origin: str,
    error: str | None = None,
) -> CheckRun:
    now = utcnow()
    previous = None if error else latest_successful(db)
    run = CheckRun(
        started_at=now,
        finished_at=now,
        status="error" if error else "success",
        origin=origin,
        computer_count=0 if error else len(computers),
        error=error,
        summary_json="{}",
    )
    db.add(run)
    db.flush()
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


def run_verification(db: Session, settings: Settings, http: httpx.Client | None = None) -> CheckRun:
    if settings.demo_active:
        from app.demo.loader import load_catalog

        return save_check(db, load_catalog().current, "demo")
    try:
        with GlpiClient(settings, http=http) as client:
            computers = client.collect()
    except GlpiError as exc:
        save_check(db, [], "glpi", error=exc.message)
        raise
    return save_check(db, computers, "glpi")


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
