from __future__ import annotations

import json
from copy import deepcopy
from datetime import timedelta
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.glpi.normalize import normalize_name
from app.glpi.service import save_check
from app.glpi.types import AgentItem, ComputerItem, SoftwareItem
from app.models.inventory import CheckRun
from app.timeutils import utcnow

DATA_PATH = Path(__file__).with_name("parc.json")


class DemoCatalog:
    def __init__(self, previous: list[ComputerItem], current: list[ComputerItem]):
        self.previous = previous
        self.current = current


def load_catalog(path: Path | None = None, now=None) -> DemoCatalog:
    raw = json.loads((path or DATA_PATH).read_text(encoding="utf-8"))
    moment = now or utcnow()
    current = [_computer(row, moment) for row in raw["computers"]]
    skipped = set(raw.get("previous_without", []))
    overrides = {int(key): value for key, value in raw.get("previous_overrides", {}).items()}
    previous = []
    for computer in current:
        if computer.glpi_id in skipped:
            continue
        clone = deepcopy(computer)
        if computer.glpi_id in overrides:
            override = overrides[computer.glpi_id]
            if "software" in override:
                clone.software = [_software(item) for item in override["software"]]
        previous.append(clone)
    for row in raw.get("previous_extra", []):
        previous.append(_computer(row, moment))
    return DemoCatalog(previous=previous, current=current)


def seed_demo_if_needed(db: Session, path: Path | None = None) -> None:
    count = db.scalar(select(func.count()).select_from(CheckRun)) or 0
    if count:
        return
    catalog = load_catalog(path)
    save_check(db, catalog.previous, "demo")
    save_check(db, catalog.current, "demo")


def _computer(row: dict, moment) -> ComputerItem:
    agent = None
    if row.get("agent_days") is not None or row.get("agent_version"):
        if row.get("agent_days") is not None or row.get("agent_id") is not None:
            agent = AgentItem(
                glpi_id=row.get("agent_id"),
                last_contact=_shift(moment, row.get("agent_days")),
                version=normalize_name(row.get("agent_version")),
                itemtype="Agent",
            )
    return ComputerItem(
        glpi_id=int(row["glpi_id"]),
        name=normalize_name(row.get("name")),
        group_name=normalize_name(row.get("group")),
        location=normalize_name(row.get("location")),
        computer_type=normalize_name(row.get("type")),
        os_name=normalize_name(row.get("os_name")),
        os_version=normalize_name(row.get("os_version")),
        os_build=normalize_name(row.get("os_build")),
        last_inventory_at=_shift(moment, row.get("inventory_days")),
        software=[_software(item) for item in row.get("software", [])],
        agent=agent,
    )


def _software(item: dict) -> SoftwareItem:
    return SoftwareItem(
        name=normalize_name(item.get("name")),
        publisher=normalize_name(item.get("publisher")),
        version=normalize_name(item.get("version")),
    )


def _shift(moment, days):
    if days is None:
        return None
    return moment + timedelta(days=int(days))
