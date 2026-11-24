from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class SoftwareItem:
    name: str
    publisher: str
    version: str


@dataclass
class AgentItem:
    glpi_id: int | None
    last_contact: datetime | None
    version: str
    itemtype: str = "Agent"


@dataclass
class ComputerItem:
    glpi_id: int
    name: str
    group_name: str
    location: str
    computer_type: str
    os_name: str
    os_version: str
    os_build: str
    last_inventory_at: datetime | None
    software: list[SoftwareItem] = field(default_factory=list)
    agent: AgentItem | None = None
