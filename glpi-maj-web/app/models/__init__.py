"""Modèles SQLAlchemy. Chaque module est importé pour l'enregistrement sur Base."""

from app.models.actions import ActionFollowUp, ComputedAction, SoftwareMapping
from app.models.auth import AppSetting, SessionToken, User
from app.models.history import SecurityWatch, SoftwareChange
from app.models.inventory import AgentRecord, CheckRun, ComputerRecord, SoftwareInstall
from app.models.sources import SourceCache, SourceRun

__all__ = [
    "ActionFollowUp",
    "AgentRecord",
    "AppSetting",
    "ComputedAction",
    "CheckRun",
    "ComputerRecord",
    "SecurityWatch",
    "SessionToken",
    "SoftwareChange",
    "SoftwareMapping",
    "SoftwareInstall",
    "SourceCache",
    "SourceRun",
    "User",
]
