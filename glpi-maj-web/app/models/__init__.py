"""Modèles SQLAlchemy. Chaque module est importé pour l'enregistrement sur Base."""

from app.models.auth import AppSetting, SessionToken, User
from app.models.inventory import AgentRecord, CheckRun, ComputerRecord, SoftwareInstall

__all__ = [
    "AgentRecord",
    "AppSetting",
    "CheckRun",
    "ComputerRecord",
    "SessionToken",
    "SoftwareInstall",
    "User",
]
