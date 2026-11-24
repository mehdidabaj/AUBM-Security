from __future__ import annotations

from sqlalchemy.orm import Session

DEFAULT_FIXED_RULES = {
    "required_feature": "26H2",
    "windows_10_title": "Migrer vers Windows 11 26H2",
    "windows_10_severity": "critique",
    "windows_upgrade_title": "Mise à niveau vers 26H2",
    "windows_upgrade_severity": "important",
    "windows_update_title": "Installer le dernier correctif Windows Update",
    "windows_update_severity": "critique",
    "office_title": "Migrer vers Microsoft 365 Apps",
    "office_severity": "critique",
    "advanced_ip_title": "Désinstaller ou réserver aux administrateurs",
    "advanced_ip_severity": "important",
}

OFFICE_SLUGS = ("office-2013", "office-2016", "office-2019", "office-2021")
SEVERITY_RANK = {"a_jour": 0, "autre": 0, "faible": 1, "important": 2, "critique": 3}


def fixed_rules(db: Session) -> dict:
    """Titres et sévérités intégrés. Ils ne se règlent pas dans l'interface."""
    return dict(DEFAULT_FIXED_RULES)


def threshold(db: Session, key: str, default: float) -> float:
    """Critique à partir de 9, Important à partir de 7."""
    return float(default)


def include_low(db: Session) -> bool:
    return False


def stale_days(db: Session) -> int:
    return 7
