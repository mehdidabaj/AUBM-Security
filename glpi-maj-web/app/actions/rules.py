from __future__ import annotations

from sqlalchemy.orm import Session

from app.settings_store import get_setting, set_setting

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


def ensure_rules(db: Session) -> None:
    """Crée les règles et les seuils une seule fois. Les collectes ne les réécrivent pas."""
    if get_setting(db, "fixed_rules", None) is None:
        set_setting(db, "fixed_rules", DEFAULT_FIXED_RULES)
    if get_setting(db, "severity_critical", None) is None:
        set_setting(db, "severity_critical", 9)
    if get_setting(db, "severity_important", None) is None:
        set_setting(db, "severity_important", 7)
    if get_setting(db, "include_low_in_uptodate", None) is None:
        set_setting(db, "include_low_in_uptodate", False)
    if get_setting(db, "stale_days", None) is None:
        set_setting(db, "stale_days", 7)


def fixed_rules(db: Session) -> dict:
    ensure_rules(db)
    stored = get_setting(db, "fixed_rules", {})
    return {**DEFAULT_FIXED_RULES, **stored}


def threshold(db: Session, key: str, default: float) -> float:
    ensure_rules(db)
    value = get_setting(db, key, default)
    return float(value)


def include_low(db: Session) -> bool:
    ensure_rules(db)
    return bool(get_setting(db, "include_low_in_uptodate", False))


def stale_days(db: Session) -> int:
    ensure_rules(db)
    return int(get_setting(db, "stale_days", 7))
