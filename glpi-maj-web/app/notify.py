from __future__ import annotations

import smtplib
from email.message import EmailMessage

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.glpi.service import latest_successful
from app.models.actions import ComputedAction
from app.models.inventory import ComputerRecord
from app.settings_store import get_setting, set_setting
from app.sources.cache import payload_of
from app.sources.cache import get_cache


def notify_changes(db: Session, settings: Settings, send=None) -> bool:
    """Envoie un message si une nouvelle CVE KEV ou un Patch Tuesday concerne le parc.

    Le premier passage mémorise l'état connu sans envoyer de message.
    """
    kev_ids = set((payload_of(get_cache(db, "kev", "catalog")).get("cves") or {}))
    release = payload_of(get_cache(db, "msrc", "catalog")).get("release_id") or ""
    known_kev = get_setting(db, "notified_kev", None)
    known_release = get_setting(db, "notified_msrc", None)
    if known_kev is None and known_release is None:
        set_setting(db, "notified_kev", sorted(kev_ids))
        set_setting(db, "notified_msrc", release)
        return False
    new_kev = sorted(kev_ids - set(known_kev or []))
    new_patch = bool(release and known_release is not None and release != known_release)
    lines = _affected_lines(db, new_kev, new_patch)
    set_setting(db, "notified_kev", sorted(kev_ids))
    set_setting(db, "notified_msrc", release)
    if not lines or not get_setting(db, "smtp_enabled", False):
        return False
    _send(settings, db, lines, send)
    return True


def _affected_lines(db: Session, new_kev: list[str], new_patch: bool) -> list[str]:
    run = latest_successful(db)
    if run is None:
        return []
    actions = list(db.scalars(select(ComputedAction).where(ComputedAction.check_run_id == run.id)))
    names = {
        row.glpi_id: row.name
        for row in db.scalars(select(ComputerRecord).where(ComputerRecord.check_run_id == run.id))
    }
    lines = []
    if new_kev:
        computers = sorted(
            {
                names.get(action.glpi_computer_id, str(action.glpi_computer_id))
                for action in actions
                if any(cve in (action.cves_json or "") for cve in new_kev)
            }
        )
        if computers:
            lines.append("Nouvelles CVE du catalogue CISA KEV : " + ", ".join(new_kev))
            lines.append("Postes concernés : " + ", ".join(computers))
    if new_patch:
        computers = sorted(
            {
                names.get(action.glpi_computer_id, str(action.glpi_computer_id))
                for action in actions
                if action.kind == "windows_update"
            }
        )
        if computers:
            lines.append("Nouveau Patch Tuesday : des postes n'ont pas le build corrigé.")
            lines.append("Postes concernés : " + ", ".join(computers))
    return lines


def _send(settings: Settings, db: Session, lines: list[str], send) -> None:
    host = get_setting(db, "smtp_host", "")
    port = int(get_setting(db, "smtp_port", 587) or 587)
    username = get_setting(db, "smtp_user", "")
    password = get_setting(db, "smtp_password", "")
    sender = get_setting(db, "smtp_from", "")
    recipient = get_setting(db, "smtp_to", "")
    use_tls = bool(get_setting(db, "smtp_tls", True))
    if not host or not sender or not recipient:
        return
    message = EmailMessage()
    message["Subject"] = "glpi-maj-web : nouvelles actions de sécurité"
    message["From"] = sender
    message["To"] = recipient
    message.set_content("\n".join(lines))
    if send is not None:
        send(message, host, port, username, password, use_tls)
        return
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        if use_tls:
            smtp.starttls()
        if username:
            smtp.login(username, password)
        smtp.send_message(message)
