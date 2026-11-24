from __future__ import annotations

from sqlalchemy import func, select

from app.actions.engine import set_follow_up
from app.glpi.service import prune_history, save_check
from app.glpi.types import ComputerItem, SoftwareItem
from app.models.history import SoftwareChange
from app.security_topics import bulletin_kind
from app.timeutils import utcnow


def _poste(version: str, build: str, extra: SoftwareItem | None = None) -> ComputerItem:
    software = [SoftwareItem("Google Chrome", "Google", version)]
    if extra is not None:
        software.append(extra)
    return ComputerItem(
        glpi_id=900,
        name="PC-HIST",
        group_name="Informatique",
        location="Labo",
        computer_type="Portable",
        os_name="Windows 11",
        os_version="26H2",
        os_build=build,
        last_inventory_at=utcnow(),
        software=software,
    )


def _rows(db) -> list[SoftwareChange]:
    return list(db.scalars(select(SoftwareChange).order_by(SoftwareChange.id)))


def test_classement_des_bulletins():
    from app.security_topics import watch_subjects

    assert bulletin_kind("Campagne du rançongiciel LockBit") == "ransomware"
    assert bulletin_kind("Multiples vulnérabilités dans FortiGate") == "materiel"
    assert bulletin_kind("Vulnérabilité dans Google Chrome") == "logiciel"
    assert {key for key, _label, _kind in watch_subjects("Vulnérabilité dans Zoom")} == {
        key for key, _label, _kind in watch_subjects("Multiples vulnérabilités dans Zoom")
    }
    assert {key for key, _label, _kind in watch_subjects("Multiples vulnérabilités dans FortiGate")} == {
        key for key, _label, _kind in watch_subjects("Vulnérabilité dans les équipements Fortinet")
    }
    assert watch_subjects("Alerte dans Google Chrome")[0][0] == "logiciel:chrome"
    assert watch_subjects("Campagne du rançongiciel LockBit")[0][0] == "ransomware"


def test_historique_automatique_manuel_et_conservation(app):
    db = app.state.SessionLocal()
    try:
        save_check(db, [_poste("120.0.1", "26300.1")], "demo")
        assert _rows(db) == []

        save_check(
            db,
            [_poste("131.0.0", "26300.2", SoftwareItem("Outil interne", "Maison", "1.0"))],
            "demo",
        )
        changes = _rows(db)
        by_key = {row.software_key: row for row in changes}
        assert set(by_key) == {"chrome", "systeme"}
        assert by_key["chrome"].origin == "automatique"
        assert by_key["chrome"].previous_version == "120.0.1"
        assert by_key["chrome"].new_version == "131.0.0"
        assert by_key["chrome"].note == "Mise à jour"
        assert by_key["systeme"].previous_version.endswith("26300.1")
        assert by_key["systeme"].new_version.endswith("26300.2")
        assert "Outil interne" not in {row.software_name for row in changes}

        save_check(db, [_poste("131", "26300.2")], "demo")
        assert len(_rows(db)) == 2

        save_check(db, [_poste("120.0.1", "26300.2")], "demo")
        lowered = [row for row in _rows(db) if row.software_key == "chrome"][-1]
        assert lowered.note == "Version inférieure à la précédente"
        assert lowered.new_version == "120.0.1"

        set_follow_up(db, "900:version:chrome", status="fait", technician="Nina", comment="Fait au labo")
        manual = [row for row in _rows(db) if row.origin == "manuel"]
        assert len(manual) == 1
        assert manual[0].actor == "Nina"
        assert manual[0].software_name == "Google Chrome"
        assert "Fait au labo" in manual[0].note
        set_follow_up(db, "900:version:chrome", status="fait", technician="Nina", comment="Fait au labo")
        assert len([row for row in _rows(db) if row.origin == "manuel"]) == 1

        kept = db.scalar(select(func.count()).select_from(SoftwareChange))
        prune_history(db, keep=1)
        assert db.scalar(select(func.count()).select_from(SoftwareChange)) == kept
    finally:
        db.close()


def test_le_suivi_ne_garde_que_le_dernier_bulletin(app):
    from app.models.history import SecurityWatch
    from app.watches import apply_latest

    db = app.state.SessionLocal()
    try:
        db.add(
            SecurityWatch(
                subject_key="sujet:zoom",
                label="Zoom",
                kind="logiciel",
                created_by="admin",
                created_at=utcnow(),
                current_reference="OLD",
                current_title="Vulnérabilité dans Zoom",
                current_revised="2026-11-01",
                current_closed=False,
            )
        )
        db.commit()
        changed = apply_latest(
            db,
            [
                {
                    "reference": "OLD",
                    "title": "Vulnérabilité dans Zoom",
                    "url": "https://exemple/old",
                    "revised": "2026-11-01",
                    "alert": False,
                    "closed": True,
                },
                {
                    "reference": "NEW",
                    "title": "Multiples vulnérabilités dans Zoom",
                    "url": "https://exemple/new",
                    "revised": "2026-11-21",
                    "alert": True,
                    "closed": False,
                },
            ],
        )
        watch = db.scalar(select(SecurityWatch))
        assert changed == 1
        assert watch.current_reference == "NEW"
        assert watch.current_closed is False
        assert watch.current_alert is True
        apply_latest(
            db,
            [
                {
                    "reference": "NEW",
                    "title": "Multiples vulnérabilités dans Zoom",
                    "url": "https://exemple/new",
                    "revised": "2026-11-21",
                    "alert": True,
                    "closed": True,
                }
            ],
        )
        db.refresh(watch)
        assert watch.current_reference == "NEW"
        assert watch.current_closed is True
        assert apply_latest(db, []) == 0
        assert watch.current_reference == "NEW"
    finally:
        db.close()


def test_page_poste_affiche_l_historique(client, app, admin):
    from tests.conftest import login

    db = app.state.SessionLocal()
    try:
        save_check(db, [_poste("120.0.1", "26300.1")], "demo")
        save_check(db, [_poste("131.0.0", "26300.1")], "demo")
    finally:
        db.close()
    login(client, "admin", "motdepasse-admin")
    page = client.get("/postes/900")
    assert page.status_code == 200
    assert "Historique des mises à jour" in page.text
    assert "Automatique" in page.text
    assert "Google Chrome" in page.text
    assert "120.0.1" in page.text
    assert "131.0.0" in page.text
