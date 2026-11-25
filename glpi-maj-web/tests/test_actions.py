from __future__ import annotations

import json
from datetime import timedelta

from sqlalchemy import select

from app.actions.engine import compute_check, follow_up_for, is_up_to_date, priority_of, set_follow_up
from app.actions.mapping import set_mapping, suggest_slug, unmatched_names
from app.actions.versions import compare_versions, is_outdated, parse_version
from app.glpi.service import latest_successful, save_check
from app.glpi.types import AgentItem, ComputerItem, SoftwareItem
from app.models.actions import ComputedAction
from app.sources.cache import put_cache
from app.sources.service import load_fallback_if_needed
from app.timeutils import utcnow


def test_comparaison_de_versions():
    assert compare_versions("16.0.20527.20150", "16.0.20527.20196") < 0
    assert compare_versions("8u511", "1.8.0_511") == 0
    assert compare_versions("8u401", "8u511") < 0
    assert compare_versions("1.8.0_401", "8u511") < 0
    assert compare_versions("157.1.99.56", "156.1.98.63") > 0
    assert compare_versions("26300.9818", "26300.9974") < 0
    assert parse_version("voir site") is None
    assert is_outdated("8u511", "8u511", "gt") is True
    assert is_outdated("8u512", "8u511", "gt") is False
    assert is_outdated("157.0.8103.50", "157.0.8103.50", "ge") is False


def _machine(**overrides) -> ComputerItem:
    now = utcnow()
    data = dict(
        glpi_id=1,
        name="PC-TEST",
        group_name="Informatique",
        location="Bâtiment A",
        computer_type="Portable",
        os_name="Windows 11",
        os_version="26H2",
        os_build="26300.9974",
        last_inventory_at=now - timedelta(days=1),
        software=[],
        agent=AgentItem(glpi_id=1, last_contact=now - timedelta(days=1), version="1.21"),
    )
    data.update(overrides)
    return ComputerItem(**data)


def _kinds(db, glpi_id: int) -> dict[str, ComputedAction]:
    run = latest_successful(db)
    rows = db.scalars(select(ComputedAction).where(ComputedAction.check_run_id == run.id, ComputedAction.glpi_computer_id == glpi_id))
    return {row.kind + ":" + row.product_slug: row for row in rows}


def test_regles_fixes_seuils_et_suivi(app):
    db = app.state.SessionLocal()
    try:
        load_fallback_if_needed(db)
        put_cache(
            db,
            "certfr",
            "catalog",
            {
                "cves": {
                    "CVE-2026-1000": {
                        "id": "CVE-2026-1000",
                        "url": "https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-001/",
                        "summary": "Chrome",
                        "alert": True,
                        "products": ["chrome"],
                    },
                    "CVE-2026-4000": {
                        "id": "CVE-2026-4000",
                        "url": "https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-0009/",
                        "summary": "Firefox",
                        "alert": False,
                        "products": ["firefox"],
                    },
                }
            },
            origin="live",
        )
        now = utcnow()
        machines = [
            _machine(
                glpi_id=1,
                name="PC-OK",
                software=[SoftwareItem("Google Chrome", "Google", "157.0.8103.50")],
                agent=AgentItem(1, now - timedelta(days=30), "1.21"),
            ),
            _machine(
                glpi_id=2,
                name="PC-WU",
                os_build="26300.9818",
                software=[SoftwareItem("Microsoft 365 Apps", "Microsoft", "16.0.20527.20150")],
            ),
            _machine(
                glpi_id=3,
                name="PC-W10",
                os_name="Windows 10",
                os_version="22H2",
                os_build="19045.6456",
                software=[SoftwareItem("Microsoft Office 2016", "Microsoft", "16.0.4266.1001")],
            ),
            _machine(
                glpi_id=4,
                name="PC-25H2",
                os_version="25H2",
                os_build="26200.7840",
                software=[SoftwareItem("Google Chrome", "Google", "120.0.6099.71")],
            ),
            _machine(glpi_id=5, name="PC-JAVA", software=[SoftwareItem("Java 8", "Oracle", "8u401"), SoftwareItem("Java 8", "Oracle", "8u391")]),
            _machine(glpi_id=6, name="PC-JAVA-OK", software=[SoftwareItem("Java 8", "Oracle", "8u512")]),
            _machine(glpi_id=7, name="PC-IP", software=[SoftwareItem("Advanced IP Scanner", "Famatech", "voir site")]),
            _machine(glpi_id=8, name="PC-NPP", software=[SoftwareItem("Notepad++", "Don Ho", "8.6.4"), SoftwareItem("Notepad++", "Don Ho", "voir site"), SoftwareItem("Notepad++", "Don Ho", "8.7.1")]),
            _machine(glpi_id=9, name="PC-VLC", software=[SoftwareItem("VLC media player", "VideoLAN", "3.0.20")]),
            _machine(glpi_id=10, name="PC-FF", software=[SoftwareItem("Mozilla Firefox", "Mozilla", "115.0")]),
            _machine(glpi_id=11, name="PC-VIDE", software=[]),
            _machine(
                glpi_id=12,
                name="SRV-FICHIERS",
                computer_type="Serveur",
                os_name="Debian",
                os_version="12",
                os_build="",
                software=[],
            ),
            _machine(
                glpi_id=13,
                name="PC-AGENT",
                last_inventory_at=now - timedelta(days=20),
                software=[SoftwareItem("Mozilla Firefox", "Mozilla", "160.0.1")],
            ),
            _machine(
                glpi_id=14,
                name="PC-SILENCE",
                last_inventory_at=now - timedelta(days=20),
                agent=AgentItem(14, now - timedelta(days=20), "1.12"),
                software=[SoftwareItem("Mozilla Firefox", "Mozilla", "160.0.1")],
            ),
        ]
        save_check(db, machines, "demo")
        kinds = _kinds(db, 1)
        assert "version:chrome" not in kinds
        assert "agent_silencieux:" not in kinds
        assert is_up_to_date(list(kinds.values()), False) is True

        wu = _kinds(db, 2)
        assert wu["windows_update:windows-26h2"].severity == "critique"
        assert wu["windows_update:windows-26h2"].installed_version == "26300.9818"
        assert wu["windows_update:windows-26h2"].target_version == "26300.9974"
        assert wu["version:m365"].severity == "faible"

        win10 = _kinds(db, 3)
        assert win10["windows_migration:windows-10"].severity == "critique"
        assert win10["windows_migration:windows-10"].title == "Migrer vers Windows 11 26H2"
        assert "windows_update:windows-10" not in win10
        assert win10["office_migration:office-2016"].severity == "critique"

        chrome = _kinds(db, 4)["version:chrome"]
        assert chrome.severity == "critique"
        assert "CVE-2026-1000" in chrome.cves_json
        assert "cert.cyber.gouv.fr" in chrome.source_url
        assert _kinds(db, 4)["windows_upgrade:windows-25h2"].severity == "important"
        assert _kinds(db, 4)["windows_update:windows-25h2"].severity == "critique"

        java = _kinds(db, 5)["version:java8"]
        assert java.installed_version == "8u401"
        assert java.target_version.startswith(">")
        assert "version:java8" not in _kinds(db, 6)
        assert _kinds(db, 7)["advanced_ip:advanced-ip"].severity == "important"
        assert _kinds(db, 8)["version:notepadpp"].installed_version == "8.7.1"
        assert _kinds(db, 9)["version:vlc"].severity == "faible"
        assert _kinds(db, 10)["version:firefox"].severity == "faible"
        assert json.loads(_kinds(db, 10)["version:firefox"].cves_json)[0]["id"] == "CVE-2026-4000"
        assert _kinds(db, 11)["sans_logiciel:"].title == "Poste sans logiciel remonté"
        assert _kinds(db, 12)["linux:"].title == "Appliquer les mises à jour Debian"
        assert "sans_logiciel:" not in _kinds(db, 12)
        assert "agent_silencieux:" not in _kinds(db, 13)
        assert "agent_silencieux:" not in _kinds(db, 14)
        assert priority_of(list(_kinds(db, 4).values())) == "critique"
        assert is_up_to_date(list(_kinds(db, 9).values()), False) is True
        assert is_up_to_date(list(_kinds(db, 10).values()), False) is True
        assert is_up_to_date(list(_kinds(db, 10).values()), True) is False

        key = _kinds(db, 9)["version:vlc"].action_key
        set_follow_up(db, key, status="fait", technician="Nina", comment="Fait au labo", followed_on=now)
        again = save_check(db, machines, "demo")
        assert follow_up_for(db, key).status == "fait"
        assert follow_up_for(db, key).technician == "Nina"
        assert any(row.action_key == key for row in db.scalars(select(ComputedAction).where(ComputedAction.check_run_id == again.id)))
    finally:
        db.close()


def test_certfr_relie_les_cves_au_produit(app):
    db = app.state.SessionLocal()
    try:
        load_fallback_if_needed(db)
        put_cache(
            db,
            "certfr",
            "catalog",
            {
                "cves": {
                    "CVE-2026-2857": {
                        "id": "CVE-2026-2857",
                        "url": "https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-0001/",
                        "summary": "Avis",
                        "alert": False,
                        "products": ["chrome"],
                    },
                    "CVE-2026-9999": {
                        "id": "CVE-2026-9999",
                        "url": "https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-001/",
                        "summary": "Alerte",
                        "alert": True,
                        "products": ["chrome"],
                    },
                    "CVE-2026-4000": {
                        "id": "CVE-2026-4000",
                        "url": "https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-0009/",
                        "summary": "Firefox",
                        "alert": True,
                        "products": ["firefox"],
                    },
                    "CVE-2018-0001": {
                        "id": "CVE-2018-0001",
                        "url": "https://www.cert.cyber.gouv.fr/avis/CERTFR-2018-AVI-0099/",
                        "summary": "Ancien avis Chrome",
                        "alert": True,
                        "products": ["chrome"],
                    },
                }
            },
            origin="live",
        )
        save_check(db, [_machine(software=[SoftwareItem("Google Chrome", "Google", "120.0")])], "demo")
        action = _kinds(db, 1)["version:chrome"]
        cves = {item["id"]: item for item in json.loads(action.cves_json)}
        assert cves["CVE-2026-2857"]["certfr"] is True
        assert cves["CVE-2026-2857"]["certfr_alert"] is False
        assert "cert.cyber.gouv.fr/avis/" in cves["CVE-2026-2857"]["certfr_url"]
        assert cves["CVE-2026-9999"]["certfr_alert"] is True
        assert "CVE-2026-4000" not in cves
        assert "CVE-2018-0001" not in cves
        assert action.severity == "critique"
        assert "CERTFR-2026-ALE-001" in action.source_url
    finally:
        db.close()


def test_noms_inconnus_et_correspondance_manuelle(app):
    db = app.state.SessionLocal()
    try:
        load_fallback_if_needed(db)
        unknown = unmatched_names(db, ["Google Chrome", "Super Outil Interne", "Google Crom"])
        names = {row["nom"] for row in unknown}
        assert "Google Chrome" not in names
        assert "Super Outil Interne" in names
        assert suggest_slug("Google Crom") == "chrome"
        set_mapping(db, "Super Outil Interne", "vlc")
        save_check(
            db,
            [_machine(software=[SoftwareItem("Super Outil Interne", "", "1.0")])],
            "demo",
        )
        assert "version:vlc" in _kinds(db, 1)
    finally:
        db.close()


def test_mise_a_jour_automatique_retire_l_action(app):
    from app.web.queries import actions_by_computer

    db = app.state.SessionLocal()
    try:
        load_fallback_if_needed(db)
        save_check(db, [_machine(software=[SoftwareItem("Google Chrome", "Google", "120.0")])], "demo")
        run = latest_successful(db)
        assert any(row.product_slug == "chrome" and row.kind == "version" for row in actions_by_computer(db, run).get(1, []))
        save_check(db, [_machine(software=[SoftwareItem("Google Chrome", "Google", "157.0.8103.50")])], "demo")
        run = latest_successful(db)
        assert not any(row.product_slug == "chrome" and row.kind == "version" for row in actions_by_computer(db, run).get(1, []))
    finally:
        db.close()


def test_parc_demo_couvre_les_cas_demandes(app):
    from app.demo.loader import seed_demo_if_needed

    db = app.state.SessionLocal()
    try:
        load_fallback_if_needed(db)
        seed_demo_if_needed(db)
        run = latest_successful(db)
        by_computer = {}
        for row in db.scalars(select(ComputedAction).where(ComputedAction.check_run_id == run.id)):
            by_computer.setdefault(row.glpi_computer_id, []).append(row)
        assert priority_of(by_computer.get(1, [])) == "a_jour"
        assert any(row.kind == "windows_migration" for row in by_computer[4])
        assert not any(row.kind == "windows_update" for row in by_computer[4])
        assert any(row.kind == "office_migration" and row.product_slug == "office-2021" for row in by_computer[7])
        assert any(row.kind == "advanced_ip" for row in by_computer[12])
        assert any(row.kind == "linux" for row in by_computer[16])
        assert not any(row.kind == "agent_silencieux" for row in by_computer.get(17, []))
        assert not any(row.kind == "agent_silencieux" for row in by_computer.get(18, []))
        assert any(row.kind == "sans_logiciel" for row in by_computer[19])
        java = next(row for row in by_computer[11] if row.product_slug == "java8")
        assert java.installed_version == "8u401"
        notepad = next(row for row in by_computer[14] if row.product_slug == "notepadpp")
        assert notepad.installed_version == "8.7.1"
    finally:
        db.close()
