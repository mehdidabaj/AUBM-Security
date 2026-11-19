from __future__ import annotations

import re

from tests.conftest import csrf_from, login


def test_tableau_de_bord_et_scripts_locaux(client, admin):
    login(client, "admin", "motdepasse-admin")
    page = client.get("/")
    assert page.status_code == 200
    assert "Bonjour" in page.text
    assert "Postes analysés" in page.text
    assert ">20<" in page.text
    assert "/static/vendor/chart.umd.min.js" in page.text
    assert "/static/vendor/htmx.min.js" in page.text
    assert "unpkg.com" not in page.text
    assert "jsdelivr" not in page.text
    assert client.get("/static/vendor/htmx.min.js").status_code == 200
    assert client.get("/static/vendor/chart.umd.min.js").status_code == 200


def test_filtre_et_tri_des_postes(client, admin):
    login(client, "admin", "motdepasse-admin")
    page = client.get("/postes", params={"service": "Comptabilité"})
    assert "PC-COMPTA-01" in page.text
    assert "PC-RH-02" not in page.text
    assert "computer.form.php?id=1" in page.text

    fragment = client.get("/postes", params={"q": "PC-RH-02"}, headers={"HX-Request": "true"})
    assert fragment.status_code == 200
    assert "PC-RH-02" in fragment.text
    assert "<html" not in fragment.text.lower()

    critiques = client.get("/postes", params={"priorite": "critique"})
    assert "PC-RH-02" in critiques.text
    assert "PC-COMPTA-01" not in critiques.text


def test_fiche_suivi_et_lien_glpi(client, app):
    from app.auth.service import create_user

    db = app.state.SessionLocal()
    try:
        create_user(db, "tech", "motdepasse-tech", "technicien")
        create_user(db, "lecteur", "motdepasse-lecture", "lecture")
    finally:
        db.close()

    login(client, "tech", "motdepasse-tech")
    page = client.get("/postes/4")
    assert page.status_code == 200
    assert "Windows 10" in page.text
    assert "Migrer vers Windows 11 26H2" in page.text
    assert "computer.form.php?id=4" in page.text
    key = re.search(r'name="action_key" value="([^"]+)"', page.text)
    assert key
    token = csrf_from(page.text)
    saved = client.post(
        "/postes/4/suivi",
        data={
            "csrf_token": token,
            "action_key": key.group(1),
            "status": "en_cours",
            "technician": "Camille",
            "followed_on": "2026-11-19",
            "comment": "Migration planifiée",
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303
    again = client.get("/postes/4")
    assert "Camille" in again.text
    assert "Migration planifiée" in again.text

    client.post("/deconnexion", data={"csrf_token": csrf_from(again.text)}, follow_redirects=False)
    login(client, "lecteur", "motdepasse-lecture")
    refused = client.post(
        "/postes/4/suivi",
        data={"csrf_token": csrf_from(client.get("/postes/4").text), "action_key": key.group(1), "status": "fait"},
    )
    assert refused.status_code == 403
    assert client.get("/parametres").status_code == 403


def test_parametres_glpi_seuils_et_sources(client, admin, monkeypatch):
    login(client, "admin", "motdepasse-admin")
    page = client.get("/parametres")
    assert "Tester la connexion GLPI" in page.text
    token = csrf_from(page.text)
    report = client.post("/parametres/glpi-test", data={"csrf_token": token})
    assert "démo" in report.text
    assert "20 ordinateurs" in report.text

    saved = client.post(
        "/parametres/seuils",
        data={
            "csrf_token": token,
            "severity_critical": "8.5",
            "severity_important": "6",
            "stale_days": "9",
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303
    refreshed = client.get("/parametres")
    assert 'name="severity_critical" value="8.5"' in refreshed.text
    assert 'name="stale_days" value="9"' in refreshed.text

    called = {}

    def fake_launch(app):
        called["app"] = app

    monkeypatch.setattr("app.sources.service.launch_source_update", fake_launch)
    sources = client.get("/sources")
    assert "secours" in sources.text
    assert "Mettre à jour les sources maintenant" in sources.text
    progress = client.post(
        "/sources/maj",
        data={"csrf_token": csrf_from(sources.text)},
        headers={"HX-Request": "true"},
    )
    assert called["app"] is client.app
    assert "Collecte lancée" in progress.text

    monkeypatch.setattr(
        "app.sources.service.probe_source",
        lambda settings, key, http=None: {"ok": True, "message": "winget répond (HTTP 200)."},
    )
    tested = client.post("/sources/winget/tester", data={"csrf_token": csrf_from(sources.text)})
    assert "winget répond" in tested.text


def test_progression_de_la_verification(client, app, admin):
    import time

    from sqlalchemy import func, select

    from app.models.inventory import CheckRun
    from app.timeutils import utcnow
    from tests.conftest import csrf_from, login

    login(client, "admin", "motdepasse-admin")
    db = app.state.SessionLocal()
    try:
        db.add(
            CheckRun(
                started_at=utcnow(),
                status="running",
                origin="glpi",
                computer_count=0,
                summary_json="{}",
                progress_current=40,
                progress_total=100,
                message="Lecture des ordinateurs : 20 / 50",
            )
        )
        db.commit()
    finally:
        db.close()

    page = client.get("/")
    assert "40 %" in page.text
    assert "Lecture des ordinateurs : 20 / 50" in page.text
    assert 'role="progressbar"' in page.text
    fragment = client.get("/verification/progression")
    assert "40 %" in fragment.text
    assert "hx-get=\"/verification/progression\"" in fragment.text

    db = app.state.SessionLocal()
    try:
        current = db.scalar(select(CheckRun).order_by(CheckRun.id.desc()))
        current.status = "success"
        current.finished_at = utcnow().replace(year=utcnow().year - 1)
        db.commit()
    finally:
        db.close()

    launched = client.post(
        "/verification",
        headers={"X-CSRF-Token": csrf_from(page.text), "HX-Request": "true"},
    )
    assert launched.status_code == 200
    assert "Taux de collecte" in launched.text
    assert "<html" not in launched.text.lower()

    deadline = time.monotonic() + 5
    status = "running"
    while time.monotonic() < deadline:
        db = app.state.SessionLocal()
        try:
            status = db.scalar(select(CheckRun.status).order_by(CheckRun.id.desc()))
            running = db.scalar(
                select(func.count()).select_from(CheckRun).where(CheckRun.status == "running")
            )
        finally:
            db.close()
        if status != "running":
            break
        time.sleep(0.05)
    assert status == "success"
    assert running == 0


def test_association_manuelle(client, app):
    from app.auth.service import create_user

    db = app.state.SessionLocal()
    try:
        create_user(db, "tech", "motdepasse-tech", "technicien")
    finally:
        db.close()
    login(client, "tech", "motdepasse-tech")
    page = client.get("/logiciels")
    assert page.status_code == 200
    assert "Google Chrome" in page.text
    unknown = client.get("/logiciels/a-associer")
    assert unknown.status_code == 200
    assert "Logiciels à associer" in unknown.text
