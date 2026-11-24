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
        run = CheckRun(
            started_at=utcnow(),
            status="running",
            origin="glpi",
            computer_count=1,
            summary_json="{}",
            progress_current=40,
            progress_total=100,
            message="Lecture des ordinateurs : 20 / 50",
        )
        db.add(run)
        db.flush()
        from app.models.inventory import ComputerRecord

        db.add(
            ComputerRecord(
                check_run_id=run.id,
                glpi_id=7,
                name="PC VISIBLE",
                group_name="Accueil",
                location="Hall",
                computer_type="Portable",
                os_name="Windows 11",
                os_version="26H2",
                os_build="26300.1",
            )
        )
        db.commit()
    finally:
        db.close()

    page = client.get("/")
    assert "40 %" in page.text
    assert "PC VISIBLE" in page.text
    assert "Lecture des ordinateurs : 20 / 50" in page.text
    assert 'role="progressbar"' in page.text
    fragment = client.get("/verification/progression")
    assert "40 %" in fragment.text
    assert "PC VISIBLE" in fragment.text
    assert 'hx-get="/verification/progression?lus=' in fragment.text
    assert "Arrêter la vérification" in page.text
    leger = client.get("/verification/progression?lus=1&logiciels=0&etat=cours")
    assert leger.status_code == 200
    assert "40 %" in leger.text
    assert "PC VISIBLE" not in leger.text

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


def test_postes_et_logiciels_suivent_la_collecte(client, app, admin):
    from app.models.inventory import CheckRun, ComputerRecord, SoftwareInstall
    from app.timeutils import utcnow

    login(client, "admin", "motdepasse-admin")
    db = app.state.SessionLocal()
    try:
        run = CheckRun(
            started_at=utcnow(),
            status="running",
            origin="glpi",
            computer_count=1,
            summary_json="{}",
            progress_current=20,
            progress_total=100,
            message="Lecture en cours",
        )
        db.add(run)
        db.flush()
        computer = ComputerRecord(
            check_run_id=run.id,
            glpi_id=77,
            name="PC EN COURS",
            group_name="Direction",
            location="Rabat",
            computer_type="Portable",
            os_name="Windows 11",
            os_version="26H2",
            os_build="26300.1",
        )
        db.add(computer)
        db.flush()
        db.add(SoftwareInstall(computer_id=computer.id, name="Google Chrome", publisher="Google", version="120.0.1"))
        db.add(SoftwareInstall(computer_id=computer.id, name="Bidule Interne", publisher="Maison", version="1.0"))
        db.commit()
    finally:
        db.close()

    postes = client.get("/postes")
    assert postes.status_code == 200
    assert "PC EN COURS" in postes.text
    assert "Collecte en cours" in postes.text
    assert 'hx-trigger="every 2s"' in postes.text
    assert "PC-COMPTA-01" not in postes.text
    assert client.get("/postes/77").status_code == 200

    assert client.get("/postes?live=1&lus=1&soft=2&etat=cours").status_code == 204

    logiciels = client.get("/logiciels")
    assert "Google Chrome" in logiciels.text
    assert "Bidule Interne" in logiciels.text
    assert 'id="logiciels-live"' in logiciels.text
    assert 'hx-trigger="every 2s"' in logiciels.text
    assert client.get("/logiciels?live=1&lus=1&soft=2&etat=cours").status_code == 204


def test_annulation_et_historique(client, app, admin):
    from sqlalchemy import func, select

    from app.glpi.service import prune_history
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
                message="Lecture",
            )
        )
        db.commit()
    finally:
        db.close()
    page = client.get("/")
    stopped = client.post(
        "/verification/annuler",
        data={"csrf_token": csrf_from(page.text)},
        headers={"HX-Request": "true"},
    )
    assert stopped.status_code == 200
    assert "Vérification annulée" in stopped.text
    db = app.state.SessionLocal()
    try:
        status = db.scalar(select(CheckRun.status).order_by(CheckRun.id.desc()))
        assert status == "annulee"
        for _ in range(12):
            db.add(
                CheckRun(
                    started_at=utcnow(),
                    finished_at=utcnow(),
                    status="success",
                    origin="glpi",
                    computer_count=0,
                    summary_json="{}",
                )
            )
        db.commit()
        prune_history(db, keep=10)
        finished = db.scalar(select(func.count()).select_from(CheckRun).where(CheckRun.status != "running"))
        assert finished == 10
    finally:
        db.close()


def test_erreur_html_est_echappee(app):
    from fastapi import HTTPException
    from fastapi.testclient import TestClient

    @app.get("/_erreur_html")
    def _boom():
        raise HTTPException(status_code=400, detail="<script>alert(1)</script>")

    with TestClient(app) as test_client:
        response = test_client.get("/_erreur_html", headers={"accept": "text/html"})
    assert response.status_code == 400
    assert "<script>" not in response.text
    assert "&lt;script&gt;" in response.text


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


def test_logiciels_affiche_la_severite_de_la_faille(client, app, admin):
    from app.sources.cache import put_cache

    login(client, "admin", "motdepasse-admin")
    db = app.state.SessionLocal()
    try:
        put_cache(
            db,
            "certfr",
            "catalog",
            {
                "cves": {
                    "CVE-2026-9999": {
                        "id": "CVE-2026-9999",
                        "url": "https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-001/",
                        "alert": True,
                        "cvss": 8.8,
                        "severite": "critique",
                        "products": ["chrome"],
                    }
                }
            },
            origin="live",
        )
    finally:
        db.close()
    page = client.get("/logiciels")
    assert page.status_code == 200
    assert "Sévérité" in page.text
    assert 'class="badge critique"' in page.text
    assert "Critique" in page.text
    assert "8.8" in page.text


def test_page_securite_liste_avis_et_alertes_hors_parc(client, app, admin):
    from app.sources.cache import put_cache

    login(client, "admin", "motdepasse-admin")
    db = app.state.SessionLocal()
    try:
        put_cache(
            db,
            "certfr",
            "bulletins",
            {
                "items": [
                    {
                        "reference": "CERTFR-2026-ALE-001",
                        "title": "Alerte dans Google Chrome",
                        "kind": "alerte",
                        "alert": True,
                        "revised": "2026-11-15",
                        "url": "https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-001/",
                        "products": ["chrome"],
                    },
                    {
                        "reference": "CERTFR-2026-AVI-0099",
                        "title": "Vulnérabilité dans un produit interne",
                        "kind": "avis",
                        "alert": False,
                        "revised": "2026-11-12",
                        "url": "https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-0099/",
                        "products": [],
                    },
                    {
                        "reference": "CERTFR-2026-AVI-0100",
                        "title": "Vulnérabilité dans Windows",
                        "kind": "avis",
                        "alert": False,
                        "revised": "2026-11-13",
                        "url": "https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-0100/",
                        "products": ["windows-10", "windows-11"],
                    },
                    {
                        "reference": "CERTFR-2026-AVI-0101",
                        "title": "Vulnérabilité dans Windows 11",
                        "kind": "avis",
                        "alert": False,
                        "revised": "2026-11-14",
                        "url": "https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-0101/",
                        "products": [],
                    },
                ],
            },
            origin="live",
        )
    finally:
        db.close()
    page = client.get("/securite")
    assert page.status_code == 200
    assert "Alertes" in page.text
    assert "Avis" in page.text
    assert "CERTFR-2026-ALE-001" in page.text
    assert "CERTFR-2026-AVI-0099" in page.text
    assert "CERTFR-2026-AVI-0100" in page.text
    assert "Google Chrome" in page.text
    lies = client.get("/securite", params={"lien": "parc"})
    assert "CERTFR-2026-ALE-001" in lies.text
    assert "CERTFR-2026-AVI-0101" in lies.text
    assert "CERTFR-2026-AVI-0099" not in lies.text
    assert "CERTFR-2026-AVI-0100" not in lies.text
    assert "Liés au parc" in lies.text


def test_types_et_suivi_hors_parc(client, app, admin):
    from app.sources.cache import put_cache
    from tests.conftest import csrf_from, login

    login(client, "admin", "motdepasse-admin")
    db = app.state.SessionLocal()
    try:
        put_cache(
            db,
            "certfr",
            "bulletins",
            {
                "items": [
                    {
                        "reference": "CERTFR-2026-ALE-017",
                        "title": "Campagne du rançongiciel LockBit",
                        "alert": True,
                        "revised": "2026-11-20",
                        "url": "https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-017/",
                    },
                    {
                        "reference": "CERTFR-2026-AVI-0200",
                        "title": "Vulnérabilité dans Zoom",
                        "alert": False,
                        "revised": "2026-11-10",
                        "url": "https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-0200/",
                    },
                    {
                        "reference": "CERTFR-2026-AVI-0201",
                        "title": "Multiples vulnérabilités dans Zoom",
                        "alert": False,
                        "revised": "2026-11-21",
                        "url": "https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-0201/",
                    },
                    {
                        "reference": "CERTFR-2026-AVI-0300",
                        "title": "Multiples vulnérabilités dans FortiGate",
                        "alert": False,
                        "revised": "2026-11-01",
                        "url": "https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-0300/",
                    },
                ],
            },
            origin="live",
        )
    finally:
        db.close()

    page = client.get("/securite")
    assert page.text.find("LockBit") < page.text.find("FortiGate")
    assert page.text.find("FortiGate") < page.text.find("Zoom")
    ransom = client.get("/securite", params={"lien": "ransomware"})
    assert "LockBit" in ransom.text
    assert "Zoom" not in ransom.text
    assert "FortiGate" not in ransom.text
    materiel = client.get("/securite", params={"lien": "materiel"})
    assert "FortiGate" in materiel.text
    assert "Zoom" not in materiel.text
    logiciel = client.get("/securite", params={"lien": "logiciel"})
    assert "CERTFR-2026-AVI-0200" in logiciel.text
    assert "LockBit" not in logiciel.text
    assert "FortiGate" not in logiciel.text
    parc = client.get("/securite", params={"lien": "parc"})
    assert "Zoom" not in parc.text
    assert "FortiGate" not in parc.text

    suivi = client.post(
        "/securite/suivi",
        data={
            "csrf_token": csrf_from(logiciel.text),
            "reference": "CERTFR-2026-AVI-0200",
            "retour": "logiciel",
        },
        follow_redirects=False,
    )
    assert suivi.status_code == 303
    suivis = client.get("/securite", params={"lien": "suivis"})
    assert "CERTFR-2026-AVI-0200" in suivis.text
    assert "CERTFR-2026-AVI-0201" in suivis.text
    assert "FortiGate" not in suivis.text
    assert "LockBit" not in suivis.text

    retire = client.post(
        "/securite/suivi",
        data={
            "csrf_token": csrf_from(suivis.text),
            "reference": "CERTFR-2026-AVI-0201",
            "retour": "suivis",
        },
        follow_redirects=True,
    )
    assert "CERTFR-2026-AVI-0200" not in retire.text
    assert "Aucun avis suivi" in retire.text
