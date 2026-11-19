from __future__ import annotations

from datetime import timedelta

from sqlalchemy import inspect

from app.auth.security import LOCK_THRESHOLD, hash_password, verify_password
from app.models import User
from app.timeutils import utcnow
from tests.conftest import csrf_from, login


def test_hachage_mot_de_passe():
    hashed = hash_password("correct-horse")
    assert verify_password("correct-horse", hashed)
    assert not verify_password("mauvais", hashed)


def test_migration_cree_les_tables(app):
    inspector = inspect(app.state.engine)
    names = set(inspector.get_table_names())
    assert {"users", "sessions", "app_settings"} <= names


def test_mode_demo_auto_sans_jeton(monkeypatch, tmp_path):
    monkeypatch.setenv("GLPI_MAJ_CONFIG", str(tmp_path / "absent.env"))
    monkeypatch.setenv("DEMO_MODE", "auto")
    monkeypatch.delenv("GLPI_APP_TOKEN", raising=False)
    monkeypatch.delenv("GLPI_USER_TOKEN", raising=False)
    from app.config import load_settings

    assert load_settings().demo_active is True
    monkeypatch.setenv("GLPI_APP_TOKEN", "app")
    monkeypatch.setenv("GLPI_USER_TOKEN", "user")
    assert load_settings().demo_active is False
    monkeypatch.setenv("DEMO_MODE", "on")
    assert load_settings().demo_active is True


def test_parametres_persistants(app):
    from app.settings_store import get_setting, set_setting

    db = app.state.SessionLocal()
    try:
        set_setting(db, "severity_critical", 9)
        assert get_setting(db, "severity_critical") == 9
        assert get_setting(db, "absent", "défaut") == "défaut"
    finally:
        db.close()


def test_connexion_et_deconnexion(client, admin):
    anonymous = client.get("/", follow_redirects=False)
    assert anonymous.status_code == 303
    assert anonymous.headers["location"] == "/connexion"

    bad = login(client, "admin", "mauvais-mot")
    assert bad.status_code == 401
    assert "incorrect" in bad.text

    ok = login(client, "admin", "motdepasse-admin")
    assert ok.status_code == 303
    home = client.get("/")
    assert home.status_code == 200
    assert "admin" in home.text
    assert "Bonjour" in home.text

    page = client.get("/")
    token = csrf_from(page.text)
    out = client.post("/deconnexion", data={"csrf_token": token}, follow_redirects=False)
    assert out.status_code == 303
    again = client.get("/", follow_redirects=False)
    assert again.status_code == 303


def test_rejet_sans_csrf(client, admin):
    login(client, "admin", "motdepasse-admin")
    response = client.post("/deconnexion", data={}, follow_redirects=False)
    assert response.status_code == 403


def test_verrouillage_apres_cinq_echecs(client, app, admin):
    for _ in range(LOCK_THRESHOLD):
        response = login(client, "admin", "mauvais-mot")
        assert response.status_code == 401
    locked = login(client, "admin", "motdepasse-admin")
    assert locked.status_code == 401
    assert "verrouillé" in locked.text

    db = app.state.SessionLocal()
    try:
        user = db.query(User).filter(User.username == "admin").one()
        assert user.failed_attempts >= LOCK_THRESHOLD
        user.locked_until = utcnow() - timedelta(minutes=1)
        db.commit()
    finally:
        db.close()

    recovered = login(client, "admin", "motdepasse-admin")
    assert recovered.status_code == 303


def test_lecture_seule_ne_cree_pas_de_compte(client, app):
    from app.auth.service import create_user

    db = app.state.SessionLocal()
    try:
        create_user(db, "lecteur", "motdepasse-lecture", "lecture")
    finally:
        db.close()
    login(client, "lecteur", "motdepasse-lecture")
    page = client.get("/")
    token = csrf_from(page.text)
    response = client.post(
        "/comptes",
        data={
            "csrf_token": token,
            "username": "autre",
            "password": "motdepasse-autre",
            "role": "technicien",
        },
    )
    assert response.status_code == 403


def test_admin_cree_un_compte(client, admin):
    login(client, "admin", "motdepasse-admin")
    page = client.get("/")
    token = csrf_from(page.text)
    response = client.post(
        "/comptes",
        data={
            "csrf_token": token,
            "username": "nina",
            "password": "motdepasse-nina",
            "role": "technicien",
        },
    )
    assert response.status_code == 201
    out = client.post("/deconnexion", data={"csrf_token": token}, follow_redirects=False)
    assert out.status_code == 303
    assert login(client, "nina", "motdepasse-nina").status_code == 303


def test_jeton_de_session_accepte_si_le_cookie_csrf_a_derape(client, admin):
    login(client, "admin", "motdepasse-admin")
    page = client.get("/")
    token = csrf_from(page.text)
    client.cookies.set("glpimaj_csrf", "ancien-jeton-perime")
    response = client.post("/deconnexion", data={"csrf_token": token}, follow_redirects=False)
    assert response.status_code == 303


def test_connexion_sans_cookie_renvoie_le_formulaire(client, admin):
    page = client.get("/connexion")
    assert page.headers["cache-control"] == "no-store"
    token = csrf_from(page.text)
    client.cookies.clear()
    response = client.post(
        "/connexion",
        data={"username": "admin", "password": "motdepasse-admin", "csrf_token": token},
    )
    assert response.status_code == 403
    assert "Jeton CSRF invalide" in response.text
    assert 'name="csrf_token"' in response.text


def test_cookie_session_httponly_samesite(client, admin):
    response = login(client, "admin", "motdepasse-admin")
    set_cookie = response.headers.get("set-cookie", "")
    assert "glpimaj_session=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "samesite=strict" in set_cookie.lower()
