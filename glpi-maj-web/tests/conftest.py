from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]


def sqlite_url(path: Path) -> str:
    return "sqlite:///" + path.resolve().as_posix()


@pytest.fixture()
def settings(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", sqlite_url(db_path))
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SECRET_KEY", "secret-de-test")
    monkeypatch.setenv("DEMO_MODE", "on")
    monkeypatch.setenv("SCHEDULER_ENABLED", "0")
    monkeypatch.setenv("GLPI_APP_TOKEN", "")
    monkeypatch.setenv("GLPI_USER_TOKEN", "")
    monkeypatch.setenv("GLPI_MAJ_CONFIG", str(tmp_path / "absent.env"))
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "0")
    from app.config import load_settings

    loaded = load_settings()
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", loaded.database_url.replace("%", "%%"))
    os.environ["DATABASE_URL"] = loaded.database_url
    command.upgrade(cfg, "head")
    return loaded


@pytest.fixture()
def app(settings):
    from app.main import create_app

    return create_app(settings)


@pytest.fixture()
def client(app):
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def admin(app):
    from app.auth.service import create_user

    db = app.state.SessionLocal()
    try:
        return create_user(db, "admin", "motdepasse-admin", "admin")
    finally:
        db.close()


def csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, html
    return match.group(1)


def login(client: TestClient, username: str, password: str):
    page = client.get("/connexion")
    token = csrf_from(page.text)
    return client.post(
        "/connexion",
        data={"username": username, "password": password, "csrf_token": token},
        follow_redirects=False,
    )
