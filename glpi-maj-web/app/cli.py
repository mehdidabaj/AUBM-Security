from __future__ import annotations

import argparse
import secrets
import sys

from alembic import command
from alembic.config import Config

from app.auth.service import AuthError, create_user
from app.config import load_settings
from app.database import ensure_database_parent, make_engine, make_session_factory
from app.models import User
from pathlib import Path


def _alembic_config(database_url: str) -> Config:
    root = Path(__file__).resolve().parents[1]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "alembic"))
    cfg.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return cfg


def upgrade_database() -> None:
    settings = load_settings()
    ensure_database_parent(settings)
    command.upgrade(_alembic_config(settings.database_url), "head")


def create_admin(username: str, password: str, force: bool) -> str:
    settings = load_settings()
    ensure_database_parent(settings)
    command.upgrade(_alembic_config(settings.database_url), "head")
    generated = False
    if not password:
        password = secrets.token_urlsafe(18)
        generated = True
    factory = make_session_factory(make_engine(settings.database_url))
    db = factory()
    try:
        existing = db.query(User).filter(User.username == username).one_or_none()
        if existing is not None and not force:
            return f"L'administrateur « {username} » existe déjà."
        if existing is not None and force:
            from app.auth.security import hash_password

            existing.password_hash = hash_password(password)
            existing.role = "admin"
            existing.failed_attempts = 0
            existing.locked_until = None
            db.commit()
        else:
            create_user(db, username, password, "admin")
    except AuthError as exc:
        print(exc.message, file=sys.stderr)
        return exc.message
    finally:
        db.close()
    if generated:
        return f"Administrateur « {username} » créé. Mot de passe (affiché une seule fois) : {password}"
    return f"Administrateur « {username} » enregistré."


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Administration de glpi-maj-web")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("upgrade", help="Applique les migrations Alembic")

    admin = sub.add_parser("create-admin", help="Crée le premier administrateur")
    admin.add_argument("--username", default="")
    admin.add_argument("--password", default="")
    admin.add_argument("--force", action="store_true", help="Remplace le mot de passe s'il existe déjà")

    args = parser.parse_args(argv)
    settings = load_settings()
    if args.command == "upgrade":
        upgrade_database()
        print("Base à jour.")
        return 0
    if args.command == "create-admin":
        username = args.username or settings.admin_user or "admin"
        message = create_admin(username, args.password or settings.admin_password, args.force)
        print(message)
        return 0 if "existe déjà" not in message and "doit contenir" not in message else 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
