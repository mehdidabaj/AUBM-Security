from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import Settings


class Base(DeclarativeBase):
    pass


def sqlite_path_from_url(url: str) -> Path | None:
    if not url.startswith("sqlite:///"):
        return None
    raw = url[len("sqlite:///") :]
    if raw.startswith(":memory:"):
        return None
    return Path(raw)


def ensure_database_parent(settings: Settings) -> None:
    path = sqlite_path_from_url(settings.database_url)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
    settings.data_dir.mkdir(parents=True, exist_ok=True)


def make_engine(url: str):
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args, future=True)


def make_session_factory(engine):
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def session_scope(factory) -> Iterator[Session]:
    db = factory()
    try:
        yield db
    finally:
        db.close()
