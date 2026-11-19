from __future__ import annotations

from collections.abc import Iterator

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.auth.security import CSRF_COOKIE, ROLE_RANK, SESSION_COOKIE, tokens_equal
from app.auth.service import get_valid_session
from app.models import User


def get_db(request: Request) -> Iterator[Session]:
    db = request.app.state.SessionLocal()
    try:
        yield db
    finally:
        db.close()


def current_user(request: Request, db: Session) -> User | None:
    row = get_valid_session(db, request.cookies.get(SESSION_COOKIE))
    if row is None:
        return None
    return db.get(User, row.user_id)


async def enforce_csrf(request: Request, db: Session) -> None:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    cookie = request.cookies.get(CSRF_COOKIE, "")
    presented = request.headers.get("x-csrf-token", "")
    if not presented:
        content_type = request.headers.get("content-type", "")
        if "application/json" not in content_type:
            form = await request.form()
            presented = str(form.get("csrf_token") or "")
    if not tokens_equal(presented, cookie):
        raise HTTPException(status_code=403, detail="Jeton CSRF invalide.")
    row = get_valid_session(db, request.cookies.get(SESSION_COOKIE))
    if row is not None and not tokens_equal(presented, row.csrf_token):
        raise HTTPException(status_code=403, detail="Jeton CSRF invalide.")


def require_user(request: Request, db: Session, minimum: str = "lecture") -> User:
    user = current_user(request, db)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentification requise.")
    if ROLE_RANK[user.role] < ROLE_RANK[minimum]:
        raise HTTPException(status_code=403, detail="Accès refusé.")
    return user
