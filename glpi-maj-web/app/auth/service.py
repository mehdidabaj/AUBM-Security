from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.security import (
    LOCK_MINUTES,
    LOCK_THRESHOLD,
    MIN_PASSWORD_LENGTH,
    ROLES,
    hash_password,
    new_token,
    verify_password,
    verify_password_dummy,
)
from app.models import SessionToken, User
from app.timeutils import utcnow


class AuthError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def create_user(db: Session, username: str, password: str, role: str) -> User:
    username = username.strip()
    if not username:
        raise AuthError("L'identifiant est obligatoire.")
    if role not in ROLES:
        raise AuthError("Rôle inconnu.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AuthError(f"Le mot de passe doit contenir au moins {MIN_PASSWORD_LENGTH} caractères.")
    existing = db.scalar(select(User).where(User.username == username))
    if existing is not None:
        raise AuthError("Cet identifiant existe déjà.")
    user = User(
        username=username,
        password_hash=hash_password(password),
        role=role,
        failed_attempts=0,
        created_at=utcnow(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate(db: Session, username: str, password: str) -> User:
    user = db.scalar(select(User).where(User.username == username.strip()))
    now = utcnow()
    if user is not None and user.locked_until is not None:
        if user.locked_until > now:
            raise AuthError("Compte verrouillé. Réessayez plus tard.")
        user.failed_attempts = 0
        user.locked_until = None
    if user is None:
        verify_password_dummy(password)
        raise AuthError("Identifiant ou mot de passe incorrect.")
    if not verify_password(password, user.password_hash):
        user.failed_attempts += 1
        if user.failed_attempts >= LOCK_THRESHOLD:
            user.locked_until = now + timedelta(minutes=LOCK_MINUTES)
        db.commit()
        raise AuthError("Identifiant ou mot de passe incorrect.")
    user.failed_attempts = 0
    user.locked_until = None
    db.commit()
    return user


def open_session(db: Session, user: User, hours: int) -> SessionToken:
    now = utcnow()
    db.query(SessionToken).filter(SessionToken.user_id == user.id, SessionToken.expires_at < now).delete()
    row = SessionToken(
        id=new_token(),
        user_id=user.id,
        csrf_token=new_token(),
        created_at=now,
        expires_at=now + timedelta(hours=hours),
    )
    db.add(row)
    db.commit()
    return row


def get_valid_session(db: Session, session_id: str | None) -> SessionToken | None:
    if not session_id:
        return None
    row = db.get(SessionToken, session_id)
    if row is None:
        return None
    if row.expires_at <= utcnow():
        db.delete(row)
        db.commit()
        return None
    return row


def destroy_session(db: Session, session_id: str | None) -> None:
    if not session_id:
        return
    row = db.get(SessionToken, session_id)
    if row is not None:
        db.delete(row)
        db.commit()
