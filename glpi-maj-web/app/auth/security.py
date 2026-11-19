from __future__ import annotations

import secrets

import bcrypt

ROLES = ("admin", "technicien", "lecture")
ROLE_RANK = {"lecture": 1, "technicien": 2, "admin": 3}
LOCK_THRESHOLD = 5
LOCK_MINUTES = 15
MIN_PASSWORD_LENGTH = 8
SESSION_COOKIE = "glpimaj_session"
CSRF_COOKIE = "glpimaj_csrf"

_DUMMY_HASH = bcrypt.hashpw(b"mot-de-passe-factice", bcrypt.gensalt(rounds=12)).decode()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def verify_password_dummy(password: str) -> None:
    verify_password(password, _DUMMY_HASH)


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)[:64]


def tokens_equal(left: str, right: str) -> bool:
    if not left or not right:
        return False
    return secrets.compare_digest(left, right)
