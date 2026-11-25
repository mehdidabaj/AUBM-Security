from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.auth.security import CSRF_COOKIE, ROLE_RANK, SESSION_COOKIE, new_token
from app.auth.service import AuthError, authenticate, create_user, destroy_session, open_session
from app.web.deps import current_user, enforce_csrf, get_db, require_user

router = APIRouter()


def _templates(request: Request):
    return request.app.state.templates


def _cookie_kwargs(request: Request, max_age: int) -> dict:
    settings = request.app.state.settings
    return {
        "max_age": max_age,
        "httponly": True,
        "samesite": "strict",
        "secure": settings.session_cookie_secure,
        "path": "/",
    }


def _no_store(response: HTMLResponse) -> HTMLResponse:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def render(request: Request, name: str, status_code: int = 200, **context) -> HTMLResponse:
    db = request.app.state.SessionLocal()
    try:
        user = current_user(request, db)
        csrf = request.cookies.get(CSRF_COOKIE, "")
        if user is not None:
            from app.auth.service import get_valid_session

            row = get_valid_session(db, request.cookies.get(SESSION_COOKIE))
            if row is not None:
                csrf = row.csrf_token
    finally:
        db.close()
    from app.web.queries import SEVERITY_LABELS

    payload = {
        "request": request,
        "user": user,
        "csrf_token": csrf,
        "role_rank": ROLE_RANK,
        "gravites": SEVERITY_LABELS,
    }
    payload.update(context)
    response = _templates(request).TemplateResponse(request, name, payload, status_code=status_code)
    if csrf:
        response.set_cookie(CSRF_COOKIE, csrf, **_cookie_kwargs(request, 3600))
    return _no_store(response)


def login_page(request: Request, error: str | None = None, status_code: int = 200) -> HTMLResponse:
    token = new_token()
    response = _templates(request).TemplateResponse(
        request,
        "login.html",
        {"request": request, "user": None, "csrf_token": token, "error": error},
        status_code=status_code,
    )
    response.set_cookie(CSRF_COOKIE, token, **_cookie_kwargs(request, 3600))
    return _no_store(response)


@router.get("/sante")
def sante() -> dict[str, str]:
    return {"statut": "ok"}


@router.get("/connexion", response_class=HTMLResponse)
def login_form(request: Request) -> HTMLResponse:
    db = request.app.state.SessionLocal()
    try:
        if current_user(request, db) is not None:
            return RedirectResponse("/", status_code=303)
    finally:
        db.close()
    return login_page(request)


@router.post("/connexion")
async def login_submit(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    await enforce_csrf(request, db)
    form = await request.form()
    username = str(form.get("username") or "")
    password = str(form.get("password") or "")
    try:
        user = authenticate(db, username, password)
    except AuthError as exc:
        return login_page(request, exc.message, status_code=401)
    hours = request.app.state.settings.session_hours
    row = open_session(db, user, hours)
    response = RedirectResponse("/", status_code=303)
    lifetime = hours * 3600
    response.set_cookie(SESSION_COOKIE, row.id, **_cookie_kwargs(request, lifetime))
    response.set_cookie(CSRF_COOKIE, row.csrf_token, **_cookie_kwargs(request, lifetime))
    return response


@router.post("/deconnexion")
async def logout(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    await enforce_csrf(request, db)
    destroy_session(db, request.cookies.get(SESSION_COOKIE))
    response = RedirectResponse("/connexion", status_code=303)
    cookie_flags = _cookie_kwargs(request, 0)
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        secure=cookie_flags["secure"],
        httponly=True,
        samesite="strict",
    )
    response.delete_cookie(
        CSRF_COOKIE,
        path="/",
        secure=cookie_flags["secure"],
        httponly=True,
        samesite="strict",
    )
    return response


@router.post("/comptes", response_class=HTMLResponse)
async def create_account(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    await enforce_csrf(request, db)
    require_user(request, db, "admin")
    form = await request.form()
    try:
        create_user(
            db,
            str(form.get("username") or ""),
            str(form.get("password") or ""),
            str(form.get("role") or "lecture"),
        )
    except AuthError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc
    return HTMLResponse("Compte créé.", status_code=201)


@router.post("/verification")
async def launch_verification(request: Request, db: Session = Depends(get_db)):
    await enforce_csrf(request, db)
    require_user(request, db, "technicien")
    if request.headers.get("hx-request"):
        from app.glpi.service import start_verification, verification_view

        start_verification(request.app, db)
        return render(
            request,
            "verification_progress.html",
            progression=verification_view(db, suivre=True, settings=request.app.state.settings),
        )
    from app.glpi.errors import GlpiError
    from app.glpi.service import run_verification

    try:
        run = run_verification(db, request.app.state.settings)
    except GlpiError as exc:
        raise HTTPException(status_code=502, detail=exc.message) from exc
    return JSONResponse(
        {
            "id": run.id,
            "ordinateurs": run.computer_count,
            "resume": json.loads(run.summary_json or "{}"),
        }
    )


@router.post("/verification/annuler")
async def annuler_verification(request: Request, db: Session = Depends(get_db)):
    await enforce_csrf(request, db)
    require_user(request, db, "technicien")
    from app.glpi.service import cancel_verification, verification_view

    cancel_verification(db)
    if request.headers.get("hx-request"):
        return render(
            request,
            "verification_progress.html",
            progression=verification_view(db, suivre=True, settings=request.app.state.settings),
        )
    return RedirectResponse("/", status_code=303)


@router.get("/verification/progression", response_class=HTMLResponse)
def verification_progression(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    from app.glpi.service import verification_view

    settings = request.app.state.settings
    leger = verification_view(db, suivre=True, settings=settings, avec_postes=False)
    demande_lus = request.query_params.get("lus")
    demande_logiciels = request.query_params.get("logiciels")
    demande_etat = request.query_params.get("etat")
    change = (
        demande_lus is None
        or demande_logiciels is None
        or demande_etat is None
        or demande_lus != str(leger["lus"])
        or demande_logiciels != str(leger["logiciels"])
        or demande_etat != leger["etat"]
    )
    progression = verification_view(db, suivre=True, settings=settings) if change else leger
    return render(request, "verification_poll.html", progression=progression, rafraichir=change)
