from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.actions.mapping import set_mapping, unmatched_names
from app.actions.rules import DEFAULT_FIXED_RULES, fixed_rules, include_low, stale_days, threshold
from app.settings_store import get_setting, set_setting
from app.sources.catalog import PRODUCTS, SOURCE_LABELS
from app.web.deps import enforce_csrf, get_db, require_user
from app.web.queries import (
    STATUS_LABELS,
    computer_detail,
    computer_views,
    dashboard,
    journal,
    software_rows,
)
from app.web.routes import render

router = APIRouter()


def _params(request: Request) -> dict[str, str]:
    return {key: request.query_params.get(key, "") for key in ("service", "lieu", "priorite", "a_jour", "logiciel", "q", "tri", "sens")}


def _chart(data: dict) -> dict:
    labels = [name for name, _count in data.get("par_logiciel") or []]
    values = [count for _name, count in data.get("par_logiciel") or []]
    evolution = data.get("evolution") or []
    return {
        "logiciels": {"labels": labels, "values": values},
        "evolution": {
            "labels": [point["label"] for point in evolution],
            "actions": [point["actions"] for point in evolution],
        },
    }


@router.get("/", response_class=HTMLResponse)
def board(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    data = dashboard(db, request.app.state.settings)
    return render(request, "dashboard.html", data=data, chart=_chart(data))


@router.get("/postes", response_class=HTMLResponse)
def postes(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    params = _params(request)
    view = computer_views(db, request.app.state.settings, params)
    if request.headers.get("hx-request"):
        return render(request, "postes_table.html", view=view, params=params)
    return render(request, "postes.html", view=view, params=params)


@router.get("/postes/{glpi_id}", response_class=HTMLResponse)
def poste(glpi_id: int, request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    detail = computer_detail(db, request.app.state.settings, glpi_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Poste introuvable dans la dernière vérification.")
    return render(request, "poste.html", detail=detail, statuts=STATUS_LABELS)


@router.post("/postes/{glpi_id}/suivi")
async def suivi(glpi_id: int, request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    await enforce_csrf(request, db)
    require_user(request, db, "technicien")
    form = await request.form()
    from app.actions.engine import set_follow_up

    raw_date = str(form.get("followed_on") or "")
    followed = datetime.strptime(raw_date, "%Y-%m-%d") if raw_date else None
    try:
        set_follow_up(
            db,
            str(form.get("action_key") or ""),
            status=str(form.get("status") or "a_faire"),
            technician=str(form.get("technician") or ""),
            comment=str(form.get("comment") or ""),
            followed_on=followed,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse(f"/postes/{glpi_id}", status_code=303)


@router.get("/logiciels", response_class=HTMLResponse)
def logiciels(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    return render(request, "logiciels.html", rows=software_rows(db))


@router.get("/logiciels/a-associer", response_class=HTMLResponse)
def a_associer(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    from app.glpi.service import latest_successful

    run = latest_successful(db)
    names = []
    if run is not None:
        names = [item.name for computer in run.computers for item in computer.software]
    return render(
        request,
        "associer.html",
        inconnus=unmatched_names(db, names),
        produits=list(PRODUCTS.values()),
    )


@router.post("/logiciels/a-associer")
async def associer(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    await enforce_csrf(request, db)
    require_user(request, db, "technicien")
    form = await request.form()
    try:
        set_mapping(db, str(form.get("nom") or ""), str(form.get("produit") or ""))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse("/logiciels/a-associer", status_code=303)


@router.get("/sources", response_class=HTMLResponse)
def sources_page(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    from app.sources.cache import source_overview

    return render(
        request,
        "sources.html",
        apercu=source_overview(db),
        journal=journal(db),
        progression=_progress(db),
    )


@router.post("/sources/maj", response_class=HTMLResponse)
async def sources_maj(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    await enforce_csrf(request, db)
    require_user(request, db, "technicien")
    from app.sources.service import launch_source_update

    launch_source_update(request.app)
    return render(request, "sources_progress.html", progression={"texte": "Collecte lancée.", "en_cours": True})


@router.get("/sources/progression", response_class=HTMLResponse)
def sources_progression(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    return render(request, "sources_progress.html", progression=_progress(db))


@router.post("/sources/{key}/tester", response_class=HTMLResponse)
async def tester_source(key: str, request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    await enforce_csrf(request, db)
    require_user(request, db, "technicien")
    from app.sources.service import probe_source

    result = probe_source(request.app.state.settings, key)
    css = "ok" if result["ok"] else "alert"
    return HTMLResponse(f'<p class="{css}">{result["message"]}</p>')


@router.get("/parametres", response_class=HTMLResponse)
def parametres(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db, "admin")
    from app.sources.service import enabled_sources

    enabled = enabled_sources(db)
    return render(
        request,
        "parametres.html",
        regles=fixed_rules(db),
        critique=threshold(db, "severity_critical", 9),
        important=threshold(db, "severity_important", 7),
        inclure_faible=include_low(db),
        jours=stale_days(db),
        heure=int(get_setting(db, "schedule_hour", 2) or 2),
        minute=int(get_setting(db, "schedule_minute", 0) or 0),
        sources=[{"cle": key, "libelle": label, "actif": key in enabled} for key, label in SOURCE_LABELS],
        smtp={
            "enabled": bool(get_setting(db, "smtp_enabled", False)),
            "host": get_setting(db, "smtp_host", "") or "",
            "port": get_setting(db, "smtp_port", 587) or 587,
            "user": get_setting(db, "smtp_user", "") or "",
            "sender": get_setting(db, "smtp_from", "") or "",
            "recipient": get_setting(db, "smtp_to", "") or "",
            "tls": bool(get_setting(db, "smtp_tls", True)),
        },
        message=request.query_params.get("message", ""),
    )


@router.post("/parametres/sources")
async def sauver_sources(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    await enforce_csrf(request, db)
    require_user(request, db, "admin")
    form = await request.form()
    set_setting(db, "sources_enabled", {key: key in form for key, _label in SOURCE_LABELS})
    return _retour("Sources enregistrées.")


@router.post("/parametres/regles")
async def sauver_regles(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    await enforce_csrf(request, db)
    require_user(request, db, "admin")
    form = await request.form()
    rules = {key: str(form.get(key) or DEFAULT_FIXED_RULES[key]) for key in DEFAULT_FIXED_RULES}
    set_setting(db, "fixed_rules", rules)
    return _retour("Règles enregistrées.")


@router.post("/parametres/seuils")
async def sauver_seuils(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    await enforce_csrf(request, db)
    require_user(request, db, "admin")
    form = await request.form()
    set_setting(db, "severity_critical", float(form.get("severity_critical") or 9))
    set_setting(db, "severity_important", float(form.get("severity_important") or 7))
    set_setting(db, "include_low_in_uptodate", "include_low" in form)
    set_setting(db, "stale_days", int(form.get("stale_days") or 7))
    return _retour("Seuils enregistrés.")


@router.post("/parametres/planification")
async def sauver_plan(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    await enforce_csrf(request, db)
    require_user(request, db, "admin")
    form = await request.form()
    hour = min(23, max(0, int(form.get("hour") or 2)))
    minute = min(59, max(0, int(form.get("minute") or 0)))
    set_setting(db, "schedule_hour", hour)
    set_setting(db, "schedule_minute", minute)
    from app.scheduler import apply_schedule

    apply_schedule(request.app)
    return _retour("Planification enregistrée.")


@router.post("/parametres/smtp")
async def sauver_smtp(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    await enforce_csrf(request, db)
    require_user(request, db, "admin")
    form = await request.form()
    set_setting(db, "smtp_enabled", "smtp_enabled" in form)
    set_setting(db, "smtp_host", str(form.get("smtp_host") or ""))
    set_setting(db, "smtp_port", int(form.get("smtp_port") or 587))
    set_setting(db, "smtp_user", str(form.get("smtp_user") or ""))
    set_setting(db, "smtp_from", str(form.get("smtp_from") or ""))
    set_setting(db, "smtp_to", str(form.get("smtp_to") or ""))
    set_setting(db, "smtp_tls", "smtp_tls" in form)
    password = str(form.get("smtp_password") or "")
    if password:
        set_setting(db, "smtp_password", password)
    return _retour("Courriel enregistré.")


@router.post("/parametres/glpi-test", response_class=HTMLResponse)
async def tester_glpi(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    await enforce_csrf(request, db)
    require_user(request, db, "admin")
    from app.glpi.errors import GlpiError
    from app.glpi.service import connection_report

    try:
        report = connection_report(request.app.state.settings)
    except GlpiError as exc:
        return HTMLResponse(f'<p class="alert">{exc.message}</p>')
    mode = "démo" if report["mode"] == "demo" else "GLPI"
    return HTMLResponse(
        f'<p class="ok">Connexion {mode} : {report["ordinateurs"]} ordinateurs, {report["agents"]} agents.</p>'
    )


def _progress(db: Session) -> dict:
    from app.models.sources import SourceRun

    run = db.scalar(select(SourceRun).where(SourceRun.source == "toutes").order_by(SourceRun.id.desc()))
    if run is None:
        return {"texte": "Aucune collecte de sources pour le moment.", "en_cours": False}
    running = run.status == "running" and run.finished_at is None
    return {
        "texte": f"{run.message} ({run.progress_current}/{run.progress_total})",
        "en_cours": running,
    }


@router.get("/exports/excel")
def export_excel(request: Request, db: Session = Depends(get_db)) -> Response:
    require_user(request, db)
    from app.exports.excel import build_workbook

    payload = build_workbook(db, request.app.state.settings)
    return Response(
        content=payload,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="plan-maj.xlsx"'},
    )


@router.get("/exports/pdf")
def export_pdf(request: Request, db: Session = Depends(get_db)) -> Response:
    require_user(request, db)
    from app.exports.pdf import build_pdf

    payload = build_pdf(db, request.app.state.settings)
    return Response(
        content=payload,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="plan-maj.pdf"'},
    )


def _retour(message: str) -> RedirectResponse:
    from urllib.parse import quote

    return RedirectResponse(f"/parametres?message={quote(message)}", status_code=303)
