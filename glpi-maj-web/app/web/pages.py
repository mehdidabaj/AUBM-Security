from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.settings_store import get_setting, set_setting
from app.sources.catalog import SOURCE_LABELS
from app.web.deps import enforce_csrf, get_db, require_user
from app.web.queries import (
    STATUS_LABELS,
    bulletin_title,
    computer_detail,
    computer_views,
    concerned_alerts,
    dashboard,
    journal,
    security_bulletins,
)
from app.web.routes import render

router = APIRouter()


def _params(request: Request) -> dict[str, str]:
    return {key: request.query_params.get(key, "") for key in ("service", "priorite", "a_jour", "logiciel", "q", "tri", "sens")}


def _live_inchange(request: Request, db: Session) -> bool:
    """Le sondage live n'a rien de nouveau à afficher."""
    if request.query_params.get("live") != "1":
        return False
    lus = request.query_params.get("lus")
    soft = request.query_params.get("soft")
    etat = request.query_params.get("etat")
    if lus is None or soft is None or etat is None:
        return False
    from app.glpi.service import inventory_counts, visible_run

    run = visible_run(db)
    courant = "cours" if run is not None and run.status == "running" else "fini"
    comptes = inventory_counts(db, run)
    return lus == str(comptes[0]) and soft == str(comptes[1]) and etat == courant


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
    from app.glpi.service import verification_view

    data = dashboard(db, request.app.state.settings)
    return render(
        request,
        "dashboard.html",
        data=data,
        chart=_chart(data),
        progression=verification_view(db, settings=request.app.state.settings),
    )


@router.get("/postes", response_class=HTMLResponse)
def postes(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    if _live_inchange(request, db):
        return Response(status_code=204)
    params = _params(request)
    view = computer_views(db, request.app.state.settings, params)
    if request.headers.get("hx-request") and request.query_params.get("live") != "1":
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


_SECURITY_LIENS = {"", "parc", "logiciel", "materiel", "ransomware", "suivis"}


@router.get("/securite", response_class=HTMLResponse)
def securite(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    lien = request.query_params.get("lien") or ""
    if lien not in _SECURITY_LIENS:
        lien = ""
    vue = security_bulletins(db, mode=lien)
    if request.query_params.get("live") == "1":
        etat = "cours" if vue["en_cours"] else "pret"
        identique = (
            request.query_params.get("n") == str(len(vue["alertes"]) + len(vue["avis"]))
            and request.query_params.get("etat") == etat
            and request.query_params.get("err") == ("1" if vue["erreur"] else "0")
        )
        if identique:
            return Response(status_code=204)
    return render(request, "securite.html", vue=vue)


@router.get("/suivis", response_class=HTMLResponse)
def suivis(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    vue = concerned_alerts(db)
    if request.query_params.get("live") == "1":
        etat = "cours" if vue["en_cours"] else "pret"
        if request.query_params.get("n") == str(len(vue["lignes"])) and request.query_params.get("etat") == etat:
            return Response(status_code=204)
    return render(request, "suivis.html", vue=vue)


@router.post("/securite/suivi")
async def suivi_securite(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    await enforce_csrf(request, db)
    user = require_user(request, db, "technicien")
    form = await request.form()
    reference = str(form.get("reference") or "").strip()
    subject = str(form.get("subject") or "").strip()
    retour = str(form.get("retour") or "")
    if retour not in _SECURITY_LIENS:
        retour = ""
    from app.watches import remove_subject, toggle_watch

    if subject:
        remove_subject(db, subject)
    else:
        title = bulletin_title(db, reference)
        if not title:
            raise HTTPException(status_code=404, detail="Bulletin introuvable.")
        toggle_watch(db, title, user.username)
    if retour == "suivis":
        target = "/suivis"
    elif retour:
        target = f"/securite?lien={retour}"
    else:
        target = "/securite"
    return RedirectResponse(target, status_code=303)


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
        historique=int(get_setting(db, "history_limit", 10) or 10),
        sources=[{"cle": key, "libelle": label, "actif": key in enabled} for key, label in SOURCE_LABELS],
        message=request.query_params.get("message", ""),
    )


@router.post("/parametres/sources")
async def sauver_sources(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    await enforce_csrf(request, db)
    require_user(request, db, "admin")
    form = await request.form()
    set_setting(db, "sources_enabled", {key: key in form for key, _label in SOURCE_LABELS})
    return _retour("Sources enregistrées.")


@router.post("/parametres/historique")
async def sauver_historique(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    await enforce_csrf(request, db)
    require_user(request, db, "admin")
    form = await request.form()
    history = min(100, max(1, int(form.get("history_limit") or 10)))
    set_setting(db, "history_limit", history)
    return _retour("Nombre de vérifications enregistré.")


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
        f'<p class="ok">Connexion {mode} : {report["ordinateurs"]} ordinateurs.</p>'
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
