from __future__ import annotations

import html
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import OperationalError

from app.config import Settings, load_settings
from app.database import ensure_database_parent, make_engine, make_session_factory
from app.web.pages import router as pages_router
from app.web.routes import router

logger = logging.getLogger(__name__)

PACKAGE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = PACKAGE_DIR / "web" / "templates"
STATIC_DIR = PACKAGE_DIR / "web" / "static"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    ensure_database_parent(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db = app.state.SessionLocal()
        try:
            from app.actions.mapping import seed_mappings
            from app.actions.rules import ensure_rules
            from app.sources.service import enable_new_sources, load_fallback_if_needed

            load_fallback_if_needed(db)
            enable_new_sources(db)
            seed_mappings(db)
            ensure_rules(db)
            from app.glpi.service import abandon_running

            abandon_running(db)
            if settings.demo_active:
                from app.demo.loader import seed_demo_if_needed

                seed_demo_if_needed(db)
        except OperationalError:
            logger.warning("Base non initialisée : démarrage sans données de référence.")
        finally:
            db.close()
        scheduler = None
        if settings.scheduler_enabled:
            try:
                from app.scheduler import start_scheduler

                scheduler = start_scheduler(app)
            except Exception:
                logger.exception("Le planificateur n'a pas démarré. L'interface reste disponible.")
        yield
        if scheduler is not None:
            scheduler.shutdown(wait=False)

    app = FastAPI(title="Suivi des mises à jour GLPI", lifespan=lifespan)
    app.state.settings = settings
    engine = make_engine(settings.database_url)
    app.state.engine = engine
    app.state.SessionLocal = make_session_factory(engine)
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    def paris(value: datetime | None) -> str:
        if value is None:
            return "—"
        aware = value.replace(tzinfo=timezone.utc)
        return aware.astimezone(ZoneInfo("Europe/Paris")).strftime("%d/%m/%Y %H:%M")

    templates.env.filters["paris"] = paris
    app.state.templates = templates
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(router)
    app.include_router(pages_router)

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        detail = exc.detail if isinstance(exc.detail, str) else "Erreur."
        if "application/json" in request.headers.get("accept", "") or request.url.path.startswith("/api/"):
            return JSONResponse({"detail": detail}, status_code=exc.status_code)
        accepts = request.headers.get("accept", "")
        if exc.status_code == 401 and request.method == "GET" and "application/json" not in accepts:
            return RedirectResponse("/connexion", status_code=303)
        if exc.status_code == 403 and request.method == "POST" and request.url.path == "/connexion":
            from app.web.routes import login_page

            return login_page(request, detail, status_code=403)
        return HTMLResponse(f"<p>{html.escape(detail)}</p>", status_code=exc.status_code)

    return app


app = create_app()
