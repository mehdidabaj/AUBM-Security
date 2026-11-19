from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import Settings, load_settings
from app.database import ensure_database_parent, make_engine, make_session_factory
from app.web.routes import router

PACKAGE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = PACKAGE_DIR / "web" / "templates"
STATIC_DIR = PACKAGE_DIR / "web" / "static"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    ensure_database_parent(settings)
    app = FastAPI(title="Suivi des mises à jour GLPI")
    app.state.settings = settings
    engine = make_engine(settings.database_url)
    app.state.engine = engine
    app.state.SessionLocal = make_session_factory(engine)
    app.state.templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(router)

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        detail = exc.detail if isinstance(exc.detail, str) else "Erreur."
        if "application/json" in request.headers.get("accept", "") or request.url.path.startswith("/api/"):
            return JSONResponse({"detail": detail}, status_code=exc.status_code)
        if exc.status_code == 401 and request.method == "GET":
            return JSONResponse({"detail": detail}, status_code=401)
        return HTMLResponse(f"<p>{detail}</p>", status_code=exc.status_code)

    return app


app = create_app()
