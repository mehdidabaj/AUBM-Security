from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler

from app.glpi.service import run_verification

logger = logging.getLogger(__name__)


def start_scheduler(app) -> BackgroundScheduler:
    """Collecte des sources à 2 h, puis vérification du parc."""
    scheduler = BackgroundScheduler(timezone="Europe/Paris")

    def nightly() -> None:
        db = app.state.SessionLocal()
        try:
            from app.sources.service import update_sources

            update_sources(db, app.state.settings)
            run_verification(db, app.state.settings)
        except Exception:
            logger.exception("La collecte planifiée a échoué")
        finally:
            db.close()

    hour, minute = _schedule(app)
    scheduler.add_job(nightly, "cron", hour=hour, minute=minute, id="nuit", replace_existing=True)
    scheduler.start()
    app.state.scheduler = scheduler
    return scheduler


def _schedule(app) -> tuple[int, int]:
    from app.settings_store import get_setting

    db = app.state.SessionLocal()
    try:
        return int(get_setting(db, "schedule_hour", 2)), int(get_setting(db, "schedule_minute", 0))
    except Exception:
        return 2, 0
    finally:
        db.close()
