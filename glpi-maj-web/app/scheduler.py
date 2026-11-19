from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler

from app.glpi.service import run_verification

logger = logging.getLogger(__name__)


def start_scheduler(app) -> BackgroundScheduler:
    """Vérification quotidienne du parc. L'étape des sources branchera la collecte devant."""
    scheduler = BackgroundScheduler(timezone="Europe/Paris")

    def verification() -> None:
        db = app.state.SessionLocal()
        try:
            run_verification(db, app.state.settings)
        except Exception:
            logger.exception("La vérification planifiée a échoué")
        finally:
            db.close()

    scheduler.add_job(verification, "cron", hour=2, minute=0, id="verification", replace_existing=True)
    scheduler.start()
    return scheduler
