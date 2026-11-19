from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app.models import AppSetting


def get_setting(db: Session, key: str, default: Any = None) -> Any:
    row = db.get(AppSetting, key)
    if row is None:
        return default
    return json.loads(row.value)


def set_setting(db: Session, key: str, value: Any) -> None:
    payload = json.dumps(value, ensure_ascii=False)
    row = db.get(AppSetting, key)
    if row is None:
        db.add(AppSetting(key=key, value=payload))
    else:
        row.value = payload
    db.commit()
