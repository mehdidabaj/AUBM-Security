from __future__ import annotations

import re
from datetime import datetime


def normalize_name(value: object) -> str:
    """Réduit espaces multiples et tabulations. Conserve la casse d'origine."""
    if value is None:
        return ""
    text = str(value).replace("\t", " ").replace("\u00a0", " ")
    return re.sub(r"\s+", " ", text).strip()


def label(value: object) -> str:
    if isinstance(value, dict):
        return normalize_name(value.get("name") or value.get("completename") or "")
    if value is None or value == 0 or value == "0":
        return ""
    return normalize_name(value)


def parse_glpi_datetime(value: object) -> datetime | None:
    text = normalize_name(value)
    if not text or text.lower() in {"null", "none"}:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text[:19], fmt)
        except ValueError:
            continue
    return None


def linked_id(value: object) -> int | None:
    """Identifiant GLPI, même quand expand_dropdowns remplace le nombre par un objet ou un nom."""
    if isinstance(value, dict):
        value = value.get("id")
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    return None


def extract_build(kernel: object) -> str:
    """10.0.26300.9974 et 26300.9974 deviennent 26300.9974."""
    if isinstance(kernel, dict):
        kernel = kernel.get("name") or kernel.get("completename") or ""
    text = normalize_name(kernel)
    if not text:
        return ""
    token = text.split()[-1]
    numbers = re.findall(r"\d+", token)
    if len(numbers) >= 2:
        return f"{numbers[-2]}.{numbers[-1]}"
    return token
