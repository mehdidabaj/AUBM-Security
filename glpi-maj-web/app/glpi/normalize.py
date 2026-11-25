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
    """10.0.26300.9974 devient 26300.9974.

    Le préfixe NT 10.0 n'est pas un numéro de build : 10.0.26300 donne 26300,
    et l'ancienne lecture 0.26300 est réparée de la même façon.
    """
    if isinstance(kernel, dict):
        kernel = kernel.get("name") or kernel.get("completename") or ""
    text = normalize_name(kernel)
    if not text:
        return ""
    token = text.split()[-1]
    numbers = [int(part) for part in re.findall(r"\d+", token)]
    if len(numbers) >= 3 and numbers[0] == 10 and numbers[1] == 0 and numbers[2] >= 10240:
        if len(numbers) >= 4:
            return f"{numbers[2]}.{numbers[3]}"
        return str(numbers[2])
    if len(numbers) == 2 and numbers[0] == 0 and numbers[1] >= 10240:
        return str(numbers[1])
    if len(numbers) >= 2:
        return f"{numbers[-2]}.{numbers[-1]}"
    return token


def canonical_windows_build(value: object) -> str:
    """Build Windows canonique, ou la valeur d'origine si ce n'en est pas un."""
    raw = "" if isinstance(value, dict) else normalize_name(value)
    built = extract_build(value)
    if not built:
        return raw
    head = built.split(".", 1)[0]
    if head.isdigit() and int(head) >= 10240:
        return built
    return raw or built
