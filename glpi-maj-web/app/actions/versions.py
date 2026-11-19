from __future__ import annotations

import re

from app.glpi.normalize import normalize_name

_JAVA_UPDATE = re.compile(r"^8u(\d+)$", re.IGNORECASE)
_JAVA_LEGACY = re.compile(r"^1\.8\.0[._](\d+)$")


def parse_version(value: object) -> tuple[int, ...] | None:
    """Transforme une version en tuple numérique.

    Les formats inattendus (lettres, texte libre) donnent None.
    Java 8u511 et 1.8.0_511 deviennent (8, 0, 511).
    """
    text = normalize_name(value)
    if not text:
        return None
    if text[0] in {"v", "V"} and len(text) > 1 and text[1].isdigit():
        text = text[1:]
    java_update = _JAVA_UPDATE.fullmatch(text)
    if java_update:
        return (8, 0, int(java_update.group(1)))
    java_legacy = _JAVA_LEGACY.fullmatch(text)
    if java_legacy:
        return (8, 0, int(java_legacy.group(1)))
    if re.search(r"[A-Za-z]", text) or not re.search(r"\d", text):
        return None
    return tuple(int(part) for part in re.findall(r"\d+", text))


def compare_versions(left: object, right: object) -> int | None:
    parsed_left = parse_version(left)
    parsed_right = parse_version(right)
    if parsed_left is None or parsed_right is None:
        return None
    width = max(len(parsed_left), len(parsed_right))
    padded_left = parsed_left + (0,) * (width - len(parsed_left))
    padded_right = parsed_right + (0,) * (width - len(parsed_right))
    return (padded_left > padded_right) - (padded_left < padded_right)


def highest_version(values: list[str]) -> str | None:
    ranked = [(parse_version(value), value) for value in values]
    ranked = [(parsed, value) for parsed, value in ranked if parsed is not None]
    if not ranked:
        return None
    return max(ranked, key=lambda item: item[0] + (0,))[1]


def is_outdated(installed: object, target: object, mode: str = "ge") -> bool | None:
    compared = compare_versions(installed, target)
    if compared is None:
        return None
    if mode == "gt":
        return compared <= 0
    return compared < 0
