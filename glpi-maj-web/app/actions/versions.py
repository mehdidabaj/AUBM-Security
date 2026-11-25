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


def windows_patch_behind(installed: object, target: object) -> bool:
    """Vrai seulement si les deux builds ont une révision et que l'installée est plus basse.

    10.0.26300 et 0.26300 n'ont pas de révision : on ne peut pas exiger 26300.9974.
    """
    from app.glpi.normalize import canonical_windows_build

    inst = canonical_windows_build(installed)
    tgt = canonical_windows_build(target)
    if "." not in inst or "." not in tgt:
        return False
    compared = compare_versions(inst, tgt)
    return compared is not None and compared < 0


_ADOBE_FILE = re.compile(r"^\d+\.0\.0\.\d+$")
_ADOBE_TRACK = re.compile(r"^\d+\.\d{3}\.\d+$")


def adobe_file_version_hides_track(installed: object, target: object) -> bool:
    """26.0.0.1 est la version fichier Windows, pas la piste 26.003.22110.

    Même année seulement : une piste 25 reste à mettre à jour vers 26.
    """
    inst = normalize_name(installed)
    tgt = normalize_name(target)
    inst_parts = parse_version(inst)
    tgt_parts = parse_version(tgt)
    if not inst_parts or not tgt_parts or inst_parts[0] != tgt_parts[0]:
        return False
    return bool(_ADOBE_FILE.fullmatch(inst) and _ADOBE_TRACK.fullmatch(tgt))


def powershell_channel_target(
    lines: dict[str, str] | None,
    installed: str,
    floor: str | None,
    latest: str | None,
) -> str | None:
    """Dernier correctif de la ligne encore supportée.

    La dernière mineure paire est la LTS, la dernière impaire est la STS.
    7.6.10 reste à jour face à 7.7.0. Une ligne plus ancienne part vers la plus récente.
    """
    parsed = parse_version(installed)
    if not parsed or len(parsed) < 2:
        return None
    by_minor: dict[tuple[int, int], str] = {}

    def keep(version: object) -> None:
        parts = parse_version(version)
        if not parts or len(parts) < 2:
            return
        key = (parts[0], parts[1])
        current = by_minor.get(key)
        if current is None or (compare_versions(version, current) or 0) > 0:
            by_minor[key] = str(version)

    for version in (lines or {}).values():
        keep(version)
    keep(floor)
    keep(latest)
    same = {minor: version for (major, minor), version in by_minor.items() if major == parsed[0]}
    if not same:
        return str(latest) if latest else None
    supported: set[int] = set()
    evens = [minor for minor in same if minor % 2 == 0]
    odds = [minor for minor in same if minor % 2 == 1]
    if evens:
        supported.add(max(evens))
    if odds:
        supported.add(max(odds))
    if parsed[1] in supported:
        return same[parsed[1]]
    if latest and parse_version(latest):
        return str(latest)
    return same[max(same)]
