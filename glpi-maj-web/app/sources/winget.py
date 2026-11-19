from __future__ import annotations

import re
from pathlib import Path

from app.actions.versions import highest_version
from app.sources.catalog import WINGET_REPO

_IDENTIFIER = re.compile(r"^PackageIdentifier:\s*(\S+)\s*$", re.MULTILINE)
_VERSION = re.compile(r"^PackageVersion:\s*(\S+)\s*$", re.MULTILINE)


def sparse_path(package_id: str) -> str:
    publisher = package_id.split(".", 1)[0]
    return f"manifests/{publisher[0].lower()}/{publisher}"


def winget_commands(dest: Path, package_ids: list[str], cloned: bool) -> list[list[str]]:
    paths = sorted({sparse_path(package_id) for package_id in package_ids})
    commands: list[list[str]] = []
    if not cloned:
        commands.append(
            ["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", WINGET_REPO, str(dest)]
        )
    commands.append(["git", "-C", str(dest), "sparse-checkout", "set", "--no-cone", *paths])
    commands.append(["git", "-C", str(dest), "pull", "--ff-only"])
    return commands


def parse_manifests(root: Path, package_ids: set[str]) -> dict[str, str]:
    found: dict[str, list[str]] = {package_id: [] for package_id in package_ids}
    if not root.exists():
        return {}
    for path in root.rglob("*.yaml"):
        text = path.read_text(encoding="utf-8", errors="replace")
        identifier = _IDENTIFIER.search(text)
        version = _VERSION.search(text)
        if not identifier or not version:
            continue
        package_id = identifier.group(1)
        if package_id in found:
            found[package_id].append(version.group(1))
    resolved = {}
    for package_id, versions in found.items():
        best = highest_version(versions)
        if best:
            resolved[package_id] = best
    return resolved


def update_winget(dest: Path, package_ids: list[str], runner) -> dict[str, str]:
    if not package_ids:
        return {}
    dest.parent.mkdir(parents=True, exist_ok=True)
    commands = winget_commands(dest, package_ids, cloned=(dest / ".git").exists())
    for command in commands:
        code = runner(command)
        if code != 0:
            raise RuntimeError("La commande git a échoué : " + " ".join(command))
    return parse_manifests(dest, set(package_ids))
