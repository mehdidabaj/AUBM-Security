from __future__ import annotations

import re

from app.sources.catalog import PRODUCTS, match_key

KIND_LABELS = {
    "ransomware": "Rançongiciel",
    "materiel": "Matériel",
    "logiciel": "Logiciel",
}

_RANSOM = re.compile(r"ran[cç]ongiciel|ransom|lockbit|cryptolocker|black ?cat|akira")
_HARDWARE_WORDS = re.compile(
    r"materiel|equipement|routeur|pare[- ]feu|firewall|commutateur|firmware|microprogramme|imprimante|onduleur|camera|nas\b"
)
_HARDWARE_FAMILIES = (
    ("fortinet", ("fortinet", "fortigate", "fortiweb", "fortios")),
    ("cisco", ("cisco",)),
    ("stormshield", ("stormshield",)),
    ("sophos", ("sophos",)),
    ("esxi", ("esxi", "vmware")),
    ("paloalto", ("palo alto", "paloalto")),
    ("juniper", ("juniper",)),
    ("synology", ("synology",)),
    ("qnap", ("qnap",)),
    ("mikrotik", ("mikrotik",)),
    ("checkpoint", ("checkpoint", "check point")),
)


def bulletin_kind(title: str) -> str:
    """Classe un avis : rançongiciel, matériel, ou logiciel."""
    key = match_key(title)
    if _RANSOM.search(key):
        return "ransomware"
    if hardware_families(title) or _HARDWARE_WORDS.search(key):
        return "materiel"
    return "logiciel"


def hardware_families(title: str) -> list[str]:
    key = match_key(title)
    return [name for name, tokens in _HARDWARE_FAMILIES if any(token in key for token in tokens)]


def cited_products(title: str) -> list[str]:
    """Produits du référentiel cités nommément, installés ou non."""
    key = match_key(title)
    if not key:
        return []
    found = []
    for product in PRODUCTS.values():
        if any(re.search(rf"(?<![\w+]){re.escape(alias)}(?![\w+])", key) for alias in product.aliases):
            found.append(product.slug)
    found.sort(key=lambda slug: PRODUCTS[slug].label.lower())
    return found


def watch_subjects(title: str) -> list[tuple[str, str, str]]:
    """Sujets à suivre pour ce bulletin : clé, libellé, type."""
    kind = bulletin_kind(title)
    if kind == "ransomware":
        return [("ransomware", "Rançongiciel", "ransomware")]
    products = cited_products(title)
    if products:
        return [(f"logiciel:{slug}", PRODUCTS[slug].label, "logiciel") for slug in products]
    families = hardware_families(title)
    if families:
        return [(f"materiel:{name}", name, "materiel") for name in families]
    if kind == "materiel":
        label = _after_dans(title) or "Matériel"
        return [(f"materiel:{match_key(label)[:80]}", label, "materiel")]
    label = _after_dans(title) or title.strip() or "Avis"
    return [(f"sujet:{match_key(label)[:80]}", label, "logiciel")]


def _after_dans(title: str) -> str:
    match = re.search(r"\bdans (?:les |le |la |l')?(.+)$", title, flags=re.IGNORECASE)
    if not match:
        return ""
    return match.group(1).strip(" .")
