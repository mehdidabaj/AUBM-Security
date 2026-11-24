from __future__ import annotations

from difflib import get_close_matches

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.actions import SoftwareMapping
from app.sources.catalog import PRODUCTS, match_key, match_name


def seed_mappings(db: Session) -> int:
    db.info.pop("slug_index", None)
    seen = set(db.scalars(select(SoftwareMapping.glpi_name)))
    created = 0
    for product in PRODUCTS.values():
        for alias in (product.label, *product.aliases):
            key = match_key(alias)
            if not key or key in seen:
                continue
            seen.add(key)
            db.add(SoftwareMapping(glpi_name=key, product_slug=product.slug, manual=0))
            created += 1
    if created:
        db.commit()
    return created


def resolve_slug(db: Session, name: str) -> str | None:
    key = match_key(name)
    if not key:
        return None
    index = db.info.get("slug_index")
    if index is None:
        index = {row.glpi_name: row.product_slug for row in db.scalars(select(SoftwareMapping))}
        db.info["slug_index"] = index
    if key in index:
        return index[key]
    product = match_name(name)
    return product.slug if product is not None else None


def suggest_slug(name: str) -> str | None:
    choices: dict[str, str] = {}
    for product in PRODUCTS.values():
        choices[match_key(product.label)] = product.slug
        for alias in product.aliases:
            choices[match_key(alias)] = product.slug
    found = get_close_matches(match_key(name), list(choices), n=1, cutoff=0.72)
    if not found:
        return None
    return choices[found[0]]


def set_mapping(db: Session, name: str, product_slug: str) -> SoftwareMapping:
    if product_slug not in PRODUCTS:
        raise ValueError("Produit de référence inconnu.")
    key = match_key(name)
    row = db.scalar(select(SoftwareMapping).where(SoftwareMapping.glpi_name == key))
    if row is None:
        row = SoftwareMapping(glpi_name=key, product_slug=product_slug, manual=1)
        db.add(row)
    else:
        row.product_slug = product_slug
        row.manual = 1
    db.info.pop("slug_index", None)
    db.commit()
    return row


def unmatched_names(db: Session, names: list[str]) -> list[dict[str, str | None]]:
    rows = []
    seen: set[str] = set()
    for name in names:
        key = match_key(name)
        if not key or key in seen or resolve_slug(db, name):
            continue
        seen.add(key)
        suggestion = suggest_slug(name)
        rows.append(
            {
                "nom": name.strip(),
                "suggestion": suggestion,
                "suggestion_libelle": PRODUCTS[suggestion].label if suggestion else None,
            }
        )
    return rows
