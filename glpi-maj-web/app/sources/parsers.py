from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime

from app.actions.versions import highest_version, parse_version

_VERSION_TOKEN = re.compile(r"\d+(?:\.\d+){1,3}")
_BUILD = re.compile(r"(?:10\.0\.)?(\d{4,5}\.\d+)")
_M365 = re.compile(r"16\.0\.\d+\.\d+")


def parse_github_release(payload: dict) -> dict:
    tag = str(payload.get("tag_name") or "")
    version = tag[1:] if tag[:1] in {"v", "V"} else tag
    return {
        "version": version,
        "url": payload.get("html_url") or "",
        "published": payload.get("published_at") or "",
    }


def parse_endoflife(payload: list, today: datetime) -> list[dict]:
    cycles = []
    for row in payload:
        raw_eol = row.get("eol")
        eol_date = raw_eol if isinstance(raw_eol, str) and raw_eol not in {"false", ""} else None
        if raw_eol is True or raw_eol == "true":
            ended = True
        elif eol_date:
            ended = eol_date <= today.date().isoformat()
        else:
            ended = False
        cycles.append(
            {
                "cycle": str(row.get("cycle") or ""),
                "eol": ended,
                "eol_date": eol_date,
                "latest": row.get("latest") or "",
            }
        )
    return cycles


def parse_msrc(document: dict) -> dict:
    names = {}
    tree = document.get("ProductTree") or {}
    products = tree.get("FullProductName") or []
    if isinstance(products, dict):
        products = [products]
    for product in products:
        names[str(product.get("ProductID"))] = str(product.get("Value") or "")
    windows: dict[str, str] = {}
    m365 = None
    cves = []
    for vulnerability in document.get("Vulnerability") or []:
        cve_id = vulnerability.get("CVE") or ""
        scores = [
            score.get("BaseScore")
            for score in (vulnerability.get("CVSSScoreSets") or [])
            if score.get("BaseScore") is not None
        ]
        score = max(scores) if scores else None
        url = ""
        for remediation in vulnerability.get("Remediations") or []:
            url = url or _text(remediation.get("URL"))
            description = _text(remediation.get("Description"))
            product_ids = remediation.get("ProductID") or []
            if isinstance(product_ids, str):
                product_ids = [product_ids]
            for product_id in product_ids:
                feature, kind = _classify_product(names.get(str(product_id), ""))
                if kind == "windows" and feature:
                    build = _highest_build(description)
                    if build:
                        current = windows.get(feature)
                        if current is None or _prefer(build, current):
                            windows[feature] = build
                if kind == "m365":
                    found = _M365.search(description)
                    if found and (m365 is None or _prefer(found.group(0), m365)):
                        m365 = found.group(0)
        if not windows or not m365:
            notes = " ".join(_text(note.get("Value")) for note in (vulnerability.get("Notes") or []))
            if not m365:
                found = _M365.search(notes)
                if found:
                    m365 = found.group(0)
        if cve_id:
            cves.append({"id": cve_id, "cvss": score, "url": url or f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}"})
    tracking = (document.get("DocumentTracking") or {}).get("Identification") or {}
    return {
        "release_id": tracking.get("ID") or document.get("DocumentTitle") or "",
        "title": _text(document.get("DocumentTitle")),
        "windows": windows,
        "m365": m365,
        "cves": cves,
    }


def parse_nvd(payload: dict) -> list[dict]:
    found = []
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        score = None
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            values = metrics.get(key) or []
            if values:
                score = (values[0].get("cvssData") or {}).get("baseScore")
                break
        summary = ""
        for description in cve.get("descriptions") or []:
            if description.get("lang") == "en":
                summary = description.get("value") or ""
                break
        cve_id = cve.get("id")
        if not cve_id:
            continue
        found.append(
            {
                "id": cve_id,
                "cvss": score,
                "summary": summary,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
        )
    return found


def parse_kev(payload: dict) -> dict:
    cves = {}
    for row in payload.get("vulnerabilities") or []:
        cve_id = row.get("cveID")
        if not cve_id:
            continue
        cves[cve_id] = {
            "id": cve_id,
            "vendor": row.get("vendorProject") or "",
            "product": row.get("product") or "",
            "name": row.get("vulnerabilityName") or "",
            "date_added": row.get("dateAdded") or "",
            "description": row.get("shortDescription") or "",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        }
    return {"catalog_version": payload.get("catalogVersion") or "", "cves": cves}


def parse_certfr(payload: dict, *, kind: str) -> dict:
    reference = str(payload.get("reference") or "").strip()
    alert = kind == "alerte" or "-ALE-" in reference
    section = "alerte" if alert else "avis"
    cves = []
    for item in payload.get("cves") or []:
        if isinstance(item, str):
            name = item
        elif isinstance(item, dict):
            name = str(item.get("name") or item.get("id") or "")
        else:
            continue
        name = name.strip().upper()
        if name.startswith("CVE-"):
            cves.append({"id": name})
    systems = []
    for system in payload.get("affected_systems") or []:
        if not isinstance(system, dict):
            continue
        product = system.get("product") if isinstance(system.get("product"), dict) else {}
        vendor = product.get("vendor") if isinstance(product.get("vendor"), dict) else {}
        systems.append(
            {
                "vendor": str(vendor.get("name") or ""),
                "product": str(product.get("name") or ""),
                "description": str(system.get("description") or ""),
            }
        )
    return {
        "reference": reference,
        "title": str(payload.get("title") or ""),
        "summary": str(payload.get("summary") or ""),
        "url": f"https://www.cert.cyber.gouv.fr/{section}/{reference}/" if reference else "",
        "alert": alert,
        "cves": cves,
        "systems": systems,
    }


def parse_feed(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    entries = []
    for node in root.iter():
        if _local(node.tag) not in {"entry", "item"}:
            continue
        title = _child_text(node, "title")
        link = _link(node)
        updated = _child_text(node, "updated") or _child_text(node, "pubDate")
        content = " ".join(
            text
            for text in (
                _child_text(node, "content"),
                _child_text(node, "summary"),
                _child_text(node, "description"),
            )
            if text
        )
        versions = _VERSION_TOKEN.findall(f"{title} {content}")
        entries.append(
            {
                "title": title,
                "url": link,
                "updated": updated,
                "version": highest_version(versions),
            }
        )
    return entries


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(node: ET.Element, name: str) -> str:
    for child in list(node):
        if _local(child.tag) == name:
            return "".join(child.itertext()).strip()
    return ""


def _link(node: ET.Element) -> str:
    for child in list(node):
        if _local(child.tag) != "link":
            continue
        href = child.attrib.get("href")
        if href:
            return href
        if child.text and child.text.strip():
            return child.text.strip()
    return ""


def _text(value) -> str:
    if isinstance(value, dict):
        return str(value.get("Value") or "")
    return str(value or "")


def _classify_product(name: str) -> tuple[str | None, str | None]:
    lowered = name.lower()
    if "365" in lowered:
        return None, "m365"
    for feature in ("26H2", "25H2", "24H2", "23H2", "22H2", "21H2"):
        if feature.lower() in lowered:
            return feature, "windows"
    return None, None


def _highest_build(text: str) -> str | None:
    found = [match.group(1) for match in _BUILD.finditer(text)]
    if not found:
        return None
    return highest_version(found)


def _prefer(candidate: str, current: str) -> bool:
    parsed_candidate = parse_version(candidate)
    parsed_current = parse_version(current)
    if parsed_candidate is None:
        return False
    if parsed_current is None:
        return True
    return parsed_candidate > parsed_current
