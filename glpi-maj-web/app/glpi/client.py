from __future__ import annotations

import json
import logging
import re
import time
from collections import defaultdict
from datetime import datetime

import httpx

from app.config import Settings
from app.glpi.errors import MESSAGES, GlpiError
from app.glpi.normalize import extract_build, label, linked_id, normalize_name, parse_glpi_datetime
from app.glpi.types import ComputerItem, SoftwareItem

logger = logging.getLogger(__name__)
USER_AGENT = "glpi-maj-web/1.0"
PAGE_SIZE = 500
VERSION_BATCH = 50
PLANNED_STEPS = 5
SESSION_ERRORS = {"ERROR_SESSION_TOKEN_INVALID", "ERROR_SESSION_TOKEN_MISSING"}
_RANGE = re.compile(r"(\d+)-(\d+)/(\d+|\*)")
_OS_DROPDOWNS = {
    "operatingsystems_id": "OperatingSystem",
    "operatingsystemversions_id": "OperatingSystemVersion",
    "operatingsystemkernelversions_id": "OperatingSystemKernelVersion",
}


class GlpiClient:
    """Client REST GLPI : initSession, pagination, killSession."""

    def __init__(
        self,
        settings: Settings,
        http: httpx.Client | None = None,
        page_size: int = PAGE_SIZE,
    ):
        self.settings = settings
        self.page_size = page_size
        self.session_token: str | None = None
        self._owns_client = http is None
        self.http = http or httpx.Client(timeout=httpx.Timeout(60.0, connect=10.0))
        self._dropdown_names: dict[tuple[str, int], str] = {}

    def __enter__(self) -> "GlpiClient":
        self.init_session()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if self.session_token:
                self.kill_session()
        finally:
            if self._owns_client:
                self.http.close()

    @property
    def base(self) -> str:
        return self.settings.glpi_url.rstrip("/")

    def init_session(self) -> str:
        response = self.http.post(
            f"{self.base}/initSession",
            headers={
                "App-Token": self.settings.glpi_app_token,
                "Authorization": f"user_token {self.settings.glpi_user_token}",
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
        )
        self._raise_for_glpi(response)
        body = _json_or_text(response)
        token = body.get("session_token") if isinstance(body, dict) else None
        if not token:
            raise GlpiError("ERROR_GLPI_LOGIN_USER_TOKEN")
        self.session_token = str(token)
        return self.session_token

    def kill_session(self) -> None:
        if not self.session_token:
            return
        try:
            response = self._request("GET", "killSession")
            self._raise_for_glpi(response)
        except GlpiError:
            pass
        finally:
            self.session_token = None

    def list_computers(self, on_page=None) -> list[dict]:
        return self._paginate("Computer", {"expand_dropdowns": "true"}, on_page=on_page)

    def list_operating_systems(self, on_page=None) -> list[dict]:
        return self._paginate("Item_OperatingSystem", {"expand_dropdowns": "true"}, on_page=on_page)

    def list_softwares(self, on_page=None) -> list[dict]:
        return self._paginate("Software", {"expand_dropdowns": "true"}, on_page=on_page)

    def list_software_versions(self, on_page=None) -> list[dict]:
        return self._paginate("SoftwareVersion", {"expand_dropdowns": "false"}, on_page=on_page)

    def list_software_links(self, on_page=None) -> list[dict]:
        return self._paginate("Item_SoftwareVersion", {"expand_dropdowns": "false"}, on_page=on_page)

    def collect(self, on_progress=None, known: dict[int, datetime | None] | None = None) -> list[ComputerItem]:
        """Lit le nom, le service, le système et les logiciels.

        La première fois, tout le parc est lu. Ensuite, seul un index (identifiant et date)
        est demandé. Le système et les logiciels ne sont relus que pour un poste nouveau
        ou modifié depuis la date déjà enregistrée.
        """

        def report(index: int, label: str, read: int, total: int | None, chunk: list | None) -> None:
            if on_progress:
                on_progress(index, PLANNED_STEPS, label, read, total, chunk or [])

        if known:
            index = self._try_index()
            if index is not None:
                self._collect_changed(index, known, report)
                return []

        named: list[dict] = []

        def on_computers(read: int, total: int | None, chunk: list) -> None:
            page = self._resolve_group_names(chunk)
            named.extend(page)
            report(0, "ordinateurs", read, total, page)

        self._paginate("Computer", {}, on_page=on_computers)
        computers = named
        os_rows: list[dict] = []
        link_rows: list[dict] = []
        unchanged, pending = _split_changes(computers, known)
        total_computers = len(computers)
        if unchanged:
            report(1, "reprise", len(unchanged), total_computers, unchanged)
        seen = len(unchanged)
        if total_computers == 0 or not pending:
            report(1, "postes", seen, total_computers, [])
        for computer in pending:
            try:
                computer_id = int(computer["id"])
            except (KeyError, TypeError, ValueError):
                continue
            seen += 1
            systems = self._subitems(
                computer_id,
                "Item_OperatingSystem",
                {"expand_dropdowns": "true"},
            )
            systems = self._resolve_os_labels(systems)
            os_rows.extend(systems)
            report(1, "systèmes", seen, total_computers, systems)
            link_rows.extend(self._subitems(computer_id, "Item_SoftwareVersion"))
            report(1, "postes", seen, total_computers, [])

        version_ids = _unique_ids(row.get("softwareversions_id") for row in link_rows)
        versions = self._fetch_many(
            "SoftwareVersion",
            version_ids,
            on_page=lambda read, total, chunk: report(2, "versions", read, total, chunk),
        )
        software_ids = _unique_ids(row.get("softwares_id") for row in versions)
        softwares = self._fetch_many(
            "Software",
            software_ids,
            on_page=lambda read, total, chunk: report(3, "logiciels", read, total, chunk),
        )
        self._report_links(link_rows, report)
        return assemble(computers, os_rows, softwares, versions, link_rows)

    def _collect_changed(self, index: list[dict], known: dict[int, datetime | None], report) -> None:
        unchanged, pending = _split_index(index, known)
        total = len(index)
        report(0, "repérage", total, total, [])
        if unchanged:
            report(1, "reprise", len(unchanged), total, [{"id": glpi_id} for glpi_id in unchanged])
        link_rows: list[dict] = []
        seen = len(unchanged)
        if not pending:
            report(1, "postes", seen, total, [])
        for glpi_id in pending:
            raw = self._resolve_group_names([self._computer(glpi_id)])[0]
            seen += 1
            report(0, "ordinateurs", seen, total, [raw])
            systems = self._resolve_os_labels(
                self._subitems(glpi_id, "Item_OperatingSystem", {"expand_dropdowns": "true"})
            )
            report(1, "systèmes", seen, total, systems)
            link_rows.extend(self._subitems(glpi_id, "Item_SoftwareVersion"))
            report(1, "postes", seen, total, [])
        version_ids = _unique_ids(row.get("softwareversions_id") for row in link_rows)
        versions = self._fetch_many(
            "SoftwareVersion",
            version_ids,
            on_page=lambda read, total_count, chunk: report(2, "versions", read, total_count, chunk),
        )
        software_ids = _unique_ids(row.get("softwares_id") for row in versions)
        self._fetch_many(
            "Software",
            software_ids,
            on_page=lambda read, total_count, chunk: report(3, "logiciels", read, total_count, chunk),
        )
        self._report_links(link_rows, report)

    def _try_index(self) -> list[dict] | None:
        try:
            found = self._search_computers()
        except (GlpiError, httpx.HTTPError, json.JSONDecodeError, ValueError, TypeError, KeyError):
            logger.warning("L'index GLPI est indisponible, la liste complète des postes sera lue.")
            return None
        return found or None

    def _search_computers(self) -> list[dict]:
        """Index léger : identifiant et date de modification, sans le système ni les logiciels."""
        rows: list[dict] = []
        start = 0
        total: int | None = None
        while True:
            params = {
                "forcedisplay[0]": "2",
                "forcedisplay[1]": "19",
                "sort": "19",
                "order": "DESC",
                "range": f"{start}-{start + self.page_size - 1}",
            }
            response = self._request("GET", "search/Computer", params=params)
            self._raise_for_glpi(response)
            body = response.json()
            if isinstance(body, dict):
                chunk = body.get("data") or []
                if body.get("totalcount") is not None:
                    total = int(body["totalcount"])
            elif isinstance(body, list):
                chunk = body
            else:
                chunk = []
            if total is None:
                total = _content_range_total(response.headers.get("Content-Range"))
            if not isinstance(chunk, list) or not chunk:
                break
            for row in chunk:
                parsed = _index_row(row)
                if parsed is not None:
                    rows.append(parsed)
            start += len(chunk)
            if total is not None and start >= total:
                break
            if total is None and len(chunk) < self.page_size:
                break
        return rows

    def _computer(self, computer_id: int) -> dict:
        response = self._request("GET", f"Computer/{computer_id}")
        self._raise_for_glpi(response)
        body = response.json()
        if isinstance(body, list):
            body = body[0] if body else {}
        if not isinstance(body, dict) or "id" not in body:
            raise GlpiError("GLPI_HTTP", f"Le poste {computer_id} est illisible.")
        return body

    def _report_links(self, link_rows: list[dict], report) -> None:
        if not link_rows:
            report(4, "installations", 0, 0, [])
            return
        written = 0
        total = len(link_rows)
        while written < total:
            chunk = link_rows[written : written + 200]
            written += len(chunk)
            report(4, "installations", written, total, chunk)

    def _subitems(self, computer_id: int, itemtype: str, params: dict | None = None) -> list[dict]:
        rows = self._paginate(f"Computer/{computer_id}/{itemtype}", params)
        kept = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            if row.get("itemtype") not in (None, "", "Computer"):
                continue
            linked = linked_id(row.get("items_id"))
            if linked is not None and linked != computer_id:
                continue
            copy = dict(row)
            copy["items_id"] = computer_id
            kept.append(copy)
        return kept

    def _resolve_group_names(self, rows: list[dict]) -> list[dict]:
        """Le service est lu à part : expand_dropdowns sur chaque poste développe tous les liens."""
        pending: set[int] = set()
        for row in rows:
            number = _bare_id(row.get("groups_id"))
            if number is not None and ("Group", number) not in self._dropdown_names:
                pending.add(number)
        if pending:
            found: dict[int, str] = {}
            for item in self._fetch_many("Group", sorted(pending)):
                try:
                    found[int(item["id"])] = label(item.get("completename") or item.get("name"))
                except (KeyError, TypeError, ValueError):
                    continue
            for number in pending:
                self._dropdown_names[("Group", number)] = found.get(number, "")
        if not any(_bare_id(row.get("groups_id")) is not None for row in rows):
            return rows
        resolved: list[dict] = []
        for row in rows:
            copy = dict(row)
            number = _bare_id(copy.get("groups_id"))
            if number is not None:
                copy["groups_id"] = self._dropdown_names.get(("Group", number), "")
            resolved.append(copy)
        return resolved

    def _resolve_os_labels(self, rows: list[dict]) -> list[dict]:
        """Remplace un identifiant nu (3) par le nom du système, de la version et du noyau.

        GLPI renvoie ces clés comme des entiers lorsque expand_dropdowns n'est pas appliqué.
        """
        pending: dict[str, set[int]] = {itemtype: set() for itemtype in _OS_DROPDOWNS.values()}
        for row in rows:
            for field, itemtype in _OS_DROPDOWNS.items():
                number = _bare_id(row.get(field))
                if number is not None and (itemtype, number) not in self._dropdown_names:
                    pending[itemtype].add(number)
        for itemtype, ids in pending.items():
            if not ids:
                continue
            found: dict[int, str] = {}
            for item in self._fetch_many(itemtype, sorted(ids)):
                try:
                    found[int(item["id"])] = label(item.get("name"))
                except (KeyError, TypeError, ValueError):
                    continue
            for number in ids:
                self._dropdown_names[(itemtype, number)] = found.get(number, "")
        if not any(_bare_id(row.get(field)) is not None for row in rows for field in _OS_DROPDOWNS):
            return rows
        resolved: list[dict] = []
        for row in rows:
            copy = dict(row)
            for field, itemtype in _OS_DROPDOWNS.items():
                number = _bare_id(copy.get(field))
                if number is not None:
                    copy[field] = self._dropdown_names.get((itemtype, number), "")
            resolved.append(copy)
        return resolved

    def _fetch_many(self, itemtype: str, ids: list[int], on_page=None) -> list[dict]:
        rows: list[dict] = []
        total = len(ids)
        if total == 0:
            if on_page is not None:
                on_page(0, 0, [])
            return rows
        for offset in range(0, total, VERSION_BATCH):
            part = ids[offset : offset + VERSION_BATCH]
            params: dict[str, str] = {"expand_dropdowns": "true"}
            for index, item_id in enumerate(part):
                params[f"items[{index}][itemtype]"] = itemtype
                params[f"items[{index}][items_id]"] = str(item_id)
            response = self._request("GET", "getMultipleItems", params=params)
            self._raise_for_glpi(response)
            chunk = response.json()
            if isinstance(chunk, dict):
                chunk = chunk.get("data") or [item for item in chunk.values() if isinstance(item, dict)]
            if not isinstance(chunk, list):
                chunk = []
            chunk = [item for item in chunk if isinstance(item, dict)]
            rows.extend(chunk)
            if on_page is not None:
                on_page(len(rows), total, chunk)
        return rows

    def _paginate(self, resource: str, params: dict | None = None, on_page=None) -> list[dict]:
        rows: list[dict] = []
        start = 0
        while True:
            query = dict(params or {})
            end = start + self.page_size - 1
            query["range"] = f"{start}-{end}"
            response = self._request("GET", resource, params=query)
            self._raise_for_glpi(response)
            chunk = response.json()
            total = _content_range_total(response.headers.get("Content-Range"))
            if isinstance(chunk, dict):
                chunk = chunk.get("data") or []
            if not isinstance(chunk, list) or not chunk:
                if on_page is not None and start == 0:
                    on_page(0, 0 if total is None else total, [])
                break
            rows.extend(chunk)
            if on_page is not None:
                on_page(len(rows), total, chunk)
            start += len(chunk)
            if total is not None and start >= total:
                break
            if total is None and len(chunk) < self.page_size:
                break
        return rows

    def _request(
        self,
        method: str,
        resource: str,
        params: dict | None = None,
        *,
        renew: bool = True,
        attempt: int = 0,
    ) -> httpx.Response:
        headers = {"User-Agent": USER_AGENT, "App-Token": self.settings.glpi_app_token}
        if self.session_token:
            headers["Session-Token"] = self.session_token
        try:
            response = self.http.request(method, f"{self.base}/{resource}", params=params, headers=headers)
        except httpx.HTTPError:
            if attempt >= 2:
                raise
            time.sleep(0.4 * (attempt + 1))
            return self._request(method, resource, params=params, renew=renew, attempt=attempt + 1)
        if response.status_code in {502, 503, 504} and attempt < 2:
            time.sleep(0.4 * (attempt + 1))
            return self._request(method, resource, params=params, renew=renew, attempt=attempt + 1)
        if renew and resource != "initSession" and _error_code(response) in SESSION_ERRORS:
            self.session_token = None
            self.init_session()
            return self._request(method, resource, params=params, renew=False)
        return response

    @staticmethod
    def _raise_for_glpi(response: httpx.Response) -> None:
        code = _error_code(response)
        if code in MESSAGES:
            raise GlpiError(code)
        if response.status_code >= 400:
            raise GlpiError("GLPI_HTTP", f"GLPI a répondu HTTP {response.status_code}.")


def _json_or_text(response: httpx.Response):
    try:
        return response.json()
    except json.JSONDecodeError:
        return response.text


def _error_code(response: httpx.Response) -> str | None:
    body = _json_or_text(response)
    blob = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
    for code in MESSAGES:
        if code in blob:
            return code
    return None


def _index_row(row: object) -> dict | None:
    if not isinstance(row, dict):
        return None
    raw_id = row.get("2", row.get("id"))
    try:
        glpi_id = int(raw_id)
    except (TypeError, ValueError):
        return None
    return {"id": glpi_id, "date_mod": row.get("19", row.get("date_mod"))}


def _split_index(index: list[dict], known: dict[int, datetime | None]) -> tuple[list[int], list[int]]:
    unchanged: list[int] = []
    pending: list[int] = []
    for row in index:
        glpi_id = int(row["id"])
        previous = known.get(glpi_id)
        current = parse_glpi_datetime(row.get("date_mod"))
        if previous is not None and current is not None and current <= previous:
            unchanged.append(glpi_id)
        else:
            pending.append(glpi_id)
    return unchanged, pending


def _split_changes(computers: list[dict], known: dict[int, datetime | None] | None) -> tuple[list[dict], list[dict]]:
    if not known:
        return [], list(computers)
    unchanged: list[dict] = []
    pending: list[dict] = []
    for computer in computers:
        try:
            glpi_id = int(computer["id"])
        except (KeyError, TypeError, ValueError):
            pending.append(computer)
            continue
        previous = known.get(glpi_id)
        current = parse_glpi_datetime(computer.get("date_mod"))
        if previous is not None and current is not None and current <= previous:
            unchanged.append(computer)
        else:
            pending.append(computer)
    return unchanged, pending


def _bare_id(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str) and value.isdigit():
        number = int(value)
        return number if number > 0 else None
    return None


def _unique_ids(values) -> list[int]:
    found: list[int] = []
    seen: set[int] = set()
    for value in values:
        if isinstance(value, dict):
            value = value.get("id")
        try:
            number = int(value)
        except (TypeError, ValueError):
            continue
        if number not in seen:
            seen.add(number)
            found.append(number)
    return found


def _content_range_total(header: str | None) -> int | None:
    if not header:
        return None
    match = _RANGE.search(header)
    if not match:
        return None
    total = match.group(3)
    if total == "*":
        return None
    return int(total)


def assemble(
    computers: list[dict],
    operating_systems: list[dict],
    softwares: list[dict],
    versions: list[dict],
    links: list[dict],
) -> list[ComputerItem]:
    software_by_id = {int(row["id"]): row for row in softwares if "id" in row}
    version_by_id = {int(row["id"]): row for row in versions if "id" in row}
    os_by_item: dict[int, dict] = {}
    for row in operating_systems:
        if row.get("itemtype") not in (None, "", "Computer"):
            continue
        item_id = linked_id(row.get("items_id"))
        if item_id is None:
            continue
        os_by_item.setdefault(item_id, row)
    links_by_item: dict[int, list] = defaultdict(list)
    for row in links:
        if row.get("itemtype") not in (None, "", "Computer"):
            continue
        item_id = linked_id(row.get("items_id"))
        if item_id is None:
            continue
        links_by_item[item_id].append(row.get("softwareversions_id"))

    collected: list[ComputerItem] = []
    for raw in computers:
        glpi_id = int(raw["id"])
        system = os_by_item.get(glpi_id, {})
        software: list[SoftwareItem] = []
        for version_ref in links_by_item.get(glpi_id, []):
            item = _software_item(version_ref, version_by_id, software_by_id)
            if item and item.name:
                software.append(item)
        collected.append(
            ComputerItem(
                glpi_id=glpi_id,
                name=normalize_name(raw.get("name")),
                group_name=label(raw.get("groups_id")),
                location="",
                computer_type="",
                os_name=label(system.get("operatingsystems_id")),
                os_version=label(system.get("operatingsystemversions_id")),
                os_build=extract_build(system.get("operatingsystemkernelversions_id")),
                last_inventory_at=parse_glpi_datetime(raw.get("date_mod")),
                software=software,
                agent=None,
            )
        )
    return collected


def _software_item(version_ref, version_by_id, software_by_id) -> SoftwareItem | None:
    if isinstance(version_ref, dict):
        version_row = version_ref
    else:
        try:
            version_row = version_by_id.get(int(version_ref))
        except (TypeError, ValueError):
            version_row = None
    if not version_row:
        return None
    version = normalize_name(version_row.get("name") or version_row.get("version"))
    soft_ref = version_row.get("softwares_id")
    publisher = ""
    if isinstance(soft_ref, dict):
        name = label(soft_ref)
    else:
        try:
            soft_id = int(soft_ref)
        except (TypeError, ValueError):
            name = label(soft_ref)
        else:
            soft = software_by_id.get(soft_id, {})
            name = normalize_name(soft.get("name"))
            publisher = label(soft.get("manufacturers_id"))
    return SoftwareItem(name=name, publisher=publisher, version=version)
