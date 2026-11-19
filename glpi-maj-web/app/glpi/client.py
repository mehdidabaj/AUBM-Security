from __future__ import annotations

import json
import re
from collections import defaultdict

import httpx

from app.config import Settings
from app.glpi.errors import MESSAGES, GlpiError
from app.glpi.normalize import extract_build, label, normalize_name, parse_glpi_datetime
from app.glpi.types import AgentItem, ComputerItem, SoftwareItem

USER_AGENT = "glpi-maj-web/1.0"
_RANGE = re.compile(r"(\d+)-(\d+)/(\d+|\*)")


class GlpiClient:
    """Client REST GLPI : initSession, pagination, killSession."""

    def __init__(
        self,
        settings: Settings,
        http: httpx.Client | None = None,
        page_size: int = 50,
    ):
        self.settings = settings
        self.page_size = page_size
        self.session_token: str | None = None
        self._owns_client = http is None
        self.http = http or httpx.Client(timeout=httpx.Timeout(30.0))

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

    def list_agents(self, on_page=None) -> list[dict]:
        return self._paginate("Agent", on_page=on_page)

    def collect(self, on_progress=None) -> list[ComputerItem]:
        steps = (
            ("ordinateurs", self.list_computers),
            ("systèmes", self.list_operating_systems),
            ("logiciels", self.list_softwares),
            ("versions", self.list_software_versions),
            ("installations", self.list_software_links),
            ("agents", self.list_agents),
        )
        loaded = []
        total_steps = len(steps)
        for index, (label, method) in enumerate(steps):
            if on_progress:
                on_progress(index, total_steps, label, 0, None, [])

            def on_page(read, total, chunk=None, index=index, label=label):
                if on_progress:
                    on_progress(index, total_steps, label, read, total, chunk or [])

            loaded.append(method(on_page=on_page))
        return assemble(*loaded)

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
            start += self.page_size
            if total is not None and start >= total:
                break
            if len(chunk) < self.page_size:
                break
        return rows

    def _request(self, method: str, resource: str, params: dict | None = None) -> httpx.Response:
        headers = {"User-Agent": USER_AGENT, "App-Token": self.settings.glpi_app_token}
        if self.session_token:
            headers["Session-Token"] = self.session_token
        return self.http.request(method, f"{self.base}/{resource}", params=params, headers=headers)

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
    agents: list[dict],
) -> list[ComputerItem]:
    software_by_id = {int(row["id"]): row for row in softwares if "id" in row}
    version_by_id = {int(row["id"]): row for row in versions if "id" in row}
    os_by_item: dict[int, dict] = {}
    for row in operating_systems:
        if row.get("itemtype") not in (None, "", "Computer"):
            continue
        os_by_item.setdefault(int(row["items_id"]), row)
    links_by_item: dict[int, list] = defaultdict(list)
    for row in links:
        if row.get("itemtype") not in (None, "", "Computer"):
            continue
        links_by_item[int(row["items_id"])].append(row.get("softwareversions_id"))
    agent_by_item: dict[int, dict] = {}
    for row in agents:
        if row.get("itemtype") not in (None, "", "Computer"):
            continue
        agent_by_item[int(row["items_id"])] = row

    collected: list[ComputerItem] = []
    for raw in computers:
        glpi_id = int(raw["id"])
        system = os_by_item.get(glpi_id, {})
        software: list[SoftwareItem] = []
        for version_ref in links_by_item.get(glpi_id, []):
            item = _software_item(version_ref, version_by_id, software_by_id)
            if item and item.name:
                software.append(item)
        agent_raw = agent_by_item.get(glpi_id)
        agent = None
        if agent_raw is not None:
            agent = AgentItem(
                glpi_id=int(agent_raw["id"]) if agent_raw.get("id") is not None else None,
                last_contact=parse_glpi_datetime(agent_raw.get("last_contact")),
                version=normalize_name(agent_raw.get("version")),
                itemtype=normalize_name(agent_raw.get("itemtype") or "Agent") or "Agent",
            )
        collected.append(
            ComputerItem(
                glpi_id=glpi_id,
                name=normalize_name(raw.get("name")),
                group_name=label(raw.get("groups_id")),
                location=label(raw.get("locations_id")),
                computer_type=label(raw.get("computertypes_id")),
                os_name=label(system.get("operatingsystems_id")),
                os_version=label(system.get("operatingsystemversions_id")),
                os_build=extract_build(system.get("operatingsystemkernelversions_id")),
                last_inventory_at=parse_glpi_datetime(raw.get("date_mod")),
                software=software,
                agent=agent,
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
