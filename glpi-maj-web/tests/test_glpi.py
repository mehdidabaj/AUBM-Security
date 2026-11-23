from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
import pytest

from app.glpi.client import GlpiClient
from app.glpi.errors import GlpiError
from app.glpi.normalize import extract_build, normalize_name
from app.glpi.service import connection_report, latest_successful, run_verification

FIXTURE = Path(__file__).parent / "fixtures" / "glpi_parc.json"


def test_normalisation_des_noms():
    assert normalize_name("Google\t\tChrome   ") == "Google Chrome"
    assert normalize_name("VLC\tmedia   player") == "VLC media player"
    assert normalize_name(None) == ""


def test_extraction_du_build_windows():
    assert extract_build("10.0.26300.9974") == "26300.9974"
    assert extract_build("26300.9974") == "26300.9974"
    assert extract_build("19045.6456") == "19045.6456"
    assert extract_build("") == ""


def _client_factory(payload: dict, sink: dict, page_size: int = 2, fail_on: dict | None = None, cap: int | None = None):
    resources = {
        "Computer": payload["computers"],
        "Item_OperatingSystem": payload["operating_systems"],
        "Software": payload["softwares"],
        "SoftwareVersion": payload["software_versions"],
        "Item_SoftwareVersion": payload["software_links"],
        "Agent": payload["agents"],
        "OperatingSystem": payload.get("OperatingSystem", []),
        "OperatingSystemVersion": payload.get("OperatingSystemVersion", []),
        "OperatingSystemKernelVersion": payload.get("OperatingSystemKernelVersion", []),
    }

    def rows_of(request: httpx.Request) -> tuple[str, list]:
        path = request.url.path.rstrip("/")
        name = path.rsplit("/", 1)[-1]
        linked = re.search(r"/Computer/(\d+)/(Item_OperatingSystem|Item_SoftwareVersion|Agent)$", path)
        if linked:
            computer_id = int(linked.group(1))
            kind = linked.group(2)
            sink.setdefault("details", []).append((computer_id, kind))
            if kind == "Item_OperatingSystem":
                sink.setdefault("os_expand", []).append(request.url.params.get("expand_dropdowns"))
            rows = [row for row in resources[kind] if int(row.get("items_id") or 0) == computer_id]
            return kind, rows
        if name == "getMultipleItems":
            grouped: dict[str, dict[str, str]] = {}
            for key, value in request.url.params.multi_items():
                match = re.match(r"items\[(\d+)\]\[(itemtype|items_id)\]", key)
                if match:
                    grouped.setdefault(match.group(1), {})[match.group(2)] = value
            kind = ""
            wanted: list[int] = []
            for item in grouped.values():
                kind = item.get("itemtype", kind)
                wanted.append(int(item["items_id"]))
            sink.setdefault("fetched", {}).setdefault(kind, []).extend(wanted)
            by_id = {int(row["id"]): row for row in resources[kind]}
            return kind, [by_id[item_id] for item_id in wanted if item_id in by_id]
        sink.setdefault("listed", []).append(name)
        return name, resources[name]

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path.rstrip("/").rsplit("/", 1)[-1]
        sink["user_agent"] = request.headers.get("user-agent")
        sink["inits"] = sink.get("inits", 0)
        if path == "initSession":
            sink["inits"] += 1
            sink["app_token"] = request.headers.get("app-token")
            sink["authorization"] = request.headers.get("authorization")
            if fail_on and fail_on.get("init"):
                return httpx.Response(400, json=fail_on["init"])
            return httpx.Response(200, json={"session_token": "sess-1"})
        if path == "killSession":
            sink["killed"] = sink.get("killed", 0) + 1
            sink["session_token"] = request.headers.get("session-token")
            return httpx.Response(200, json={"ok": True})
        if fail_on and fail_on.get("session_once") and not sink.get("session_failed"):
            sink["session_failed"] = True
            return httpx.Response(401, json=["ERROR_SESSION_TOKEN_INVALID", "expiree"])
        name, rows = rows_of(request)
        if fail_on and fail_on.get("resource") == name:
            sink["pages"] = sink.get("pages", 0) + 1
            if sink["pages"] == fail_on.get("page", 1):
                return httpx.Response(403, json=fail_on["body"])
        if name == "getMultipleItems" or path == "getMultipleItems":
            assert request.headers.get("session-token") == "sess-1"
            return httpx.Response(200, json=rows)
        start_text, end_text = request.url.params["range"].split("-")
        start, end = int(start_text), int(end_text)
        chunk = rows[start : end + 1]
        if cap:
            chunk = chunk[:cap]
        total = len(rows)
        if chunk:
            header = f"{start}-{start + len(chunk) - 1}/{total}"
        else:
            header = f"*/{total}"
        assert request.headers.get("session-token") == "sess-1"
        assert request.headers.get("app-token") == "app-token"
        return httpx.Response(200, json=chunk, headers={"Content-Range": header})

    return handler


def test_collecte_paginee_et_session(app):
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    sink: dict = {}
    app.state.settings.glpi_app_token = "app-token"
    app.state.settings.glpi_user_token = "user-token"
    http = httpx.Client(transport=httpx.MockTransport(_client_factory(payload, sink)))
    with GlpiClient(app.state.settings, http=http, page_size=2) as client:
        computers = client.collect()
    assert sink["authorization"] == "user_token user-token"
    assert sink["app_token"] == "app-token"
    assert sink["user_agent"] == "glpi-maj-web/1.0"
    assert sink["killed"] == 1
    assert sink["session_token"] == "sess-1"
    assert "SoftwareVersion" not in sink.get("listed", [])
    assert sink["fetched"]["SoftwareVersion"] == [100, 101]
    assert [computer.glpi_id for computer in computers] == [1, 2, 3]
    first = computers[0]
    assert first.name == "PC COMPTA 01"
    assert first.group_name == "Compta bilité"
    assert first.os_version == "26H2"
    assert first.os_build == "26300.9974"
    assert first.software[0].name == "Google Chrome"
    assert first.software[0].version == "157.0.8103.50"
    assert first.agent is not None and first.agent.version == "1.21"
    assert computers[1].os_name == "Windows 10"
    assert computers[1].os_build == "19045.6456"
    assert computers[1].group_name == "Ressources humaines"
    assert computers[2].software == []
    assert computers[2].agent is None
    assert sink["os_expand"] == ["true", "true", "true"]
    assert "OperatingSystem" not in sink.get("fetched", {})


def test_identifiant_de_systeme_remplace_par_son_nom(app):
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for row, system_id, version_id, kernel_id in (
        (payload["operating_systems"][0], 2, 5, 9),
        (payload["operating_systems"][1], 3, 6, 10),
        (payload["operating_systems"][2], 4, 7, 11),
    ):
        row["operatingsystems_id"] = system_id
        row["operatingsystemversions_id"] = version_id
        row["operatingsystemkernelversions_id"] = kernel_id
    payload["OperatingSystem"] = [
        {"id": 2, "name": "Windows 11"},
        {"id": 3, "name": "Windows 10"},
        {"id": 4, "name": "Windows 11"},
    ]
    payload["OperatingSystemVersion"] = [
        {"id": 5, "name": "26H2"},
        {"id": 6, "name": "22H2"},
        {"id": 7, "name": "25H2"},
    ]
    payload["OperatingSystemKernelVersion"] = [
        {"id": 9, "name": "10.0.26300.9974"},
        {"id": 10, "name": "19045.6456"},
        {"id": 11, "name": "10.0.26200.7840"},
    ]
    sink: dict = {}
    app.state.settings.glpi_app_token = "app-token"
    app.state.settings.glpi_user_token = "user-token"
    http = httpx.Client(transport=httpx.MockTransport(_client_factory(payload, sink)))
    with GlpiClient(app.state.settings, http=http, page_size=2) as client:
        computers = client.collect()
    assert [(computer.os_name, computer.os_version, computer.os_build) for computer in computers] == [
        ("Windows 11", "26H2", "26300.9974"),
        ("Windows 10", "22H2", "19045.6456"),
        ("Windows 11", "25H2", "26200.7840"),
    ]
    assert sink["fetched"]["OperatingSystem"] == [2, 3, 4]
    assert sink["fetched"]["OperatingSystemVersion"] == [5, 6, 7]
    assert sink["fetched"]["OperatingSystemKernelVersion"] == [9, 10, 11]


def test_les_versions_non_citees_ne_sont_pas_lues(app):
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["software_versions"].append({"id": 999, "name": "0.0.1", "softwares_id": 10})
    sink: dict = {}
    app.state.settings.glpi_app_token = "app-token"
    app.state.settings.glpi_user_token = "user-token"
    http = httpx.Client(transport=httpx.MockTransport(_client_factory(payload, sink, cap=1)))
    with GlpiClient(app.state.settings, http=http, page_size=500) as client:
        computers = client.collect()
    assert [computer.glpi_id for computer in computers] == [1, 2, 3]
    assert 999 not in sink["fetched"]["SoftwareVersion"]
    assert sink["fetched"]["SoftwareVersion"] == [100, 101]


def test_session_glpi_renouvelee(app):
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    sink: dict = {}
    app.state.settings.glpi_app_token = "app-token"
    app.state.settings.glpi_user_token = "user-token"
    http = httpx.Client(transport=httpx.MockTransport(_client_factory(payload, sink, fail_on={"session_once": True})))
    with GlpiClient(app.state.settings, http=http, page_size=2) as client:
        computers = client.collect()
    assert len(computers) == 3
    assert sink["inits"] == 2
    assert sink["killed"] == 1


def test_barre_ponderee_par_le_volume():
    from app.glpi.service import ProgressMeter

    meter = ProgressMeter(3)
    debut = meter.update("ordinateurs", 88, 88)
    assert debut < 50
    bloque = meter.update("versions", 0, 1000)
    assert bloque == debut
    milieu = meter.update("versions", 500, 1000)
    assert milieu > debut
    assert meter.update("versions", 1000, 1000) >= milieu


def test_pourcentage_de_collecte():
    from app.glpi.service import collection_percent

    assert collection_percent(0, 6, 0, None) == 0
    assert collection_percent(0, 6, 50, 100) == int(0.5 * (95 / 6))
    assert collection_percent(5, 6, 10, 10) == 95
    assert collection_percent(0, 6, 0, 0) == int(95 / 6)


def test_collecte_rapporte_la_progression(app):
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    app.state.settings.glpi_app_token = "app-token"
    app.state.settings.glpi_user_token = "user-token"
    seen: list[tuple] = []
    http = httpx.Client(transport=httpx.MockTransport(_client_factory(payload, {})))
    with GlpiClient(app.state.settings, http=http, page_size=2) as client:
        client.collect(on_progress=lambda *args: seen.append(args))
    assert any(item[2] == "ordinateurs" and item[3] == 3 and item[4] == 3 for item in seen)
    assert any(item[2] == "agents" for item in seen)


def test_poste_visible_avant_la_fin_de_la_collecte(app):
    from app.glpi.service import _LiveCatalog, _open_run, noter_page, verification_view

    db = app.state.SessionLocal()
    try:
        run = _open_run(db, "glpi")
        live = _LiveCatalog()
        noter_page(
            db,
            run,
            live,
            "ordinateurs",
            [{
                "id": 7,
                "name": "PC VISIBLE",
                "groups_id": "Accueil",
                "locations_id": "Hall",
                "computertypes_id": "Portable",
                "date_mod": "2026-11-19 10:00:00",
            }],
        )
        noter_page(db, run, live, "logiciels", [{"id": 3, "name": "Google Chrome", "manufacturers_id": "Google"}])
        noter_page(db, run, live, "versions", [{"id": 9, "name": "157.0", "softwares_id": 3}])
        noter_page(
            db,
            run,
            live,
            "installations",
            [{"itemtype": "Computer", "items_id": 7, "softwareversions_id": 9}],
        )
        db.commit()
        view = verification_view(db)
        assert view["en_cours"] is True
        assert view["lus"] == 1
        poste = view["postes"][0]
        assert poste["nom"] == "PC VISIBLE"
        assert poste["service"] == "Accueil"
        assert "Google Chrome" in poste["logiciels"]
    finally:
        db.close()


@pytest.mark.parametrize(
    ("body", "code", "fragment"),
    [
        (["ERROR_NOT_ALLOWED_IP", "refus"], "ERROR_NOT_ALLOWED_IP", "127.0.0.1"),
        (["ERROR_APP_TOKEN_PARAMETERS_MISSING", "manquant"], "ERROR_APP_TOKEN_PARAMETERS_MISSING", "GLPI_APP_TOKEN"),
        (["ERROR_GLPI_LOGIN_USER_TOKEN", "refus"], "ERROR_GLPI_LOGIN_USER_TOKEN", "GLPI_USER_TOKEN"),
        (["ERROR_RIGHT_MISSING", "droits"], "ERROR_RIGHT_MISSING", "Super-Admin"),
    ],
)
def test_messages_derreur_glpi(app, body, code, fragment):
    sink: dict = {"killed": 0}
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    app.state.settings.glpi_app_token = "app-token"
    app.state.settings.glpi_user_token = "user-token"
    http = httpx.Client(
        transport=httpx.MockTransport(_client_factory(payload, sink, fail_on={"init": body}))
    )
    with pytest.raises(GlpiError) as caught:
        with GlpiClient(app.state.settings, http=http) as client:
            client.collect()
    assert caught.value.code == code
    assert fragment in caught.value.message
    assert sink["killed"] == 0


def test_kill_session_meme_si_la_collecte_echoue(app):
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    sink: dict = {}
    app.state.settings.glpi_app_token = "app-token"
    app.state.settings.glpi_user_token = "user-token"
    http = httpx.Client(
        transport=httpx.MockTransport(
            _client_factory(
                payload,
                sink,
                fail_on={"resource": "Computer", "page": 2, "body": ["ERROR_NOT_ALLOWED_IP", "non"]},
            )
        )
    )
    with pytest.raises(GlpiError) as caught:
        with GlpiClient(app.state.settings, http=http, page_size=2) as client:
            client.collect()
    assert caught.value.code == "ERROR_NOT_ALLOWED_IP"
    assert sink["killed"] == 1


def test_parc_demo_vingt_postes_et_ecart(app):
    from app.demo.loader import load_catalog, seed_demo_if_needed

    catalog = load_catalog()
    assert len(catalog.current) == 20
    assert len({computer.glpi_id for computer in catalog.current}) == 20
    db = app.state.SessionLocal()
    try:
        seed_demo_if_needed(db)
        seed_demo_if_needed(db)
        run = latest_successful(db)
        assert run is not None
        assert run.computer_count == 20
        assert run.origin == "demo"
        summary = json.loads(run.summary_json)
        assert summary["postes_ajoutes"] == [19, 20]
        assert summary["postes_retires"] == [99]
        by_id = {computer.glpi_id: computer for computer in run.computers}
        assert by_id[3].group_name == "Ressources humaines"
        assert by_id[12].software[0].name == "Advanced IP Scanner"
        assert by_id[15].software[0].name == "VLC media player"
        assert len(by_id[11].software) == 2
        assert {item.version for item in by_id[14].software} == {"8.7.1", "voir site", "8.6.4"}
        runs = db.query(type(run)).count()
        assert runs == 2
    finally:
        db.close()


def test_verification_glpi_simulee_historisee(app):
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    sink: dict = {}
    app.state.settings.demo_mode = "off"
    app.state.settings.glpi_app_token = "app-token"
    app.state.settings.glpi_user_token = "user-token"
    assert app.state.settings.demo_active is False
    http = httpx.Client(transport=httpx.MockTransport(_client_factory(payload, sink)))
    db = app.state.SessionLocal()
    try:
        run = run_verification(db, app.state.settings, http=http)
        assert run.origin == "glpi"
        assert run.computer_count == 3
        assert len(run.computers) == 3
        assert run.progress_current == 100
        assert "3 postes" in run.message
        assert json.loads(run.summary_json)["postes_ajoutes"] == [1, 2, 3]
        counts = connection_report(
            app.state.settings,
            http=httpx.Client(transport=httpx.MockTransport(_client_factory(payload, {}))),
        )
        assert counts == {"mode": "glpi", "ordinateurs": 3, "agents": 2}
    finally:
        db.close()


def test_redemarrage_interrompt_la_verification_en_cours(app):
    from app.glpi.service import abandon_running
    from app.models.inventory import CheckRun
    from app.timeutils import utcnow

    db = app.state.SessionLocal()
    try:
        run = CheckRun(
            started_at=utcnow(),
            status="running",
            origin="glpi",
            computer_count=1,
            summary_json="{}",
            message="Lecture",
        )
        db.add(run)
        db.commit()
        assert abandon_running(db) == 1
        db.refresh(run)
        assert run.status == "error"
        assert "redémarrage" in run.message
    finally:
        db.close()


def test_deuxieme_collecte_ne_relit_que_les_postes_modifies(app):
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    app.state.settings.demo_mode = "off"
    app.state.settings.glpi_app_token = "app-token"
    app.state.settings.glpi_user_token = "user-token"
    db = app.state.SessionLocal()
    try:
        first = run_verification(
            db,
            app.state.settings,
            http=httpx.Client(transport=httpx.MockTransport(_client_factory(payload, {}))),
        )
        assert "repris" not in first.message
        payload["computers"][1]["date_mod"] = "2026-11-23 12:00:00"
        payload["computers"] = [row for row in payload["computers"] if row["id"] != 3]
        sink: dict = {}
        second = run_verification(
            db,
            app.state.settings,
            http=httpx.Client(transport=httpx.MockTransport(_client_factory(payload, sink))),
        )
        assert second.computer_count == 2
        assert json.loads(second.summary_json)["postes_retires"] == [3]
        assert "repris" in second.message
        relus = {computer_id for computer_id, _kind in sink.get("details", [])}
        assert relus == {2}
        by_id = {computer.glpi_id: computer for computer in second.computers}
        assert by_id[1].software[0].name == "Google Chrome"
        assert by_id[1].os_build == "26300.9974"
        assert by_id[1].agent is not None and by_id[1].agent.version == "1.21"
        assert by_id[2].software[0].name == "Microsoft Office 2016"
        by_id[1].os_name = "3"
        by_id[1].os_version = "3"
        db.commit()
        sink = {}
        third = run_verification(
            db,
            app.state.settings,
            http=httpx.Client(transport=httpx.MockTransport(_client_factory(payload, sink))),
        )
        relus = {computer_id for computer_id, _kind in sink.get("details", [])}
        assert 1 in relus
        restored = {computer.glpi_id: computer for computer in third.computers}
        assert restored[1].os_name == "Windows 11"
        assert restored[1].os_version == "26H2"
    finally:
        db.close()


def test_connexion_demo_compte_les_postes(app):
    app.state.settings.demo_mode = "on"
    counts = connection_report(app.state.settings)
    assert counts["mode"] == "demo"
    assert counts["ordinateurs"] == 20
    assert counts["agents"] == 20


def test_lancement_reserve_au_technicien(client, app):
    from app.auth.service import create_user
    from tests.conftest import csrf_from, login

    db = app.state.SessionLocal()
    try:
        create_user(db, "lecteur", "motdepasse-lecture", "lecture")
        create_user(db, "tech", "motdepasse-tech", "technicien")
    finally:
        db.close()

    login(client, "lecteur", "motdepasse-lecture")
    token = csrf_from(client.get("/").text)
    refused = client.post("/verification", headers={"X-CSRF-Token": token})
    assert refused.status_code == 403

    client.post("/deconnexion", data={"csrf_token": token}, follow_redirects=False)
    login(client, "tech", "motdepasse-tech")
    token = csrf_from(client.get("/").text)
    response = client.post("/verification", headers={"X-CSRF-Token": token})
    assert response.status_code == 200
    body = response.json()
    assert body["ordinateurs"] == 20
    assert body["resume"]["postes_ajoutes"] == []
