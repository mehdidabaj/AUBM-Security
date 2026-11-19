from __future__ import annotations

import json
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


def _client_factory(payload: dict, sink: dict, page_size: int = 2, fail_on: dict | None = None):
    resources = {
        "Computer": payload["computers"],
        "Item_OperatingSystem": payload["operating_systems"],
        "Software": payload["softwares"],
        "SoftwareVersion": payload["software_versions"],
        "Item_SoftwareVersion": payload["software_links"],
        "Agent": payload["agents"],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path.rstrip("/").rsplit("/", 1)[-1]
        sink["user_agent"] = request.headers.get("user-agent")
        if path == "initSession":
            sink["app_token"] = request.headers.get("app-token")
            sink["authorization"] = request.headers.get("authorization")
            if fail_on and fail_on.get("init"):
                return httpx.Response(400, json=fail_on["init"])
            return httpx.Response(200, json={"session_token": "sess-1"})
        if path == "killSession":
            sink["killed"] = sink.get("killed", 0) + 1
            sink["session_token"] = request.headers.get("session-token")
            return httpx.Response(200, json={"ok": True})
        if fail_on and fail_on.get("resource") == path:
            sink["pages"] = sink.get("pages", 0) + 1
            if sink["pages"] == fail_on.get("page", 1):
                return httpx.Response(403, json=fail_on["body"])
        rows = resources[path]
        start_text, end_text = request.url.params["range"].split("-")
        start, end = int(start_text), int(end_text)
        chunk = rows[start : end + 1]
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
    assert any(label == "ordinateurs" and read == 3 and total == 3 for _, _, label, read, total in seen)
    assert any(label == "agents" for _, _, label, _, _ in seen)


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
