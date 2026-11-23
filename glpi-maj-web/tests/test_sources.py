from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import httpx

from app.sources.cache import get_cache, payload_of, put_cache, source_overview, version_target
from app.sources.limiter import RateLimiter
from app.sources.parsers import parse_certfr, parse_feed, parse_msrc
from app.sources.service import _nvd_get, load_fallback_if_needed, update_sources
from app.sources.winget import parse_manifests, winget_commands
from app.timeutils import utcnow

FIXTURES = Path(__file__).parent / "fixtures" / "sources"
NOW = datetime(2026, 11, 19, 3, 0, 0)


class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.t += seconds


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_commandes_winget_et_version_la_plus_haute(tmp_path):
    dest = tmp_path / "winget"
    commands = winget_commands(dest, ["Google.Chrome", "Notepad++.Notepad++"], cloned=False)
    assert commands[0][:6] == ["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse"]
    assert "https://github.com/microsoft/winget-pkgs.git" in commands[0]
    assert "manifests/g/Google" in commands[1]
    assert "manifests/n/Notepad++" in commands[1]
    assert commands[2][-2:] == ["pull", "--ff-only"]

    chrome = dest / "manifests" / "g" / "Google"
    chrome.mkdir(parents=True)
    (chrome / "old.yaml").write_text("PackageIdentifier: Google.Chrome\nPackageVersion: 157.0.0.0\n", encoding="utf-8")
    (chrome / "new.yaml").write_text("PackageIdentifier: Google.Chrome\nPackageVersion: 158.0.0.0\n", encoding="utf-8")
    (chrome / "edge.yaml").write_text("PackageIdentifier: Microsoft.Edge\nPackageVersion: 9.0.0.0\n", encoding="utf-8")
    found = parse_manifests(dest, {"Google.Chrome"})
    assert found == {"Google.Chrome": "158.0.0.0"}


def test_analyse_msrc_endoflife_et_flux():
    parsed = parse_msrc(json.loads(_read("msrc_cvrf.json")))
    assert parsed["windows"]["26H2"] == "26300.9974"
    assert parsed["windows"]["25H2"] == "26200.9974"
    assert parsed["m365"] == "16.0.20527.20196"
    assert parsed["cves"][0]["id"] == "CVE-2026-5001"
    assert parsed["cves"][0]["cvss"] == 8.8
    entries = parse_feed(_read("chrome_feed.xml"))
    assert entries[0]["version"] == "157.0.8103.50"
    assert entries[0]["url"].endswith("stable.html")
    avis = parse_certfr(json.loads(_read("certfr_avis_chrome.json")), kind="avis")
    assert avis["alert"] is False
    assert avis["cves"] == [{"id": "CVE-2026-2857"}]
    assert avis["systems"][0]["product"] == "Chrome"
    assert avis["url"].endswith("/avis/CERTFR-2026-AVI-0001/")
    alerte = parse_certfr(json.loads(_read("certfr_alerte_chrome.json")), kind="alerte")
    assert alerte["alert"] is True
    assert alerte["url"].endswith("/alerte/CERTFR-2026-ALE-001/")


def test_reprise_nvd_apres_429():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, json={"error": "slow"})
        return httpx.Response(200, json={"vulnerabilities": []})

    clock = FakeClock()
    limiter = RateLimiter(interval=6.5, sleep=clock.sleep, clock=clock.clock)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    first = _nvd_get(client, {"cpeName": "cpe:chrome"}, "", limiter, clock.sleep)
    second = _nvd_get(client, {"cpeName": "cpe:notepad"}, "", limiter, clock.sleep)
    assert first.status_code == 200
    assert second.status_code == 200
    assert clock.sleeps == [10, 6.5]
    assert calls["n"] == 3


def test_collecte_limitee_a_linventaire_etag_et_remplacement(app, tmp_path):
    clock = FakeClock()
    seen: list[str] = []
    github_calls = {"n": 0, "etag": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        assert request.headers["user-agent"] == "glpi-maj-web/1.0"
        url = str(request.url)
        if "api.github.com" in url:
            github_calls["n"] += 1
            assert request.headers["authorization"] == "Bearer gh-token"
            if request.headers.get("if-none-match") == "abc":
                github_calls["etag"] += 1
                return httpx.Response(304, headers={"ETag": "abc"})
            return httpx.Response(200, json=json.loads(_read("github_notepad.json")), headers={"ETag": "abc"})
        if "services.nvd.nist.gov" in url:
            assert request.headers["apikey"] == "nvd-key"
            cpe = request.url.params["cpeName"]
            if "chrome" in cpe:
                return httpx.Response(200, json=json.loads(_read("nvd_chrome.json")))
            if "notepad" in cpe:
                return httpx.Response(200, json=json.loads(_read("nvd_notepad.json")))
        if url.startswith("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"):
            return httpx.Response(200, json=json.loads(_read("kev.json")))
        if url.rstrip("/").endswith("/avis/json"):
            return httpx.Response(200, json=json.loads(_read("certfr_avis_index.json")))
        if url.rstrip("/").endswith("/alerte/json"):
            return httpx.Response(200, json=json.loads(_read("certfr_alerte_index.json")))
        if "CERTFR-2026-AVI-0001" in url:
            return httpx.Response(200, json=json.loads(_read("certfr_avis_chrome.json")))
        if "CERTFR-2026-ALE-001" in url:
            return httpx.Response(200, json=json.loads(_read("certfr_alerte_chrome.json")))
        if "chromereleases.googleblog.com" in url:
            return httpx.Response(200, text=_read("chrome_feed.xml"))
        return httpx.Response(500, text="inattendu " + url)

    def runner(command: list[str]) -> int:
        if command[1] == "clone":
            Path(command[-1], ".git").mkdir(parents=True)
            return 0
        if "pull" in command:
            dest = Path(command[2])
            folder = dest / "manifests" / "g" / "Google"
            folder.mkdir(parents=True, exist_ok=True)
            (folder / "chrome.yaml").write_text(
                "PackageIdentifier: Google.Chrome\nPackageVersion: 158.0.0.0\n",
                encoding="utf-8",
            )
            note = dest / "manifests" / "n" / "Notepad++"
            note.mkdir(parents=True, exist_ok=True)
            (note / "npp.yaml").write_text(
                "PackageIdentifier: Notepad++.Notepad++\nPackageVersion: 8.9.5\n",
                encoding="utf-8",
            )
        return 0

    app.state.settings.data_dir = tmp_path
    app.state.settings.github_token = "gh-token"
    app.state.settings.nvd_api_key = "nvd-key"
    db = app.state.SessionLocal()
    try:
        load_fallback_if_needed(db)
        assert payload_of(get_cache(db, "fallback", "chrome"))["version"] == "157.0.8103.50"
        assert payload_of(get_cache(db, "fallback", "java8"))["mode"] == "gt"
        assert payload_of(get_cache(db, "fallback", "office-2016"))["eol"] is True
        http = httpx.Client(transport=httpx.MockTransport(handler))
        common = dict(
            names=["Google Chrome", "Notepad++"],
            http=http,
            sleep=clock.sleep,
            clock=clock.clock,
            git_runner=runner,
        )
        first = update_sources(db, app.state.settings, now=datetime(2026, 11, 18, 3, 0, 0), **common)
        assert first.status == "success", first.message
        assert clock.sleeps == [0.6]
        assert version_target(db, "chrome")["version"] == "158.0.0.0"
        assert version_target(db, "chrome")["source"] == "winget"
        assert payload_of(get_cache(db, "github", "notepadpp"))["version"] == "8.9.7"
        assert payload_of(get_cache(db, "nvd", "chrome"))["cves"][0]["cvss"] == 9.1
        assert "CVE-2026-1000" in payload_of(get_cache(db, "kev", "catalog"))["cves"]
        certfr = payload_of(get_cache(db, "certfr", "catalog"))["cves"]
        assert certfr["CVE-2026-2857"]["products"] == ["chrome"]
        assert certfr["CVE-2026-2857"]["alert"] is False
        assert certfr["CVE-2026-9999"]["alert"] is True
        assert not any("CERTFR-2024" in url or "AVI-0002" in url for url in seen)
        assert not any("firefox" in url or "api.msrc" in url or "endoflife" in url for url in seen)

        update_sources(db, app.state.settings, now=NOW, **common)
        assert github_calls["etag"] == 1
        assert github_calls["n"] == 2
        before = github_calls["n"]
        update_sources(db, app.state.settings, now=NOW, **common)
        assert github_calls["n"] == before
    finally:
        db.close()


def test_echec_conserve_les_donnees_et_alerte_au_dela_de_trois_jours(app):
    db = app.state.SessionLocal()
    try:
        put_cache(db, "winget", "chrome", {"version": "157.0.8103.50"}, origin="live", now=NOW - timedelta(days=1))
        app.state.settings.data_dir = Path(app.state.settings.data_dir)

        def runner(_command: list[str]) -> int:
            return 1

        from app.settings_store import set_setting

        set_setting(db, "sources_enabled", {key: key == "winget" for key in ("winget", "github", "endoflife", "msrc", "nvd", "kev", "feeds")})
        run = update_sources(
            db,
            app.state.settings,
            names=["Google Chrome"],
            git_runner=runner,
            sleep=lambda _seconds: None,
            now=NOW,
        )
        assert run.status == "error"
        assert payload_of(get_cache(db, "winget", "chrome"))["version"] == "157.0.8103.50"
        assert get_cache(db, "winget", "chrome").last_error
        states = {row["source"]: row["etat"] for row in source_overview(db, NOW)}
        assert states["winget"] == "conserve"

        row = get_cache(db, "winget", "chrome")
        row.checked_at = NOW - timedelta(days=4)
        db.commit()
        states = {item["source"]: item["etat"] for item in source_overview(db, NOW)}
        assert states["winget"] == "alerte"
    finally:
        db.close()


def test_msrc_et_endoflife_pour_les_produits_presents(app):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/cvrf/v3.0/updates"):
            return httpx.Response(200, json=json.loads(_read("msrc_updates.json")))
        if url.endswith("/cvrf/2026-Nov"):
            return httpx.Response(200, json=json.loads(_read("msrc_cvrf.json")))
        if url.endswith("/api/windows.json"):
            return httpx.Response(200, json=json.loads(_read("endoflife_windows.json")))
        if url.endswith("/api/office.json"):
            return httpx.Response(200, json=json.loads(_read("endoflife_office.json")))
        if "services.nvd.nist.gov" in url or "known_exploited" in url:
            if "known_exploited" in url:
                return httpx.Response(200, json=json.loads(_read("kev.json")))
            return httpx.Response(200, json={"vulnerabilities": []})
        if "github.com" in url:
            return httpx.Response(500, text=url)
        return httpx.Response(500, text="inattendu " + url)

    db = app.state.SessionLocal()
    try:
        from app.settings_store import set_setting

        set_setting(
            db,
            "sources_enabled",
            {"winget": False, "github": False, "endoflife": True, "msrc": True, "nvd": True, "kev": True, "feeds": False},
        )
        http = httpx.Client(transport=httpx.MockTransport(handler))
        run = update_sources(
            db,
            app.state.settings,
            names=["Windows 11", "Windows 10", "Microsoft 365 Apps", "Office 2016"],
            http=http,
            sleep=lambda _seconds: None,
            now=NOW,
        )
        assert run.status == "success", run.message
        assert payload_of(get_cache(db, "msrc", "windows-26h2"))["version"] == "26300.9974"
        assert payload_of(get_cache(db, "msrc", "m365"))["version"] == "16.0.20527.20196"
        assert payload_of(get_cache(db, "endoflife", "windows-10"))["eol"] is True
        assert payload_of(get_cache(db, "endoflife", "windows-11"))["eol"] is False
        assert payload_of(get_cache(db, "endoflife", "office-2016"))["eol"] is True
        assert get_cache(db, "nvd", "chrome") is None
    finally:
        db.close()


def test_plancher_strict_tant_que_la_version_publiee_ne_le_depasse_pas(app):
    db = app.state.SessionLocal()
    try:
        load_fallback_if_needed(db)
        put_cache(db, "winget", "reader", {"version": "26.002.21900", "mode": "ge"}, origin="live", now=NOW)
        target = version_target(db, "reader")
        assert target is not None
        assert target["source"] == "fallback"
        assert target["mode"] == "gt"
        put_cache(db, "winget", "reader", {"version": "26.003.1", "mode": "ge"}, origin="live", now=NOW)
        target = version_target(db, "reader")
        assert target["source"] == "winget"
        assert target["version"] == "26.003.1"
        assert version_target(db, "java8")["version"] == "8u511"
    finally:
        db.close()


def test_referentiel_de_secours_si_aucune_collecte(app):
    db = app.state.SessionLocal()
    try:
        load_fallback_if_needed(db)
        states = {row["source"]: row["etat"] for row in source_overview(db, utcnow())}
        assert states["winget"] == "secours"
        assert states["nvd"] == "secours"
    finally:
        db.close()
