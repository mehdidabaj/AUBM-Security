from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import httpx

from app.sources.cache import get_cache, payload_of, put_cache, source_overview, version_target
from app.sources.limiter import RateLimiter
from app.sources.parsers import parse_certfr, parse_cve_score, parse_feed, parse_github_releases, parse_msrc, severity_name
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
    assert "manifests/g/Google/Chrome" in commands[1]
    assert "manifests/n/Notepad++/Notepad++" in commands[1]
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
    assert {item["id"] for item in alerte["cves"]} == {"CVE-2026-1000", "CVE-2026-9999"}


def test_les_bulletins_restent_listes_si_une_fiche_echoue(app):
    from app.sources.catalog import PRODUCTS
    from app.sources.service import _collect_certfr

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.rstrip("/").endswith("/avis/json"):
            return httpx.Response(200, json=json.loads(_read("certfr_avis_index.json")))
        if url.rstrip("/").endswith("/alerte/json"):
            return httpx.Response(200, json=json.loads(_read("certfr_alerte_index.json")))
        return httpx.Response(500, text="fiche indisponible")

    db = app.state.SessionLocal()
    try:
        http = httpx.Client(transport=httpx.MockTransport(handler))
        count = _collect_certfr(db, http, list(PRODUCTS.values()), lambda _seconds: None, datetime(2026, 11, 18))
        assert count == 3
        references = {row["reference"] for row in payload_of(get_cache(db, "certfr", "bulletins"))["items"]}
        assert "CERTFR-2026-AVI-0002" in references
        assert "CERTFR-2024-AVI-0001" not in references
    finally:
        db.close()


def test_collecte_certfr_remplace_le_bulletin_suivi(app):
    from sqlalchemy import select

    from app.models.history import SecurityWatch
    from app.sources.catalog import PRODUCTS
    from app.sources.service import _collect_certfr
    from app.timeutils import utcnow

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.rstrip("/").endswith("/avis/json"):
            return httpx.Response(
                200,
                json=[
                    {
                        "reference": "CERTFR-2026-AVI-0009",
                        "title": "Vulnérabilité dans Google Chrome",
                        "last_revision_date": "2026-10-01T00:00:00",
                        "json_url": "/avis/CERTFR-2026-AVI-0009/json/",
                    }
                ],
            )
        if url.rstrip("/").endswith("/alerte/json"):
            return httpx.Response(
                200,
                json=[
                    {
                        "reference": "CERTFR-2026-ALE-009",
                        "title": "Alerte dans Google Chrome",
                        "last_revision_date": "2026-11-18T00:00:00",
                        "json_url": "/alerte/CERTFR-2026-ALE-009/json/",
                    }
                ],
            )
        if url.rstrip("/").endswith("/alerte/CERTFR-2026-ALE-009/json"):
            return httpx.Response(
                200,
                json={
                    "reference": "CERTFR-2026-ALE-009",
                    "title": "Alerte dans Google Chrome",
                    "closed_at": "2026-11-20T00:00:00",
                    "cves": [],
                },
            )
        return httpx.Response(200, json={"cves": []})

    db = app.state.SessionLocal()
    try:
        db.add(
            SecurityWatch(
                subject_key="logiciel:chrome",
                label="Google Chrome",
                kind="logiciel",
                created_by="admin",
                created_at=utcnow(),
                current_reference="CERTFR-2024-AVI-0001",
                current_title="Ancienne alerte Chrome",
                current_revised="2024-01-02",
            )
        )
        db.commit()
        http = httpx.Client(transport=httpx.MockTransport(handler))
        _collect_certfr(db, http, list(PRODUCTS.values()), lambda _seconds: None, datetime(2026, 11, 18))
        watch = db.scalar(select(SecurityWatch))
        assert watch.current_reference == "CERTFR-2026-ALE-009"
        assert watch.current_closed is True
        assert watch.current_alert is True
        assert watch.current_revised == "2026-11-18"
    finally:
        db.close()


def test_certfr_ecarte_un_vieux_bulletin_et_une_autre_version():
    from datetime import datetime

    from app.sources.catalog import PRODUCTS
    from app.sources.service import _certfr_latest_rows

    products = [PRODUCTS["chrome"], PRODUCTS["windows-11"], PRODUCTS["java8"]]
    avis = [
        {
            "reference": "CERTFR-2018-AVI-0099",
            "title": "Vulnérabilité dans Google Chrome",
            "last_revision_date": "2026-11-20T00:00:00",
        },
        {
            "reference": "CERTFR-2026-AVI-0100",
            "title": "Vulnérabilité dans Google Chrome",
            "last_revision_date": "2026-06-01T00:00:00",
        },
        {
            "reference": "CERTFR-2012-AVI-0004",
            "title": "Vulnérabilité dans Windows Server 2012",
            "last_revision_date": "2026-11-18T00:00:00",
        },
        {
            "reference": "CERTFR-2026-AVI-0200",
            "title": "Multiples vulnérabilités dans Microsoft Windows",
            "last_revision_date": "2026-11-01T00:00:00",
        },
        {
            "reference": "CERTFR-2026-AVI-0300",
            "title": "Vulnérabilité dans Oracle Java SE 21",
            "last_revision_date": "2026-11-18T00:00:00",
        },
    ]
    latest = _certfr_latest_rows(avis, [], products, datetime(2026, 11, 25))
    assert latest["chrome"]["reference"] == "CERTFR-2026-AVI-0100"
    assert latest["windows-11"]["reference"] == "CERTFR-2026-AVI-0200"
    assert "java8" not in latest
    ancient = _certfr_latest_rows(avis[:1], [], products, datetime(2026, 11, 25))
    assert "chrome" not in ancient


def test_certfr_ne_retient_que_le_dernier_bulletin_de_chaque_logiciel():
    from app.sources.catalog import PRODUCTS
    from app.sources.service import _certfr_latest_rows, _newest_cve

    products = [PRODUCTS["chrome"], PRODUCTS["firefox"]]
    avis = [
        {"reference": "OLD", "title": "Vulnérabilité dans Google Chrome", "last_revision_date": "2026-01-01T00:00:00"},
        {"reference": "FF", "title": "Vulnérabilité dans Mozilla Firefox", "last_revision_date": "2026-02-01T00:00:00"},
    ]
    alertes = [
        {"reference": "NEW", "title": "Alerte dans Google Chrome", "last_revision_date": "2026-03-01T00:00:00"},
    ]
    latest = _certfr_latest_rows(avis, alertes, products)
    assert latest["chrome"]["reference"] == "NEW"
    assert latest["firefox"]["reference"] == "FF"
    kept = _newest_cve([{"id": "CVE-2026-1000"}, {"id": "CVE-2026-9999"}])
    assert kept is not None
    assert kept["id"] == "CVE-2026-9999"
    score = parse_cve_score({"containers": {"adp": [{"metrics": [{"cvssV3_1": {"baseScore": 5.4, "baseSeverity": "MEDIUM"}}]}]}})
    assert score["cvss"] == 5.4
    assert severity_name(score["cvss"], cvss_label=score["cvss_label"]) == "moyenne"
    assert severity_name(5.4, alert=True, cvss_label="MEDIUM") == "critique"


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
            assert "lastModStartDate" in request.url.params
            assert "lastModEndDate" in request.url.params
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
        if "cveawg.mitre.org/api/cve/" in url:
            return httpx.Response(
                200,
                json={
                    "containers": {
                        "adp": [{"metrics": [{"cvssV3_1": {"baseScore": 8.8, "baseSeverity": "HIGH"}}]}]
                    }
                },
            )
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
        assert clock.sleeps == []
        assert version_target(db, "chrome")["version"] == "158.0.0.0"
        assert version_target(db, "chrome")["source"] == "winget"
        assert payload_of(get_cache(db, "github", "notepadpp"))["version"] == "8.9.7"
        assert not any(
            host in url
            for url in seen
            for host in ("nvd.nist.gov", "known_exploited", "endoflife.date", "googleblog.com", "mozilla.org")
        )
        certfr = payload_of(get_cache(db, "certfr", "catalog"))["cves"]
        assert list(certfr) == ["CVE-2026-9999"]
        assert certfr["CVE-2026-9999"]["products"] == ["chrome"]
        assert certfr["CVE-2026-9999"]["alert"] is True
        assert certfr["CVE-2026-9999"]["cvss"] == 8.8
        assert certfr["CVE-2026-9999"]["severite"] == "critique"
        bulletins = {row["reference"]: row for row in payload_of(get_cache(db, "certfr", "bulletins"))["items"]}
        assert set(bulletins) == {"CERTFR-2026-ALE-001", "CERTFR-2026-AVI-0001", "CERTFR-2026-AVI-0002"}
        assert bulletins["CERTFR-2026-ALE-001"]["alert"] is True
        assert bulletins["CERTFR-2026-ALE-001"]["products"] == ["chrome"]
        assert bulletins["CERTFR-2026-AVI-0002"]["products"] == []
        assert bulletins["CERTFR-2026-AVI-0002"]["url"].endswith("/avis/CERTFR-2026-AVI-0002/")
        assert not any("CERTFR-2024" in url or "AVI-0001" in url or "AVI-0002" in url for url in seen)
        assert any("ALE-001" in url for url in seen)
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
    msrc_calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "api.msrc.microsoft.com" in url:
            msrc_calls["n"] += 1
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

        set_setting(db, "sources_enabled", {"winget": False, "github": False, "msrc": True, "certfr": False})
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
        assert get_cache(db, "endoflife", "windows-10") is None
        again = update_sources(
            db,
            app.state.settings,
            names=["Windows 11", "Microsoft 365 Apps"],
            http=http,
            sleep=lambda _seconds: None,
            now=NOW,
        )
        assert again.status == "success"
        assert msrc_calls["n"] == 2
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


def test_un_depot_github_absent_laisse_passer_les_autres(app):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "notepad-plus-plus" in url:
            return httpx.Response(200, json=json.loads(_read("github_notepad.json")), headers={"ETag": "abc"})
        return httpx.Response(404, text=url)

    db = app.state.SessionLocal()
    try:
        from sqlalchemy import select

        from app.models.sources import SourceRun
        from app.settings_store import set_setting

        set_setting(db, "sources_enabled", {"winget": False, "github": True, "msrc": False, "certfr": False})
        http = httpx.Client(transport=httpx.MockTransport(handler))
        run = update_sources(
            db,
            app.state.settings,
            names=["Notepad++", "PowerShell 7"],
            http=http,
            sleep=lambda _seconds: None,
            now=NOW,
        )
        assert run.status == "success", run.message
        assert payload_of(get_cache(db, "github", "notepadpp"))["version"] == "8.9.7"
        github = db.scalar(select(SourceRun).where(SourceRun.source == "github"))
        assert github is not None
        assert github.status == "success"
        assert "Incomplet" in github.message
        assert get_cache(db, "github", "powershell").last_error
    finally:
        db.close()


def test_powershell_garde_la_ligne_lts_et_la_sts(app):
    parsed = parse_github_releases(
        [
            {"tag_name": "v7.7.0-rc.1", "prerelease": True, "html_url": "https://github.com/rc"},
            {"tag_name": "v7.7.0", "prerelease": False, "html_url": "https://github.com/77"},
            {"tag_name": "v7.6.10", "prerelease": False, "html_url": "https://github.com/76"},
            {"tag_name": "v7.6.9", "prerelease": False, "html_url": "https://github.com/769"},
        ]
    )
    assert parsed["version"] == "7.7.0"
    assert parsed["lines"] == {"7.6": "7.6.10", "7.7": "7.7.0"}
    db = app.state.SessionLocal()
    try:
        load_fallback_if_needed(db)
        put_cache(db, "github", "powershell", parsed, origin="live")
        assert version_target(db, "powershell", "7.6.10.0")["version"] == "7.6.10"
        assert version_target(db, "powershell", "7.5.4")["version"] == "7.7.0"
    finally:
        db.close()


def test_referentiel_de_secours_si_aucune_collecte(app):
    db = app.state.SessionLocal()
    try:
        load_fallback_if_needed(db)
        states = {row["source"]: row["etat"] for row in source_overview(db, utcnow())}
        assert states["winget"] == "secours"
        assert states["certfr"] == "secours"
        assert "nvd" not in states
        assert "endoflife" not in states
        assert "kev" not in states
        assert "feeds" not in states
    finally:
        db.close()
