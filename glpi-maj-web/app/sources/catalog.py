from __future__ import annotations

import re
from dataclasses import dataclass

from app.glpi.normalize import normalize_name

USER_AGENT = "glpi-maj-web/1.0"
WINGET_REPO = "https://github.com/microsoft/winget-pkgs.git"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CERTFR_AVIS_URL = "https://www.cert.cyber.gouv.fr/avis/json/"
CERTFR_ALERTE_URL = "https://www.cert.cyber.gouv.fr/alerte/json/"
CERTFR_SITE = "https://www.cert.cyber.gouv.fr"
CVE_RECORD_URL = "https://cveawg.mitre.org/api/cve/{cve}"
MSRC_UPDATES = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ENDOLIFE_URL = "https://endoflife.date/api/{product}.json"
GITHUB_RELEASE = "https://api.github.com/repos/{repo}/releases/latest"
GITHUB_RELEASES = "https://api.github.com/repos/{repo}/releases?per_page=40"

FEEDS = {
    "chrome": "https://chromereleases.googleblog.com/feeds/posts/default",
    "mozilla": "https://www.mozilla.org/en-US/security/advisories/feed/",
    "adobe": "https://helpx.adobe.com/security/security-bulletin.rss",
    "eset": "https://support.eset.com/rss/advisories",
    "oracle": "https://blogs.oracle.com/security/feed",
}

SOURCE_LABELS = (
    ("winget", "Versions Windows (winget)"),
    ("github", "Logiciels libres (GitHub Releases)"),
    ("msrc", "Correctifs Microsoft (MSRC)"),
    ("certfr", "Avis de sécurité (CERT-FR)"),
)

RETIRED_SOURCES = frozenset({"endoflife", "nvd", "kev", "feeds"})


@dataclass(frozen=True)
class Product:
    slug: str
    label: str
    aliases: tuple[str, ...]
    winget_id: str | None = None
    github: str | None = None
    endoflife: str | None = None
    cpe: str | None = None
    feed: str | None = None
    version_mode: str = "ge"
    triggers_msrc: bool = False


PRODUCTS: dict[str, Product] = {
    item.slug: item
    for item in (
        Product("chrome", "Google Chrome", ("google chrome", "chrome"), "Google.Chrome", cpe="cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", feed="chrome"),
        Product("edge", "Microsoft Edge", ("microsoft edge", "edge"), "Microsoft.Edge", cpe="cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*"),
        Product("firefox", "Mozilla Firefox", ("mozilla firefox", "firefox"), "Mozilla.Firefox", cpe="cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*", feed="mozilla"),
        Product("reader", "Adobe Acrobat Reader", ("adobe acrobat reader", "acrobat reader", "adobe reader"), "Adobe.Acrobat.Reader.64-bit", cpe="cpe:2.3:a:adobe:acrobat_reader:*:*:*:*:*:*:*:*", feed="adobe", version_mode="gt"),
        Product("acrobat", "Adobe Acrobat", ("adobe acrobat",), "Adobe.Acrobat.Pro", cpe="cpe:2.3:a:adobe:acrobat:*:*:*:*:*:*:*:*", feed="adobe", version_mode="gt"),
        Product("notepadpp", "Notepad++", ("notepad++",), "Notepad++.Notepad++", "notepad-plus-plus/notepad-plus-plus", cpe="cpe:2.3:a:notepad-plus-plus:notepad_plus_plus:*:*:*:*:*:*:*:*"),
        Product("teamviewer", "TeamViewer", ("teamviewer",), "TeamViewer.TeamViewer", cpe="cpe:2.3:a:teamviewer:teamviewer:*:*:*:*:*:*:*:*"),
        Product("java8", "Java 8", ("java 8", "jre 8", "java(tm) se runtime environment 8"), "Oracle.JavaRuntimeEnvironment", endoflife="java", cpe="cpe:2.3:a:oracle:jre:*:*:*:*:*:*:*:*", version_mode="gt"),
        Product("m365", "Microsoft 365 Apps", ("microsoft 365 apps", "microsoft 365", "office 365"), "Microsoft.Office", cpe="cpe:2.3:a:microsoft:365_apps:*:*:*:*:*:*:*:*", triggers_msrc=True),
        Product("windows-11", "Windows 11", ("windows 11",), endoflife="windows", cpe="cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*", triggers_msrc=True),
        Product("windows-10", "Windows 10", ("windows 10",), endoflife="windows", cpe="cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"),
        Product("office-2013", "Office 2013", ("office 2013",), endoflife="office"),
        Product("office-2016", "Office 2016", ("office 2016",), endoflife="office"),
        Product("office-2019", "Office 2019", ("office 2019",), endoflife="office"),
        Product("office-2021", "Office 2021", ("office 2021",), endoflife="office"),
        Product("winrar", "WinRAR", ("winrar",), "RARLab.WinRAR", cpe="cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*"),
        Product("vlc", "VLC media player", ("vlc media player", "vlc"), "VideoLAN.VLC", cpe="cpe:2.3:a:videolan:vlc_media_player:*:*:*:*:*:*:*:*"),
        Product("brave", "Brave", ("brave",), "Brave.Brave", cpe="cpe:2.3:a:brave:brave:*:*:*:*:*:*:*:*"),
        Product("eset-endpoint", "ESET Endpoint Security", ("eset endpoint security",), cpe="cpe:2.3:a:eset:endpoint_security:*:*:*:*:*:*:*:*", feed="eset"),
        Product("eset-agent", "ESET Management Agent", ("eset management agent",), feed="eset"),
        Product("photoshop", "Adobe Photoshop", ("photoshop",), cpe="cpe:2.3:a:adobe:photoshop:*:*:*:*:*:*:*:*", feed="adobe", version_mode="gt"),
        Product("powershell", "PowerShell 7", ("powershell",), "Microsoft.PowerShell", "PowerShell/PowerShell", endoflife="powershell", cpe="cpe:2.3:a:microsoft:powershell:*:*:*:*:*:*:*:*"),
        Product("glpi-agent", "GLPI Agent", ("glpi agent", "glpi-agent"), "GLPI-Project.GLPI-Agent", "glpi-project/glpi-agent"),
        Product("advanced-ip", "Advanced IP Scanner", ("advanced ip scanner",)),
    )
}


def match_key(value: object) -> str:
    return normalize_name(value).lower().replace("®", "").replace("™", "")


def match_name(value: object) -> Product | None:
    key = match_key(value)
    if not key:
        return None
    best: Product | None = None
    best_length = 0
    for product in PRODUCTS.values():
        for alias in product.aliases:
            if re.search(rf"(?<![\w+]){re.escape(alias)}(?![\w+])", key):
                if len(alias) > best_length:
                    best = product
                    best_length = len(alias)
    return best


def match_products(names: list[str]) -> list[Product]:
    found: list[Product] = []
    seen: set[str] = set()
    for name in names:
        product = match_name(name)
        if product is not None and product.slug not in seen:
            seen.add(product.slug)
            found.append(product)
    return found
