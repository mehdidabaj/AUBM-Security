from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key.strip()] = value
    return values


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on", "oui"}


def sqlite_url(path: Path) -> str:
    return "sqlite:///" + path.resolve().as_posix()


@dataclass
class Settings:
    app_port: int
    web_port: int
    secret_key: str
    database_url: str
    data_dir: Path
    glpi_url: str
    glpi_app_token: str
    glpi_user_token: str
    glpi_base_url: str
    demo_mode: str
    nvd_api_key: str
    github_token: str
    session_cookie_secure: bool
    session_hours: int
    admin_user: str
    admin_password: str

    @property
    def demo_active(self) -> bool:
        mode = (self.demo_mode or "auto").strip().lower()
        if mode in {"on", "1", "true", "oui"}:
            return True
        if mode in {"off", "0", "false", "non"}:
            return False
        return not (self.glpi_app_token.strip() and self.glpi_user_token.strip())


def load_settings(env_file: str | None = None) -> Settings:
    """Les variables d'environnement écrasent le fichier de configuration."""
    configured = env_file or os.environ.get("GLPI_MAJ_CONFIG", "/etc/glpi-maj-web/config.env")
    file_values = _load_env_file(Path(configured))

    def get(key: str, default: str = "") -> str:
        if key in os.environ:
            return os.environ[key]
        return file_values.get(key, default)

    data_dir = Path(get("DATA_DIR", "/var/lib/glpi-maj-web"))
    database_url = get("DATABASE_URL", f"sqlite:///{data_dir}/glpi-maj.db")
    return Settings(
        app_port=int(get("APP_PORT", "8001") or "8001"),
        web_port=int(get("WEB_PORT", "8090") or "8090"),
        secret_key=get("SECRET_KEY", "dev-secret-a-remplacer"),
        database_url=database_url,
        data_dir=data_dir,
        glpi_url=get("GLPI_URL", "http://127.0.0.1/apirest.php").rstrip("/"),
        glpi_app_token=get("GLPI_APP_TOKEN", ""),
        glpi_user_token=get("GLPI_USER_TOKEN", ""),
        glpi_base_url=get("GLPI_BASE_URL", "http://195.200.200.16").rstrip("/"),
        demo_mode=get("DEMO_MODE", "auto"),
        nvd_api_key=get("NVD_API_KEY", ""),
        github_token=get("GITHUB_TOKEN", ""),
        session_cookie_secure=_bool(get("SESSION_COOKIE_SECURE", "0")),
        session_hours=int(get("SESSION_HOURS", "8") or "8"),
        admin_user=get("ADMIN_USER", "admin"),
        admin_password=get("ADMIN_PASSWORD", ""),
    )
