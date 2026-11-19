from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"


def test_scripts_passent_bash_n():
    scripts = sorted(DEPLOY.glob("*.sh"))
    assert scripts
    for script in scripts:
        subprocess.run(["bash", "-n", str(script)], check=True)


def test_mise_a_jour_refuse_un_depot_sans_application(tmp_path):
    depot = tmp_path / "depot"
    depot.mkdir()
    (depot / "README.md").write_text("racine\n", encoding="utf-8")
    app = depot / "glpi-maj-web"
    (app / "app").mkdir(parents=True)
    (app / "app" / "main.py").write_text("app = None\n", encoding="utf-8")
    (app / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    script = f"""
source '{DEPLOY / "layout.sh"}'
resolve_app_dir '{depot}' '{depot}'
"""
    found = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
    assert found.returncode == 0
    assert found.stdout.strip() == str(app)


def test_le_port_8080_est_refuse():
    refused = _bash("ports_a_verifier 8080 8090")
    assert refused.returncode != 0
    assert "8080" in refused.stderr
    also = _bash("ports_a_verifier 8001 8080")
    assert also.returncode != 0
    allowed = _bash("ports_a_verifier 8001 8090")
    assert allowed.returncode == 0


def test_port_occupe_puis_libre():
    busy = _bash(
        'ss() { echo "LISTEN 0 128 127.0.0.1:8001 0.0.0.0:*"; }\n'
        "verifier_ports_libres 8001 8090"
    )
    assert busy.returncode != 0
    assert "8001" in busy.stderr

    free = _bash(
        'ss() { echo "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"; }\n'
        "verifier_ports_libres 8001 8090"
    )
    assert free.returncode == 0
    assert "ss -tlnp" in (DEPLOY / "ports.sh").read_text(encoding="utf-8")


def test_service_apache_et_desinstallation():
    unit = (DEPLOY / "glpi-maj-web.service").read_text(encoding="utf-8")
    for clause in (
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "ReadWritePaths=/var/lib/glpi-maj-web",
        "127.0.0.1",
        "PYTHONDONTWRITEBYTECODE=1",
    ):
        assert clause in unit
    vhost = (DEPLOY / "apache-glpi-maj.conf").read_text(encoding="utf-8")
    assert "<VirtualHost *:8090>" in vhost
    assert "ProxyPass / http://127.0.0.1:8001/" in vhost
    listen = (DEPLOY / "apache-listen-8090.conf").read_text(encoding="utf-8")
    assert "Listen 8090" in listen
    assert "8080" not in listen
    uninstall = (DEPLOY / "uninstall.sh").read_text(encoding="utf-8")
    assert "--purge" in uninstall
    assert "/var/lib/glpi-maj-web" in uninstall
    assert "ports.conf" not in uninstall
    install = (DEPLOY / "install.sh").read_text(encoding="utf-8")
    assert "apache2ctl configtest" in install
    assert "systemctl stop glpi-maj-web" in install


def _bash(body: str) -> subprocess.CompletedProcess[str]:
    script = f"source '{DEPLOY / 'ports.sh'}'\n{body}\n"
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
