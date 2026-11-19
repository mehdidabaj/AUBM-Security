#!/bin/bash
# Installation idempotente sur Debian 12. À lancer en root depuis un clone du dépôt.
# Ne modifie ni le VirtualHost de GLPI ni l'application qui occupe le port 8080.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SOURCE="$(cd "$HERE/.." && pwd)"
# shellcheck source=ports.sh
. "$HERE/ports.sh"

if [ "$(id -u)" -ne 0 ]; then
    echo "Lancez install.sh avec les droits root." >&2
    exit 1
fi

lire() {
    local fichier="$1"
    local cle="$2"
    local defaut="$3"
    local valeur=""
    if [ -f "$fichier" ]; then
        valeur="$(grep -E "^${cle}=" "$fichier" | tail -n 1 | cut -d= -f2- | tr -d "\"'" || true)"
    fi
    if [ -z "$valeur" ]; then
        echo "$defaut"
    else
        echo "$valeur"
    fi
}

CONFIG=/etc/glpi-maj-web/config.env
MODELE="$SOURCE/config.env.example"
APP_PORT="$(lire "$CONFIG" APP_PORT "$(lire "$MODELE" APP_PORT 8001)")"
WEB_PORT="$(lire "$CONFIG" WEB_PORT "$(lire "$MODELE" WEB_PORT 8090)")"
ports_a_verifier "$APP_PORT" "$WEB_PORT"

if systemctl is-active --quiet glpi-maj-web 2>/dev/null; then
    systemctl stop glpi-maj-web
fi
verifier_ports_libres "$APP_PORT" "$WEB_PORT"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3-venv python3-pip git sqlite3 fonts-dejavu curl ca-certificates rsync openssl tzdata

if ! id glpimaj >/dev/null 2>&1; then
    useradd --system --home-dir /opt/glpi-maj-web --shell /usr/sbin/nologin glpimaj
fi

install -d -o glpimaj -g glpimaj -m 0750 /opt/glpi-maj-web
install -d -o root -g glpimaj -m 0750 /etc/glpi-maj-web
install -d -o glpimaj -g glpimaj -m 0750 /var/lib/glpi-maj-web
install -d -o glpimaj -g glpimaj -m 0750 /var/backups/glpi-maj-web

if [ ! -s /etc/glpi-maj-web/repo_root ]; then
    if git -C "$SOURCE" rev-parse --show-toplevel >/dev/null 2>&1; then
        git -C "$SOURCE" rev-parse --show-toplevel > /etc/glpi-maj-web/repo_root
    else
        echo "$SOURCE" > /etc/glpi-maj-web/repo_root
    fi
fi
if [ ! -s /etc/glpi-maj-web/app_dir ]; then
    echo "$SOURCE" > /etc/glpi-maj-web/app_dir
fi

rsync -a --delete \
    --exclude '.venv' \
    --exclude '__pycache__' \
    --exclude '.pytest_cache' \
    --exclude '*.db' \
    --exclude 'config.env' \
    "$SOURCE/" /opt/glpi-maj-web/

if [ ! -x /opt/glpi-maj-web/.venv/bin/python ]; then
    python3 -m venv /opt/glpi-maj-web/.venv
fi
/opt/glpi-maj-web/.venv/bin/pip install --disable-pip-version-check -r /opt/glpi-maj-web/requirements.txt
chown -R glpimaj:glpimaj /opt/glpi-maj-web

if [ ! -f "$CONFIG" ]; then
    install -o glpimaj -g glpimaj -m 0600 "$MODELE" "$CONFIG"
fi
chown glpimaj:glpimaj "$CONFIG"
chmod 0600 "$CONFIG"
if ! grep -Eq '^SECRET_KEY=.+' "$CONFIG"; then
    secret="$(openssl rand -hex 32)"
    sed -i "s/^SECRET_KEY=.*/SECRET_KEY=${secret}/" "$CONFIG"
fi

sudo -u glpimaj env GLPI_MAJ_CONFIG="$CONFIG" \
    bash -c 'cd /opt/glpi-maj-web && .venv/bin/python -m app.cli upgrade'
sudo -u glpimaj env GLPI_MAJ_CONFIG="$CONFIG" \
    bash -c 'cd /opt/glpi-maj-web && .venv/bin/python -m app.cli create-admin'

install -m 0644 "$HERE/glpi-maj-web.service" /etc/systemd/system/glpi-maj-web.service
install -m 0644 "$HERE/glpi-maj-web-backup.service" /etc/systemd/system/glpi-maj-web-backup.service
install -m 0644 "$HERE/glpi-maj-web-backup.timer" /etc/systemd/system/glpi-maj-web-backup.timer
systemctl daemon-reload
systemctl enable --now glpi-maj-web.service
systemctl enable --now glpi-maj-web-backup.timer

if command -v apache2ctl >/dev/null 2>&1; then
    install -m 0644 "$HERE/apache-listen-8090.conf" /etc/apache2/conf-available/glpi-maj-listen-8090.conf
    install -m 0644 "$HERE/apache-glpi-maj.conf" /etc/apache2/sites-available/glpi-maj.conf
    a2enmod proxy proxy_http headers
    a2enconf glpi-maj-listen-8090
    a2ensite glpi-maj
    apache2ctl configtest
    systemctl reload apache2
else
    echo "Apache n'est pas installé : le service écoute seulement sur 127.0.0.1:${APP_PORT}."
fi

echo "Vérification de l'accès sortant aux sources :"
"$HERE/probe-sources.sh" || true

echo "Installation terminée. Interface : http://195.200.200.16:${WEB_PORT}/"
echo "Journaux : journalctl -u glpi-maj-web -u glpi-maj-web-backup"
