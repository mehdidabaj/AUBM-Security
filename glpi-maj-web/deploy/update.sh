#!/bin/bash
# Met à jour le code depuis le clone enregistré, les dépendances et la base.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Lancez update.sh avec les droits root." >&2
    exit 1
fi

if [ ! -f /etc/glpi-maj-web/repo_root ]; then
    echo "Clone d'origine introuvable (/etc/glpi-maj-web/repo_root)." >&2
    exit 1
fi

depot="$(cat /etc/glpi-maj-web/repo_root)"
hint=""
if [ -s /etc/glpi-maj-web/app_dir ]; then
    hint="$(cat /etc/glpi-maj-web/app_dir)"
fi
# shellcheck source=layout.sh
. "$(cd "$(dirname "$0")" && pwd)/layout.sh"
git -C "$depot" pull --ff-only
application="$(resolve_app_dir "$depot" "$hint")"
rsync -a --delete \
    --exclude '.venv' \
    --exclude '__pycache__' \
    --exclude '.pytest_cache' \
    --exclude '*.db' \
    --exclude 'config.env' \
    "$application/" /opt/glpi-maj-web/
/opt/glpi-maj-web/.venv/bin/pip install --disable-pip-version-check -r /opt/glpi-maj-web/requirements.txt
chown -R glpimaj:glpimaj /opt/glpi-maj-web
sudo -u glpimaj env GLPI_MAJ_CONFIG=/etc/glpi-maj-web/config.env \
    bash -c 'cd /opt/glpi-maj-web && .venv/bin/python -m app.cli upgrade'
systemctl restart glpi-maj-web
echo "Mise à jour terminée."
