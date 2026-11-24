#!/bin/bash
# Copie cohérente de la base SQLite et rotation à 30 jours.
set -euo pipefail

config=/etc/glpi-maj-web/config.env
destination=/var/backups/glpi-maj-web
mkdir -p "$destination"

database="/var/lib/glpi-maj-web/glpi-maj.db"
if [ -f "$config" ]; then
    # shellcheck disable=SC1090
    set -a
    # Ne charge que les affectations simples, pas les commentaires.
    . "$config"
    set +a
    if [ -n "${DATABASE_URL:-}" ]; then
        case "$DATABASE_URL" in
            sqlite:////*) database="/${DATABASE_URL#sqlite:////}" ;;
            sqlite:///*) database="${DATABASE_URL#sqlite:///}" ;;
        esac
    fi
fi

stamp="$(date +%Y%m%d-%H%M%S)"
sqlite3 "$database" ".backup '${destination}/glpi-maj-${stamp}.db'"
find "$destination" -type f -name 'glpi-maj-*.db' -mtime +30 -delete
echo "Sauvegarde écrite dans ${destination}/glpi-maj-${stamp}.db"
