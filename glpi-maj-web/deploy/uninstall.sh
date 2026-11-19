#!/bin/bash
# Retire l'application. GLPI, son VirtualHost et le port 8080 ne sont pas touchés.
# Les données (/var/lib, sauvegardes, configuration) restent en place,
# sauf si --purge est passé.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Lancez uninstall.sh avec les droits root." >&2
    exit 1
fi

purge=0
if [ "${1:-}" = "--purge" ]; then
    purge=1
fi

systemctl disable --now glpi-maj-web.service 2>/dev/null || true
systemctl disable --now glpi-maj-web-backup.timer 2>/dev/null || true
rm -f /etc/systemd/system/glpi-maj-web.service \
    /etc/systemd/system/glpi-maj-web-backup.service \
    /etc/systemd/system/glpi-maj-web-backup.timer
systemctl daemon-reload

if command -v a2dissite >/dev/null 2>&1; then
    a2dissite glpi-maj >/dev/null 2>&1 || true
    a2disconf glpi-maj-listen-8090 >/dev/null 2>&1 || true
    rm -f /etc/apache2/sites-available/glpi-maj.conf \
        /etc/apache2/conf-available/glpi-maj-listen-8090.conf
    if apache2ctl configtest; then
        systemctl reload apache2
    fi
fi

rm -rf /opt/glpi-maj-web

if [ "$purge" -eq 1 ]; then
    rm -rf /var/lib/glpi-maj-web /var/backups/glpi-maj-web /etc/glpi-maj-web
    echo "Données, sauvegardes et configuration supprimées."
else
    echo "Données conservées dans /var/lib/glpi-maj-web et /var/backups/glpi-maj-web."
    echo "Relancez avec --purge pour les supprimer aussi."
fi
