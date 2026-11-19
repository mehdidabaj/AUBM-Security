#!/bin/bash
# Retrouve le dossier qui contient réellement l'application.

resolve_app_dir() {
    local depot="$1"
    local hinted="${2:-}"
    local candidat
    for candidat in "$hinted" "$depot/glpi-maj-web" "$depot"; do
        if [ -n "$candidat" ] && [ -f "$candidat/app/main.py" ] && [ -f "$candidat/requirements.txt" ]; then
            printf '%s\n' "$candidat"
            return 0
        fi
    done
    echo "Dossier d'application introuvable (attendu : app/main.py)." >&2
    return 1
}
