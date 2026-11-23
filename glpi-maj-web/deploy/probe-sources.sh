#!/bin/bash
# Affiche les sources qui ne répondent pas. Ne fait pas échouer l'installation.
set -u

verifier() {
    local nom="$1"
    local url="$2"
    local code
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 -A 'glpi-maj-web/1.0' "$url" || true)"
    if [ -z "$code" ] || [ "$code" = "000" ]; then
        echo "Source injoignable : ${nom}"
        return 1
    fi
    echo "${nom} : HTTP ${code}"
}

echec=0
verifier "winget" "https://github.com/microsoft/winget-pkgs" || echec=1
verifier "GitHub" "https://api.github.com/rate_limit" || echec=1
verifier "MSRC" "https://api.msrc.microsoft.com/cvrf/v3.0/updates" || echec=1
verifier "CERT-FR" "https://www.cert.cyber.gouv.fr/avis/json/" || echec=1
exit "$echec"
