#!/bin/bash
# Contrôle des ports. Ce fichier est sourcé par install.sh et par les tests.

port_interdit() {
    [ "$1" = "8080" ]
}

ports_a_verifier() {
    local app_port="$1"
    local web_port="$2"
    if port_interdit "$app_port" || port_interdit "$web_port"; then
        echo "Le port 8080 est déjà utilisé par une autre application et ne doit pas être choisi." >&2
        return 1
    fi
}

port_occupe() {
    local port="$1"
    ss -tlnp | awk '{print $4}' | grep -Eq "[.:]${port}([^0-9]|$)"
}

verifier_ports_libres() {
    local app_port="$1"
    local web_port="$2"
    local occupe=""
    ports_a_verifier "$app_port" "$web_port" || return 1
    if port_occupe "$app_port"; then
        occupe="${occupe} ${app_port}"
    fi
    if port_occupe "$web_port"; then
        occupe="${occupe} ${web_port}"
    fi
    if [ -n "$occupe" ]; then
        echo "Port déjà occupé :${occupe}. Arrêtez le service qui l'utilise, puis relancez l'installation." >&2
        return 1
    fi
}
