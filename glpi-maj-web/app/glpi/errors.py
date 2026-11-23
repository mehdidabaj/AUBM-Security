from __future__ import annotations

MESSAGES = {
    "ERROR_NOT_ALLOWED_IP": (
        "GLPI refuse l'adresse de cette machine (ERROR_NOT_ALLOWED_IP). "
        "Le client API « glpi-maj-web » doit autoriser uniquement 127.0.0.1 et ::1, "
        "et l'application doit interroger GLPI depuis le serveur lui-même."
    ),
    "ERROR_APP_TOKEN_PARAMETERS_MISSING": (
        "Jeton d'application absent ou refusé (ERROR_APP_TOKEN_PARAMETERS_MISSING). "
        "Renseignez GLPI_APP_TOKEN dans /etc/glpi-maj-web/config.env."
    ),
    "ERROR_GLPI_LOGIN_USER_TOKEN": (
        "Jeton utilisateur refusé (ERROR_GLPI_LOGIN_USER_TOKEN). "
        "Vérifiez GLPI_USER_TOKEN et activez la connexion par jeton externe dans GLPI."
    ),
    "ERROR_RIGHT_MISSING": (
        "Droit manquant (ERROR_RIGHT_MISSING). "
        "Le profil de la session API doit pouvoir lire les ordinateurs, leur système et leurs logiciels. "
        "Sur le compte api-maj, choisissez Super-Admin comme profil par défaut."
    ),
    "ERROR_SESSION_TOKEN_INVALID": (
        "La session GLPI a expiré (ERROR_SESSION_TOKEN_INVALID). Relancez la vérification."
    ),
    "ERROR_SESSION_TOKEN_MISSING": (
        "Session GLPI absente (ERROR_SESSION_TOKEN_MISSING). Relancez la vérification."
    ),
}


class GlpiError(Exception):
    def __init__(self, code: str, message: str | None = None):
        self.code = code
        self.message = message or MESSAGES.get(code, "Erreur GLPI.")
        super().__init__(self.message)
