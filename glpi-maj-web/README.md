# Suivi des mises à jour du parc GLPI

Application interne qui lit les ordinateurs, les logiciels et les agents dans GLPI, les compare à des sources publiques (winget, GitHub Releases, MSRC et CERT-FR) et présente les actions à mener. Elle tourne sur le serveur Debian qui héberge déjà GLPI, sans Docker.

L'interface est en français : tableau de bord, postes, logiciels, sources, paramètres, export Excel et rapport PDF. Le bouton « Lancer une vérification » lit le parc en arrière-plan. La première collecte interroge les ordinateurs, puis seulement les versions qu'ils installent. La suivante ne relit que les postes dont la date GLPI a changé et reprend les autres. Le pourcentage suit le volume annoncé par GLPI. Les pages se mettent à jour quand un poste ou un logiciel apparaît. « Arrêter la vérification » interrompt la lecture. Les dix dernières vérifications sont conservées (réglable dans Paramètres). À 100 %, le tableau de bord se recharge.

## Prérequis

- Debian 12, Python 3.11, droits root pour l'installation.
- Apache déjà en place pour GLPI. Le port 8080 est occupé par une autre application et ne doit pas être réutilisé.
- Paquets installés par `deploy/install.sh` : `python3-venv`, `python3-pip`, `git`, `sqlite3`, `fonts-dejavu`, `curl`, `rsync`, `openssl`.
- Accès sortant HTTPS vers les sources publiques. Un proxy éventuel se déclare avec `HTTPS_PROXY` dans `config.env`.

## Configurer l'API GLPI

Dans GLPI, compte administrateur :

1. **Configuration > Générale > API**
   - activer l'API REST ;
   - désactiver la connexion par identifiants ;
   - activer la connexion par jeton externe ;
   - l'URL de l'API sur ce serveur est `http://195.200.200.16/apirest.php`.
2. Ajouter un client API nommé `glpi-maj-web`.
   - le limiter aux adresses `127.0.0.1` et `::1` (l'application l'appelle depuis le serveur lui-même) ;
   - régénérer l'App-Token et le copier dans `GLPI_APP_TOKEN`.
3. Créer un compte `api-maj`.
   - profil **Observer** sur l'entité racine, récursif, avec lecture des ordinateurs, des logiciels et des agents ;
   - générer un User-Token (jeton distant) et le copier dans `GLPI_USER_TOKEN`.

Tant que ces deux jetons sont vides, `DEMO_MODE=auto` affiche un parc d'exemple de 20 postes. Renseigner les jetons, puis relancer le service, pour interroger le vrai GLPI.

## Tester l'API avec curl

Depuis le serveur, en remplaçant les jetons :

```bash
SESSION=$(curl -sS -X POST 'http://127.0.0.1/apirest.php/initSession' \
  -H 'Content-Type: application/json' \
  -H 'App-Token: VOTRE_APP_TOKEN' \
  -H 'Authorization: user_token VOTRE_USER_TOKEN' \
  -H 'User-Agent: glpi-maj-web/1.0' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["session_token"])')

curl -sS 'http://127.0.0.1/apirest.php/Computer?range=0-1&expand_dropdowns=true' \
  -H "App-Token: VOTRE_APP_TOKEN" \
  -H "Session-Token: ${SESSION}" \
  -H 'User-Agent: glpi-maj-web/1.0'

curl -sS 'http://127.0.0.1/apirest.php/Agent?range=0-1' \
  -H "App-Token: VOTRE_APP_TOKEN" \
  -H "Session-Token: ${SESSION}" \
  -H 'User-Agent: glpi-maj-web/1.0'

curl -sS 'http://127.0.0.1/apirest.php/killSession' \
  -H "App-Token: VOTRE_APP_TOKEN" \
  -H "Session-Token: ${SESSION}" \
  -H 'User-Agent: glpi-maj-web/1.0'
```

`initSession` doit renvoyer un `session_token`. Les deux lectures doivent renvoyer un tableau JSON. `killSession` doit répondre sans erreur.

## Installation

Le script n'est pas sur le serveur tant que le dépôt n'y a pas été cloné. Depuis n'importe quel dossier, y compris `/root` :

```bash
sudo mkdir -p /opt/src
sudo git clone --branch feature/glpi-maj-web \
  https://github.com/mehdidabaj/AUBM-Security.git /opt/src/AUBM-Security
sudo bash /opt/src/AUBM-Security/glpi-maj-web/deploy/install.sh
```

Après la fusion de cette branche dans `main`, remplacez `--branch feature/glpi-maj-web` par `--branch main`.

L'installation recopie le dossier `glpi-maj-web` vers `/opt/glpi-maj-web` et mémorise l'emplacement du clone. Elle ne se lance pas avec un chemin relatif depuis le dossier personnel.

Le script est idempotent. S'il trouve le service déjà démarré, il l'arrête, puis refuse de continuer si le port 8001 ou 8090 est encore pris. Il refuse aussi le port 8080. Il crée l'utilisateur système `glpimaj`, le virtualenv, `/etc/glpi-maj-web/config.env` (mode `0600`) et la base dans `/var/lib/glpi-maj-web/`. Il applique les migrations, crée le premier administrateur, active systemd et Apache, puis affiche les sources qui ne répondent pas.

Éditez ensuite `/etc/glpi-maj-web/config.env` (jetons GLPI, et éventuellement le proxy), puis :

```bash
sudo systemctl restart glpi-maj-web
```

L'interface est servie par Apache sur `http://195.200.200.16:8090/`. Uvicorn n'écoute que sur `127.0.0.1:8001`.

Si `ADMIN_PASSWORD` est vide, le mot de passe généré s'affiche une seule fois dans la sortie de l'installation. On peut le recréer avec :

```bash
sudo -u glpimaj env GLPI_MAJ_CONFIG=/etc/glpi-maj-web/config.env \
  bash -c 'cd /opt/glpi-maj-web && .venv/bin/python -m app.cli create-admin --force'
```

## Mise à jour

Depuis le clone d'origine enregistré dans `/etc/glpi-maj-web/repo_root` :

```bash
sudo bash /opt/glpi-maj-web/deploy/update.sh
```

La commande fait un `git pull --ff-only`, recopie le dossier de l'application, réinstalle les dépendances, migre la base et redémarre le service. `config.env` n'est pas écrasé.

## Sauvegarde et restauration

Un timer systemd copie la base chaque jour dans `/var/backups/glpi-maj-web/` et supprime les copies de plus de 30 jours.

```bash
sudo systemctl start glpi-maj-web-backup.service
sudo journalctl -u glpi-maj-web -u glpi-maj-web-backup
```

Pour restaurer une copie :

```bash
sudo systemctl stop glpi-maj-web
sudo -u glpimaj sqlite3 /var/lib/glpi-maj-web/glpi-maj.db \
  ".restore '/var/backups/glpi-maj-web/glpi-maj-AAAAMMJJ-HHMMSS.db'"
sudo systemctl start glpi-maj-web
```

## Désinstallation

```bash
sudo bash /opt/glpi-maj-web/deploy/uninstall.sh
```

Le service, le timer et le VirtualHost de cette application sont retirés. GLPI et le port 8080 ne sont pas modifiés. La base, les sauvegardes et `config.env` restent en place. Ajoutez `--purge` pour les supprimer aussi.

## Clé GitHub, plus tard

Les collectes fonctionnent sans clé. Une clé augmente seulement le quota GitHub.

- **GitHub** : créer un jeton classique sur <https://github.com/settings/tokens> (aucun droit sur les dépôts privés n'est nécessaire pour les dépôts publics), puis le coller dans `GITHUB_TOKEN`.

Laissez le champ vide pour conserver l'accès anonyme. Redémarrez le service après modification.

## Dépannage

- **ERROR_NOT_ALLOWED_IP** : le client API `glpi-maj-web` n'autorise pas l'adresse qui l'appelle. N'autorisez que `127.0.0.1` et `::1`, et n'interrogez pas GLPI depuis un autre poste.
- **ERROR_APP_TOKEN_PARAMETERS_MISSING** : `GLPI_APP_TOKEN` est vide ou ne correspond pas au client API. Régénérez le jeton et recopiez-le.
- **ERROR_GLPI_LOGIN_USER_TOKEN** : `GLPI_USER_TOKEN` est refusé, ou la connexion par jeton externe n'est pas activée. Vérifiez aussi que le compte `api-maj` n'est pas désactivé.
- **ERROR_RIGHT_MISSING** : le profil ouvert par la session API ne peut pas lire les ordinateurs ou les agents. Sur `api-maj`, le profil par défaut doit être Super-Admin, récursif, sur l'entité racine.
- **Port occupé** : `ss -tlnp` montre qui écoute sur 8001 ou 8090. L'installation s'arrête avec le numéro du port. Ne libérez pas 8080 pour cette application.
- **Source injoignable** : la page Sources et la fin de `install.sh` nomment la source. Vérifiez le pare-feu sortant et, s'il y a un proxy, `HTTPS_PROXY`. La dernière réponse connue reste utilisée.
- **Droits** : le rôle `lecture` consulte, `technicien` lance une vérification et met à jour le suivi, `admin` modifie les paramètres et les comptes. Un compte technique GLPI doit rester en Observer récursif : un profil sans lecture des logiciels produit des postes « sans logiciel ».

## Choix techniques

- **HTTP interne.** Les cookies sont `HttpOnly` et `SameSite=Strict`. L'attribut `Secure` est commandé par `SESSION_COOKIE_SECURE` et reste à `0`, parce qu'Apache sert l'application en HTTP sur le port 8090.
- **Verrouillage.** Cinq échecs de connexion bloquent le compte 15 minutes. Les sessions sont stockées en base, ce qui permet la déconnexion et l'invalidation.
- **Premier admin.** `install.sh` lit `ADMIN_USER` et `ADMIN_PASSWORD`. Sans mot de passe, il en génère un et l'affiche une seule fois. `python -m app.cli create-admin` reprend le même rôle.
- **Configuration.** Un chargeur de la bibliothèque standard lit `config.env`, puis les variables d'environnement l'emportent. `HTTPS_PROXY` est honoré par httpx. Le fichier d'exemple est versionné ; le fichier réel est en `chmod 600` et ignoré par Git.
- **Base.** SQLite `glpi-maj.db` dans `/var/lib/glpi-maj-web/`, chemin surchargeable pour les tests. L'URL absolue s'écrit `sqlite:////var/lib/glpi-maj-web/glpi-maj.db` (les trois slashs du schéma, plus celui du chemin). Migrations Alembic, une révision par grande étape. Mode WAL activé à chaque connexion.
- **Planification.** APScheduler dans le processus Uvicorn, fuseau `Europe/Paris`, collecte à 02:00 puis vérification du parc. L'heure se modifie dans Paramètres.
- **Mode démo.** `DEMO_MODE=auto` est actif lorsque `GLPI_APP_TOKEN` et `GLPI_USER_TOKEN` sont vides. Vingt postes et une vérification précédente sont enregistrés, pour que le comparatif ait des données.
- **Versions.** Comparateur maison par tuples numériques : builds Windows (`26300.9974`), Java (`8u511` et `1.8.0_511`), versions à quatre composants. Les formats non reconnus, dont « voir site », sont ignorés pour l'action de version.
- **Manifests winget.** Lecture de la clé `PackageVersion` sans PyYAML. Clone superficiel `git clone --depth 1 --filter=blob:none --sparse`, puis sparse-checkout du dossier `manifests/{lettre}/{éditeur}` et filtre sur `PackageIdentifier`. Les flux RSS et Atom sont lus avec `xml.etree`, sans `feedparser`.
- **Sources retenues.** winget, GitHub Releases, MSRC et CERT-FR. Les fins de support (Windows 10 et anciennes versions d'Office) viennent du référentiel local, pas d'endoflife.date. NVD, CISA KEV et les flux d'éditeurs ne sont plus interrogés.
- **Limites d'API.** CERT-FR : les deux index une fois par jour, puis les avis et les alertes des 120 derniers jours dont le titre cite un produit du parc (80 avis et 20 alertes au plus, les plus récents). MSRC : une requête pour le document entier. GitHub Releases : au plus une requête par produit et par jour UTC, avec ETag. La clé GitHub reste vide par défaut.
- **Règles fixes.** Enregistrées dans `app_settings` sous la clé `fixed_rules`, éditables dans l'interface, jamais réécrites par une collecte. Le référentiel de secours est chargé au premier démarrage et conservé comme plancher : pour Reader, Java 8 et Photoshop, la comparaison reste stricte (`gt`) tant que la version publiée ne dépasse pas ce plancher, puis devient `ge` sur la version obtenue.
- **Suivi des actions.** La clé stable est `glpi_id:kind:slug`. L'état, le technicien, la date et le commentaire survivent aux vérifications suivantes.
- **« Tout est à jour ? ».** Oui seulement en l'absence d'action Critique ou Importante. L'option `include_low_in_uptodate` inclut aussi les actions Faibles. Les autres actions (agent silencieux, inventaire ancien, poste sans logiciel, serveur Debian) ne bloquent pas cet indicateur. Un serveur Linux sans logiciel ne reçoit que l'action Debian. Une CVE sous le seuil Important reste citée, avec la sévérité Faible. La priorité du poste est la sévérité la plus haute.
- **Courriel.** `smtplib` de la bibliothèque standard, SMTP désactivé par défaut. Le premier passage mémorise les alertes CERT-FR et l'identifiant MSRC déjà connus, sans rien envoyer. Ensuite, un message part si une nouvelle alerte CERT-FR ou un nouveau Patch Tuesday concerne des postes du parc.
- **Interface.** htmx 2.0.4 et Chart.js 4.4.6 sont copiés dans `app/web/static/vendor/`. Le PDF A4 paysage utilise DejaVu Sans, copié dans le dépôt, en plus du paquet `fonts-dejavu` installé sur le serveur.
- **Service.** Uvicorn est lancé par `sh -c` pour développer `$APP_PORT` lu dans `EnvironmentFile`. `PYTHONDONTWRITEBYTECODE=1` évite d'écrire des fichiers `.pyc` sous `ProtectSystem=strict`. Le fuseau du service est `Europe/Paris`.
- **Mise à jour du code.** Le clone Git est noté dans `/etc/glpi-maj-web/repo_root` et le dossier de l'application dans `app_dir`. `update.sh` fait `git pull` puis `rsync`. `uninstall.sh` laisse `/var/lib/glpi-maj-web` et les sauvegardes, sauf avec `--purge`.
- **Dépendances.** FastAPI, Uvicorn, SQLAlchemy 2, Alembic, httpx, APScheduler 3.10, bcrypt, openpyxl, reportlab, Jinja2, python-multipart, itsdangerous, pytest, versions épinglées dans `requirements.txt`. Python 3.11. Pas de Node.js, pas de CDN, pas de Docker.
- **Intouchable.** Le VirtualHost GLPI, l'application du port 8080, et toute source DGSSI.

## Tests

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pytest
```

Les tests utilisent une base SQLite temporaire, le parc démo et des réponses JSON enregistrées. Ils ne contactent ni le réseau interne ni les API réelles. L'installation Debian n'est pas exécutée : seuls la syntaxe des scripts et le contrôle des ports sont vérifiés.
