# 🛡️ Sentinelle

**Plateforme souveraine d'audit de sécurité et de cyber-défense — démonstrateur.**

Sentinelle unifie derrière une interface web moderne les capacités d'audit offensif
**strictement encadré** (scans nmap sur périmètre autorisé), de suivi des
vulnérabilités et, à terme, de détection d'intrusion et de veille sur les menaces.
Pensée comme la brique technique d'un dossier de candidature à des fonctions cyber
dans le secteur public : technique **et** doctrine.

> ⚖️ **Cadre légal** — Sentinelle n'opère que sur des cibles explicitement
> autorisées : réseaux privés (RFC1918), labo local (`.lab`, `.local`, …) ou
> cibles externes accompagnées d'une **référence d'autorisation écrite**.
> Ce garde-fou est appliqué côté serveur, pas côté interface. Voir
> [SECURITY.md](SECURITY.md).

---

## Fonctionnalités

### v0.1 — Socle

- 🔐 Authentification JWT (rôles analyste / admin)
- 🎯 Gestion des cibles avec **validation de périmètre côté serveur**
- 🔎 Scans nmap asynchrones (workers isolés, files Redis) — profils `quick` / `full`
- 📋 Constats structurés (port, service, version, sévérité)
- 📊 Tableau de bord temps réel (stats, répartition par sévérité, derniers scans)
- 📜 Page Doctrine : les 5 piliers d'une stratégie cyber nationale

### v0.2 — Audit de vulnérabilités

- 🧬 Intégration **nuclei** dans le worker (templates communautaires)
- 🗂️ Correspondance service/version → **CVE** (API NVD)
- 🎯 Score de risque par scan et par cible
- 📤 Export CSV des constats

### v0.3 — Défense

- 🛰️ **Ingestion Suricata** (EVE JSON) : capteur dans le profil `lab`, tail
  incrémental idempotent, événements normalisés
- 🧠 **Moteur de règles de détection** : balayage de ports, force brute SSH,
  beaconing — règles déclaratives en YAML ([docs/DETECTION.md](docs/DETECTION.md))
- 🚨 **Page Alertes** : flux filtrable, auto-rafraîchi, acquittement avec
  compteur des non acquittées dans la barre latérale
- 🗄️ **Migrations Alembic** : schéma rejouable, testé sur SQLite *et* PostgreSQL
  en CI
- 🧹 **Rétention configurable** : purge quotidienne des constats, alertes et
  événements (`RETENTION_DAYS`, 0 = désactivé)

### v0.4 — Renseignement sur les menaces

- 🔌 **Connecteurs** MISP (attributs), AlienVault OTX (pulses) et flux **CERT**
  RSS/Atom — normalisation commune, dégradation propre si une source est
  injoignable ([docs/INTEL.md](docs/INTEL.md))
- 🧩 **Dédoublonnage inter-sources** : un indicateur rapporté par deux flux reste
  une seule ligne, avec toutes ses provenances
- 🎯 **Corrélation IoC ↔ observé** : un indicateur retrouvé dans une alerte ou un
  constat crée une alerte `intel` de sévérité ≥ élevée, signalée une seule fois
- 🌍 **Page Renseignement** : veille CERT, indicateurs filtrables, correspondances
  et **carte des campagnes** (coordonnées fournies par les flux uniquement)

### v0.5 — Rapports & gouvernance

- 📄 **Rapports PDF** : synthèse dirigeant (score, points saillants,
  recommandations justifiables) + annexe technique exhaustive, générés sans
  dépendance native
- 🔐 **RBAC fin** (lecteur / analyste / administrateur) appliqué par dépendance
  FastAPI sur toutes les routes, **fail closed** — matrice dans
  [docs/RBAC.md](docs/RBAC.md)
- 🧾 **Journal d'audit** : une ligne par requête modifiante, écrite par
  middleware, en lecture seule, filtrable — sans jamais stocker de corps de requête
- 🏢 **Multi-organisation** : isolation stricte par requête (404 et non 403),
  couverte par des tests négatifs
- 🪪 **SSO / OIDC** (Keycloak, profil `sso`) : code d'autorisation + mapping des
  rôles de realm, l'authentification locale restant disponible
  ([docs/SSO.md](docs/SSO.md))

## Stack

| Couche | Choix | Pourquoi |
|---|---|---|
| API | Python 3.12 / FastAPI | L'écosystème sécu est en Python ; OpenAPI gratuit |
| Front | React 18 + TS + Vite + Tailwind | Vite = itérations rapides, UI sobre type SOC |
| Données | PostgreSQL 16 (+ SQLite en dev) | Solide, standard |
| Files | Redis + arq | Workers async légers, conteneur de scan isolé |
| Scans | nmap (nuclei en v0.2) | Le standard de la reconnaissance réseau |
| Ops | Docker Compose, GitHub Actions | Reproductible, démontrable partout |

## Démarrage rapide (Docker)

```bash
git clone <repo> && cd sentinelle
docker compose up -d --build
docker compose exec api python seed.py   # compte démo + cible lab
```

- Interface : http://localhost:3000
- API / Swagger : http://localhost:8000/docs
- Compte démo : `admin@sentinelle.local` / `Sentinelle2026!`

## Dev local (sans Docker)

```bash
# API (SQLite + Redis local pour les scans)
cd backend && pip install -r requirements.txt
alembic upgrade head                   # schéma (obligatoire au premier lancement)
uvicorn app.main:app --reload          # http://localhost:8000
arq app.worker.settings.WorkerSettings # terminal 2 : worker de scan + ingestion

# Front
cd frontend && npm install && npm run dev   # http://localhost:5173 (proxy /api)
```

## Base de données & migrations

Le schéma appartient à **Alembic** (et non plus à `create_all`). L'API applique
`alembic upgrade head` au démarrage ; les commandes restent disponibles :

```bash
cd backend
alembic upgrade head        # applique les migrations
make migration m="ajout de x"   # nouvelle révision autogénérée
alembic check               # échoue s'il existe une dérive schéma/modèles
alembic downgrade -1        # retour arrière
```

> **Adoption d'une base v0.2 existante** (créée par `create_all`) : le schéma est
> identique, il suffit de marquer la révision initiale comme déjà appliquée —
> `alembic stamp 0001_initial` — puis d'enchaîner `alembic upgrade head`.

La CI rejoue la série complète (upgrade → check → downgrade → upgrade) sur
**SQLite et PostgreSQL**.

## Structure

```
sentinelle/
├── backend/            # API FastAPI + worker arq + tests (248 tests)
│   ├── alembic/        # migrations (initial, défense, renseignement, gouvernance)
│   ├── rules/          # règles de détection déclaratives (YAML)
│   └── app/
│       ├── api/        # routes (auth, oidc, targets, scans, dashboard,
│       │               #   alerts, intel, users, audit)
│       ├── core/       # config, sécurité, rôles
│       ├── services/   # scope, scanner, detection, ingest, retention,
│       │               #   intel/, audit, oidc, reports
│       └── worker/     # jobs arq : run_scan, ingest_eve, purge, sync_*, correlate
├── frontend/           # SPA React/TS (dashboard, cibles, scans, alertes,
│                       #   renseignement, rapports, journal, doctrine)
├── deploy/keycloak/    # realm SSO de démonstration (#14)
├── docs/
│   ├── ARCHITECTURE.md # composants, flux, modèle de données
│   ├── DETECTION.md    # écrire et régler une règle de détection
│   ├── INTEL.md        # brancher MISP / OTX / CERT et comprendre la corrélation
│   ├── RBAC.md         # matrice des rôles et frontières entre organisations
│   ├── SSO.md          # brancher Keycloak, comprendre le flux OIDC
│   ├── ROADMAP.md      # v0.1 → v0.6 (secrets, monitoring, production)
│   └── DOCTRINE.md     # le volet stratégique : doctrine cyber nationale
├── .github/workflows/  # CI : tests backend, migrations (SQLite + PostgreSQL), build front
└── docker-compose.yml  # db + redis + api + worker + web (+ capteur en profil `lab`)
```

## Capteur du lab

```bash
make sensor                          # démarre Suricata (profil `lab`)
docker compose --profile lab up -d   # ou toute la stack avec le capteur
```

Le worker lit `/var/log/suricata/eve.json` toutes les 15 s. Sans capteur, le
cycle est simplement ignoré : rien ne tombe en erreur.

## Renseignement sur les menaces

Trois sources sont supportées, chacune indépendante et facultative : MISP, OTX
et les flux d'avis CERT. Configurez ce que vous avez, le reste est marqué
`skipped` :

```bash
MISP_URL=https://misp.example.org
MISP_API_KEY=…
OTX_API_KEY=…
CERT_FEEDS=CERT-FR=https://www.cert.ssi.gouv.fr/feed/
```

Puis, sur la page **Renseignement**, le bouton « Synchroniser » déclenche un
cycle complet à la demande. Détails et diagnostic : [docs/INTEL.md](docs/INTEL.md).

## Rôles, organisations et journal d'audit

Trois rôles hiérarchiques : **lecteur** (lecture seule), **analyste** (cibles,
scans, acquittements) et **administrateur** (utilisateurs, journal). La matrice
complète est dans [docs/RBAC.md](docs/RBAC.md).

Chaque donnée appartient à une **organisation** ; toute lecture filtre dessus, et
une ressource d'un autre tenant répond 404 — jamais 403, qui confirmerait son
existence.

Le **journal d'audit** est écrit automatiquement par un middleware à chaque
requête modifiante (acteur, action, ressource, statut, IP). Il est en lecture
seule et ne conserve **aucun corps de requête** : mots de passe et jetons n'y
apparaissent jamais.

```bash
# SSO (profil `sso`) — le secret du client est injecté, jamais versionné
SENTINELLE_CLIENT_SECRET=un-secret-solide docker compose --profile sso up -d
```

Détails du flux OIDC et diagnostic : [docs/SSO.md](docs/SSO.md).

## Roadmap

Voir [docs/ROADMAP.md](docs/ROADMAP.md) — prochaine étape : **v0.6** (chart Helm,
secrets externalisés, chiffrement au repos, monitoring Prometheus/Grafana, PRA).

## Licence

MIT — voir [LICENSE](LICENSE).
