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

## Fonctionnalités (v0.1)

- 🔐 Authentification JWT (rôles analyste / admin)
- 🎯 Gestion des cibles avec **validation de périmètre côté serveur**
- 🔎 Scans nmap asynchrones (workers isolés, files Redis) — profils `quick` / `full`
- 📋 Constats structurés (port, service, version, sévérité)
- 📊 Tableau de bord temps réel (stats, répartition par sévérité, derniers scans)
- 📜 Page Doctrine : les 5 piliers d'une stratégie cyber nationale

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
uvicorn app.main:app --reload          # http://localhost:8000
arq app.worker.settings.WorkerSettings # terminal 2 : worker de scan

# Front
cd frontend && npm install && npm run dev   # http://localhost:5173 (proxy /api)
```

## Structure

```
sentinelle/
├── backend/            # API FastAPI + worker arq + tests (18 tests)
├── frontend/           # SPA React/TS (dashboard, cibles, scans, doctrine)
├── docs/
│   ├── ARCHITECTURE.md # composants, flux, modèle de données
│   ├── ROADMAP.md      # v0.1 → v0.6 (nuclei, Suricata, threat intel, rapports PDF)
│   └── DOCTRINE.md     # le volet stratégique : doctrine cyber nationale
├── .github/workflows/  # CI : tests backend + build frontend
└── docker-compose.yml  # db + redis + api + worker + web
```

## Roadmap

Voir [docs/ROADMAP.md](docs/ROADMAP.md) — prochaine étape : **v0.2** (nuclei +
correspondance CVE), puis **v0.3** (ingestion Suricata/Zeek → volet défensif).

## Licence

MIT — voir [LICENSE](LICENSE).
