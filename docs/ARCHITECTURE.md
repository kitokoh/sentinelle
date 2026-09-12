# Architecture — Sentinelle

## Vue d'ensemble

```mermaid
flowchart LR
    subgraph Client
        W[SPA React/TS<br/>nginx :80]
    end
    subgraph Backend
        A[API FastAPI<br/>:8000]
        R[(Redis<br/>file de jobs)]
        WK[Worker arq<br/>+ nmap]
    end
    DB[(PostgreSQL 16)]
    T[Cible autorisée<br/>lab / périmètre client]

    W -->|/api (proxy)| A
    A --> DB
    A -->|enqueue run_scan| R
    R --> WK
    WK --> DB
    WK -->|nmap -oX| T
```

## Composants

| Composant | Rôle | Isolation |
|---|---|---|
| `web` | SPA servie par nginx, proxifie `/api` | stateless |
| `api` | Auth JWT, CRUD cibles/scans, stats, **validation de périmètre** | stateless, sans nmap |
| `worker` | Exécute les scans nmap, parse le XML, écrit les constats | conteneur dédié, seul à avoir nmap |
| `db` | Persistance (utilisateurs, cibles, scans, constats) | volume `pgdata` |
| `redis` | File de jobs arq | éphémère |

Séparation volontaire : **l'API ne sait pas scanner**. Le binaire nmap n'existe
que dans l'image du worker — la surface d'attaque de l'API reste minimale.

## Le garde-fou de périmètre (`services/scope.py`)

Point central du design. À la création d'une cible :

```
valeur (ip|cidr|hostname)
   ├─ IP/CIDR privée, loopback, link-local (v4/v6)  → scope_status = allowed
   ├─ hostname en .lab/.local/.test/.internal/.example → allowed
   └─ sinon (cible publique)
        ├─ authorization_reference fournie → allowed (référence stockée, traçabilité)
        └─ sinon → denied  →  POST /scans renvoie 403
```

- Appliqué **côté serveur**, jamais côté front.
- Aucune résolution DNS lors de la validation (pas de bypass par rebinding
  déclaré ; la résolution n'a lieu qu'au moment du scan, dans le worker).

## Modèle de données

- **User** `id, email, hashed_password, role, created_at`
- **Target** `id, name, value, kind(ip|hostname|cidr), scope_status(allowed|denied), authorization_reference, owner_id → User`
- **Scan** `id, target_id → Target, profile(quick|full), status(pending|running|done|failed|denied), started_at, finished_at, error`
- **Finding** `id, scan_id → Scan, port, protocol, service, version, severity(info→critical), detail`

## Flux d'un scan

1. `POST /api/scans {target_id, profile}` — 403 si cible `denied`
2. Scan créé en `pending`, job `run_scan` poussé dans Redis
3. Worker : `running` → `nmap -oX - --top-ports 100 -sV -T4 <cible>`
   (`full` = `-p-`) → parse XML → remplace les constats → `done` (ou `failed`
   + message d'erreur)
4. Le front rafraîchit automatiquement (polling 3–5 s)

## Sécurité applicative

- Mots de passe hashés bcrypt, tokens JWT à expiration configurable
- Requêtes paramétrées (SQLModel/SQLAlchemy), CORS restreint au front
- Sévérités calculées par table de correspondance (services à risque :
  telnet, ftp, smb, rdp…) — base extensible pour la v0.2 (CVE via nuclei)

## Limites assumées (démonstrateur)

- `create_all` au démarrage au lieu de migrations Alembic (prévu v0.3)
- Scan d'une cible publique nécessite un Redis joignable, sinon 500 après
  création du scan `pending` (à durcir : file persistante + reprise)
- Mono-tenant. Multi-organisation + RBAC fin en v0.5.
