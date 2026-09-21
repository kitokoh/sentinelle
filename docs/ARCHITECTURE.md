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
    S[Capteur Suricata<br/>profil `lab`]

    W -->|/api (proxy)| A
    A --> DB
    A -->|enqueue run_scan| R
    R --> WK
    WK --> DB
    WK -->|nmap -oX| T
    S -->|eve.json| WK
```

## Composants

| Composant | Rôle | Isolation |
|---|---|---|
| `web` | SPA servie par nginx, proxifie `/api` | stateless |
| `api` | Auth JWT, CRUD cibles/scans, stats, alertes, **validation de périmètre** | stateless, sans nmap |
| `worker` | Scans nmap/nuclei, **ingestion EVE + moteur de détection**, purge de rétention | conteneur dédié, seul à avoir nmap |
| `sensor` | Suricata du lab, écrit `eve.json` dans un volume partagé | profil `lab`, `NET_ADMIN` |
| `db` | Persistance (utilisateurs, cibles, scans, constats, alertes, événements, IoC, avis) | volume `pgdata` |
| `redis` | File de jobs arq (scans) + planification des jobs périodiques | éphémère |

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
- **Finding** `id, scan_id → Scan, port, protocol, service, version, severity(info→critical), detail, source(nmap|nuclei|nvd)`
- **Alert** (v0.3) `id, created_at, source(suricata|rule|intel), event_type, severity, src/dst ip+port, rule_name, confidence, occurrences, dedup_key, signature, detail, payload, status(new|ack), acknowledged_at/by`
- **SensorEvent** (v0.3) `id, event_id(unique), occurred_at, event_type, src/dst ip+port, proto, app_proto, signature, payload`
- **IngestState** (v0.3) curseur `key, offset, inode` — rend le tail idempotent
- **Ioc** (v0.4) `id, type(ip|domain|url|md5|sha1|sha256|email), value, sources, severity, first_seen, last_seen, metadata_json` — **unique sur `(type, value)`**
- **IntelFeedItem** (v0.4) `id, guid(unique), source, title, link, summary, published_at`

Le schéma est versionné par **Alembic** (`backend/alembic/versions/`) :
`0001_initial` reproduit le schéma v0.2, `0002_defense` ajoute les trois tables
de la défense, `0003_intel` celles du renseignement. `alembic check` est exécuté
en CI — toute dérive entre modèles et migrations échoue la construction.

## Flux défensif (v0.3)

```
Suricata → eve.json ─┐
                     │ (worker, toutes les 15 s)
                     ▼
             read_new_lines()      offset/inode persistés → idempotent
                     ▼
             normalize_events()    → sensor_events (dédup sur event_id)
                     ▼
        ┌────────────┴────────────┐
        ▼                         ▼
  event_type = alert         moteur de règles (fenêtre glissante)
  → alerts (suricata)        port_scan / ssh_bruteforce / beaconing
                             → alerts (rule, rule_name, confidence)
```

Deux propriétés structurent ce flux :

1. **Les événements bruts sont conservés** dans `sensor_events`. Une détection
   n'est pas un jugement sur un événement isolé mais sur une fenêtre — sans les
   événements, aucune règle ne serait réévaluable ni explicable.
2. **Déduplication par `dedup_key`.** Une activité qui dure fait monter le
   compteur `occurrences` d'une même alerte au lieu de créer une tempête
   d'alertes. Le détail des règles et de la confiance est dans
   [DETECTION.md](DETECTION.md).

## Flux de renseignement (v0.4)

```
MISP ─┐                          normalisation commune
OTX  ─┼─▶ connecteurs ──▶ candidate(type, value, source, sévérité, metadata)
CERT ─┘                                   │
                                          ▼
                        `iocs`  — unique sur (type, value) :
                                  un même indicateur vu par deux flux
                                  = une ligne, `sources` = "misp,otx"
                                          │
                     alertes + constats ──┼──▶ corrélation
                                          ▼
                        `alerts` source="intel", sévérité ≥ high,
                        une seule fois par couple (indicateur, entité)
```

Deux choix structurent ce flux :

1. **La clé d'unicité est l'indicateur, pas la source.** Sans cela, le corrélateur
   signalerait deux fois la même chose. La provenance est une liste, pas une ligne.
2. **Un connecteur ne fait jamais échouer un cycle.** Source injoignable ou
   non configurée → 0 indicateur et une ligne de journal (`status: skipped`),
   jamais une exception. Une plateforme souveraine ne dépend pas de la
   disponibilité d'un tiers pour démarrer.

Détails de configuration et de réglage : [INTEL.md](INTEL.md).

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

- Le capteur Suricata tourne en `network_mode: host` et n'est pas supervisé :
  s'il s'arrête, l'ingestion se contente de ne rien faire (pas d'alerte de
  santé — voir le monitoring en v0.6).
- Scan d'une cible publique nécessite un Redis joignable, sinon 500 après
  création du scan `pending` (à durcir : file persistante + reprise)
- Mono-tenant. Multi-organisation + RBAC fin en v0.5.
- Les alertes sont globales (pas encore cloisonnées par organisation) : la vue
  SOC est unique, ce qui est le comportement attendu en v0.3.
- La carte des campagnes n'affiche que les coordonnées fournies par les flux :
  aucun indicateur n'est envoyé à un service de géolocalisation tiers.
