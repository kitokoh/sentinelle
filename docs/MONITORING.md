# Supervision — métriques, tableau de bord et alertes

> v0.6 (issue #19). Ce document dit quoi regarder, ce que chaque métrique
> signifie, et quoi faire quand une alerte se déclenche.

## Démarrage

```bash
make monitoring        # Prometheus (9090) + Grafana (3001)
```

Grafana arrive déjà branché sur Prometheus et charge le tableau de bord
`Sentinelle — SOC & plateforme` versionné dans
`deploy/monitoring/grafana/dashboards/`. Il n'y a rien à cliquer après un
déploiement : la configuration est du code, relue en revue comme le reste.

## Le point de collecte : `GET /metrics`

Format d'exposition Prometheus, **hors `/api`** (convention des collecteurs).

- Protégé par `METRICS_TOKEN` quand il est défini (en-tête `Authorization: Bearer`).
- **Ouvert quand il ne l'est pas** — acceptable seulement si l'endpoint n'est pas
  exposé publiquement. Le code journalise un avertissement au premier scrape.

### Métriques exposées

| Métrique | Type | Ce qu'elle dit |
|---|---|---|
| `sentinelle_http_requests_total{method,route,status}` | compteur | débit et codes de réponse |
| `sentinelle_http_request_duration_seconds{method,route}` | histogramme | latence (p50/p95/p99) |
| `sentinelle_scans_created_total{profile}` | compteur | scans acceptés par l'API |
| `sentinelle_alerts_created_total{source,severity}` | compteur | alertes produites (capteur, règles, renseignement) |
| `sentinelle_detections_total{rule}` | compteur | détections par moteur (`port_scan`, `ssh_bruteforce`, `beaconing`) |
| `sentinelle_iocs_total` | jauge | indicateurs détenus |
| `sentinelle_intel_feed_items_total` | jauge | avis CERT collectés |
| `sentinelle_alerts_unacknowledged` | jauge | **charge de travail humaine réelle** |
| `sentinelle_worker_up{worker}` | jauge | 1 si le worker a battu récemment, 0 sinon |
| `sentinelle_worker_last_seen_timestamp_seconds{worker}` | jauge | horodatage Unix du dernier battement |

**Le label `route` est le *template* de chemin**, jamais l'URL brute :
`/api/scans/4711` est enregistré comme `/api/scans/{scan_id}`. Sans cela, chaque
identifiant créerait sa propre série temporelle et Prometheus serait noyé sous la
cardinalité. Un test le vérifie.

**Les jauges issues de la base sont rafraîchies au moment du scrape** : le tableau
de bord ne peut pas être en désaccord avec ce que la plateforme contient.

## Battement de cœur du worker

C'est le point important de cette issue.

Dans une architecture à file d'attente, la panne la plus vicieuse est **silencieuse** :
l'API répond, la file accepte les jobs, et plus personne ne consomme. Rien dans un
tableau de bord applicatif classique ne le montre.

Chaque cycle d'ingestion (toutes les 15 s) écrit donc un battement de cœur en
base, **avant même de chercher le fichier EVE**. Un worker sans capteur est vivant
et doit le dire — sinon « pas de capteur » et « worker mort » seraient
indistinguables.

- `WORKER_STALE_SECONDS` (défaut **300 s**) est le seuil de péremption.
- `GET /api/health/dependencies` expose l'âge de chaque worker ; il répond
  `degraded` dès qu'un worker est périmé **ou n'a jamais battu**.
- `GET /api/health` reste une sonde de vivacité simple : elle ne doit pas échouer
  parce qu'une *dépendance* est tombée, sinon Kubernetes redémarrerait une API
  parfaitement saine.

## Règles d'alerte

Définies dans `deploy/monitoring/prometheus/alerts.yml` :

| Alerte | Condition | Sévérité |
|---|---|---|
| `SentinelleWorkerDown` | `sentinelle_worker_up == 0` pendant 1 min | critique |
| `SentinelleWorkerNeverStarted` | `absent(sentinelle_worker_up)` pendant 5 min | critique |
| `SentinelleApiDown` | `up{job="sentinelle-api"} == 0` pendant 2 min | critique |
| `SentinelleHighErrorRate` | plus de 5 % de 5xx sur 5 min, pendant 10 min | avertissement |
| `SentinelleSlowRequests` | p95 > 1,5 s pendant 15 min | avertissement |
| `SentinelleAlertBacklog` | plus de 100 alertes non acquittées pendant 30 min | avertissement |

> `for:` est un **anti-rebond**, pas le seuil. Le seuil de « worker injoignable »
> est `WORKER_STALE_SECONDS` (300 s) : la jauge ne passe à 0 qu'après ce délai, et
> le `for` n'ajoute qu'une minute de confirmation. Total : ~6 minutes au pire.
> Un test vérifie que les deux valeurs ne peuvent pas diverger silencieusement.

## Runbooks

### Worker injoignable

1. `docker compose ps worker` — le conteneur tourne-t-il ?
2. `docker compose logs --tail=100 worker` — erreur de démarrage, Redis
   injoignable, migration non appliquée ?
3. `GET /api/health/dependencies` — l'âge exact du dernier battement.
4. Si le conteneur tourne mais ne bat plus : le worker est bloqué sur un job. Le
   cycle d'ingestion est planifié, donc un job `run_scan` long ne l'empêche pas de
   battre — un battement figé signifie un worker réellement bloqué, à redémarrer.
5. Après redémarrage, la file Redis a conservé les jobs : les scans en attente
   repartent seuls.

### Taux d'erreur élevé

1. `sentinelle_http_requests_total{status=~"5.."}` par route — quelle route ?
2. Les points chauds connus sont `GET /api/scans/{id}/report.pdf` (génération PDF)
   et `GET /api/scans/{id}/export` (export CSV).
3. Base de données injoignable ou migrations non appliquées : voir les journaux de
   l'API, `alembic upgrade head` s'exécute au démarrage.

### Stock d'alertes qui monte

Ce n'est pas une panne technique, c'est un signal d'organisation : le volume de
détection dépasse la capacité d'analyse. Pistes : relever les seuils des règles
bruyantes (`backend/rules/detection.yaml`), acquitter en masse, ou revoir le
périmètre surveillé.

## Limites assumées

- Pas de collecte des métriques **PostgreSQL** ni **Redis** : ce serait un
  exportateur de plus à déployer et à maintenir, hors du périmètre de cette issue.
- `sentinelle_worker_up` ne dit pas *quel* job a échoué — le détail est dans les
  journaux du worker, pas dans les métriques.
