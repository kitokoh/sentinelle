# Charte Helm `sentinelle`

Charte de déploiement Kubernetes de la plateforme **Sentinelle** (issue #16,
jalon v0.6 « Durcissement production »). Elle déploie l'API FastAPI, le worker
de scan asynchrone (arq + nmap + nuclei) et le frontend React servi par nginx.

## Ce que la charte déploie — et ce qu'elle ne déploie pas

| Composant | Objet Kubernetes | Remarque |
| --- | --- | --- |
| API | `Deployment` + `Service` (ClusterIP) | Applique `alembic upgrade head` au démarrage |
| Worker | `Deployment` (sans `Service`) | Aucun port ouvert : arq consomme une file Redis |
| Web | `Deployment` + `Service` (ClusterIP) | nginx sert la SPA et proxifie `/api` |
| Redis | `Deployment` + `Service` — **démonstration** | Gated par `redis.enabled` |
| PostgreSQL | **rien** | Instance managée externe attendue |
| Config non secrète | `ConfigMap` | Aucun secret n'y figure |
| Secret | `Secret` **optionnel** | Uniquement si `existingSecret` est vide |
| Exposition | `Ingress` optionnel | Désactivé par défaut |
| Mise à l'échelle | `HorizontalPodAutoscaler` optionnel | API et web par défaut |
| Disponibilité | `PodDisruptionBudget` optionnel | API et web uniquement |

## Prérequis

* Kubernetes ≥ 1.27 (les PDB utilisent `policy/v1`, le HPA `autoscaling/v2`) ;
* Helm 3 ;
* une instance **PostgreSQL managée** accessible depuis le cluster ;
* un contrôleur d'Ingress *seulement* si `ingress.enabled=true`.

## Installation

```bash
# 1. Créer le Secret attendu par défaut (cf. section « Secrets »).
kubectl -n sentinelle create secret generic sentinelle-secrets \
  --from-literal=postgresql-password="$(openssl rand -hex 24)" \
  --from-literal=jwt-secret="$(openssl rand -hex 32)"

# 2. Vérifier le rendu avant d'appliquer quoi que ce soit.
helm lint helm/sentinelle
helm template sentinelle helm/sentinelle \
  --set postgresql.host=pg.interne.example.org

# 3. Installer.
helm upgrade --install sentinelle helm/sentinelle \
  --namespace sentinelle --create-namespace \
  --set postgresql.host=pg.interne.example.org
```

Le rendu sans `--set` désigne volontairement un hôte PostgreSQL de repli
(`postgresql`) : c'est un garde-fou contre la mise en service distraite, pas une
valeur d'exploitation. `NOTES.txt` le rappelle à chaque installation.

## Secrets

**Aucune valeur sensible ne figure dans `values.yaml`.** Deux modes exclusifs :

1. **`existingSecret` (défaut, recommandé en production)** — la charte ne crée
   aucun Secret et référence un objet géré hors d'elle : Vault, External
   Secrets Operator, SealedSecret, ou simplement `kubectl create secret`. Les
   deux clés obligatoires sont `postgresql-password` et `jwt-secret` ; les autres
   sont optionnelles et activent une fonctionnalité :

   | Clé | Variable | Effet si absente |
   | --- | --- | --- |
   | `postgresql-password` | *(composée dans `DATABASE_URL`)* | **pod en erreur** |
   | `jwt-secret` | `JWT_SECRET` | **pod en erreur** |
   | `oidc-client-secret` | `OIDC_CLIENT_SECRET` | SSO désactivé |
   | `field-encryption-key` | `FIELD_ENCRYPTION_KEY` | clé dérivée de `JWT_SECRET` (interdit en production) |
   | `metrics-token` | `METRICS_TOKEN` | `/metrics` sans authentification |
   | `misp-api-key` | `MISP_API_KEY` | connecteur MISP ignoré |
   | `otx-api-key` | `OTX_API_KEY` | connecteur OTX ignoré |

   `METRICS_TOKEN` est délibérément absent du `ConfigMap` : c'est un secret, il
   n'a rien à faire dans un objet lisible par tous.

2. **`existingSecret: ""` (développement/démonstration uniquement)** — la
   charte crée le Secret depuis `secret.*` et `postgresql.password`, rendus
   obligatoires par `required` : un rendu incomplet échoue bruyamment plutôt que
   de déployer un mot de passe connu. Ce mode expose les valeurs via
   `helm get values` — à proscrire en production.

```bash
# Exemple de rendu en mode « secret géré par la charte » (démo).
helm template sentinelle helm/sentinelle \
  --set existingSecret= \
  --set postgresql.password=demo \
  --set secret.jwtSecret=demo-jwt
```

## PostgreSQL — jamais dans le cluster

La charte ne déploie **aucun** `StatefulSet` PostgreSQL, et c'est délibéré : un
SGBD en production suppose sauvegardes, PRA, montées de version mineures et
supervision, quatre sujets qu'un chart applicatif ne peut pas traiter
correctement. Renseignez :

```yaml
postgresql:
  host: pg.interne.example.org   # instance managée
  port: 5432
  database: sentinelle
  username: sentinelle
  sslMode: require               # TLS exigé par défaut
```

La charte compose `DATABASE_URL` dans le pod à partir de ces valeurs et du
`POSTGRES_PASSWORD` issu du Secret : le mot de passe ne transite donc jamais par
le `ConfigMap` ni par `values.yaml`. Le mot de passe doit être compatible URL
(échappement) ; à défaut, fournissez `DATABASE_URL` complète via
`api.extraEnv` / `worker.extraEnv`.

## Redis — trois options, dans l'ordre de préférence

1. **Redis managé** (production) :
   `--set redis.enabled=false --set redis.external.host=redis.managed.example.org`.
2. **Sous-charte bitnami** (production, si vous gérez votre Redis vous-même) :
   ```bash
   helm repo add bitnami https://charts.bitnami.com/bitnami
   ```
   puis, dans `Chart.yaml`, ajoutez `bitnami/redis` à `dependencies:` avec la
   condition `redis.enabled`, et lancez `helm dependency update helm/sentinelle`.
   **Cette dépendance n'est volontairement pas déclarée dans le dépôt** : la
   vendre obligerait chaque `helm template` (donc chaque job CI) à télécharger
   une archive depuis `charts.bitnami.com`. Un rendu qui dépend d'un accès
   réseau n'est pas une garantie reproductible.
3. **Redis embarqué** (démonstration, `redis.enabled=true`, défaut) : un seul
   pod, sans réplication, **sans persistance et sans authentification**. Il perd
   ses données à chaque redémarrage. Acceptable pour la file de scans en
   démonstration, jamais pour une mise en production.

## Secret et ordre de démarrage

L'API exécute `alembic upgrade head` au premier boot (`app/db.py -> init_db`).
Le worker écrivant dans le même schéma, **déployez l'API avant le worker** :

```bash
kubectl -n sentinelle rollout status deployment/sentinelle-api
kubectl -n sentinelle rollout restart deployment/sentinelle-worker
```

Tant que les migrations vivent dans le démarrage de l'API, gardez
`api.replicaCount: 1` : deux réplicas lanceraient la même migration en
parallèle. Pour scaler l'API au-delà, déplacez les migrations dans un Job
(hook `pre-upgrade`) ou un `initContainer` — c'est la contrepartie assumée de
ce choix.

## Contexte de sécurité — durci par défaut, avec deux exceptions documentées

Défauts (`securityContext`) : `runAsNonRoot: true`, `runAsUser: 10001`,
`allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`,
`capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`, et un volume
`emptyDir` sur `/tmp` pour l'API (Python/uvicorn ont besoin d'un temporaire
inscriptible même en racine en lecture seule).

Deux composants dérogent, **volontairement** :

| Composant | Dérogation | Raison |
| --- | --- | --- |
| worker | `runAsNonRoot: false`, `runAsUser: 0`, `readOnlyRootFilesystem: false`, `capabilities.add: [NET_RAW]` | L'image officielle est construite en root et met en cache les gabarits nuclei sous `/root/.config/nuclei`, tandis que nmap/nuclei écrivent leurs temporaires et leurs mises à jour dans le conteneur. Passer en non-root suppose de reconstruire l'image avec un utilisateur dédié et `HOME` inscriptible — hors périmètre de la charte. `NET_RAW` est la seule capacité conservée : exécuté en root, nmap choisit le scan SYN (`-sS`), qui exige des sockets brutes ; la retirer ferait échouer `-sV` en `EPERM`. `allowPrivilegeEscalation: false` reste actif. |
| web | `runAsNonRoot: false`, capacités `NET_BIND_SERVICE`, `SETUID`, `SETGID`, `CHOWN`, `DAC_OVERRIDE` | `nginx:alpine` démarre en root puis abandonne ses droits via `setuid`. Sans root ni capacités correspondantes, le master nginx échoue sur `setuid()` et le conteneur meurt. Variante durcie possible : fournir un `nginx.conf` complet écoutant sur 8080 et passer `web.securityContext.pod.runAsNonRoot=true`. |

Préciser le profil `restricted` de Pod Security Admission au namespace rejettera
le worker et le web tels quels ; `baseline` est le profil compatible par défaut.

> Pour surcharger un contexte par composant, rappel : la fusion se fait par
> `mergeOverwrite`, qui **ne sait pas supprimer une clé**. Un composant passé en
> `runAsNonRoot: false` doit donc aussi redéclarer `runAsUser: 0`, sinon il
> hérite du `runAsUser: 10001` global. Les surcharges de listes
> (`capabilities.drop`/`add`) remplacent la liste globale au lieu de s'y ajouter.

## Sondes

| Composant | `readinessProbe` / `livenessProbe` | Détail |
| --- | --- | --- |
| API | `GET /api/health` | Endpoint réel (`app/main.py`). Un `startupProbe` couvre les migrations Alembic du boot : sans lui, une migration plus longue que le délai de vivacité provoquerait un `CrashLoopBackOff`. |
| Web | `GET /` | Requête servie par nginx (index.html du SPA). Une panne de l'API ne fait **pas** redémarrer le frontend : responsabilités distinctes. |
| Worker | `exec` sur `/proc/1/cmdline` | **Aucune sonde HTTP inventée.** Le worker n'ouvre aucun port. `pgrep` (paquet `procps`) est absent de l'image `python:3.12-slim` ; une sonde `pgrep -f 'arq app.worker.settings'` échouerait en boucle et redémarrerait un worker sain. La sonde vérifie donc, avec `tr`/`grep`, que la ligne de commande de PID 1 contient `app.worker.settings`. Si `pgrep` devient disponible dans l'image, `pgrep -f 'arq app.worker.settings'` est équivalent. |
| Redis (démo) | `redis-cli ping` | Sonde recommandée par l'image officielle. |

Chaque conteneur dispose de `resources.requests` et `resources.limits` (QoS
`Burstable`). Le worker est calibré plus haut : nmap et nuclei sont gourmands en
CPU et en mémoire.

## Mise à l'échelle automatique

`autoscaling.enabled=true` crée un HPA CPU pour l'API et le frontend. Le worker
est **exclu par défaut** : son CPU ne décrit pas sa charge (un scan passe
l'essentiel de son temps à attendre le réseau). Le bon signal est la profondeur
de la file arq dans Redis, que le HPA natif ne sait pas lire — utilisez
[KEDA](https://keda.sh/) avec le scaler Redis et laissez
`autoscaling.worker.enabled` à `false`.

## Valeurs principales

| Clé | Défaut | Rôle |
| --- | --- | --- |
| `existingSecret` | `sentinelle-secrets` | Nom du Secret portant les valeurs sensibles |
| `image.pullPolicy` / `image.pullSecrets` | `IfNotPresent` / `[]` | Réglages communs aux images |
| `{api,worker,web}.image.{repository,tag,pullPolicy}` | `ghcr.io/sentinelle/*` | Un tag vide retombe sur `appVersion` |
| `{api,worker,web}.replicaCount` | `1` / `1` / `2` | Réplicas (ignorés quand le HPA est actif) |
| `config.*` | cf. `values.yaml` | Environnement non secret (`CERT_FEEDS`, `RETENTION_DAYS`, OIDC, `FRONTEND_URL`…) |
| `postgresql.*` | hôte de repli | Instance managée externe |
| `redis.enabled` / `redis.external.host` | `true` / `""` | Redis de démonstration ou externe |
| `ingress.enabled` | `false` | Exposition HTTP |
| `autoscaling.enabled` | `false` | HPA API + web |
| `podDisruptionBudget.enabled` | `false` | PDB API + web |
| `resources.*` | cf. `values.yaml` | Requêtes/limites par conteneur |

## Vérifier la charte

```bash
helm lint helm/sentinelle
helm template sentinelle helm/sentinelle
helm template sentinelle helm/sentinelle \
  --set ingress.enabled=true --set autoscaling.enabled=true --set redis.enabled=false
```

## Hors périmètre

* migrations de schéma en Job dédié (aujourd'hui au démarrage de l'API) ;
* `NetworkPolicy`, `ServiceMonitor` Prometheus, anti-affinité imposée ;
* chiffrement au repos des constats (#18) et supervision (#19) : ces sujets
  concernent l'application, pas son packaging.
