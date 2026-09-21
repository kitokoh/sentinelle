# Tests de charge — Sentinelle (issue #20)

Test de charge du **tableau de bord** : on vérifie que l'API tient
**100 requêtes/seconde soutenues** sur `GET /api/dashboard/stats` sans erreur,
avec une latence p95 maîtrisée.

Script : [`k6-dashboard.js`](k6-dashboard.js) — [k6](https://k6.io) (Go, binaire
unique, pas de runtime à installer côté serveur).

> ⚖️ **Périmètre** — un test de charge ne s'exécute que contre une instance dont
> vous êtes responsable (instance de démo, labo, préproduction). Le même cadre
> légal que les scans s'applique : voir [SECURITY.md](../../SECURITY.md). En
> particulier, ne jamais lancer ce script contre une plateforme tierce.

---

## 1. Pourquoi le dashboard est le canari

`GET /api/dashboard/stats` est l'endpoint le plus lourd de la plateforme :

| Ce qu'il fait | Pourquoi c'est un bon révélateur |
|---|---|
| 4 `COUNT(*)` filtrés (cibles, scans, constats, alertes) + jointures | une index manquant ou une dérive de schéma se voit tout de suite |
| 1 `GROUP BY severity` sur les constats | agrégation, pas seulement de la lecture de ligne |
| 1 tri + `LIMIT 5` avec jointure cible/scan | coût variable avec le volume d'historique |
| Dépendance à la session base et au middleware d'audit | mesure la chaîne complète : nginx → uvicorn → PostgreSQL, pas seulement une fonction |

C'est aussi la page d'accueil : c'est la requête que **tout le monde** déclenche
en même temps, y compris (et surtout) pendant un incident. Et c'est une lecture
pure (`viewer_required`) : le test ne crée ni scan, ni alerte, ni ligne d'audit,
donc il ne fausse pas les données qu'il mesure.

## 2. Prérequis

```bash
# Option 1 — binaire unique (dépôts officiels Grafana) :
#   https://grafana.com/docs/k6/latest/set-up/install-k6/
# Option 2 — conteneur, rien à installer sur l'hôte :
docker run --rm --network host \
  -e SENTINELLE_BASE_URL=http://localhost:8000 \
  -e SENTINELLE_EMAIL=admin@sentinelle.local \
  -e SENTINELLE_PASSWORD=Sentinelle2026! \
  -v "$PWD/deploy/load:/load:ro" grafana/k6 run /load/k6-dashboard.js
```

Une instance amorcée (compte de démonstration + quelques données, sinon on
mesure une base vide, ce qui n'est pas la peine) :

```bash
docker compose up -d --build
docker compose exec api python seed.py
curl -s http://localhost:8000/api/health
```

## 3. Lancer le test

```bash
export SENTINELLE_BASE_URL=http://localhost:8000
export SENTINELLE_EMAIL=admin@sentinelle.local      # compte de démo (seed.py)
export SENTINELLE_PASSWORD=Sentinelle2026!

k6 run deploy/load/k6-dashboard.js
# contre l'interface complète (nginx + SPA + API) plutôt que l'API seule :
#   SENTINELLE_BASE_URL=http://localhost:3000 k6 run deploy/load/k6-dashboard.js
```

| Variable | Défaut | Rôle |
|---|---|---|
| `SENTINELLE_BASE_URL` | `http://localhost:8000` | base de l'API (`:3000` mesure en plus la couche nginx) |
| `SENTINELLE_EMAIL` | — (requis) | compte utilisé pour l'authentification |
| `SENTINELLE_PASSWORD` | — (requis) | mot de passe (jamais écrit dans le script) |
| `SENTINELLE_TARGET_RPS` | `100` | débit visé ; permet d'explorer la limite de la plateforme |
| `SENTINELLE_DURATION` | `2m` | durée de chaque scénario |

Les identifiants passent par l'environnement, **jamais** par le dépôt : le
script lit `__ENV`, et `SENTINELLE_PASSWORD` est un secret comme un autre.

## 4. Ce qui est mesuré

| Métrique k6 | Signification | Seuil |
|---|---|---|
| `http_req_failed` | taux de requêtes en échec (réseau, 4xx/5xx) | `rate<0.01` (< 1 %) |
| `http_req_duration{scenario:dashboard}` | latence du dashboard | `p(95)<500` ms |
| `http_req_duration{scenario:reads}` | latence des autres lectures | `p(95)<300` ms |
| `checks` | vérifications fonctionnelles (HTTP 200, corps exploitable) | `rate>0.99` |
| `dropped_iterations` | itérations que k6 **n'a pas pu placer** | `count==0` |
| `iterations{scenario:dashboard}` | débit réellement atteint | ~100/s ⇒ 12 000 en 2 min |

## 5. Ce que veut dire le seuil d'acceptation

**« 100 req/s sans erreur »** = `http_req_failed < 1 %` **pendant que la cadence
de 100 req/s est effectivement tenue**. Les deux moitiés de la phrase comptent :

- **1 % de tolérance et pas 5 %** : sur un tableau de bord de supervision, une
  requête perdue est une décision prise à l'aveugle. La tolérance laisse la
  place aux aléas réseau et aux `keep-alive` qui se ferment, pas aux erreurs
  applicatives.
- **Le débit compte autant que les erreurs** : un test qui n'aurait exécuté que
  40 req/s en affichant 0 % d'erreur serait *vert* et pourtant mensonger. C'est
  pourquoi `dropped_iterations: ['count==0']` est un seuil du scénario : si k6
  n'arrive pas à placer les itérations, **le test échoue** au lieu de flatter la
  plateforme. Si ce seuil casse, augmenter `preAllocatedVUs` … ou constater que
  la latence réelle interdit la cadence visée.
- Un seuil franchi fait sortir k6 en **code retour 99** (`ThresholdsHaveFailed`),
  et une exception de script en 107 : le test est donc directement exploitable
  comme critère d'acceptation dans un script ou une CI (`k6 run … || echo KO`).

**Latence** : p95 < 500 ms pour le dashboard, parce qu'au-delà l'interface
paraît figée et la plateforme n'est plus « temps réel » ; p95 < 300 ms pour les
lectures simples. La moyenne est volontairement absente du rapport — elle
cacherait précisément la queue de distribution qui dégrade l'expérience.

## 6. Lire le résultat

```
http_req_duration{scenario:dashboard}...: avg=42ms  med=31ms  p(95)=180ms p(99)=410ms
http_req_failed........................: 0.00%  ✓ 0  ✗ 0
dropped_iterations.....................: 0       ✓ 0  ✗ 0
checks.................................: 100.00% ✓ 25320 ✗ 0
iterations{scenario:dashboard}.........: 12000   (≈ 100/s)
```

*(exemple : 12 000 itérations × 2 vérifications, plus le scénario secondaire)*

- **Tout est vert** ⇒ critère d'acceptation rempli pour cette instance et ce
  jeu de données.
- **`http_req_failed` monte** ⇒ d'abord vérifier les logs de l'API
  (`docker compose logs api`) : 5xx = base ou pool de connexions saturé ; 401 =
  jeton expiré (campagne > 60 min) ; erreurs réseau = nginx ou `ulimit`.
- **`dropped_iterations > 0`** ⇒ la plateforme n'a pas tenu la cadence. Ce n'est
  pas un échec du script, c'est le résultat : la latence réelle ne permet pas
  100 req/s avec les ressources provisionnées.
- **p95 dégradé mais pas d'erreur** ⇒ chercher côté PostgreSQL (index, volume de
  la table `findings`, `shared_buffers`) avant de chercher côté Python.

## 7. Limites (à lire avant de citer un chiffre)

- **C'est un test de tenue, pas une étude de capacité.** Une instance de démo
  (PostgreSQL et API sur un même hôte, sans réplication, sans pool dimensionné)
  n'est pas un dimensionnement de production. Le chiffre qui compte pour un
  dossier public est « l'instance de démonstration tient 100 req/s sur le
  dashboard avec moins de 1 % d'erreur », pas « Sentinelle encaisse N req/s ».
- **Une seule forme de charge** : de la lecture agrégée. Scans concurrents,
  ingestion Suricata et synchronisations de renseignement (write-lourds) ne sont
  pas couverts ici.
- **SQLite n'est pas PostgreSQL** : un résultat obtenu en dev SQLite ne dit rien
  de la tenue en production. Mesurer sur PostgreSQL.
- **k6 ne mesure pas l'expérience réelle** : pas de rendu navigateur, pas de
  chargement des cartes. Mesurer la page complète demande un autre outil
  (Playwright, Lighthouse).
- Les seuils sont ceux d'un test exécuté **à la main** ou en acceptation avant
  livraison ; aucun test de charge n'est lancé en CI (pas d'instance ni de base
  disponibles dans les runners GitHub Actions).

## 8. Reproduire en une commande

```bash
docker compose up -d --build && docker compose exec api python seed.py
SENTINELLE_EMAIL=admin@sentinelle.local SENTINELLE_PASSWORD=Sentinelle2026! \
  k6 run deploy/load/k6-dashboard.js
```

Résultat, seuils et limites se lisent dans le rapport k6 et dans
[docs/PRA.md](../../docs/PRA.md) pour ce qui concerne la reprise.
