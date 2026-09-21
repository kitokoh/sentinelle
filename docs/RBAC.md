# RBAC & isolation — matrice des rôles et frontières de données

> v0.5 (issues #12 et #15). Ce document est la référence d'autorisation de la
> plateforme. Toute route de l'API doit être justifiable par une ligne de la
> matrice ci-dessous.

## Les trois rôles

| Rôle (code) | Libellé | Ce qu'il peut faire |
|---|---|---|
| `viewer` | Lecteur | Lire : tableau de bord, cibles, scans, constats, alertes, renseignement, rapports PDF/CSV |
| `analyst` | Analyste | Tout ce que fait le lecteur, **plus** : déclarer/supprimer une cible, lancer un scan, acquitter une alerte, déclencher une synchronisation de renseignement |
| `admin` | Administrateur | Tout ce que fait l'analyste, **plus** : gérer les utilisateurs et consulter le journal d'audit |

La hiérarchie est **stricte** : `admin ⊃ analyst ⊃ viewer`. Un rôle supérieur
possède toujours les droits du rôle inférieur — il n'existe pas de permission
accordée à un lecteur mais refusée à un administrateur.

## La matrice, endpoint par endpoint

| Endpoint | Méthode | Lecteur | Analyste | Admin |
|---|---|---|---|---|
| `/api/auth/me` | GET | ✅ | ✅ | ✅ |
| `/api/dashboard/stats` | GET | ✅ | ✅ | ✅ |
| `/api/targets` | GET | ✅ | ✅ | ✅ |
| `/api/targets` | POST | ⛔ 403 | ✅ | ✅ |
| `/api/targets/{id}` | GET | ✅ | ✅ | ✅ |
| `/api/targets/{id}` | DELETE | ⛔ 403 | ✅ | ✅ |
| `/api/scans` | GET | ✅ | ✅ | ✅ |
| `/api/scans` | POST | ⛔ 403 | ✅ | ✅ |
| `/api/scans/{id}` | GET | ✅ | ✅ | ✅ |
| `/api/scans/{id}/export` | GET | ✅ | ✅ | ✅ |
| `/api/scans/{id}/report.pdf` | GET | ✅ | ✅ | ✅ |
| `/api/alerts` · `/stats` | GET | ✅ | ✅ | ✅ |
| `/api/alerts/{id}` | PATCH | ⛔ 403 | ✅ | ✅ |
| `/api/intel/**` | GET | ✅ | ✅ | ✅ |
| `/api/intel/sync` | POST | ⛔ 403 | ✅ | ✅ |
| `/api/users` | GET | ⛔ 403 | ⛔ 403 | ✅ |
| `/api/users/{id}/role` | PATCH | ⛔ 403 | ⛔ 403 | ✅ |
| `/api/users/organization` | GET | ✅ | ✅ | ✅ |
| `/api/audit` · `/actions` | GET | ⛔ 403 | ⛔ 403 | ✅ |

Les routes publiques sont volontairement hors matrice : `/api/health`,
`/api/auth/login`, `/api/auth/register` et le flux `/api/auth/oidc/*`.

## Comment c'est appliqué

Une seule dépendance FastAPI, dans `app/api/deps.py` :

```python
from app.api.deps import viewer_required, analyst_required, admin_required

@router.post("", dependencies=[])          # lecture : tout membre de l'organisation
async def list_targets(user: User = Depends(viewer_required)): ...

@router.post("")                            # écriture : analyste minimum
async def create_target(user: User = Depends(analyst_required)): ...

@router.get("")                             # administration : admin seulement
async def list_users(user: User = Depends(admin_required)): ...
```

### Le refus est *fail closed*

Un rôle inconnu (faute de frappe en base, valeur héritée d'une ancienne version)
est traité comme `viewer`, le niveau le plus faible :

```python
def normalise(role): return role if role in ROLE_ORDER else "viewer"
```

Une valeur inattendue doit faire **perdre** des privilèges, jamais en donner.
Le message de refus indique le rôle requis et le rôle effectif, pour qu'un
opérateur comprenne sans lire le code :

```
This action requires the 'analyst' role or higher. Your role is 'viewer' (Lecteur).
```

## Isolation entre organisations

Depuis la v0.5, chaque donnée appartient à une **organisation** (table
`organizations`). Deux frontières se cumulent — en fermer une seule laisserait un
trou :

1. **Tenant** — `org_id` sur `users`, `targets`, `scans`, `findings`, `alerts`.
   Toute lecture filtre dessus.
2. **Propriétaire** — les cibles et les scans restent, en plus, filtrés sur
   `owner_id`. Deux analystes de la même organisation ne voient pas les cibles
   l'un de l'autre ; c'est un choix de cloisonnement interne, pas une frontière
   de sécurité.

### 404, jamais 403

Une ressource d'une autre organisation répond **404**, pas 403 : un 403
confirmerait que l'identifiant existe, ce qui est déjà une fuite d'information.

### Les alertes plateforme

`alerts.org_id` est **nullable** et `NULL` a un sens précis : *plateforme*.
Le flux du capteur Suricata et les correspondances de renseignement appartiennent
à la plateforme, pas à un client, et sont donc visibles par toutes les
organisations. Un `org_id` non nul est en revanche une frontière dure.

| `alerts.org_id` | Origine | Visibilité |
|---|---|---|
| `NULL` | Capteur Suricata, corrélation renseignement | Toutes les organisations |
| `42` | Alerte rattachée à une organisation | Organisation 42 uniquement |

C'est un choix assumé : un capteur réseau unique alimente la plateforme entière.
Une instance multi-capteurs par client relèvera de la v0.6.

## Garde-fous d'administration

Deux règles empêchent de se verrouiller hors de son propre compte :

- **un administrateur ne peut pas retirer son propre rôle** (erreur 400) ;
- **un rôle inexistant est refusé à l'écriture** (erreur 422) — sans quoi une
  faute de frappe serait stockée, puis silencieusement rétrogradée en `viewer` à
  l'autorisation, sans que personne ne comprenne pourquoi.

## Vérifications

```bash
cd backend && pytest tests/test_rbac.py tests/test_tenancy.py -q
```

`tests/test_rbac.py` croise la matrice : chaque endpoint sensible est appelé par
les trois rôles. `tests/test_tenancy.py` ne contient que des **cas négatifs** :
la fuite cross-tenant est ce qu'on teste.
