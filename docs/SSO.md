# SSO / OIDC — brancher Keycloak

> v0.5 (issue #14). Ce document décrit le flux implémenté, comment le configurer,
> et ce qui se passe quand le fournisseur d'identité est indisponible.

## Principe

L'authentification déléguée **s'ajoute** à l'authentification locale, elle ne la
remplace pas. Une instance dont le fournisseur d'identité tombe reste
administrable par mot de passe : c'est la condition pour ne pas se retrouver
enfermé dehors lors d'une panne d'annuaire.

## Démarrage avec Keycloak

```bash
SENTINELLE_CLIENT_SECRET=un-secret-solide \
  docker compose --profile sso up -d
```

Le realm `sentinelle` est importé automatiquement (`deploy/keycloak/realm-sentinelle.json`) :

| Élément | Valeur |
|---|---|
| Console d'administration | http://localhost:8081 (`admin` / `KC_ADMIN_PASSWORD`) |
| Realm | `sentinelle` |
| Client | `sentinelle` (confidentiel, code d'autorisation + PKCE S256) |
| Rôles de realm | `sentinelle-admin`, `sentinelle-analyst` |
| Comptes de démonstration | `admin.demo@sentinelle.local`, `analyste.demo@sentinelle.local` (mot de passe `Demo2026!`) |

> ⚠️ Le secret du client n'est **pas** écrit dans le fichier de realm : il est
> injecté par variable d'environnement (`"secret": "${env.SENTINELLE_CLIENT_SECRET}"`).
> Le fichier reste donc versionnable sans embarquer de secret — voir l'issue #17.

## Configuration côté API

```bash
OIDC_ISSUER=http://localhost:8081/realms/sentinelle
OIDC_CLIENT_ID=sentinelle
OIDC_CLIENT_SECRET=…            # doit correspondre à celui du client Keycloak
OIDC_REDIRECT_URI=http://localhost:8000/api/auth/oidc/callback
OIDC_SCOPES=openid profile email
OIDC_ROLE_CLAIM=realm_access.roles
OIDC_ADMIN_ROLES=sentinelle-admin,admin
OIDC_ANALYST_ROLES=sentinelle-analyst,analyst
OIDC_DEFAULT_ROLE=viewer
FRONTEND_URL=http://localhost:5173
```

Les **trois premières** sont nécessaires : sans l'une d'elles, le SSO est
désactivé et le bouton n'apparaît pas sur la page de connexion
(`GET /api/auth/oidc/config` dit laquelle manque).

## Le flux

```
Navigateur → GET /api/auth/oidc/login
                  │  state = JWT signé, valable 10 min (pas de session serveur)
                  ▼
            302 vers le fournisseur (authorization_endpoint)
                  │  l'utilisateur s'authentifie
                  ▼
         GET /api/auth/oidc/callback?code=…&state=…
                  │  1. vérification du state
                  │  2. échange du code (authlib) → access_token + id_token
                  │  3. lecture des claims → rôle Sentinelle
                  │  4. création/liaison du compte
                  ▼
  302 vers {FRONTEND_URL}/auth/callback#token=<JWT Sentinelle>
```

### Trois choix à connaître

**Le `state` est un JWT, pas une session.** Aucun stockage serveur à garder
cohérent entre plusieurs workers ; la protection CSRF tient quand même.

**Les claims sont lus dans le jeton reçu à l'instant, sur TLS.** Le *token
endpoint* est joint sur une connexion TLS vérifiée : la signature n'est pas
revérifiée, ce qui évite de gérer le JWKS du realm pour aucun gain de sécurité
dans ce flux. La découverte du fournisseur, elle, est bien récupérée en HTTPS et
mise en cache.

**Le jeton revient dans le fragment d'URL** (`#token=…`). Les fragments ne sont
pas transmis au serveur : le jeton n'apparaît donc pas dans les journaux du
reverse proxy. La page `/auth/callback` le stocke puis recharge l'application.

## Mapping des rôles

Le claim est configurable (`OIDC_ROLE_CLAIM`), `realm_access.roles` par défaut.
**Le privilège le plus élevé l'emporte** : un compte porteur de
`sentinelle-analyst` *et* `sentinelle-admin` est administrateur.

| Rôles du fournisseur | Rôle Sentinelle |
|---|---|
| `sentinelle-admin` (ou `admin`) | `admin` |
| `sentinelle-analyst` (ou `analyst`) | `analyst` |
| aucun rôle reconnu, ou aucun rôle | `viewer` |

Un compte sans rôle reconnu obtient **le minimum** : c'est le seul défaut
défendable pour une identité dont on ne sait rien. La comparaison est insensible
à la casse mais ne devine rien : `admin-ish` n'est pas `admin`.

## Provisionnement des comptes

- **Nouveau compte** : créé dans l'organisation par défaut, avec un mot de passe
  **aléatoire et inutilisable**. Un compte SSO ne peut donc pas être attaqué par
  la route de connexion locale.
- **Compte local existant portant le même e-mail** : il est **lié** au compte du
  fournisseur, et son rôle est rafraîchi depuis celui-ci. Cela suppose que le
  fournisseur vérifie les adresses e-mail — c'est la raison de cette note.
- **Connexion suivante** : le compte est retrouvé par son identifiant stable
  (`sso_subject`), jamais dupliqué.

## Diagnostic

| Symptôme | Cause probable |
|---|---|
| Pas de bouton SSO | une des trois variables `OIDC_*` manque → `GET /api/auth/oidc/config` le dit |
| `SSO is not configured` (503) | idem, appel direct à `/oidc/login` |
| `The identity provider could not be reached` (502) | découverte injoignable : URL, réseau ou certificat |
| Retour sur `/login?sso_error=invalid_state` | `state` expiré (> 10 min) ou altéré |
| Retour avec `sso_error=exchange_failed` | secret de client erroné, ou `redirect_uri` non déclarée côté Keycloak |
| Tout le monde arrive en `viewer` | les rôles de realm ne sont pas dans le jeton : vérifier le mapper `realm roles` du client |
