# Secrets — inventaire, gestion et rotation

> v0.6 (issue #17). Ce document est la référence : tout secret utilisé par la
> plateforme doit y figurer, avec sa source et sa procédure de rotation. Un secret
> qui n'est pas dans ce tableau est un secret que personne ne saura faire tourner.

## Règle unique

**Aucun secret n'est committé.** Le dépôt ne contient que des noms de variables,
des placeholders explicites, et des références à un secret externe. Cette règle
est vérifiée en CI par **gitleaks**, sur l'arbre de travail *et* sur l'historique
git : un secret committé puis supprimé reste détecté.

## Inventaire

| Secret | Variable | Rôle | Source en production | Rotation |
|---|---|---|---|---|
| Clé de signature JWT | `JWT_SECRET` | signe les jetons d'accès | SOPS+age / Vault | trimestrielle ; invalide les sessions en cours |
| Clé de chiffrement au repos | `FIELD_ENCRYPTION_KEY` | Fernet sur `findings.detail` et `alerts.payload` (#18) | SOPS+age / Vault | **voir la procédure dédiée ci-dessous** |
| Mot de passe PostgreSQL | `POSTGRES_PASSWORD` | accès à la base | SOPS+age / Vault | semestrielle, avec redémarrage de l'API et du worker |
| Clé API MISP | `MISP_API_KEY` | lecture des attributs (#6) | console MISP (compte de service en lecture seule) | annuelle, ou immédiate en cas de départ |
| Clé API OTX | `OTX_API_KEY` | pulses souscrits (#7) | console AlienVault | annuelle |
| Secret client OIDC | `OIDC_CLIENT_SECRET` | échange du code d'autorisation (#14) | console Keycloak | annuelle ; doit rester **identique** à `SENTINELLE_CLIENT_SECRET` |
| Secret client Keycloak (provisionnement) | `SENTINELLE_CLIENT_SECRET` | injecté dans le realm au démarrage de Keycloak (`${env.…}`) | variables d'environnement / Vault | annuelle ; la valeur du realm et celle de l'API doivent être changées ensemble |
| Mot de passe d'administration Keycloak | `KC_ADMIN_PASSWORD` | console d'administration du realm | variables d'environnement / Vault | semestrielle |
| Jeton de scrape | `METRICS_TOKEN` | protège `/metrics` (#19) | SOPS+age / Vault | annuelle |
| Mot de passe Grafana | `GRAFANA_ADMIN_PASSWORD` | console de supervision | SOPS+age / Vault | annuelle |
| Secrets de démonstration Keycloak | — | comptes `*.demo` du realm | **démonstration uniquement** | à supprimer avant tout déploiement réel |

## Rotation de `FIELD_ENCRYPTION_KEY` (le cas délicat)

Changer cette clé **sans re-chiffrer les données rend les valeurs illisibles** :
`decrypt_text` renvoie alors un placeholder `[chiffré — clé indisponible]` au lieu
de planter, et journalise une erreur. La procédure est donc outillée, pas laissée
à la main :

```bash
# 1. Générer la nouvelle clé
NEW=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')

# 2. Simuler d'abord : combien de valeurs seraient concernées ?
make rotate-key DRY=1 FIELD_ENCRYPTION_KEY_OLD="$FIELD_ENCRYPTION_KEY" FIELD_ENCRYPTION_KEY_NEW="$NEW"

# 3. Re-chiffrer en place (déchiffre avec l'ancienne, écrit avec la nouvelle)
make rotate-key FIELD_ENCRYPTION_KEY_OLD="$FIELD_ENCRYPTION_KEY" FIELD_ENCRYPTION_KEY_NEW="$NEW"

# 4. Basculer la variable et redémarrer API + worker
export FIELD_ENCRYPTION_KEY="$NEW"
```

Le script est `backend/scripts/rotate_field_key.py`. Trois propriétés rendent
l'opération sûre :

- **re-chiffrement en place** : aucune fenêtre pendant laquelle les données sont
  illisibles, et le service peut rester en marche ;
- **refus de détruire** : si l'ancienne clé n'ouvre pas une ligne, le script
  s'arrête avec une erreur explicite au lieu d'écraser la valeur ;
- **les clés passent par l'environnement**, jamais par la ligne de commande — un
  secret en argument finit dans `ps` et dans l'historique du shell.

Un test (`backend/tests/test_crypto.py`) vérifie les trois, sur une base isolée.

C'est aussi la raison pour laquelle la clé est distincte de `JWT_SECRET` : sans
`FIELD_ENCRYPTION_KEY` explicite, la clé est **dérivée de `JWT_SECRET`**, et faire
tourner ce dernier casserait la lecture des données chiffrées. Le code journalise
un avertissement explicite dans ce cas au démarrage.

## Procédure standard (SOPS + age)

```bash
./scripts/secrets.sh init       # créer le fichier chiffré (valeurs aléatoires)
./scripts/secrets.sh edit       # modifier une valeur
eval "$(./scripts/secrets.sh export)"   # injecter dans la session, sans fichier en clair
./scripts/secrets.sh rotate jwt_secret  # rotation ciblée
```

Le fichier chiffré `deploy/secrets/sentinelle.enc.yaml` est le seul artefact
versionné. Les destinataires age sont déclarés dans `deploy/secrets/.sops.yaml` :
**chaque administrateur a sa propre clé**, plus une clé de secours hors ligne —
perdre la seule clé privée, c'est perdre définitivement les secrets.

## Alternative Vault

Vault apporte le journal d'accès aux secrets et l'expiration automatique (leases),
ce que SOPS ne sait pas faire :

```bash
vault kv put secret/sentinelle jwt_secret="$(openssl rand -base64 48)"
export JWT_SECRET="$(vault kv get -field=jwt_secret secret/sentinelle)"
```

SOPS reste préférable sans infrastructure dédiée (VPS, déploiement Compose), ce
qui est le cas du démonstrateur.

## Défauts de démonstration

`docker-compose.yml` utilise `${VAR:-défaut}` : la valeur vient toujours de
l'environnement, et le défaut n'existe que pour que `docker compose up` fonctionne
sans configuration. Ces défauts (`sentinelle`, `change-me-in-production`) sont
**inutilisables en production** et documentés comme tels — `tests/test_secrets_hygiene.py`
échoue si une valeur littérale apparaît à la place d'une interpolation.

## Déploiement

| Cible | Mécanisme |
|---|---|
| Docker Compose | `${VAR:-placeholder}` — la valeur vient de l'environnement, jamais du fichier |
| Kubernetes (chart Helm) | `existingSecret` — le chart ne crée un Secret que si on le lui demande explicitement, et refuse alors de rendre sans les valeurs |
| API / worker locaux | `.env` (dans `.gitignore`) ou `eval "$(./scripts/secrets.sh export)"` |

## Vérification

```bash
# Aucun secret dans le dépôt (arbre + historique)
gitleaks detect --source . --config .gitleaks.toml --redact --exit-code 1

# Hygiène des fichiers de configuration
cd backend && pytest tests/test_secrets_hygiene.py -q
```

Ces deux commandes sont exécutées par la CI (job `secrets`).
