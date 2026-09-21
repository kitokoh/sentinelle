# Secrets externalisés — Sentinelle (v0.6, issue #17)

> Référence courte. Le document complet (inventaire des secrets, procédure de
> rotation, cas Vault) est **[docs/SECRETS.md](../../docs/SECRETS.md)**.

## Le principe

**Aucun secret n'est committé.** Le dépôt ne contient que :

1. des **noms** de variables (`backend/.env.example`, la ConfigMap Helm) ;
2. des **placeholders** explicites (`change-me-in-production`) qui font échouer
   ou avertissent au démarrage ;
3. des **références** à un secret externe (`existingSecret` dans le chart Helm,
   `${VAR:-défaut}` dans Compose).

La CI vérifie la règle avec **gitleaks** (job `secrets`), sur l'arbre de travail
**et** sur l'historique git : un secret committé puis supprimé reste détecté.

## SOPS + age (voie recommandée en démonstration)

SOPS chiffre les valeurs *dans un fichier YAML ou dotenv* et laisse les clés en
clair, ce qui rend les diffs relisibles. age sert de porte-clés : une clé privée
locale, une clé publique committée.

```bash
# 1. Générer une paire de clés (une seule fois par opérateur)
age-keygen -o ~/.config/sops/age/keys.txt     # affiche la clé PUBLIQUE (age1...)

# 2. La déclarer destinataire
$EDITOR deploy/secrets/.sops.yaml             # remplacer age1REMPLACER_PAR_VOTRE_CLE_PUBLIQUE

# 3. Créer / modifier le fichier de secrets
make secrets-edit                             # ouvre une copie déchiffrée dans $EDITOR

# 4. Déchiffrer au déploiement, sans jamais écrire en clair sur disque
make secrets-show                             # affiche (pour vérification)
eval "$(make secrets-export)"                 # exporte dans l'environnement courant
```

`deploy/secrets/sentinelle.enc.yaml` est la **seule** forme versionnée. Le
`.gitignore` couvre les variantes en clair.

## Vault (alternative)

Si une instance Vault est disponible, le chemin est plus court pour la rotation :

```bash
vault kv put secret/sentinelle \
  jwt_secret="$(openssl rand -base64 48)" \
  field_encryption_key="$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"

# Injection à l'exécution, sans fichier intermédiaire :
export JWT_SECRET="$(vault kv get -field=jwt_secret secret/sentinelle)"
```

Vault apporte en plus l'audit des accès aux secrets et l'expiration automatique
(leases). SOPS reste préférable quand l'infrastructure est un simple VPS ou un
déploiement Compose, ce qui est le cas ici.

## Ce que la CI refuse

| Situation | Détection |
|---|---|
| Clé d'API en clair dans un fichier versionné | gitleaks — job `secrets` |
| Mot de passe dans `docker-compose.yml` | gitleaks + `tests/test_secrets_hygiene.py` |
| Secret dans les `values.yaml` Helm | `tests/test_secrets_hygiene.py` (le chart n'accepte qu'`existingSecret`) |
| `.env` committé par erreur | `.gitignore` + test d'hygiène |
