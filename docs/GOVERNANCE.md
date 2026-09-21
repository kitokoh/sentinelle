# Gouvernance du dépôt

> v0.7 (issue #23). Ce qui est **appliqué** et ce qui est **documenté mais non
> appliqué** sont séparés : mélanger les deux fait croire à des garanties qui
> n'existent pas.

## Ce qui est appliqué

| Mesure | État | Preuve |
|---|---|---|
| CI obligatoire sur `main` | ✅ | protection de branche : 7 vérifications requises |
| PR obligatoire (pas de push direct) | ✅ | protection de branche |
| Pas de force-push ni de suppression de `main` | ✅ | protection de branche |
| CODEOWNERS | ✅ | `/CODEOWNERS` |
| Gabarits d'issue et de PR | ✅ | `.github/ISSUE_TEMPLATE/`, `.github/pull_request_template.md` |
| Détection de secrets en CI | ✅ | job `secrets` (gitleaks, arbre + historique) |
| Barrière de couverture | ✅ | job `backend` (80 % global, 90 % modules critiques) |

```bash
# Rejouer la configuration de protection (idempotent)
./scripts/apply-branch-protection.sh

# Vérifier ce qui est réellement appliqué
curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/repos/kitokoh/sentinelle/branches/main/protection | jq
```

### Les 7 vérifications requises

`backend (sqlite)`, `backend (postgres)`, `migrations`, `secrets`, `helm`, `e2e`, `frontend`.

Deux d'entre elles méritent une justification, parce qu'elles ne sont pas
évidentes :

- **`backend (postgres)` en plus de `backend (sqlite)`** : un bug de production
  a vécu plusieurs semaines parce que la suite ne tournait que sur SQLite (voir
  `backend/app/models/columns.py`). Une seule base de test ne prouve pas la
  portabilité du schéma.
- **`helm`** : un chart qui ne se rend pas est un chart que personne ne déploiera,
  et une erreur de gabarit ne se voit qu'au rendu.
- **`e2e`** : les tests unitaires ne voient pas une rupture de contrat entre le
  front et l'API. Celui-ci a été mis en place après avoir trouvé exactement ce
  genre de bug : le front lisait `scan.target.name` alors que l'API renvoie
  `target_name`, et toutes les pages Scans affichaient « Cible #N ».

### `enforce_admins: false`, et pourquoi

Le propriétaire peut encore fusionner malgré une vérification rouge. C'est
délibéré : la protection sert à rendre la barrière **explicite**, pas à
s'enfermer dehors. Un dépôt à un seul mainteneur où une vérification instable rend
`main` immuable est un dépôt qu'on finit par déprotéger entièrement. Le maintien
de cette exception est un choix, pas un oubli.

## Ce qui est documenté mais non appliqué

| Mesure | Pourquoi pas encore |
|---|---|
| **Commits signés** (SSH ou GPG) | Aucune clé n'est associée au compte. Les commits actuels sont donc non signés, et un contrôle « tout est signé » échouerait. La procédure est ci-dessous. |
| **Mode vigilance** (`vigilant mode`) | Se règle dans l'interface GitHub, par utilisateur, pas par API de dépôt. |
| **Revue obligatoire par un tiers** | Sans second mainteneur, exiger une approbation bloquerait toute fusion. À activer à la première arrivée. |

### Activer les commits signés

```bash
# 1. Générer une clé SSH de signature (à ne pas confondre avec une clé d'authentification)
ssh-keygen -t ed25519 -C "signature@exemple" -f ~/.ssh/id_ed25519_signing

# 2. Déclarer la clé comme clé de signature auprès de GitHub
gh ssh-key add ~/.ssh/id_ed25519_signing.pub --type signing

# 3. Dire à git de s'en servir
git config --global user.signingkey ~/.ssh/id_ed25519_signing.pub
git config --global gpg.format ssh
git config --global commit.gpgsign true
```

Puis, dans GitHub → *Settings → SSH and GPG keys*, activer le **mode vigilance** :
les commits non signés apparaîtront alors explicitement comme tels.

Vérifier ce qui est signé dans le dépôt :

```bash
./scripts/verify-signatures.sh          # résumé sur les 20 derniers commits
./scripts/verify-signatures.sh --strict # code de sortie 1 si un commit n'est pas signé
```

Le mode `--strict` est destiné à un futur job de CI : il échoue aujourd'hui sur
les commits antérieurs à la mise en place, c'est attendu.

## Règles de contribution

1. **Une branche par sujet**, nommée `feat/…`, `fix/…`, `ops/…`, `docs/…`.
2. **Une PR par sujet**, référençant l'issue fermée (`Closes #N`).
3. **Les tests d'abord** : une correction sans test qui la reproduit n'est pas
   terminée.
4. **La documentation fait partie de la définition de fini** : code + tests +
   doc, sinon la fonctionnalité n'existe que pour son auteur.
5. **Aucun secret committé** — la CI refuse.

La définition de fini complète est dans [BACKLOG.md](BACKLOG.md) ; la matrice de
rôles et les frontières de données dans [RBAC.md](RBAC.md).
