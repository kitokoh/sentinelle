# Sauvegarde & restauration PostgreSQL — Sentinelle (issue #20)

- [`backup.sh`](backup.sh) — `pg_dump --format=custom`, rotation, somme sur une
  ligne, conçu pour cron.
- [`restore.sh`](restore.sh) — restauration d'un dump, garde-fou contre la
  fausse manœuvre, chronométrage du RTO.
- Plan de reprise complet, RPO/RTO et limites :
  [docs/PRA.md](../../docs/PRA.md).

> **RPO 24 h / RTO 2 h** sur une instance de démonstration (une seule passe
> `pg_dump` par nuit, PostgreSQL sans archivage WAL). Chiffres, justification et
> limites : [docs/PRA.md](../../docs/PRA.md).

---

## 1. Ce qui est sauvegardé (et ce qui ne l'est pas)

`pg_dump` sauvegarde **une base** : tout le schéma (les migrations Alembic
comprises, table `alembic_version` incluse) et toutes les données applicatives.

| Sauvegardé | Détail |
|---|---|
| Utilisateurs, organisations | comptes, rôles, appartenances |
| Cibles, scans, constats | y compris scores de risque et résultats nmap/nuclei |
| Alertes, événements capteur | détections Suricata normalisées |
| Renseignement | IoC, avis CERT, états d'ingestion |
| Journal d'audit | la trace de qui a fait quoi — valeur juridique, non recalculable |

| **Non** sauvegardé | Pourquoi, et conséquence |
|---|---|
| File Redis (jobs `arq`) | éphémère par conception : les scans en vol sont perdus. À reprendre explicitement après restauration (§ 6) |
| Journal EVE brut de Suricata | les événements déjà ingérés sont en base ; au pire les 15 dernières secondes (cadence du job `ingest_eve`) sont perdues |
| Statistiques du planificateur | `pg_dump` ne les embarque **pas** (documentation PostgreSQL) : d'où l'`ANALYZE` exécuté par `restore.sh` |
| Rôles, mots de passe, *tablespaces*, extensions du cluster | objets globaux, hors périmètre d'un `pg_dump` ; ils doivent exister dans la cible (voir § 9) |
| Realm Keycloak | versionné dans `deploy/keycloak/realm-sentinelle.json` : c'est de la configuration, pas de la donnée |
| Secrets (`JWT_SECRET`, `FIELD_ENCRYPTION_KEY`, `PGPASSWORD`…) | hors base, par construction. **À conserver par ailleurs** : sans `FIELD_ENCRYPTION_KEY`, des constats chiffrés au repos restent illisibles, même restaurés |
| Copie hors site | **non faite par ces scripts** : `BACKUP_DIR` est local. Un sinistre du serveur emporte la sauvegarde avec lui (§ 9) |

## 2. Paramètres (environnement)

| Variable | Défaut | Rôle |
|---|---|---|
| `PGHOST` / `PGPORT` | `localhost` / `5432` | serveur PostgreSQL |
| `PGUSER` | — (**requis**) | compte de sauvegarde ; aucun défaut volontaire (libpq choisirait le compte système) |
| `PGDATABASE` | — (**requis**) | base à sauvegarder |
| `PGPASSWORD` | — | mot de passe ; **préférer `~/.pgpass`** (chmod 600), qui ne le laisse pas traîner dans l'environnement |
| `BACKUP_DIR` | `/var/backups/sentinelle` | destination des dumps |
| `RETENTION_DAYS` | `7` | rotation : dumps strictement plus vieux que N jours. `0` ou négatif : rotation désactivée (même convention que `RETENTION_DAYS` de l'application) |
| `PG_DUMP_LOCK_TIMEOUT` | `60s` | au-delà, `pg_dump` échoue au lieu de rester bloqué |
| `RESTORE_CONFIRM` | — | doit valoir exactement `1` pour autoriser une restauration |
| `RESTORE_TARGET_DB` | — | base cible d'une restauration (ou `--dbname`) |
| `RESTORE_JOBS` | `1` | parallélisme `pg_restore --jobs` |

## 3. Sauvegarde manuelle

```bash
PGHOST=localhost PGUSER=sentinelle PGDATABASE=sentinelle \
  BACKUP_DIR=/var/backups/sentinelle RETENTION_DAYS=7 \
  ./deploy/backup/backup.sh
```

Sortie (une seule ligne, conçue pour un journal) :

```
sentinelle-backup: OK base=sentinelle fichier=/var/backups/sentinelle/sentinelle_20260921T034500Z.dump octets=8123456 duree=4s supprimes=1 conservation_jours=7 debut=2026-09-21T03:45:02Z
```

En cas d'échec, la ligne `sentinelle-backup: ECHEC base=… horodatage=…` est
écrite sur `stderr` et le code retour est non nul : c'est ce que cron alertera.

**Propriétés de sûreté du script** (chacune répond à un échec vécu ailleurs) :

- le dump est écrit en `.dump.partial` puis renommé : un fichier
  `sentinelle_*.dump` **existe ⇔ il est complet et vérifié** ;
- tôt après le dump, l'archive est contrôlée par `pg_restore --list` — sans
  aucune base : c'est la seule vérification possible au moment où l'on produit
  la sauvegarde ;
- `--no-password` : en cron, personne ne saisira de mot de passe, donc on échoue
  au lieu de rester suspendu ;
- `umask 077` (`PATH` fixé) : un dump contient des données personnelles
  (courriels, empreintes de mots de passe, journal d'audit) ;
- rotation **après** création : la sauvegarde de la nuit ne peut pas être
  supprimée par la rotation de la nuit, même si `RETENTION_DAYS` est petit ;
- la rotation nettoie aussi les `.partial` **orphelins** (plus de 24 h) : un
  `SIGKILL` ou un reboot ne laisse pas toujours le piège `EXIT` s'exécuter, et
  ces fichiers ne correspondent pas au motif des dumps — sans cette règle, ils
  s'accumuleraient indéfiniment. Le `.partial` d'une sauvegarde **en cours** est
  épargné (fraîcheur < 24 h).

## 4. Planification (cron)

```cron
# Sauvegarde PostgreSQL Sentinelle — tous les jours à 03:45 (heure du serveur).
# 03:45 et non 03:15 : la purge de rétention du worker s'exécute à 03:15
# (app/worker/settings.py). Les deux horaires produiraient un état tout aussi
# cohérent, mais sauvegarder *après* la purge donne une sauvegarde plus simple à
# expliquer lors d'un exercice de reprise.
# Serveur en UTC recommandé ; sinon adapter l'heure.
45 3 * * * PGHOST=db PGPORT=5432 PGUSER=sentinelle PGDATABASE=sentinelle BACKUP_DIR=/var/backups/sentinelle RETENTION_DAYS=7 /opt/sentinelle/deploy/backup/backup.sh >> /var/log/sentinelle-backup.log 2>&1
```

Le mot de passe se met dans `~/.pgpass` du compte qui exécute la tâche, **pas**
dans la ligne de crontab (lisible par tous, recopiée dans les sauvegardes de
fichiers de configuration) :

```bash
# ~/.pgpass — doit appartenir à l'utilisateur et être en chmod 600, sinon libpq l'ignore
printf '%s:%s:%s:%s:%s\n' db 5432 sentinelle sentinelle 'mot-de-passe' >> ~/.pgpass
chmod 600 ~/.pgpass
```

### Rotation

- un fichier par nuit : `sentinelle_<AAAAMMJJ>T<hhmmss>Z.dump` — timestamps en
  **UTC** (une nuit d'automne dure 25 heures en heure locale : deux dumps
  porteraient le même nom, et le second écraserait le premier) ;
- `RETENTION_DAYS=7` ⇒ environ une semaine d'historique, soit **7 fenêtres de
  reprise** : de quoi revenir en arrière après une suppression de données
  constatée plusieurs jours plus tard, ce que la fenêtre RPO de 24 h ne
  couvrirait pas ;
- la rotation **n'est pas** le RPO. Le RPO (24 h) est la perte maximale en cas
  de sinistre ; la rotation est la profondeur de l'historique conservé.

### Où exécuter la tâche

`docker-compose.yml` **ne publie pas** le port de PostgreSQL (le service `db`
n'est joignable que sur le réseau compose). Deux options, aucune modification de
la pile n'étant nécessaire :

1. **Recommandé** — exécuter la tâche depuis un hôte qui atteint la base (serveur
   de base, hôte de sauvegarde) avec `postgresql-client` de version ≥ serveur :
   `PGHOST` = adresse de la base.
2. Depuis un hôte qui n'a que Docker — l'image officielle `postgres:16` contient
   les outils clients (`bash`, `pg_dump`, `pg_restore`, `psql`) :
   ```bash
   # <nom_du_projet>_default : réseau créé par docker compose (projet = dossier)
   docker run --rm --network sentinelle_default \
     -e PGHOST=db -e PGPORT=5432 -e PGUSER=sentinelle -e PGDATABASE=sentinelle -e PGPASSWORD=… \
     -e BACKUP_DIR=/backup \
     -v /var/backups/sentinelle:/backup \
     -v /opt/sentinelle/deploy/backup/backup.sh:/backup/backup.sh:ro \
     postgres:16 bash /backup/backup.sh
   ```
   Le dump est écrit dans le répertoire **hôte** monté sur `/backup` ; le reste
   du conteneur est jetable.

## 5. Restaurer une sauvegarde

```bash
# 1. base cible vide : template0 garantit l'absence d'objets hérités de template1
createdb -T template0 -h localhost -p 5432 -U sentinelle sentinelle_drill

# 2. restauration — destructive, donc confirmée explicitement
RESTORE_CONFIRM=1 ./deploy/backup/restore.sh --dbname sentinelle_drill \
    /var/backups/sentinelle/sentinelle_20260921T034500Z.dump
```

`restore.sh` :

- **refuse de s'exécuter** sans `--yes` ni `RESTORE_CONFIRM=1`, et n'accepte que
  la valeur exacte `1` (un « oui » approximatif n'est pas un consentement) ;
- **ne déduit jamais** la base cible de `PGDATABASE` : il faut `--dbname` ou
  `RESTORE_TARGET_DB`. Une restauration destructive ne doit pas pouvoir viser la
  base de production par oubli d'un paramètre ;
- avertit si la cible porte le nom de la base d'origine (restauration *en
  place*, légitime après sinistre, rarement ce que l'on croit taper) ;
- vérifie la cible avant de commencer (une erreur de connexion claire vaut mieux
  que cinquante lignes de `pg_restore`) ;
- applique `--clean --if-exists --no-owner --no-privileges` : le dump ne porte
  pas les affectations de propriétaire (options ignorées pour les formats
  archive), c'est donc à la restauration de les poser ;
- est en `--exit-on-error` par défaut : un exercice de reprise doit **échouer
  bruyamment**, pas se terminer à moitié ;
- exécute `ANALYZE` ensuite, parce que `pg_dump` n'embarque pas les statistiques
  du planificateur : sans cela, la base restaurée répond avec de mauvais plans
  et le dashboard peut violer son seuil p95 (celui du test de charge). Une
  reprise qui « répond » mais qui viole le p95 n'est pas une reprise réussie ;
- **chronomètre** et imprime la durée réelle : `--dry-run` affiche la commande
  sans rien modifier (les contrôles, y compris de joignabilité, sont faits).

| Code retour | Signification |
|---|---|
| `0` | restauration terminée |
| `2` | refusée : confirmation absente ou usage invalide — **rien n'a été touché** |
| `3` | précondition non tenue : dump introuvable/vide, cible injoignable, `pg_restore` absent |
| autre | code retour de `pg_restore` |

## 6. Après restauration : remettre la plateforme d'aplomb

La base restaurée est un instantané : les **scans en vol au moment du dump**
sont réapparus avec un statut actif, alors qu'aucun job correspondant n'existe
dans Redis (file perdue). Sans cette étape, l'interface affiche des scans qui ne
finiront jamais.

```bash
psql -d sentinelle -c "SELECT status, count(*) FROM scans GROUP BY status ORDER BY 1;"
# marquer les zombies, puis relancer les scans utiles depuis l'interface
psql -d sentinelle -c "UPDATE scans SET status='failed', finished_at=now() WHERE status IN ('pending','running');"
```

À faire aussi selon l'ampleur du sinistre : re-déclencher une synchronisation de
renseignement (les flux sont re-téléchargeables, rien de critique n'est perdu) et
vérifier que le worker redémarre bien ses tâches périodiques.

## 7. L'exercice de reprise (drill) — obligatoire

**Pourquoi un exercice plutôt qu'une case cochée** : une sauvegarde n'a
strictement aucune valeur tant qu'une restauration n'a pas été faite avec. Le
seul échec que ce document ne doit pas permettre, c'est de découvrir au pire
moment que le dump est tronqué, que la cible manque de droits, ou que la
procédure n'est écrite que dans la tête d'une personne. Un **code retour 0 de
`pg_restore` ne prouve pas une reprise** : un dump peut être complet
structurellement et vide de données, une restauration peut « réussir » sans
qu'aucune ligne ne soit utilisable. D'où l'étape 3 ci-dessous, qui **compte des
lignes**.

Fréquence : **avant chaque mise en production** (ou au moins une fois par
trimestre), et après tout changement de schéma ou de version majeure de
PostgreSQL. Consigner le résultat dans le tableau de suivi de
[docs/PRA.md](../../docs/PRA.md).

### Procédure (à exécuter sur un serveur de recette, pas en production)

```bash
export PGHOST=localhost PGPORT=5432 PGUSER=sentinelle
export DUMP=/var/backups/sentinelle/sentinelle_20260921T034500Z.dump

# 0. OPTIONNEL mais utile : un dump frais, pour une comparaison exacte des
#    comptages. Avec le dump de la nuit, la production a travaillé depuis et des
#    écarts de quelques pour cent sont normaux — pas pour autant un échec.
BACKUP_DIR=/tmp/sentinelle-drill ./deploy/backup/backup.sh
DUMP=$(ls -1t /tmp/sentinelle-drill/*.dump | head -n 1)

# 1. base de travail, garantie vide (template0, jamais template1)
dropdb --if-exists sentinelle_drill
createdb -T template0 sentinelle_drill

# 2. restauration confirmée + chronométrée (durée = partie outillée du RTO)
RESTORE_CONFIRM=1 ./deploy/backup/restore.sh --dbname sentinelle_drill "$DUMP"

# 3. COMPTAGES — c'est le cœur de l'exercice
psql -d sentinelle_drill <<'SQL'
SELECT 'organizations' AS table_name, count(*) AS lignes FROM organizations
UNION ALL SELECT 'users',            count(*) FROM users
UNION ALL SELECT 'targets',          count(*) FROM targets
UNION ALL SELECT 'scans',            count(*) FROM scans
UNION ALL SELECT 'findings',         count(*) FROM findings
UNION ALL SELECT 'alerts',           count(*) FROM alerts
UNION ALL SELECT 'sensor_events',    count(*) FROM sensor_events
UNION ALL SELECT 'audit_logs',       count(*) FROM audit_logs
UNION ALL SELECT 'iocs',             count(*) FROM iocs
UNION ALL SELECT 'intel_feed_items', count(*) FROM intel_feed_items
ORDER BY table_name;
SQL

# 4. INTÉGRITÉ — chaque requête doit renvoyer 0
psql -d sentinelle_drill <<'SQL'
SELECT 'findings orphelins' AS controle, count(*) AS attendu_zero
  FROM findings f LEFT JOIN scans s ON s.id = f.scan_id WHERE s.id IS NULL
UNION ALL
SELECT 'scans orphelins', count(*)
  FROM scans s LEFT JOIN targets t ON t.id = s.target_id WHERE t.id IS NULL
;
-- doit renvoyer exactement 1 ligne : le schéma restauré est bien migré
SELECT 'revision Alembic', count(*) FROM alembic_version;
SQL
```

**Critères de réussite** — les trois, pas seulement le premier :

1. `restore.sh` sort en `0` (aucune erreur, `--exit-on-error`) et la durée
   mesurée reste compatible avec le budget RTO de 2 h ;
2. les comptages des tables métier (users, targets, scans, findings, alerts)
   sont **non nuls** et cohérents avec la source (égalité stricte si l'étape 0 a
   été faite juste avant ; écart faible et explicable sinon) ;
3. l'étape 4 renvoie `0` partout : la base restaurée est **utilisable**, pas
   seulement présente.

Optionnel, pour éprouver la chaîne complète (le meilleur test réaliste) : pointer
une API éphémère sur la base restaurée et lire le dashboard.

```bash
cd backend && DATABASE_URL=postgresql+asyncpg://sentinelle@localhost:5432/sentinelle_drill \
  uvicorn app.main:app --port 8001 &
# puis GET /api/dashboard/stats avec un jeton valide : les agrégats doivent
# répondre — c'est exactement la requête du test de charge (deploy/load/)
```

Nettoyage (l'exercice ne doit pas laisser d'instance de test qui traîne) :

```bash
dropdb --if-exists sentinelle_drill
rm -rf /tmp/sentinelle-drill
```

### Ce qu'un exercice doit vérifier en plus (si la cause est réaliste)

| Variante | Ce que ça valide |
|---|---|
| restauration sur une **autre machine** | la sauvegarde est autonome (pas de dépendance à un chemin local) |
| restauration avec un **autre compte** PostgreSQL | les droits suffisent (grâce à `--no-owner`) |
| restauration d'un dump **de la veille** | la rotation conserve bien l'historique attendu |
| `--dry-run` sur la base de production | la commande finale est relue à froid, avant le jour où elle sera tapée sous stress |

## 8. Hygiène et sécurité

- Un dump est une **copie complète des données personnelles** (courriels,
  empreintes de mots de passe, journal d'audit) : `chmod 700` sur `BACKUP_DIR`,
  `umask 077` dans le script, et pas de dépôt dans un espace partagé.
- Transfert et stockage hors site : **à chiffrer**. Le script ne le fait pas
  (voir § 9).
- Sauvegarder la sauvegarde : un dump sur le même disque que la base ne protège
  ni d'une panne matérielle, ni d'un rançongiciel.
- Ne jamais restaurer un dump d'origine non fiable : la restauration exécute du
  code SQL arbitraire (avertissement de la documentation `pg_restore`).

## 9. Limites connues

- **Une seule passe par jour, pas d'archivage WAL** ⇒ RPO de 24 h. Un RPO de
  quelques minutes exige une réplication en flux ou un archivage WAL avec PITR
  (pgBackRest, barman…) — voir [docs/PRA.md](../../docs/PRA.md) § Évolutions.
- **Pas de copie hors site** : `backup.sh` écrit dans `BACKUP_DIR`, et c'est
  tout. C'est le trou le plus grave de ce dispositif, et il se comble avec un
  `rsync`/`restic` vers un autre site (une ligne de cron), hors du périmètre de
  ces scripts.
- **Objets globaux non sauvegardés** (rôles, mots de passe, *tablespaces*) :
  `pg_dump` ne couvre qu'une base. Ils doivent être recréés à la main, ou
  sauvegardés par `pg_dumpall --globals-only`. Sans extensions particulières,
  l'application n'en dépend pas, mais l'exercice doit le confirmer.
- **`pg_restore --jobs > 1` n'arrête pas à la première erreur** : le détail des
  échecs devient un compteur de fin de restauration. À réserver au mode
  exploration, pas à l'exercice certifié.
- **Le temps de reprise mesuré ici n'est pas le RTO** : il ne compte ni la
  décision, ni le provisionnement, ni les vérifications humaines.
- **Aucun test automatisé** de ces scripts en CI : les runners GitHub Actions du
  projet n'exécutent pas de PostgreSQL pour la recette ops (l'image de la CI
  contient un service PostgreSQL, mais le déclencher pour un exercice de
  restauration n'a pas été fait). Ce qui est vérifié automatiquement :
  syntaxe (`bash -n`), mode exécutable, règle de nommage et rotation
  (`backend/tests/test_operations.py`) — le drill, lui, reste humain.

## 10. Aide-mémoire

```bash
# sauvegarder
PGDATABASE=sentinelle PGUSER=sentinelle ./deploy/backup/backup.sh

# vérifier une archive sans base
pg_restore --list /var/backups/sentinelle/sentinelle_20260921T034500Z.dump | less

# voir ce qui serait restauré, sans rien toucher
./deploy/backup/restore.sh --yes --dbname sentinelle_drill --dry-run <dump>

# restaurer (destructif)
RESTORE_CONFIRM=1 ./deploy/backup/restore.sh --dbname sentinelle_drill <dump>
```
