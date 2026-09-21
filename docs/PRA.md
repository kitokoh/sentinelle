# Plan de reprise d'activité (PRA) — Sentinelle

Issue [#20](https://github.com/kitokoh/sentinelle/issues/20) — v0.6 « Durcissement
production ».

Document de référence pour **repartir après sinistre** : ce qui est sauvegardé,
ce qui ne l'est pas, ce que l'on perd au pire, en combien de temps on repart, et
comment on s'en assure avant d'en avoir besoin.

Outils : [`deploy/backup/backup.sh`](../deploy/backup/backup.sh) et
[`deploy/backup/restore.sh`](../deploy/backup/restore.sh) — mode d'emploi détaillé
et procédure d'exercice dans [deploy/backup/README.md](../deploy/backup/README.md).

> **Ce document décrit une reprise, pas une haute disponibilité.** Sentinelle
> s'exécute aujourd'hui sur un nœud unique (`docker compose`). Un PRA dit
> comment revenir ; il ne dit pas comment ne pas tomber. L'absence de bascule
> automatique est une limite assumée (§ 7).

---

## 1. Périmètre et vocabulaire

| Terme | Définition retenue ici |
|---|---|
| **RPO** — *Recovery Point Objective* | quantité de données qu'on accepte de perdre, exprimée en temps. C'est la question « jusqu'à quand en arrière ? » |
| **RTO** — *Recovery Time Objective* | délai maximal pour que le service redevienne utilisable. C'est la question « pendant combien de temps c'est indisponible ? » |
| **Dump** | archive `pg_dump --format=custom` produite chaque nuit |
| **Exercice** (*drill*) | restauration réelle d'un dump dans une base jetable, avec vérification des comptages |

**Ce que la reprise doit rendre** : une plateforme où un analyste peut se
connecter, voir son tableau de bord, ses cibles, ses constats, ses alertes et
son journal d'audit. Autrement dit : **la base** et la pile qui la sert.

## 2. Les cibles, en clair

| Indicateur | Cible affichée | Ce que ça veut dire concrètement |
|---|---|---|
| **RPO** | **24 h** | Au pire, on perd la dernière journée d'activité (cibles créées, scans lancés, constats produits, alertes reçues, lignes de journal). La sauvegarde a lieu chaque nuit à 03:45. |
| **RTO** | **2 h** | Au pire, la plateforme est indisponible pendant deux heures, vérifications comprises, sur une instance de démonstration. |

Le README annonce ces deux valeurs ; elles sont la référence contractuelle tant
qu'une ligne différente n'a pas été décidée ici.

**Ces chiffres sont des cibles d'ingénierie, pas des mesures.** La seule partie
déjà outillée et chronométrée est la restauration du dump elle-même
(`restore.sh` imprime sa durée). Les étapes humaines du RTO doivent être
mesurées en exercice (§ 5) ; en l'absence d'exercice consigné, la cible reste une
intention.

## 3. Justification

### RPO = 24 h

- **Ce qui détermine le RPO est le mécanisme de sauvegarde, pas une envie.** Le
  dispositif est une passe `pg_dump` **quotidienne** sur PostgreSQL **sans
  archivage WAL** : entre deux dumps, il n'existe aucune copie des transactions
  intermédiaires. La perte maximale vaut donc exactement l'intervalle entre deux
  sauvegardes, soit 24 h, et non une valeur choisie.
- **Ce RPO est acceptable pour une instance de démonstration** — c'est la
  qualification qui compte. Une journée de constats de démonstration peut être
  reproduite en relançant les scans sur les mêmes cibles autorisées.
- **Il ne serait pas acceptable en production**, et l'asymétrie des données le
  montre : dans Sentinelle, tout n'est pas recalculable (tableau ci-dessous).

| Nature de la donnée | Recalculable ? |
|---|---|
| Constats nmap/nuclei, score de risque | **Oui** — un scan peut être relancé sur la même cible autorisée (c'est le principe même de la plateforme) |
| Cibles, utilisateurs, organisations | Non, mais re-saisissables en quelques minutes sur un périmètre de démo |
| Alertes Suricata, événements capteur | **Non** — le trafic réseau qui les a produits n'existe plus. Une détection perdue est perdue définitivement |
| **Journal d'audit** | **Non** — c'est la trace de qui a fait quoi. Sa valeur est juridique : un trou dans le journal n'est pas réparable |

C'est cette asymétrie — le journal d'audit et les détections ne se rattrapent
pas — qui justifie de viser un RPO de quelques minutes dès qu'on parle de
production (§ 7).

### RTO = 2 h

Le budget se décompose ainsi (instance de démonstration, un seul nœud) :

| Étape | Budget | Nature |
|---|---|---|
| Constat du sinistre et décision de restaurer | 15 min | humaine |
| Redémarrage de la pile (`docker compose up -d --build`) sur un hôte disponible | 20 min | technique |
| Restauration du dump (`restore.sh`, **chronométrée**) + `ANALYZE` | 30 min | technique, mesurée |
| Vérifications (§ 5, comptages et intégrité) | 15 min | humaine |
| Reprise d'activité : statuts de scans incohérents, reprise des jobs, réamorçage des flux de renseignement | 30 min | humaine + technique |
| Marge | 10 min | — |
| **Total** | **120 min** | |

Pourquoi 30 minutes allouées à la restauration : une base de démonstration pèse
quelques centaines de Mo ; `pg_restore` sur un PostgreSQL local traite cela en
quelques minutes. Le budget est volontairement cinq à dix fois supérieur au
temps attendu, parce que l'ordre de grandeur qui compte est celui d'un
**exercice réussi en conditions dégradées** (hôte plus lent, dump plus gros que
prévu, opérateur sous stress), pas celui d'un `time` sur un poste au repos.

Deux composantes du RTO méritent d'être nommées, car elles sont souvent
oubliées :

- **l'`ANALYZE`** : `pg_dump` n'embarque pas les statistiques du planificateur
  (documentation PostgreSQL). Sans lui, la base restaurée répond avec de mauvais
  plans sur les agrégations du tableau de bord — c'est-à-dire que la plateforme
  peut être « revenue » au sens du code retour, et échouer au critère de
  performance pourtant publié (100 req/s, p95 < 500 ms — voir
  [deploy/load/README.md](../deploy/load/README.md)) ;
- **les statuts de scans incohérents** : les scans en vol au moment du dump
  réapparaissent actifs, alors qu'aucun job ne les exécute (file Redis perdue).
  Les remettre en état fait partie de la reprise, pas du nettoyage (§ 5, étape 6).

## 4. Ce qui est sauvegardé, ce qui ne l'est pas

Le tableau exhaustif (et sa justification ligne à ligne) est dans
[deploy/backup/README.md § 1](../deploy/backup/README.md). Le résumé :

| Élément | Sauvegardé ? | Comment s'en sortir |
|---|---|---|
| PostgreSQL (schéma + données + journal d'audit) | **Oui**, chaque nuit | restauration du dernier dump |
| File Redis (scans en attente/en cours) | **Non**, éphémère par conception | marquer les scans orphelins en échec, relancer les scans voulus |
| Journal EVE brut de Suricata | **Non** (déjà ingéré en base) | au pire les 15 dernières secondes, cadence du job d'ingestion |
| Secrets (`JWT_SECRET`, `FIELD_ENCRYPTION_KEY`, mots de passe) | **Non** (hors base) | **indispensables** : sans `FIELD_ENCRYPTION_KEY`, les champs chiffrés au repos restent illisibles même restaurés. À conserver dans un coffre |
| Realm Keycloak | Non — versionné (`deploy/keycloak/realm-sentinelle.json`) | redéployé avec la pile |
| Copie hors site du dump | **Non — trou connu** | à couvrir par un `rsync`/`restic` vers un autre site (§ 6, § 7) |

## 5. Procédure de reprise

### Étape 0 — Qualification du sinistre

Deux cas, deux traitements :

| Cas | Exemple | Traitement |
|---|---|---|
| **Perte d'hôte** | disque mort, serveur inaccessible | reconstruction de la pile + restauration complète (ci-dessous) |
| **Corruption logique** | migration ratée, purge trop agressive, suppression de données | restauration **dans une base jetable** d'abord, comparaison, puis bascule ou restauration ciblée (jamais « écraser la production » en premier réflexe : l'état actuel peut contenir les données saines) |

### Étapes

1. **Constater et décider** (15 min) — le responsable de la plateforme qualifie le
   sinistre et choisit l'horodatage de reprise : le dump le plus récent est le
   choix par défaut, le dump de la veille peut être préférable si l'incident est
   une corruption logique détectée le lendemain.
2. **Provisionner** (20 min) — hôte disponible, dépôt déployé, `docker compose up -d`
   (base + Redis + API + worker + web). Les services applicatifs démarrent avec
   les **mêmes secrets** qu'avant (sinon les jetons et les champs chiffrés sont
   perdus).
3. **Restaurer** (30 min) — `createdb -T template0`, puis `restore.sh` avec
   confirmation explicite. Le script imprime la durée réelle : la comparer au
   budget. La procédure exacte est dans
   [deploy/backup/README.md § 5](../deploy/backup/README.md).
4. **Vérifier** (15 min) — **compter des lignes**, pas se contenter d'un code
   retour : comptages des tables métier, absence de constats/scans orphelins,
   présence de la révision Alembic, et lecture du tableau de bord sur la base
   restaurée. Les requêtes sont fournies dans
   [deploy/backup/README.md § 7](../deploy/backup/README.md).
5. **`ANALYZE`** — exécuté automatiquement par `restore.sh` (sauf `--no-analyze`).
   S'il a été sauté, le lancer avant d'annoncer la reprise : sans statistiques,
   le tableau de bord ne tient pas ses seuils.
6. **Remettre la plateforme d'aplomb** (30 min) — marquer en échec les scans
   dont le statut est actif sans job, relancer les scans utiles, déclencher une
   synchronisation de renseignement (les flux sont re-téléchargeables), vérifier
   que le worker reprend ses tâches périodiques (ingestion, purge, corrélations).
7. **Clôturer** — consigner : heure de début, heure de reprise, dump utilisé,
   durée mesurée, écarts constatés. Une reprise non consignée ne pourra pas être
   améliorée.

## 6. S'assurer que ça marche : les exercices

**Pourquoi un exercice plutôt qu'une case cochée** : une sauvegarde n'a aucune
valeur tant qu'une restauration n'a pas été faite avec. Le scénario que ce
document doit empêcher est celui où l'on découvre, le jour du sinistre, que le
dump est tronqué, que la cible manque de droits, ou que la procédure n'existait
que dans la tête d'une personne. Et **un code retour 0 de `pg_restore` ne prouve
rien** : une restauration peut réussir sans qu'aucune ligne ne soit exploitable.
D'où la règle : un exercice **compte** des lignes.

| | |
|---|---|
| **Fréquence** | avant chaque mise en production ; a minima une fois par trimestre ; après tout changement de schéma ou montée de version majeure de PostgreSQL |
| **Durée** | environ 30 min |
| **Procédure** | [deploy/backup/README.md § 7](../deploy/backup/README.md) |
| **Critères de réussite** | code retour 0 **et** comptages non nuls et cohérents **et** 0 ligne orpheline **et** durée compatible avec le budget RTO |
| **Après l'exercice** | noter les durées réelles, corriger le budget s'il est faux, nettoyer la base jetable |

### Suivi des exercices

| Date | Dump utilisé | Durée restauration | Écart aux comptages | Résultat | Commentaire |
|---|---|---|---|---|---|
| _à planifier_ | — | — | — | — | **aucun exercice exécuté à ce jour** : le RTO de 2 h n'est pas encore validé par une mesure |

> Cette ligne vide est volontaire et honnête : l'outillage est en place
> (scripts, procédure, critères), la cible n'est pas encore corroborée par un
> exercice réel. Tant qu'elle reste vide, lire le RTO comme un objectif, pas
> comme une mesure. Le premier exercice **doit** avoir lieu avant toute annonce
> externe de ce chiffre.

## 7. Limites connues

1. **RPO de 24 h, pas de PITR.** PostgreSQL tourne sans archivage WAL : on ne
   peut pas rejouer les transactions jusqu'à une seconde près. Atteindre un RPO
   de quelques minutes exige une **réplication en flux** vers un second serveur
   ou un **archivage WAL continu** (pgBackRest, barman, `wal-g`). C'est la
   première évolution à financer si Sentinelle passe en production ; ces
   mécanismes changent radicalement le RPO, pas le RTO.
2. **Pas de copie hors site.** Le dump reste sur le même hôte (`BACKUP_DIR`
   local) : une panne matérielle ou un rançongiciel emporte les deux copies. À
   couvrir par une réplication de fichiers chiffrée vers un autre site — une
   ligne de cron, mais un prérequis non négociable pour parler de reprise.
3. **Rotation limitée** (`RETENTION_DAYS=7` par défaut) : une corruption
   constatée plus de sept jours après les faits n'est plus rattrapable.
4. **Pas de haute disponibilité, pas de bascule automatique.** Le RTO inclut donc
   l'intervention humaine, et une reprise de nuit est plus lente qu'une reprise
   en heures ouvrées : le RTO annoncé suppose une personne joignable.
5. **Secrets hors périmètre.** Une restauration avec une `FIELD_ENCRYPTION_KEY`
   différente rend des champs illisibles sans erreur visible. Le coffre de
   secrets fait partie de la reprise, même s'il n'est pas dans ce document.
6. **Objets globaux non sauvegardés** (rôles PostgreSQL, *tablespaces*) :
   `pg_dump` ne couvre qu'une base. À confirmer lors du premier exercice.
7. **L'outillage n'est pas testé en CI** : la syntaxe des scripts, la règle de
   nommage et la rotation sont couvertes par
   [`backend/tests/test_operations.py`](../backend/tests/test_operations.py),
   mais la restauration elle-même ne l'est pas (aucun PostgreSQL n'est consommé
   par ces tests). Cela reste un exercice humain, d'où l'importance de le
   planifier réellement.
8. **Les chiffres annoncés valent pour une instance de démonstration.** Un
   déploiement réel (base plus grosse, secteur public, exigences réglementaires)
   doit refaire ce PRA avec ses propres mesures et, probablement, une autre
   architecture de sauvegarde.

## 8. Évolutions vers un RPO de quelques minutes

Par ordre de rendement décroissant :

1. **Archivage WAL continu + PITR** (`pgBackRest` ou `barman`) : le RPO passe de
   24 h à quelques minutes, avec la possibilité de revenir à une seconde près
   avant une corruption logique. C'est la réponse directe à la limite n° 1.
2. **Copie hors site chiffrée et testée** : sans elle, les points suivants
   n'auraient pas de sens (limite n° 2).
3. **Réplication en flux** vers un second nœud : réduit le RTO en supprimant la
   restauration complète (bascule), et sert de source pour des exercices sur
   données réelles.
4. **Automatiser l'exercice** : restauration nocturne dans une base jetable,
   comparaison automatique des comptages, alerte en cas d'écart. C'est ce qui
   transforme « la sauvegarde existe » en « la sauvegarde est prouvée ».
5. **Page de reprise dans l'interface** : rendre l'état de la dernière
   sauvegarde et du dernier exercice visible sans se connecter au serveur.

## 9. Renvois

| Sujet | Où |
|---|---|
| Sauvegarde, rotation, cron, procédure de drill | [deploy/backup/README.md](../deploy/backup/README.md) |
| Tests de charge et seuils de performance | [deploy/load/README.md](../deploy/load/README.md) |
| Composants et flux | [docs/ARCHITECTURE.md](ARCHITECTURE.md) |
| Rétention des données (purge) | [docs/ARCHITECTURE.md](ARCHITECTURE.md) et `app/services/retention.py` |
| Rôles, isolation par organisation | [docs/RBAC.md](RBAC.md) |
| Cadre légal et périmètre autorisé | [SECURITY.md](../SECURITY.md) |
