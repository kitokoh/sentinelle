#!/usr/bin/env bash
#
# backup.sh — sauvegarde logique PostgreSQL de Sentinelle (issue #20).
#
# Usage :
#   PGHOST=… PGPORT=… PGUSER=… PGDATABASE=… PGPASSWORD=… \
#     BACKUP_DIR=/var/backups/sentinelle RETENTION_DAYS=7 \
#     deploy/backup/backup.sh
#
# Le script n'écrit que dans BACKUP_DIR et ne touche jamais à la base :
# c'est un `pg_dump`, donc une lecture.
#
# POURQUOI UN pg_dump « custom » PLUTÔT QU'UNE COPIE DU VOLUME DE DONNÉES
# ---------------------------------------------------------------------
#   * `--format=custom` s'exécute dans un **snapshot MVCC** : la sauvegarde est
#     cohérente même si l'API écrit pendant ce temps, et sans bloquer les
#     écritures. Un `rsync`/`tar` du répertoire `pgdata` à chaud copie un état
#     *inutilisable* (fichiers en cours d'écriture, WAL incohérent) : ce n'est
#     pas une sauvegarde, c'est une fausse assurance ;
#   * le format custom est compressé par défaut (gzip) et **vérifiable sans
#     base** (`pg_restore --list`), ce qui permet de contrôler l'archive au
#     moment où on la produit, et pas le jour où on en a besoin ;
#   * il est restaurable sélectivement (table par table) et supporte la
#     restauration parallèle (`pg_restore --jobs`).
#
# POURQUOI L'ÉCRITURE SE FAIT EN `.partial` PUIS RENOMMAGE ATOMIQUE
# -----------------------------------------------------------------
#   Une sauvegarde interrompue (disque plein, OOM, reboot) ne doit jamais
#   laisser derrière elle un fichier qui *ressemble* à une sauvegarde valide :
#   c'est le scénario classique où l'on croit avoir une sauvegarde de la nuit
#   et où l'on découvre le problème le jour de la reprise. Ici, un fichier
#   `sentinelle_*.dump` existe ⇔ le dump est complet **et** vérifié.
#
# POURQUOI CE SCRIPT EST FAISABLE EN CRON
# ----------------------------------------
#   * aucun prompt (--no-password : sans mot de passe disponible, on échoue
#     immédiatement au lieu d'attendre indéfiniment une saisie) ;
#   * PATH fixé explicitement (l'environnement de cron est minimal) ;
#   * `umask 077` : un dump contient des données personnelles (courriels,
#     empreintes de mots de passe, journal d'audit) — jamais lisible par tous ;
#   * `--lock-wait-timeout` : un verrou long fait échouer le dump au lieu de
#     laisser un processus cron s'empiler pendant des heures ;
#   * sortie sur une seule ligne, avec un code retour net (cron alerte sur un
#     code non nul ou sur la ligne ECHEC).

set -euo pipefail

# L'environnement de cron ne contient presque rien : on ne dépend pas de celui
# de l'opérateur (ni PATH, ni locale, ni variables libpq héritées).
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# Un dump contient des données personnelles (courriels, empreintes de mots de
# passe, journal d'audit) : il ne doit jamais être lisible par les autres
# comptes de la machine, ni sous cron (umask par défaut = 022).
umask 077

# --- Paramètres : tout par l'environnement --------------------------------

PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5432}"
# PGUSER et PGDATABASE n'ont volontairement AUCUNE valeur par défaut : libpq
# les déduit du compte système, et une sauvegarde qui vise silencieusement la
# mauvaise base est plus dangereuse qu'une sauvegarde qui échoue. Ils sont
# validés dans `main`.
PGUSER="${PGUSER:-}"
PGDATABASE="${PGDATABASE:-}"
# Optionnel : préférer un ~/.pgpass (chmod 600), qui ne laisse pas le mot de
# passe dans l'environnement du processus (visible via /proc, hérité par les
# enfants, présent dans le crontab).
PGPASSWORD="${PGPASSWORD:-}"

BACKUP_DIR="${BACKUP_DIR:-/var/backups/sentinelle}"
# Durée de conservation des dumps (jours). 0 ou négatif : rotation désactivée
# — même convention que RETENTION_DAYS de l'application (app/core/config.py).
RETENTION_DAYS="${RETENTION_DAYS:-7}"
# Verrou initial : au-delà, le dump échoue au lieu de s'éterniser.
PG_DUMP_LOCK_TIMEOUT="${PG_DUMP_LOCK_TIMEOUT:-60s}"

export PGHOST PGPORT PGUSER PGDATABASE PGPASSWORD

die() {
	failure_reported=1
	echo "sentinelle-backup: ERREUR: $*" >&2
	exit 2
}

# --- Fonctions pures ------------------------------------------------------
# Volontairement séparées de `main` : elles ne dépendent ni de la base ni de
# pg_dump, et peuvent donc être testées en sourçant ce fichier (la garde en
# fin de fichier empêche toute exécution). Voir backend/tests/test_operations.py.

# Nom du fichier de sauvegarde.
#
# POURQUOI UTC ET JAMAIS L'HEURE LOCALE : la chronologie d'une restauration ne
# doit pas dépendre du fuseau du serveur ni d'un changement d'heure (une nuit
# d'automne dure 25 heures en heure locale : deux dumps pourraient porter le
# même nom, et le second écraserait le premier).
#
# Le paramètre optionnel existe pour rendre la règle de nommage testable sans
# dépendre de l'horloge.
sentinelle_dump_filename() {
	local timestamp="${1:-$(date -u '+%Y%m%dT%H%M%SZ')}"
	printf 'sentinelle_%s.dump\n' "$timestamp"
}

# Horodatage lisible (UTC) pour les journaux.
sentinelle_now() {
	date -u '+%Y-%m-%dT%H:%M:%SZ'
}

#: Fichier en cours d'écriture, nettoyé par `on_exit`. Globale, et non locale à
#: `main` : le piège EXIT s'exécute hors de sa portée, où une variable locale
#: n'existe plus.
#: Passe à 1 dès qu'une ligne d'échec a été écrite, pour ne pas la doubler.
failure_reported=0

#: Fichier en cours d'écriture, nettoyé par `on_exit`. Globale, et non locale à
#: `main` : le piège EXIT s'exécute hors de sa portée, où une variable locale
#: n'existe plus.
partial_path=""

# Nettoyage **et** rapport d'échec, en un seul piège EXIT.
#
# POURQUOI EXIT ET NON ERR : un piège ERR posé au niveau racine n'est PAS hérité
# par les fonctions (manuel bash : il faut `set -E`/errtrace). Installé ici, il
# ne se déclencherait donc jamais dans `main` — et un échec de pg_dump sortirait
# sans la ligne d'échec que cron doit alerter.
#
# POURQUOI ON N'APPELLE PAS `if ! main` DANS LA GARDE : appeler une fonction dans
# une *condition* désactive `errexit` dans tout son corps (même manuel, `set -e`).
# Un échec de pg_dump serait alors ignoré et le script aurait l'air d'avoir
# réussi — le pire des scénarios pour une sauvegarde.
on_exit() {
	local status=$?

	if [[ -n "$partial_path" ]]; then
		rm -f "$partial_path"
	fi

	if ((status != 0 && failure_reported == 0)); then
		printf 'sentinelle-backup: ECHEC base=%s code=%s horodatage=%s\n' \
			"${PGDATABASE:-?}" "$status" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >&2
	fi

	return 0
}

# Rotation : supprime les dumps strictement plus vieux que `days` jours
# (jamais les autres fichiers du répertoire). Affiche sur la sortie standard
# le chemin de chaque fichier supprimé, afin que l'appelant puisse les
# compter et les journaliser.
#
# POURQUOI find -mtime ET PAS « garder les N derniers » : les deux logiques
# sont acceptables, mais -mtime est vérifiable par l'opérateur (un `ls -l` suffit)
# et ne fait dépendre la purge d'aucun état externe.
prune_old_dumps() {
	local directory="$1"
	local days="$2"

	[[ "$days" =~ ^-?[0-9]+$ ]] || die "RETENTION_DAYS invalide : '$days' (entier attendu)"

	if (( days <= 0 )); then
		echo "sentinelle-backup: rotation désactivée (RETENTION_DAYS=${days})" >&2
		return 0
	fi

	find "$directory" -maxdepth 1 -type f -name 'sentinelle_*.dump' \
		-mtime "+${days}" -print -delete

	# Les fichiers `.partial` orphelins (sauvegarde tuée par un OOM, un reboot ou
	# un SIGKILL : le piège EXIT ne s'exécute pas toujours) ne correspondent pas
	# au motif des dumps et s'accumuleraient indéfiniment. On ne les supprime
	# qu'au-delà d'une journée : le `.partial` d'une sauvegarde EN COURS doit
	# survivre à la rotation de la même nuit.
	find "$directory" -maxdepth 1 -type f -name 'sentinelle_*.dump.partial' \
		-mtime +1 -print -delete
}

# Taille en octets, sans dépendre de la locale (`du -h` varie selon le
# séparateur décimal) : la valeur brute est la seule comparable d'un run à
# l'autre, donc la seule exploitable pour une alerte de dérive.
file_size_bytes() {
	wc -c <"$1" | tr -d ' [:space:]'
}

# --- Sauvegarde -----------------------------------------------------------

main() {
	local started_epoch
	started_epoch="$(date +%s)"

	# Contrôles explicites : un message clair vaut mieux qu'une erreur libpq.
	[[ -n "$PGDATABASE" ]] || die "PGDATABASE est requis (base à sauvegarder)"
	[[ -n "$PGUSER" ]] || die "PGUSER est requis (compte utilisé par pg_dump)"
	command -v pg_dump >/dev/null 2>&1 ||
		die "pg_dump introuvable dans le PATH — installer postgresql-client (version ≥ serveur)"

	mkdir -p "$BACKUP_DIR"

	local target partial
	target="${BACKUP_DIR}/$(sentinelle_dump_filename)"
	partial="${target}.partial"

	# Un fichier partiel ne doit jamais survivre à l'échec du dump, et un échec
	# doit être visible sous cron : les deux sont assurés par `on_exit` (voir sa
	# définition — c'est un piège EXIT, hérité par les fonctions).
	partial_path="$partial"
	trap 'on_exit' EXIT

	# --no-password : en cron, personne ne saisira le mot de passe ; on préfère
	#   un échec net à un processus bloqué indéfiniment.
	# --format=custom : cf. en-tête.
	# --lock-wait-timeout : le dump échoue si un verrou l'empêche de démarrer.
	# Pas de --no-sync : par défaut pg_dump attend l'écriture disque effective ;
	#   --no-sync est plus rapide mais une coupure système peut alors laisser une
	#   archive corrompue. Sur une sauvegarde, on paie les millisecondes.
	# Pas de --no-owner/--no-privileges : ignorés pour les formats archive, ils
	#   se règlent à la restauration (voir restore.sh).
	pg_dump \
		--format=custom \
		--file="$partial" \
		--host="$PGHOST" \
		--port="$PGPORT" \
		--username="$PGUSER" \
		--dbname="$PGDATABASE" \
		--no-password \
		--lock-wait-timeout="$PG_DUMP_LOCK_TIMEOUT"

	[[ -s "$partial" ]] || die "dump vide ou absent : $partial"

	# Vérification de l'archive, sans aucune base : `pg_restore --list` lit le
	# sommaire du fichier. C'est la seule preuve disponible au moment où l'on
	# produit la sauvegarde — après, il est trop tard.
	if command -v pg_restore >/dev/null 2>&1; then
		pg_restore --list "$partial" >/dev/null ||
			die "archive illisible (pg_restore --list a échoué) : $partial"
	else
		echo "sentinelle-backup: AVERTISSEMENT: pg_restore absent, archive non vérifiée" >&2
	fi

	# Renommage atomique : à partir d'ici, le fichier est une sauvegarde.
	mv "$partial" "$target"

	# Rotation APRÈS la création : la sauvegarde de cette nuit ne peut pas être
	# supprimée par la rotation de cette nuit, même avec RETENTION_DAYS petit.
	local pruned=0
	if [[ "$RETENTION_DAYS" =~ ^-?[0-9]+$ ]]; then
		pruned="$(prune_old_dumps "$BACKUP_DIR" "$RETENTION_DAYS" | wc -l | tr -d ' [:space:]')"
	else
		die "RETENTION_DAYS invalide : '$RETENTION_DAYS' (entier attendu)"
	fi

	local elapsed size
	elapsed=$(($(date +%s) - started_epoch))
	size="$(file_size_bytes "$target")"

	# Une seule ligne : lisible par un humain dans un mail de cron, et
	# agrégeable par grep/awk dans un journal.
	printf 'sentinelle-backup: OK base=%s fichier=%s octets=%s duree=%ss supprimes=%s conservation_jours=%s debut=%s\n' \
		"$PGDATABASE" "$target" "$size" "$elapsed" "$pruned" "$RETENTION_DAYS" "$(sentinelle_now)"
}

# Garde d'exécution : le fichier peut être *sourcé* pour tester ses fonctions
# sans lancer de sauvegarde (backend/tests/test_operations.py). L'appel est
# inconditionnel : cf. `on_exit` pour ce qu'un `if ! main` aurait cassé.
# (Le piège EXIT est installé dans `main`, donc un fichier sourcé n'y touche pas.)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	main "$@"
fi
