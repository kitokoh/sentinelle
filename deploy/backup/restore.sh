#!/usr/bin/env bash
#
# restore.sh — restauration d'un dump Sentinelle et chronométrage du RTO
# (issue #20).
#
# Usage :
#   RESTORE_CONFIRM=1 deploy/backup/restore.sh --dbname sentinelle_drill \
#     /var/backups/sentinelle/sentinelle_20260921T034500Z.dump
#
#   deploy/backup/restore.sh --yes --dbname sentinelle_drill dump --jobs 4
#
# Codes retour :
#   0   restauration terminée
#   2   refusée : confirmation absente (ou usage invalide) — RIEN n'a été touché
#   3   précondition non satisfaite (dump introuvable, cible injoignable)
#   ≠0  sinon : code retour de pg_restore
#
# POURQUOI UNE CONFIRMATION EXPLICITE
# -----------------------------------
#   `pg_restore --clean` **détruit** les objets de la base cible avant de les
#   recréer. Lancé par erreur sur la base active, ce script n'est pas un
#   incident : c'est une perte de données. Il exige donc `--yes` ou
#   RESTORE_CONFIRM=1, et refuse une valeur approchante (`yes`, `true`, `0…`) —
#   un « oui » ambigu n'est pas un consentement.
#
# POURQUOI LA CIBLE N'EST JAMAIS DÉDUITE
# --------------------------------------
#   La base cible doit être nommée explicitement (`--dbname`, sinon
#   RESTORE_TARGET_DB). On ne retombe **jamais** sur PGDATABASE : une
#   restauration destructive ne doit pas pouvoir viser la base de production
#   par simple oubli d'un paramètre.
#
# POURQUOI CE SCRIPT CHRONOMÈTRE
# ------------------------------
#   Un RTO annoncé dans un PRA et jamais mesuré est une opinion. Ce script
#   imprime la durée réelle de la restauration (et celle de l'`ANALYZE`), qui
#   est la seule partie du RTO déjà outillée : le reste (décision,
#   provisionnement, vérifications) reste humain et doit être chronométré lors
#   des exercices — voir docs/PRA.md.

set -euo pipefail

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# --- Paramètres -----------------------------------------------------------

PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-}"
PGPASSWORD="${PGPASSWORD:-}"
# Jamais de repli sur PGDATABASE (cf. en-tête).
TARGET_DB="${RESTORE_TARGET_DB:-}"
JOBS="${RESTORE_JOBS:-1}"

export PGHOST PGPORT PGUSER PGPASSWORD

DUMP_FILE=""
CONFIRMED=0
DO_ANALYZE=1
DRY_RUN=0

warn() {
	echo "sentinelle-restore: AVERTISSEMENT: $*" >&2
}

#: Passe à 1 dès qu'une ligne d'échec a été écrite, pour ne pas la doubler.
failure_reported=0

die() {
	local code="$1"
	shift
	failure_reported=1
	echo "sentinelle-restore: ERREUR: $*" >&2
	exit "$code"
}

# Rapport d'échec pour les sorties *non prévues* : erreur d'`ANALYZE`, disque
# plein, cible qui disparaît en cours de route… Sans lui, seul le code retour
# signalerait le problème — et personne ne lit un code retour dans un mail
# de cron.
#
# C'est un piège EXIT et non ERR : un piège ERR posé au niveau racine n'est pas
# hérité par les fonctions (manuel bash : il faudrait `set -E`), donc il ne se
# déclencherait jamais dans `main`.
on_exit() {
	local status=$?

	if ((status != 0 && failure_reported == 0)); then
		printf 'sentinelle-restore: ECHEC inattendu cible=%s code=%s\n' \
			"${TARGET_DB:-?}" "$status" >&2
	fi

	return 0
}

usage() {
	cat <<'USAGE'
Restauration d'une sauvegarde PostgreSQL Sentinelle (destructif).

Usage :
  restore.sh --dbname <base_cible> [options] <fichier.dump>

Options :
  -d, --dbname <base>   base cible (obligatoire ; défaut : RESTORE_TARGET_DB)
      --yes             confirme l'opération destructrice (ou RESTORE_CONFIRM=1)
  -j, --jobs <n>        restauration parallèle pg_restore (défaut : 1)
      --no-analyze      ne pas exécuter ANALYZE après la restauration
      --dry-run         afficher la commande sans rien exécuter
  -h, --help            cet écran

Paramètres de connexion : PGHOST, PGPORT, PGUSER, PGPASSWORD (ou ~/.pgpass).

Exemple (exercice de reprise, base jetable) :
  createdb -T template0 sentinelle_drill
  RESTORE_CONFIRM=1 ./deploy/backup/restore.sh --dbname sentinelle_drill \
      /var/backups/sentinelle/sentinelle_20260921T034500Z.dump
USAGE
}

# --- Fonctions pures ------------------------------------------------------
# Séparées de `main` pour être testables sans base ni pg_restore (le fichier
# est sourçable : la garde en fin de fichier empêche l'exécution).

# Base d'origine, lue dans l'en-tête de l'archive (`pg_restore --list`).
# Sert uniquement à avertir quand la cible porte le nom de la base source :
# c'est le cas « restauration en place », légitime après sinistre, mais
# rarement ce que l'on croit taper.
dump_source_dbname() {
	local dump="$1"
	command -v pg_restore >/dev/null 2>&1 || return 0
	pg_restore --list "$dump" 2>/dev/null |
		sed -n 's/^; *dbname: *//p' |
		head -n 1
}

# La confirmation est-elle valide ? Seules deux formes sont acceptées.
confirmation_is_valid() {
	local flag="$1"
	local env_value="$2"
	[[ "$flag" == "1" || "$env_value" == "1" ]]
}

file_size_bytes() {
	wc -c <"$1" | tr -d ' [:space:]'
}

# --- Restauration ---------------------------------------------------------

main() {
	local -a positional=()

	# Toute sortie (normale, refus, erreur) passe par ce piège : c'est lui qui
	# garantit qu'un échec inattendu reste visible sous cron.
	trap 'on_exit' EXIT

	while (($# > 0)); do
		case "$1" in
		-d | --dbname)
			[[ $# -ge 2 ]] || die 2 "l'option $1 attend un argument"
			TARGET_DB="$2"
			shift 2
			;;
		--yes)
			CONFIRMED=1
			shift
			;;
		-j | --jobs)
			[[ $# -ge 2 ]] || die 2 "l'option $1 attend un argument"
			JOBS="$2"
			shift 2
			;;
		--no-analyze)
			DO_ANALYZE=0
			shift
			;;
		--dry-run)
			DRY_RUN=1
			shift
			;;
		-h | --help)
			usage
			exit 0
			;;
		--)
			shift
			positional+=("$@")
			break
			;;
		-*)
			die 2 "option inconnue : $1 (voir --help)"
			;;
		*)
			positional+=("$1")
			shift
			;;
		esac
	done

	DUMP_FILE="${positional[0]:-}"

	# $USER n'existe pas toujours sous cron : on ne le suppose pas.
	local db_user="${PGUSER:-${USER:-$(id -un)}}"

	# 1. Le refus vient AVANT toute autre vérification : aucune erreur de
	#    paramétrage ne doit pouvoir conduire à un accès à la base.
	confirmation_is_valid "$CONFIRMED" "${RESTORE_CONFIRM:-}" ||
		die 2 "restauration NON confirmée : ajouter --yes ou RESTORE_CONFIRM=1 (opération destructrice)"

	# 2. Préconditions.
	[[ -n "$DUMP_FILE" ]] || die 2 "fichier de sauvegarde manquant (voir --help)"
	[[ -n "$TARGET_DB" ]] ||
		die 2 "base cible manquante : --dbname <base> ou RESTORE_TARGET_DB (jamais déduite de PGDATABASE)"
	[[ -f "$DUMP_FILE" ]] || die 3 "fichier de sauvegarde introuvable : $DUMP_FILE"
	[[ -s "$DUMP_FILE" ]] || die 3 "fichier de sauvegarde vide : $DUMP_FILE"
	[[ "$JOBS" =~ ^[0-9]+$ ]] || die 2 "—jobs attend un entier strictement positif (reçu : $JOBS)"
	((JOBS >= 1)) || die 2 "—jobs attend un entier strictement positif (reçu : $JOBS)"
	command -v pg_restore >/dev/null 2>&1 ||
		die 3 "pg_restore introuvable dans le PATH — installer postgresql-client (version ≥ serveur)"

	local source_db
	source_db="$(dump_source_dbname "$DUMP_FILE")"
	if [[ -n "$source_db" && "$source_db" == "$TARGET_DB" ]]; then
		warn "la cible porte le nom de la base d'origine ($source_db) : les objets ACTIFS seront supprimés puis recréés"
	fi

	# 3. Cible joignable ? Mieux vaut le dire ici, en une ligne, que de laisser
	#    pg_restore produire cinquante erreurs de connexion.
	if command -v psql >/dev/null 2>&1; then
		psql --no-password --host="$PGHOST" --port="$PGPORT" --username="$db_user" \
			--dbname="$TARGET_DB" --command 'SELECT 1' >/dev/null 2>&1 ||
			die 3 "base cible injoignable : $TARGET_DB sur $PGHOST:$PGPORT (créer la base vide : createdb -T template0 $TARGET_DB)"
	else
		warn "psql absent : contrôle de la cible sauté"
	fi

	# 4. Construction de la commande.
	#    --clean --if-exists : repartir d'un état propre sans échouer sur les
	#      objets absents (une base neuve).
	#    --no-owner/--no-privileges : le dump ne les porte pas (options ignorées
	#      pour les formats archive) ; la restauration doit donc les poser ici,
	#      sinon elle échoue dès que le compte de restauration n'est pas
	#      propriétaire des objets d'origine.
	local -a restore_args=(
		--clean
		--if-exists
		--no-owner
		--no-privileges
		--host="$PGHOST"
		--port="$PGPORT"
		--username="$db_user"
		--dbname="$TARGET_DB"
		--no-password
	)
	if ((JOBS > 1)); then
		# Parallélisme : gain de temps réel sur les grosses bases, mais les
		# erreurs deviennent des compteurs de fin de restauration au lieu d'un
		# arrêt immédiat. On n'active donc PAS --exit-on-error dans ce mode :
		# l'opérateur sait qu'il doit lire le compte d'erreurs.
		restore_args+=(--jobs "$JOBS")
	else
		# Mode par défaut : toute erreur interrompt la restauration. Un
		# exercice de reprise doit échouer bruyamment, pas finir à moitié.
		restore_args+=(--exit-on-error)
	fi
	restore_args+=("$DUMP_FILE")

	local size
	size="$(file_size_bytes "$DUMP_FILE")"

	printf '=== Restauration Sentinelle ===\n'
	printf 'dump            : %s (%s octets)\n' "$DUMP_FILE" "$size"
	printf 'base d origine  : %s\n' "${source_db:-inconnue}"
	printf 'cible           : %s @ %s:%s (utilisateur %s)\n' "$TARGET_DB" "$PGHOST" "$PGPORT" "$db_user"
	printf 'commande        : pg_restore %s\n' "${restore_args[*]}"

	if ((DRY_RUN == 1)); then
		printf 'mode            : --dry-run — rien n’a été exécuté\n'
		exit 0
	fi

	local started_epoch started_at
	started_epoch="$(date +%s)"
	started_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	printf 'début (UTC)     : %s\n' "$started_at"

	local restore_status=0
	pg_restore "${restore_args[@]}" || restore_status=$?
	local restored_epoch
	restored_epoch="$(date +%s)"

	if ((restore_status != 0)); then
		failure_reported=1
		printf 'sentinelle-restore: ECHEC cible=%s duree=%ss code=%s\n' \
			"$TARGET_DB" "$((restored_epoch - started_epoch))" "$restore_status" >&2
		exit "$restore_status"
	fi

	# 5. ANALYZE. pg_dump n'embarque PAS les statistiques du planificateur
	#    (cf. documentation pg_dump) : sans cette étape, la base restaurée
	#    planifie les agrégations du tableau de bord sur des estimations par
	#    défaut — exactement ce que mesure le test de charge. Une reprise qui
	#    « répond » mais qui viole le p95 n'est pas une reprise réussie.
	local analyze_elapsed=0
	if ((DO_ANALYZE == 1)); then
		if command -v psql >/dev/null 2>&1; then
			local analyze_started
			analyze_started="$(date +%s)"
			psql --no-password --host="$PGHOST" --port="$PGPORT" --username="$db_user" \
				--dbname="$TARGET_DB" --set=ON_ERROR_STOP=1 --command 'ANALYZE;' >/dev/null
			analyze_elapsed=$(($(date +%s) - analyze_started))
		else
			warn "psql absent : ANALYZE non exécuté (statistiques du planificateur absentes)"
		fi
	fi

	local finished_epoch total
	finished_epoch="$(date +%s)"
	total=$((finished_epoch - started_epoch))

	printf -- '--- Fin\n'
	printf 'fin (UTC)       : %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	printf 'durée pg_restore: %ss\n' "$((restored_epoch - started_epoch))"
	printf 'durée ANALYZE   : %ss\n' "$analyze_elapsed"
	printf 'durée totale    : %ss\n' "$total"
	printf 'sentinelle-restore: OK cible=%s duree_totale=%ss dump=%s\n' "$TARGET_DB" "$total" "$DUMP_FILE"
	printf 'rappel          : le RTO cible est de 2 h (docs/PRA.md) ; cette étape en consomme %ss — la reprise n’est pas terminée tant que les comptages du drill (deploy/backup/README.md) n’ont pas été vérifiés.\n' "$total"
}

# Garde d'exécution : le fichier peut être *sourcé* pour tester ses fonctions
# sans lancer de restauration (backend/tests/test_operations.py). L'appel est
# inconditionnel : dans une condition (`if ! main`), `errexit` serait désactivé
# dans tout le corps de `main`, et un échec de pg_restore serait ignoré.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	main "$@"
fi
