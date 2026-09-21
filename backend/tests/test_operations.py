"""Tests de l'outillage d'exploitation (#20) : sauvegarde/restauration et charge.

Ce que ces tests protègent
--------------------------
Le jour où l'on a besoin d'une sauvegarde, il est trop tard pour découvrir une
faute de frappe. L'outillage ops est donc testé comme du code applicatif —
et testé **partout**, y compris sur un poste sans PostgreSQL.

Trois propriétés, chacune choisie parce qu'elle se vérifie sans base :

* les scripts sont **syntaxiquement valides** (`bash -n`) et **exécutables** :
  un script non exécutable ne tourne pas sous cron, et cron échoue en silence ;
* la **règle de nommage et la rotation** sont réellement exécutées — en sourçant
  le script, sans jamais appeler `pg_dump` : on teste la logique, pas la base ;
* le **garde-fou de la restauration** est vérifié en exécutant le script : il
  doit refuser, et refuser *avant* tout accès à la base.

Aucun test ne démarre l'application, n'ouvre de connexion, ni n'appelle un
binaire PostgreSQL : `pg_dump`, `pg_restore` et `psql` sont absents de
l'environnement de test, et c'est justement ce que ce fichier démontre.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

# Le dépôt est à un niveau au-dessus de backend/ (tests/ -> backend/ -> racine).
REPO_ROOT = Path(__file__).resolve().parents[2]
BACKUP_DIR = REPO_ROOT / "deploy" / "backup"
LOAD_DIR = REPO_ROOT / "deploy" / "load"

BACKUP_SCRIPT = BACKUP_DIR / "backup.sh"
RESTORE_SCRIPT = BACKUP_DIR / "restore.sh"
BACKUP_README = BACKUP_DIR / "README.md"
K6_SCRIPT = LOAD_DIR / "k6-dashboard.js"
LOAD_README = LOAD_DIR / "README.md"
PRA_DOC = REPO_ROOT / "docs" / "PRA.md"

BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash est requis pour tester les scripts ops")

SHELL_SCRIPTS = [
    pytest.param(BACKUP_SCRIPT, id="backup"),
    pytest.param(RESTORE_SCRIPT, id="restore"),
]


@pytest.fixture(autouse=True)
def _schema():
    """Surcharge la fixture autouse de ``conftest.py``.

    Celle de ``conftest`` garantit le schéma aux tests qui parlent à la base ;
    l'imposer ici ferait démarrer l'application (et donc les migrations et une
    base temporaire) pour des tests d'outillage qui n'en veulent aucune. La
    surcharge est volontaire, locale à ce module, et ne touche pas conftest.
    """
    return None


def bash(script: str, *, env: dict | None = None, timeout: int = 60) -> subprocess.CompletedProcess:
    """Exécute un fragment de shell et renvoie le résultat complet."""
    return subprocess.run(
        [BASH, "-c", script],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


def run_script(script: Path, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    """Exécute un script ops directement (bash <script> ...)."""
    return subprocess.run(
        [BASH, str(script), *args],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )


def env_without(*names: str, **overrides: str) -> dict:
    """Environnement nettoyé : les variables retirées ne fuient pas du test runner."""
    env = dict(os.environ)
    for name in names:
        env.pop(name, None)
    env.update({key: str(value) for key, value in overrides.items()})
    return env


def make_dump(directory: Path, name: str, age_days: float) -> Path:
    """Crée un faux dump avec un âge donné (aucun appel à pg_dump)."""
    path = directory / name
    path.write_bytes(b"faux dump pour la rotation")
    timestamp = dt.datetime.now().timestamp() - age_days * 86400
    os.utime(path, (timestamp, timestamp))
    return path


# ---------------------------------------------------------------------------
# 1. Invariants de base : syntaxe et mode d'exécution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("script", SHELL_SCRIPTS)
def test_shell_scripts_pass_the_syntax_check(script: Path) -> None:
    """``bash -n`` : le script est parsable. Une faute de frappe ici, sinon, c'est
    un cron qui ne fait rien pendant des mois sans que personne ne s'en aperçoive."""
    result = bash(f'bash -n "{script}"')
    assert result.returncode == 0, f"bash -n {script.name} a échoué :\n{result.stderr}"


@pytest.mark.parametrize("script", SHELL_SCRIPTS)
def test_shell_scripts_are_executable(script: Path) -> None:
    """Sans bit exécutable, la tâche cron échoue — silencieusement."""
    assert script.is_file(), f"{script} est absent"
    mode = script.stat().st_mode
    assert mode & stat.S_IXUSR, f"{script.name} doit être exécutable (chmod +x)"
    assert os.access(script, os.X_OK)


# ---------------------------------------------------------------------------
# 2. Règle de nommage : le script est *sourcé*, pg_dump n'est jamais appelé
# ---------------------------------------------------------------------------


def test_dump_filename_is_deterministic_for_a_given_timestamp() -> None:
    """La règle de nommage est appelée pour de vrai, avec un horodatage imposé.

    C'est la raison d'être de la fonction ``sentinelle_dump_filename`` : sortir la
    règle du flux d'exécution pour qu'elle soit testable sans base.
    """
    result = bash(f'source "{BACKUP_SCRIPT}"\nsentinelle_dump_filename 20260921T034500Z')
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "sentinelle_20260921T034500Z.dump"


def test_dump_filename_defaults_to_the_current_utc_time() -> None:
    """Le nom est horodaté en UTC, jamais en heure locale.

    Deux sauvegardes ne doivent pas pouvoir porter le même nom parce que la
    machine a changé de fuseau ou d'heure : la seconde écraserait la première.
    """
    result = bash(f'source "{BACKUP_SCRIPT}"\nsentinelle_dump_filename')
    assert result.returncode == 0, result.stderr

    name = result.stdout.strip()
    match = re.fullmatch(r"sentinelle_(\d{8}T\d{6}Z)\.dump", name)
    assert match, f"format de nom inattendu : {name!r}"

    # Le nom se compare à l'heure UTC : un passage en heure locale ferait
    # échouer l'assertion dès que le fuseau du runner n'est pas UTC.
    stamped = dt.datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc)
    delta = abs((dt.datetime.now(dt.timezone.utc) - stamped).total_seconds())
    assert delta < 120, f"horodatage non UTC (écart de {delta:.0f}s) : {name!r}"


# ---------------------------------------------------------------------------
# 3. Rotation : logique réelle, fichiers temporaires uniquement
# ---------------------------------------------------------------------------


def test_rotation_removes_old_dumps_and_keeps_recent_ones(tmp_path: Path) -> None:
    recent = make_dump(tmp_path, "sentinelle_20260921T034500Z.dump", age_days=0)
    old = make_dump(tmp_path, "sentinelle_20260910T034500Z.dump", age_days=10)
    # Un fichier qui n'est pas un dump Sentinelle ne doit jamais être touché :
    # la rotation ne doit pas se transformer en nettoyage de répertoire.
    foreign = tmp_path / "sauvegarde-manuelle.sql"
    foreign.write_text("select 1;\n")
    stamp = dt.datetime.now().timestamp() - 30 * 86400
    os.utime(foreign, (stamp, stamp))

    result = bash(f'source "{BACKUP_SCRIPT}"\nprune_old_dumps "{tmp_path}" 7')
    assert result.returncode == 0, result.stderr

    assert not old.exists(), "le dump de 10 jours devait être supprimé (RETENTION_DAYS=7)"
    assert recent.exists(), "le dump du jour ne doit jamais être supprimé"
    assert foreign.exists(), "un fichier étranger ne doit jamais être supprimé"
    assert old.name in result.stdout, "les fichiers supprimés doivent être journalisés"


def test_rotation_is_disabled_when_retention_is_zero(tmp_path: Path) -> None:
    """``RETENTION_DAYS=0`` conserve tout, comme la rétention applicative."""
    old = make_dump(tmp_path, "sentinelle_20200101T034500Z.dump", age_days=365)

    result = bash(f'source "{BACKUP_SCRIPT}"\nprune_old_dumps "{tmp_path}" 0')
    assert result.returncode == 0, result.stderr
    assert old.exists()


def test_rotation_cleans_orphaned_partial_files(tmp_path: Path) -> None:
    """Un ``.partial`` peut survivre à un OOM ou à un reboot (le piège EXIT ne
    s'exécute pas toujours). Il ne correspond pas au motif des dumps : sans
    cette règle, il s'accumulerait indéfiniment dans BACKUP_DIR."""
    orphan = make_dump(tmp_path, "sentinelle_20260920T034500Z.dump.partial", age_days=3)
    # Le .partial d'une sauvegarde en cours ne doit jamais être supprimé par la
    # rotation de la même nuit.
    in_flight = make_dump(tmp_path, "sentinelle_20260921T034500Z.dump.partial", age_days=0)

    result = bash(f'source "{BACKUP_SCRIPT}"\nprune_old_dumps "{tmp_path}" 7')
    assert result.returncode == 0, result.stderr

    assert not orphan.exists(), "le fichier partiel orphelin devait être nettoyé"
    assert in_flight.exists(), "le fichier partiel en cours ne doit pas être supprimé"


def test_rotation_refuses_a_non_numeric_retention(tmp_path: Path) -> None:
    """Une valeur non numérique doit faire échouer la rotation, pas la rendre folle."""
    old = make_dump(tmp_path, "sentinelle_20200101T034500Z.dump", age_days=365)

    result = bash(f'source "{BACKUP_SCRIPT}"\nprune_old_dumps "{tmp_path}" sept')
    assert result.returncode == 2
    assert "RETENTION_DAYS invalide" in result.stderr
    assert old.exists()


# ---------------------------------------------------------------------------
# 4. backup.sh : paramètres, hygiène, sûreté
# ---------------------------------------------------------------------------


def test_backup_refuses_to_run_without_a_target_database(tmp_path: Path) -> None:
    """PGDATABASE est requis : libpq choisirait sinon silencieusement le compte
    système et la mauvaise base — pire qu'un échec."""
    result = run_script(
        BACKUP_SCRIPT,
        env=env_without("PGDATABASE", "PGUSER", "PGPASSWORD", BACKUP_DIR=str(tmp_path)),
    )
    assert result.returncode == 2
    assert "PGDATABASE est requis" in result.stderr
    assert not list(tmp_path.iterdir()), "rien ne doit être écrit avant les contrôles"


def stub_script(tmp_path: Path, script: Path, *tools: Path) -> Path:
    """Copie un script ops en le reliant à un répertoire de faux binaires.

    Le script fixe son `PATH` (sûreté cron : on ne dépend pas de l'environnement
    de l'opérateur), donc on ne peut pas injecter un faux `pg_dump` par
    l'environnement. On exécute une copie dont **seule** la ligne `PATH` est
    remplacée : le reste du fichier est identique à celui qui est livré, ce que
    l'assertion ci-dessous vérifie.
    """
    fake_bin = tmp_path / "faux-bin"
    fake_bin.mkdir(exist_ok=True)
    for tool in tools:
        destination = fake_bin / tool.name
        shutil.copy2(tool, destination)
        destination.chmod(0o755)

    original_lines = script.read_text(encoding="utf-8").splitlines(keepends=True)
    patched = []
    for line in original_lines:
        if line.startswith("PATH="):
            patched.append(f'PATH="{fake_bin}:/usr/bin:/bin"\n')
        else:
            patched.append(line)

    # Garde-fou : la copie ne diffère de l'original que par le PATH. Sans cette
    # assertion, le test pourrait valider une version modifiée du script.
    assert [line for line in original_lines if not line.startswith("PATH=")] == [
        line for line in patched if not line.startswith("PATH=")
    ]

    copy = tmp_path / f"faux-{script.name}"
    copy.write_text("".join(patched), encoding="utf-8")
    copy.chmod(0o755)
    return copy


@pytest.fixture
def fake_pg_dump(tmp_path: Path) -> Path:
    """Faux pg_dump : écrit un fichier non vide à l'emplacement demandé."""
    tool = tmp_path / "pg_dump"
    tool.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'out=""\n'
        'for arg in "$@"; do case "$arg" in --file=*) out="${arg#--file=}" ;; esac; done\n'
        'printf "faux dump pour le test\\n" > "$out"\n',
        encoding="utf-8",
    )
    return tool


@pytest.fixture
def fake_pg_restore(tmp_path: Path) -> Path:
    """Faux pg_restore : suffit à `--list` (vérification de l'archive)."""
    tool = tmp_path / "pg_restore"
    tool.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    return tool


def test_backup_completes_the_nightly_cycle_end_to_end(
    tmp_path: Path, fake_pg_dump: Path, fake_pg_restore: Path
) -> None:
    """Cycle complet, avec de faux binaires PostgreSQL : nommage, écriture en
    `.partial`, vérification de l'archive, renommage, ligne de résumé unique.

    C'est la seule façon de couvrir ce contrôle d'exécution sans base : aucun
    `pg_dump` réel n'est appelé (il n'en existe pas dans l'environnement de test).
    """
    backup_dir = tmp_path / "dumps"
    script = stub_script(tmp_path, BACKUP_SCRIPT, fake_pg_dump, fake_pg_restore)

    result = run_script(
        script,
        env=env_without(
            "PGPASSWORD",
            PGDATABASE="sentinelle",
            PGUSER="sentinelle",
            BACKUP_DIR=str(backup_dir),
            RETENTION_DAYS="7",
        ),
    )

    assert result.returncode == 0, result.stderr
    assert "ECHEC" not in result.stderr

    dumps = sorted(backup_dir.glob("sentinelle_*.dump"))
    assert len(dumps) == 1, f"une seule sauvegarde attendue, vu : {dumps}"
    assert re.fullmatch(r"sentinelle_\d{8}T\d{6}Z\.dump", dumps[0].name)
    assert dumps[0].read_text(encoding="utf-8") == "faux dump pour le test\n"

    # Le fichier partiel ne doit jamais subsister après un succès.
    assert not list(backup_dir.glob("*.partial"))

    # Résumé sur une seule ligne, exploitable par un grep de cron.
    summary = [line for line in result.stdout.splitlines() if line.startswith("sentinelle-backup: OK")]
    assert len(summary) == 1, result.stdout
    assert "base=sentinelle" in summary[0]
    assert f"fichier={dumps[0]}" in summary[0]


def test_backup_failure_is_reported_and_leaves_no_partial_file(tmp_path: Path) -> None:
    """Un échec de `pg_dump` doit être **visible** (ligne ECHEC + code retour) et
    ne laisser aucun fichier derrière lui.

    Ce test couvre le piège bash qui a réellement menacé ce script : appeler
    `main` dans une condition (`if ! main`) désactive `errexit` dans tout son
    corps — un échec serait passé inaperçu et le script aurait eu l'air d'avoir
    réussi.
    """
    backup_dir = tmp_path / "dumps"
    failing_dump = tmp_path / "pg_dump"
    failing_dump.write_text(
        "#!/usr/bin/env bash\nprintf 'pg_dump: echec simule\\n' >&2\nexit 1\n",
        encoding="utf-8",
    )
    script = stub_script(tmp_path, BACKUP_SCRIPT, failing_dump)

    result = run_script(
        script,
        env=env_without(
            "PGPASSWORD",
            PGDATABASE="sentinelle",
            PGUSER="sentinelle",
            BACKUP_DIR=str(backup_dir),
            RETENTION_DAYS="7",
        ),
    )

    assert result.returncode != 0, "un échec de pg_dump ne doit jamais sortir en 0"
    assert "sentinelle-backup: ECHEC" in result.stderr, result.stderr
    assert not list(backup_dir.glob("*.dump")), "aucune sauvegarde ne doit rester"
    assert not list(backup_dir.glob("*.partial")), "le fichier partiel devait être nettoyé"


def test_backup_script_guards_its_security_properties() -> None:
    """Les propriétés annoncées dans la documentation doivent exister dans le code.

    Un ``umask 077`` documenté mais absent laisserait des dumps contenant des
    données personnelles lisibles par tous les comptes de la machine.
    """
    text = BACKUP_SCRIPT.read_text(encoding="utf-8")

    assert re.search(r"^umask 077$", text, re.MULTILINE), "umask 077 manquant"
    assert 'PGPASSWORD="${PGPASSWORD:-}"' in text, "le mot de passe doit venir de l'environnement"
    for option in ("--format=custom", "--no-password", "--lock-wait-timeout"):
        assert option in text, f"option pg_dump attendue absente : {option}"


# ---------------------------------------------------------------------------
# 5. restore.sh : le garde-fou destructif est exécuté, pas seulement lu
# ---------------------------------------------------------------------------


def test_restore_refuses_without_confirmation(tmp_path: Path) -> None:
    """Rien ne doit être tenté avant la confirmation : le code retour 2 est un
    refus (et non 127 « commande introuvable », qui prouverait une tentative)."""
    dump = make_dump(tmp_path, "sentinelle_20260921T034500Z.dump", age_days=0)

    result = run_script(
        RESTORE_SCRIPT,
        "--dbname",
        "sentinelle_drill",
        str(dump),
        env=env_without("RESTORE_CONFIRM"),
    )

    assert result.returncode == 2, result.stderr
    assert "NON confirmée" in result.stderr
    assert "command not found" not in result.stderr, "aucun binaire ne doit être appelé"
    assert dump.exists()


@pytest.mark.parametrize("value", ["", "0", "true", "yes", "OUI"])
def test_restore_accepts_only_an_explicit_confirmation(tmp_path: Path, value: str) -> None:
    """Une valeur approchante n'est pas un consentement."""
    dump = make_dump(tmp_path, "sentinelle_20260921T034500Z.dump", age_days=0)

    result = run_script(
        RESTORE_SCRIPT,
        "--dbname",
        "sentinelle_drill",
        str(dump),
        env=env_without("RESTORE_CONFIRM", RESTORE_CONFIRM=value),
    )

    assert result.returncode == 2, result.stderr
    assert "NON confirmée" in result.stderr


def test_restore_goes_past_the_guard_with_an_explicit_flag(tmp_path: Path) -> None:
    """Avec la confirmation, le script poursuit : il échoue alors sur la
    précondition suivante (fichier absent, code 3), ce qui prouve que le
    garde-fou est bien la seule chose qui bloquait."""
    missing = tmp_path / "absent.dump"

    result = run_script(
        RESTORE_SCRIPT,
        "--yes",
        "--dbname",
        "sentinelle_drill",
        str(missing),
        env=env_without("RESTORE_CONFIRM"),
    )

    assert result.returncode == 3, result.stderr
    assert "introuvable" in result.stderr


def test_restore_never_infers_the_target_database(tmp_path: Path) -> None:
    """La cible doit être nommée : une restauration destructive ne doit pas
    pouvoir viser PGDATABASE par simple oubli."""
    dump = make_dump(tmp_path, "sentinelle_20260921T034500Z.dump", age_days=0)

    result = run_script(
        RESTORE_SCRIPT,
        str(dump),
        env=env_without("RESTORE_TARGET_DB", PGDATABASE="sentinelle", RESTORE_CONFIRM="1"),
    )

    assert result.returncode == 2, result.stderr
    assert "base cible manquante" in result.stderr


def test_restore_help_documents_the_confirmation() -> None:
    result = run_script(RESTORE_SCRIPT, "--help", env=env_without("RESTORE_CONFIRM"))
    assert result.returncode == 0, result.stderr
    assert "--yes" in result.stdout
    assert "RESTORE_CONFIRM" in result.stdout


def test_restore_rejects_an_unknown_option(tmp_path: Path) -> None:
    """Les fautes de frappe ne doivent pas être interprétées comme un feu vert."""
    result = run_script(RESTORE_SCRIPT, "--forcement", env=env_without("RESTORE_CONFIRM"))
    assert result.returncode == 2
    assert "option inconnue" in result.stderr


# ---------------------------------------------------------------------------
# 6. Script k6 : assertion structurelle (pas d'analyse syntaxique JS)
# ---------------------------------------------------------------------------


def test_k6_script_exists_and_is_the_expected_load_test() -> None:
    assert K6_SCRIPT.is_file(), f"{K6_SCRIPT} est absent"

    text = K6_SCRIPT.read_text(encoding="utf-8")

    for expected in (
        "import http from 'k6/http'",
        "import { check, sleep } from 'k6'",
        "export const options",
        "thresholds",
        "constant-arrival-rate",
        "timeUnit: '1s'",
        "/api/auth/login",
        "/api/dashboard/stats",
    ):
        assert expected in text, f"attendu dans k6-dashboard.js : {expected!r}"


def test_k6_script_targets_one_hundred_requests_per_second() -> None:
    """Le critère d'acceptation (#20) doit être lisible dans le script lui-même."""
    text = K6_SCRIPT.read_text(encoding="utf-8")

    # Débit cible : 100 req/s (surchargeable par l'environnement, mais le défaut
    # est le critère d'acceptation).
    assert re.search(
        r"TARGET_RPS\s*=\s*Number\(__ENV\.SENTINELLE_TARGET_RPS\s*\|\|\s*100\)", text
    ), "le débit par défaut doit valoir 100 req/s"
    assert re.search(r"rate:\s*TARGET_RPS", text), "le scénario doit consommer TARGET_RPS"


def test_k6_script_asserts_the_documented_thresholds() -> None:
    text = K6_SCRIPT.read_text(encoding="utf-8")

    assert "http_req_failed" in text
    assert "'rate<0.01'" in text, "seuil de taux d'échec attendu : rate<0.01"
    assert re.search(r"'p\(95\)<\d+'", text), "seuil de latence p95 attendu"
    # Garde-fou d'honnêteté : un test qui n'a pas tenu la cadence doit échouer.
    assert "dropped_iterations" in text


def test_k6_script_is_read_only_apart_from_authentication() -> None:
    """Un test de charge ne doit pas écrire de données : la seule requête mutante
    est l'authentification, exécutée une fois dans ``setup()``."""
    text = K6_SCRIPT.read_text(encoding="utf-8")

    posts = re.findall(r"http\.post\(\s*`([^`]+)`", text, re.DOTALL)
    assert posts == ["${BASE_URL}/api/auth/login"], f"requêtes mutantes inattendues : {posts}"

    # Aucun identifiant en dur : tout vient de l'environnement.
    for variable in ("__ENV.SENTINELLE_EMAIL", "__ENV.SENTINELLE_PASSWORD", "__ENV.SENTINELLE_BASE_URL"):
        assert variable in text, f"{variable} doit être lu depuis l'environnement"
    assert "Sentinelle2026!" not in text, "aucun mot de passe en dur dans le script de charge"


# ---------------------------------------------------------------------------
# 7. Documentation : les engagements doivent être écrits, et cohérents
# ---------------------------------------------------------------------------


def test_recovery_plan_states_the_documented_rpo_and_rto() -> None:
    """Le PRA doit annoncer les valeurs publiées, et dire pourquoi PostgreSQL
    sans archivage WAL ne peut pas faire mieux qu'une journée."""
    assert PRA_DOC.is_file(), f"{PRA_DOC} est absent"
    text = PRA_DOC.read_text(encoding="utf-8")

    assert re.search(r"RPO[^\n]*24 h", text), "le PRA doit annoncer un RPO de 24 h"
    assert re.search(r"RTO[^\n]*2 h", text), "le PRA doit annoncer un RTO de 2 h"
    assert "archivage WAL" in text or "PITR" in text, "la limite « pas de PITR » doit être écrite"
    assert "Redis" in text, "les données non sauvegardées (file Redis) doivent être listées"


def test_backup_readme_documents_a_restore_drill_that_counts_rows() -> None:
    """Un exercice de reprise doit *compter des lignes* : un code retour 0 ne
    prouve pas qu'une base est exploitable."""
    text = BACKUP_README.read_text(encoding="utf-8")
    lowered = text.lower()

    assert "drill" in lowered
    assert "count(*)" in lowered, "le drill doit reposer sur des comptages"
    assert "restore.sh" in text
    assert "cron" in lowered, "la planification doit être documentée"


def test_scripts_report_failures_through_an_inherited_exit_trap() -> None:
    """Deux pièges bash qui rendraient un échec **silencieux** sous cron :

    * un piège `ERR` posé au niveau racine n'est pas hérité par les fonctions
      (il faudrait `set -E`) : installé là, il ne se déclencherait jamais dans
      `main` ;
    * appeler `main` dans une condition (`if ! main`) désactive `errexit` dans
      tout son corps.

    Le rapport d'échec passe donc par un piège `EXIT` installé dans `main`,
    hérité par construction.
    """
    for script in (BACKUP_SCRIPT, RESTORE_SCRIPT):
        raw = script.read_text(encoding="utf-8")
        # On ignore les lignes de commentaire : documenter le piège est souhaitable,
        # le commettre ne l'est pas.
        code = "\n".join(
            line for line in raw.splitlines() if not line.lstrip().startswith("#")
        )

        assert "! main" not in code, f"{script.name} : main ne doit pas être appelée dans une condition"
        assert 'main "$@" ||' not in code, f"{script.name} : un `||` désactiverait errexit"
        assert "trap 'on_exit' EXIT" in code, f"{script.name} : piège EXIT attendu"
        assert re.search(r'^\s*main "\$@"\s*$', code, re.MULTILINE), f"{script.name} : appel inconditionnel attendu"
        assert "local status=$?" in code, f"{script.name} : on_exit doit lire le code de sortie"


def test_load_readme_documents_the_acceptance_criterion() -> None:
    text = LOAD_README.read_text(encoding="utf-8")

    assert "100 req/s" in text
    assert "http_req_failed" in text
    assert "p95" in text
