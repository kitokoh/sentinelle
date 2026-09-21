"""Secrets hygiene tests (v0.6, issue #17).

Acceptance criteria: no plaintext secret in the compose file or the Helm values,
and a `gitleaks` run that finds nothing. The gitleaks run itself happens in CI;
what is checked here is the part a test can check deterministically:

* every secret-bearing environment variable is fed by **interpolation**, never by
  a literal value written in the file;
* the Helm chart refuses to embed passwords (it takes a reference to an existing
  Secret);
* the inventory in ``docs/SECRETS.md`` covers every secret the deployment declares
  — a secret that is not documented is a secret nobody will know how to rotate;
* no ``.env`` file is committed, and the ignore rules actually cover it.
"""

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE = REPO_ROOT / "docker-compose.yml"
HELM_VALUES = REPO_ROOT / "helm" / "sentinelle" / "values.yaml"
HELM_SECRET_TEMPLATE = REPO_ROOT / "helm" / "sentinelle" / "templates" / "secret.yaml"
SECRETS_DOC = REPO_ROOT / "docs" / "SECRETS.md"
GITLEAKS_CONFIG = REPO_ROOT / ".gitleaks.toml"
GITIGNORE = REPO_ROOT / ".gitignore"

#: Environment variables that carry a credential, and are therefore expected to be
#: interpolated from the environment rather than written in the file.
SECRET_ENV_VARS = (
    "JWT_SECRET",
    "POSTGRES_PASSWORD",
    "OIDC_CLIENT_SECRET",
    "METRICS_TOKEN",
    "GRAFANA_ADMIN_PASSWORD",
    "SENTINELLE_CLIENT_SECRET",
    "KC_ADMIN_PASSWORD",
    "MISP_API_KEY",
    "OTX_API_KEY",
    "FIELD_ENCRYPTION_KEY",
)

#: Values that are deliberately not secret: placeholders that must be replaced,
#: and the demo credentials of the Keycloak realm.
KNOWN_PLACEHOLDERS = {
    "change-me-in-production",
    "change-me-admin",
    "not-configured-change-me",
    "",
}

INTERPOLATION = re.compile(r"^\$\{[A-Z0-9_]+(:[-?][^}]*)?\}$")


def _compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def _environment_of(service: str) -> dict:
    environment = _compose()["services"][service].get("environment", {})
    # Compose accepts both a mapping and a list of "K=V".
    if isinstance(environment, list):
        return dict(item.split("=", 1) for item in environment)
    return environment


# --------------------------------------------------------------------------- #
# Compose
# --------------------------------------------------------------------------- #


def test_every_secret_in_compose_comes_from_the_environment():
    """A literal in compose is a secret in git — the exact thing #17 forbids."""
    offenders: list[str] = []

    for service, spec in _compose()["services"].items():
        environment = spec.get("environment", {})
        if isinstance(environment, list):
            environment = dict(item.split("=", 1) for item in environment)
        for name, value in (environment or {}).items():
            if name not in SECRET_ENV_VARS:
                continue
            text = "" if value is None else str(value)
            if text in KNOWN_PLACEHOLDERS:
                continue
            if INTERPOLATION.match(text):
                continue
            offenders.append(f"{service}.{name} = {text!r}")

    assert not offenders, (
        "Ces valeurs doivent venir de l'environnement (${VAR:-defaut}) :\n  "
        + "\n  ".join(offenders)
    )


def test_compose_configures_the_encryption_key():
    """#18 is only real if the key can actually be provided at deployment."""
    api_environment = _environment_of("api")

    # Either present as an interpolation, or deliberately absent from compose and
    # documented as coming from the secret store. Both are acceptable; silence is not.
    documented = "FIELD_ENCRYPTION_KEY" in SECRETS_DOC.read_text(encoding="utf-8")
    assert documented
    assert "FIELD_ENCRYPTION_KEY" not in api_environment or INTERPOLATION.match(
        str(api_environment["FIELD_ENCRYPTION_KEY"])
    )


def test_no_env_file_is_committed():
    assert not (REPO_ROOT / ".env").exists()
    assert not (REPO_ROOT / "backend" / ".env").exists()

    ignored = GITIGNORE.read_text(encoding="utf-8")
    assert ".env" in ignored


# --------------------------------------------------------------------------- #
# Helm chart
# --------------------------------------------------------------------------- #


def test_helm_values_contain_no_password():
    """The chart takes a reference to a Secret, not the secret itself."""
    values = yaml.safe_load(HELM_VALUES.read_text(encoding="utf-8"))

    def walk(node, path=""):
        found = []
        if isinstance(node, dict):
            for key, value in node.items():
                found.extend(walk(value, f"{path}.{key}" if path else key))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                found.extend(walk(value, f"{path}[{index}]"))
        else:
            key = path.rsplit(".", 1)[-1].lower()
            # `existingSecret` names a Kubernetes Secret to use -- a reference, not
            # a value. Flagging it would train us to ignore this check.
            if key in {"existingsecret", "secretname", "secretkeyref"}:
                return found
            if any(word in key for word in ("password", "secret", "token", "key")):
                text = "" if node is None else str(node)
                if text not in KNOWN_PLACEHOLDERS and not INTERPOLATION.match(text):
                    found.append(f"{path} = {text!r}")
        return found

    offenders = walk(values)

    assert not offenders, "Valeurs ressemblant à des secrets dans values.yaml :\n  " + "\n  ".join(
        offenders
    )


def test_the_chart_prefers_an_existing_secret():
    """The default must be the secure path: an externally managed Secret."""
    values = yaml.safe_load(HELM_VALUES.read_text(encoding="utf-8"))

    assert values.get("existingSecret"), "existingSecret doit être défini par défaut"
    template = HELM_SECRET_TEMPLATE.read_text(encoding="utf-8")
    assert "existingSecret" in template
    # When the chart does render a Secret, it must refuse to invent values.
    assert "required" in template


# --------------------------------------------------------------------------- #
# Documentation completeness
# --------------------------------------------------------------------------- #


def test_the_secret_inventory_documents_every_secret_we_use():
    """A secret absent from the inventory is a secret nobody can rotate."""
    inventory = SECRETS_DOC.read_text(encoding="utf-8")

    compose_text = COMPOSE.read_text(encoding="utf-8")
    helm_text = HELM_VALUES.read_text(encoding="utf-8")
    declared = {
        name
        for name in SECRET_ENV_VARS
        if name in compose_text or name in helm_text or name in (REPO_ROOT / "backend" / ".env.example").read_text(encoding="utf-8")
    }

    missing = sorted(name for name in declared if name not in inventory)

    assert not missing, f"Secrets absents de docs/SECRETS.md : {missing}"
    # And the inventory must explain the tricky one instead of just listing it.
    assert "rotation" in inventory.lower()
    assert "FIELD_ENCRYPTION_KEY" in inventory


def test_the_rotation_procedure_is_actually_implemented():
    """A documented procedure nobody can run is a trap, not documentation."""
    inventory = SECRETS_DOC.read_text(encoding="utf-8")

    assert "scripts/rotate_field_key.py" in inventory
    assert (REPO_ROOT / "backend" / "scripts" / "rotate_field_key.py").exists()


# --------------------------------------------------------------------------- #
# gitleaks configuration
# --------------------------------------------------------------------------- #


def test_gitleaks_configuration_exists_and_keeps_the_default_rules():
    assert GITLEAKS_CONFIG.exists()
    text = GITLEAKS_CONFIG.read_text(encoding="utf-8")

    # Extending the default ruleset matters: a hand-written config that only
    # covers our own patterns would silently drop AWS keys and private keys.
    assert "useDefault = true" in text

    tomllib = pytest.importorskip("tomllib", reason="tomllib requires Python 3.11+")
    document = tomllib.loads(text)
    assert document["extend"]["useDefault"] is True
    allowlist = document.get("allowlist", {})
    # The allowlist must stay narrow: file-specific and regex-specific.
    assert allowlist, "l'allowlist doit documenter ses exceptions"
    assert len(allowlist.get("paths", [])) <= 2


def test_the_secrets_helper_script_is_present_and_executable():
    script = REPO_ROOT / "scripts" / "secrets.sh"

    assert script.exists()
    assert script.stat().st_mode & 0o111, "scripts/secrets.sh doit être exécutable"
    # Refusing a destructive rotation without a name is the whole point of `rotate`.
    assert "rotate" in script.read_text(encoding="utf-8")
