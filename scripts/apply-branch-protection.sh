#!/usr/bin/env bash
#
# Applique la protection de branche sur `main` (v0.7, issue #23).
#
# Idempotent : rejouer le script remet la configuration dans cet état. C'est ce
# qui permet de versionner la politique d'accès au dépôt — la lire dans un
# fichier vaut mieux que la deviner dans l'interface GitHub.
#
# Prérequis : un jeton avec le droit d'administration sur le dépôt.
#   GITHUB_TOKEN=… ./scripts/apply-branch-protection.sh [owner/repo]

set -euo pipefail

REPO="${1:-${GITHUB_REPOSITORY:-kitokoh/sentinelle}}"
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
BRANCH="${BRANCH:-main}"

[[ -n "${TOKEN}" ]] || {
  echo "Un jeton est requis : GITHUB_TOKEN=… $0" >&2
  exit 2
}

# Les noms de vérifications doivent correspondre EXACTEMENT aux noms de jobs de
# .github/workflows/ci.yml. Une faute de frappe ici rend la vérification
# simplement... ignorée : GitHub attend un statut qui n'arrivera jamais, et la
# fusion reste bloquée.
read -r -d '' PAYLOAD <<'JSON' || true
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "backend (sqlite)",
      "backend (postgres)",
      "migrations",
      "secrets",
      "helm",
      "e2e",
      "frontend"
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
JSON

echo "Application de la protection sur ${REPO}@${BRANCH}…"
response="$(
  curl -sS -X PUT \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -d "${PAYLOAD}" \
    "https://api.github.com/repos/${REPO}/branches/${BRANCH}/protection"
)"

if command -v jq >/dev/null 2>&1; then
  echo "${response}" | jq '{strict: .required_status_checks.strict, checks: .required_status_checks.contexts, enforce_admins: .enforce_admins.enabled, force_push: .allow_force_pushes.enabled}'
else
  echo "${response}"
fi

echo
echo "Vérification :"
echo "  curl -s -H \"Authorization: Bearer \$GITHUB_TOKEN\" \\"
echo "    https://api.github.com/repos/${REPO}/branches/${BRANCH}/protection | jq"
