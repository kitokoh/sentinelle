#!/usr/bin/env bash
#
# Vérifie la signature des commits (v0.7, issue #23).
#
# Deux usages :
#   ./scripts/verify-signatures.sh            # rapport sur les 20 derniers commits
#   ./scripts/verify-signatures.sh --strict   # code de sortie 1 si un commit n'est pas signé
#
# Le mode strict est destiné à un futur job de CI. Il échoue aujourd'hui sur les
# commits antérieurs à la mise en place des clés : c'est le comportement attendu,
# et c'est la raison pour laquelle il n'est pas encore branché sur la CI — un
# contrôle qui échoue en permanence ne contrôle rien.

set -euo pipefail

COUNT="${COUNT:-20}"
STRICT=0
[[ "${1:-}" == "--strict" ]] && STRICT=1

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "Ce script doit être exécuté dans un dépôt git." >&2
  exit 2
fi

# `%G?` : G = bonne signature, U = bonne mais clé inconnue, B = mauvaise,
# N = non signé. On ne considère valides que G et U : une signature qu'on ne peut
# pas rattacher à une clé connue n'apporte pas la garantie recherchée.
total=0
signed=0
unsigned=0
untrusted=0

while IFS=$'\t' read -r status sha subject; do
  total=$((total + 1))
  case "${status}" in
    G) signed=$((signed + 1)) ;;
    U) signed=$((signed + 1)); untrusted=$((untrusted + 1)) ;;
    N) unsigned=$((unsigned + 1)); printf 'non signé   %s  %s\n' "${sha}" "${subject}" ;;
    *) printf 'signature invalide (%s)  %s  %s\n' "${status}" "${sha}" "${subject}" ;;
  esac
done < <(git log -n "${COUNT}" --pretty=format:'%G?%x09%h%x09%s')

echo
printf '%d commit(s) analysé(s) — signés : %d, non signés : %d' "${total}" "${signed}" "${unsigned}"
[[ "${untrusted}" -gt 0 ]] && printf ', dont %d avec une clé inconnue' "${untrusted}"
printf '\n'

if [[ "${STRICT}" -eq 1 && "${unsigned}" -gt 0 ]]; then
  echo "Échec : ${unsigned} commit(s) sans signature." >&2
  exit 1
fi

if [[ "${unsigned}" -gt 0 ]]; then
  echo "Rappel : voir docs/GOVERNANCE.md pour activer la signature des commits."
fi
