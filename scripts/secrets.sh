#!/usr/bin/env bash
#
# Manipulation des secrets chiffrés (SOPS + age) — v0.6, issue #17.
#
# Pourquoi un script plutôt qu'une ligne de commande dans la documentation :
# une procédure de rotation recopiée de travers est la façon la plus courante de
# fuiter un secret. Les commandes sont donc écrites une fois, ici, et testées.
#
# Aucune valeur secrète ne transite par un fichier en clair persistant :
# `edit` travaille dans un répertoire temporaire dont le contenu est effacé à la
# sortie, même en cas d'échec.

set -euo pipefail

SECRETS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/deploy/secrets"
SECRETS_FILE="${SECRETS_DIR}/sentinelle.enc.yaml"
SOPS_CONFIG="${SECRETS_DIR}/.sops.yaml"

log() { printf '[secrets] %s\n' "$*" >&2; }
die() { printf '[secrets] ERREUR : %s\n' "$*" >&2; exit 1; }

require_tools() {
  command -v sops >/dev/null 2>&1 || die "sops est introuvable. Installez-le : https://getsops.io"
  command -v age >/dev/null 2>&1 || log "age est introuvable — nécessaire seulement pour générer une clé."
}

ensure_file() {
  if [[ ! -f "${SECRETS_FILE}" ]]; then
    die "fichier de secrets absent : ${SECRETS_FILE}
Créez-le d'abord avec : $0 init"
  fi
}

# Gabarit vide : les NOMS des variables attendues, aucune valeur.
template() {
  cat <<'EOF'
jwt_secret: ""
field_encryption_key: ""
postgres_password: ""
misp_api_key: ""
otx_api_key: ""
oidc_client_secret: ""
metrics_token: ""
grafana_admin_password: ""
EOF
}

cmd_init() {
  [[ -f "${SECRETS_FILE}" ]] && die "le fichier existe déjà : ${SECRETS_FILE}"
  local tmp
  tmp="$(mktemp)"
  chmod 600 "${tmp}"
  trap 'rm -f "${tmp}"' EXIT
  template > "${tmp}"
  log "génération des valeurs aléatoires…"
  # Les trois secrets qui ne viennent d'aucun fournisseur sont générés ici ;
  # les autres (MISP, OTX, OIDC) sont fournis par les services concernés.
  python3 - "${tmp}" <<'PY'
import pathlib, secrets, sys
from cryptography.fernet import Fernet

path = pathlib.Path(sys.argv[1])
text = path.read_text()
text = text.replace('jwt_secret: ""', f'jwt_secret: "{secrets.token_urlsafe(48)}"', 1)
text = text.replace('field_encryption_key: ""', f'field_encryption_key: "{Fernet.generate_key().decode()}"', 1)
text = text.replace('postgres_password: ""', f'postgres_password: "{secrets.token_urlsafe(24)}"', 1)
text = text.replace('metrics_token: ""', f'metrics_token: "{secrets.token_urlsafe(32)}"', 1)
text = text.replace('grafana_admin_password: ""', f'grafana_admin_password: "{secrets.token_urlsafe(24)}"', 1)
path.write_text(text)
PY
  sops --config "${SOPS_CONFIG}" --encrypt --input-type yaml --output "${SECRETS_FILE}" "${tmp}"
  log "créé et chiffré : ${SECRETS_FILE}"
}

cmd_edit() {
  ensure_file
  sops --config "${SOPS_CONFIG}" "${SECRETS_FILE}"
}

cmd_show() {
  ensure_file
  sops --config "${SOPS_CONFIG}" --decrypt "${SECRETS_FILE}"
}

cmd_export() {
  ensure_file
  log "émission des variables d'environnement (à évaluer)…"
  printf 'export JWT_SECRET=%q\n' "$(sops --config "${SOPS_CONFIG}" --extract '["jwt_secret"]' --decrypt "${SECRETS_FILE}")"
  printf 'export FIELD_ENCRYPTION_KEY=%q\n' "$(sops --config "${SOPS_CONFIG}" --extract '["field_encryption_key"]' --decrypt "${SECRETS_FILE}")"
  printf 'export POSTGRES_PASSWORD=%q\n' "$(sops --config "${SOPS_CONFIG}" --extract '["postgres_password"]' --decrypt "${SECRETS_FILE}")"
}

cmd_rotate() {
  local key="${1:-}"
  [[ -n "${key}" ]] || die "usage : $0 rotate <nom_du_secret>"
  ensure_file
  log "rotation de '${key}' — l'ancienne valeur sera perdue à l'enregistrement."
  sops --config "${SOPS_CONFIG}" set "${SECRETS_FILE}" "[\"${key}\"]" "$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
  log "pensez à redémarrer les services consommateurs : la valeur en mémoire est périmée."
}

case "${1:-}" in
  init)    cmd_init ;;
  edit)    cmd_edit ;;
  show)    cmd_show ;;
  export)  cmd_export ;;
  rotate)  cmd_rotate "${2:-}" ;;
  *)
    cat >&2 <<EOF
Usage: $0 <commande>

  init            créer le fichier de secrets (valeurs aléatoires + chiffrement)
  edit            modifier les secrets dans \$EDITOR (déchiffré à la volée)
  show            afficher les secrets déchiffrés
  export          émettre les 'export VAR=…' pour la session courante
  rotate <nom>    régénérer un secret et l'enregistrer chiffré

Fichier : ${SECRETS_FILE}
EOF
    exit 64
    ;;
esac
