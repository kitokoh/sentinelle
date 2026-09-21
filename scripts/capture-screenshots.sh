#!/usr/bin/env bash
#
# Produit les captures d'écran et le GIF de démonstration (v0.7, issue #24).
#
#    ./scripts/capture-screenshots.sh
#
# Le script démarre ce qu'il faut (API + interface), remplit une base de
# démonstration jetable, capture, assemble le GIF, puis nettoie. Rien n'est
# laissé en marche, et rien n'est fabriqué : les images sortent de l'interface
# réelle.
#
# Prérequis : node, python3, ffmpeg, et les navigateurs Playwright
# (`cd frontend && npx playwright install chromium`).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_PORT="${API_PORT:-8000}"
WEB_PORT="${WEB_PORT:-5173}"
WEB_URL="${WEB_URL:-http://localhost:${WEB_PORT}}"
DB_PATH="$(mktemp -t sentinelle-demo-XXXXXX.db)"
ASSETS="${ROOT}/docs/assets"
FRAMES="${ROOT}/frontend/.playwright-frames"

API_PID=""
WEB_PID=""

log() { printf '\n\033[1m[captures]\033[0m %s\n' "$*"; }
die() { printf '[captures] ERREUR : %s\n' "$*" >&2; exit 1; }

cleanup() {
  [[ -n "${WEB_PID}" ]] && kill "${WEB_PID}" 2>/dev/null || true
  [[ -n "${API_PID}" ]] && kill "${API_PID}" 2>/dev/null || true
  rm -f "${DB_PATH}"
}
trap cleanup EXIT

command -v ffmpeg >/dev/null 2>&1 || die "ffmpeg est requis pour assembler le GIF."
command -v node   >/dev/null 2>&1 || die "node est requis."

# --- 1. Base de démonstration ------------------------------------------------
log "Préparation de la base de démonstration…"
(
  cd "${ROOT}/backend"
  DATABASE_URL="sqlite+aiosqlite:///${DB_PATH}" ENV=dev python3 seed_demo.py >/dev/null
)

# --- 2. API ------------------------------------------------------------------
log "Démarrage de l'API sur le port ${API_PORT}…"
(
  cd "${ROOT}/backend"
  DATABASE_URL="sqlite+aiosqlite:///${DB_PATH}" ENV=dev \
    nohup python3 -m uvicorn app.main:app --host 127.0.0.1 --port "${API_PORT}" \
    > /tmp/sentinelle-capture-api.log 2>&1 &
  echo $! > /tmp/sentinelle-capture-api.pid
)
API_PID="$(cat /tmp/sentinelle-capture-api.pid)"

for _ in $(seq 1 30); do
  curl -sf -m 2 "http://127.0.0.1:${API_PORT}/api/health" >/dev/null && break
  sleep 1
done
curl -sf -m 2 "http://127.0.0.1:${API_PORT}/api/health" >/dev/null \
  || die "l'API n'a pas démarré — voir /tmp/sentinelle-capture-api.log"

# --- 3. Interface ------------------------------------------------------------
log "Démarrage de l'interface sur le port ${WEB_PORT}…"
(
  cd "${ROOT}/frontend"
  nohup npm run dev -- --port "${WEB_PORT}" > /tmp/sentinelle-capture-web.log 2>&1 &
  echo $! > /tmp/sentinelle-capture-web.pid
)
WEB_PID="$(cat /tmp/sentinelle-capture-web.pid)"

for _ in $(seq 1 30); do
  curl -sf -m 2 "${WEB_URL}/" >/dev/null && break
  sleep 1
done
curl -sf -m 5 "${WEB_URL}/api/health" >/dev/null \
  || die "l'interface ou son proxy /api ne répond pas — voir /tmp/sentinelle-capture-web.log"

# --- 4. Capture --------------------------------------------------------------
log "Capture en cours…"
mkdir -p "${ASSETS}"
rm -rf "${FRAMES}"
mkdir -p "${FRAMES}"

(
  cd "${ROOT}/frontend"
  E2E_BASE_URL="${WEB_URL}" CAPTURE_DIR="${ASSETS}" CAPTURE_FRAMES="${FRAMES}" \
    npx playwright test e2e/capture.spec.ts
)

# --- 5. GIF ------------------------------------------------------------------
# Le GIF est assemblé à partir des images du parcours. Contrainte : rester sous
# 2 Mo, sinon GitHub ne l'anime pas. On y arrive par la palette (256 couleurs
# réellement présentes) plutôt qu'en réduisant la durée — un GIF saccadé ne
# montre rien.
log "Assemblage du GIF…"
ffmpeg -hide_banner -loglevel error -y \
  -framerate 1 -pattern_type glob -i "${FRAMES}/*.png" \
  -vf "scale=1100:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=192[p];[s1][p]paletteuse=dither=bayer" \
  -loop 0 "${ASSETS}/demo.gif"

SIZE_KB=$(( $(stat -c%s "${ASSETS}/demo.gif") / 1024 ))
log "GIF : ${ASSETS}/demo.gif (${SIZE_KB} Ko)"
if [[ "${SIZE_KB}" -gt 2048 ]]; then
  echo "[captures] AVERTISSEMENT : le GIF dépasse 2 Mo, GitHub ne l'animera pas." >&2
  echo "[captures] Réduire CAPTURE_FRAMES ou la largeur du redimensionnement." >&2
fi

log "Terminé. Images dans ${ASSETS} :"
ls -la "${ASSETS}" | tail -n +2
