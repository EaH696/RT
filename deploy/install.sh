#!/usr/bin/env bash
# RT Community Edition — single-host appliance installer.
#
# Brings up the policy-gate, sandbox and orchestrator console via Docker
# Compose. Requires: docker (with the compose plugin). Run from the repo root
# or from deploy/.
#
#   ./deploy/install.sh up        # build + start the appliance
#   ./deploy/install.sh down      # stop it
#   ./deploy/install.sh logs      # follow logs
#
# AUTHORIZED SECURITY TESTING ONLY. Provide a signed engagement scope before
# running an engagement — see docs/engagement-scope-template.md.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$HERE/docker-compose.yml"
cmd="${1:-up}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required but not installed." >&2; exit 1; }; }
need docker
if docker compose version >/dev/null 2>&1; then
  DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  DC=(docker-compose)
else
  echo "error: the Docker Compose plugin (or docker-compose) is required." >&2
  exit 1
fi

mkdir -p "$HERE/scope" "$HERE/engagements"

case "$cmd" in
  up)
    if [ ! -f "$HERE/scope/scope.json" ]; then
      cat >&2 <<'EOF'
note: no signed scope found at deploy/scope/scope.json

  The policy-gate needs a signed Rules-of-Engagement scope. Create and sign one:

    cd orchestrator && pip install -e .
    rt scope new --engagement ACME-2026 \
        --allow 10.0.0.0/24 --allow app.acme.test \
        --exclude 10.0.0.9/32 --file ../deploy/scope/scope.json
    rt scope sign --operator "$USER" --file ../deploy/scope/scope.json

  Then re-run: ./deploy/install.sh up
EOF
      exit 1
    fi
    echo ">> building and starting the RT appliance..."
    "${DC[@]}" -f "$COMPOSE_FILE" up -d --build
    echo
    echo ">> RT is up. Operator console: http://127.0.0.1:8900"
    echo ">> Logs:  ./deploy/install.sh logs      Stop:  ./deploy/install.sh down"
    ;;
  down)
    "${DC[@]}" -f "$COMPOSE_FILE" down
    ;;
  logs)
    "${DC[@]}" -f "$COMPOSE_FILE" logs -f
    ;;
  *)
    echo "usage: $0 {up|down|logs}" >&2
    exit 2
    ;;
esac
