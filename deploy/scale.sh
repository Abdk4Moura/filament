#!/usr/bin/env bash
# Fast horizontal scale of the api (signaling) — up or down in seconds.
# The api is Redis-backed, so replicas share room state and any of them can
# serve any peer. cloudflared round-robins across them.
#
#   ./scale.sh 4      # 4 api replicas
#   ./scale.sh 1      # back to one
set -euo pipefail
N="${1:?usage: scale.sh <replica-count>}"
cd "$(dirname "$0")"
# --no-recreate keeps existing replicas running (only add/remove the delta).
docker compose up -d --no-deps --no-recreate --scale api="$N" api
docker compose ps api
