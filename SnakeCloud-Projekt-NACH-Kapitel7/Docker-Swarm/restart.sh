#!/usr/bin/env bash
set -euo pipefail

STACK=snakecloud
FILE=docker-stack.yml
NET="${STACK}_snake"

have_services() { docker service ls --format '{{.Name}}' | grep -q "^${STACK}_"; }
have_network()  { docker network ls  --format '{{.Name}}' | grep -qx "$NET"; }
have_configs()  { docker config  ls  --format '{{.Name}}' | grep -q "^${STACK}_"; }

echo ">> Remove old stack (if any)…"
docker stack rm "$STACK" 2>/dev/null || true

echo ">> Wait for services to disappear…"
for i in {1..120}; do have_services && sleep 1 || break; done

echo ">> Wait for network to disappear…"
for i in {1..60}; do have_network && sleep 1 || break; done

echo ">> Cleanup old configs (immutable)…"
have_configs && docker config ls --format '{{.Name}}' | grep "^${STACK}_" | xargs -r docker config rm || true

echo ">> Deploy stack…"
docker stack deploy -c "$FILE" "$STACK" --prune --detach=false

echo ">> Services:"
docker stack services "$STACK"