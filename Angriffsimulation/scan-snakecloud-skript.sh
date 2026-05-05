#!/usr/bin/env bash

set -euo pipefail

BASE="${BASE:-176.118.193}"
KEYWORD="${KEYWORD:-SnakeCloud}"
CONCURRENCY="${CONCURRENCY:-64}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-4}"
TOTAL_TIMEOUT="${TOTAL_TIMEOUT:-8}"

command -v curl >/dev/null || { echo "curl wird benötigt" >&2; exit 1; }

scan_one() {
  local ip="$1" html title port scheme
  for scheme in https http; do
    port=$([ "$scheme" = https ] && echo 443 || echo 80)
    html="$(curl -s -k -L \
      --connect-timeout "$CONNECT_TIMEOUT" \
      -m "$TOTAL_TIMEOUT" \
      "$scheme://$ip:$port/" 2>/dev/null || true)"
    [[ -z "$html" ]] && continue
    title="$(printf '%s' "$html" | tr '\r\n' ' ' \
      | sed -n 's/.*<title[^>]*>\(.*\)<\/title>.*/\1/pI' | head -n1)"
    if printf '%s' "$title" | grep -qi -- "$KEYWORD"; then
      echo "$ip"
      return 0
    fi
  done
  return 1
}

export -f scan_one
export KEYWORD CONNECT_TIMEOUT TOTAL_TIMEOUT

seq 1 254 | xargs -I{} -P "$CONCURRENCY" bash -c 'scan_one "'"$BASE"'.{}"'