#!/usr/bin/env bash
# Usage: ./lab.sh up <weak|hardened> | down | status
set -euo pipefail
cd "$(dirname "$0")"

# down uses the weak env file so the weak-only services are included too.
compose() { docker compose --env-file "profiles/$1/lab.env" "${@:2}"; }

case "${1:-}" in
  up)
    profile="${2:-}"
    [[ -f "profiles/$profile/lab.env" ]] || { echo "usage: $0 up <weak|hardened>" >&2; exit 2; }
    compose weak down -v --remove-orphans
    compose "$profile" up -d --build --wait
    compose "$profile" --profile setup run --rm search-setup
    ln -sfn "profiles/$profile" .current  # read by target.yaml
    echo "lab is up with the '$profile' profile"
    ;;
  down)
    compose weak down -v --remove-orphans
    rm -f .current
    ;;
  status)
    echo "profile: $(readlink .current || echo none)"
    compose weak ps
    ;;
  *) echo "usage: $0 up <weak|hardened> | down | status" >&2; exit 2 ;;
esac
