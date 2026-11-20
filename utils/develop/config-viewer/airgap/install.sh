#!/bin/bash
# pan-os-php config viewer - installation / update without internet. Needs Docker with "docker compose".
#
#   ./install.sh                                   this computer only: http://127.0.0.1:8080/
#   VIEWER_DOMAIN=viewer.example.com ./install.sh  for several users: https://viewer.example.com/ (see README.txt)
#
# Run it again with a newer bundle to update; the data (volume panosphp-viewer-data) stays.
set -euo pipefail
cd "$(dirname "$0")"

docker version >/dev/null 2>&1 || { echo "Docker is not installed or not running." >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "\"docker compose\" (Compose plugin) is missing." >&2; exit 1; }

want="$(sed -n 's/^platform *//p' VERSION.txt 2>/dev/null || true)"
have="linux/$(docker version --format '{{.Server.Arch}}' 2>/dev/null || echo unknown)"
if [ -n "$want" ] && [ "$have" != "linux/unknown" ] && [ "$want" != "$have" ]; then
    echo "This bundle is for $want, this Docker runs $have - ask for the matching bundle." >&2; exit 1
fi

echo "loading the images (this takes a moment) ..."
gunzip -c images.tar.gz | docker load

files=( -f docker-compose.yml )
if [ -n "${VIEWER_DOMAIN:-}" ]; then files+=( -f docker-compose.https.yml ); fi
docker compose "${files[@]}" up -d

echo
if [ -n "${VIEWER_DOMAIN:-}" ]; then echo "config viewer: https://${VIEWER_DOMAIN}/"; else echo "config viewer: http://127.0.0.1:${VIEWER_PORT:-8080}/"; fi
sleep 3
docker compose "${files[@]}" logs web 2>/dev/null | grep "config-viewer:" | grep -E "first start|password" || echo "(users exist already - log in as before)"
