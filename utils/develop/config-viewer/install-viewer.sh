#!/bin/bash
# pan-os-php config viewer - installation with one file (computer with internet and Docker).
#
#   curl -fsSL https://raw.githubusercontent.com/swaschkut/pan-os-php/alpha/utils/develop/config-viewer/install-viewer.sh | bash
#   or:  bash install-viewer.sh [folder]
#
# Makes the folder (default ./panosphp-viewer), downloads the start script and the compose files into it, and starts
# the viewer (asks the first time: only this computer, or HTTPS for several users). Run it again to update: the files
# are downloaded again, settings (.env), plug-ins (plugins/) and all data stay.
#
# Settings:  PANOSPHP_CHANNEL  alpha (default) | beta | dev | main  - branch of the files and tag of the image
#            VIEWER_HTTPS=yes VIEWER_DOMAIN=<name>                  - HTTPS without questions (see panosphp-viewer setup)
# Without internet: the air-gap bundle (one file with images, install.sh inside) - ask for it.
set -euo pipefail

CHANNEL="${PANOSPHP_CHANNEL:-alpha}"
case "$CHANNEL" in
    alpha) TAG=alpha ;; beta) TAG=beta ;; dev) TAG=develop ;; main) TAG=latest ;;
    *) echo "install-viewer: PANOSPHP_CHANNEL must be alpha, beta, dev or main" >&2; exit 1 ;;
esac
BASE="${PANOSPHP_VIEWER_BASE_URL:-https://raw.githubusercontent.com/swaschkut/pan-os-php/$CHANNEL/utils/develop/config-viewer}"
DIR="${1:-panosphp-viewer}"

fail() { echo "install-viewer: $*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || fail "curl is missing"
command -v docker >/dev/null 2>&1 || fail "Docker is not installed (https://docs.docker.com/get-docker/)"
docker version >/dev/null 2>&1 || fail "Docker is not running (or this user may not use it: group docker, or run with sudo)"
docker compose version >/dev/null 2>&1 || fail "\"docker compose\" is missing (Compose plugin of Docker)"

mkdir -p "$DIR/docker" "$DIR/plugins"
cd "$DIR"
echo "pan-os-php config viewer ($CHANNEL) in $(pwd)"

# all files first into a temporary folder: a broken download changes nothing
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
for f in panosphp-viewer docker-compose.yml docker-compose.https.yml docker/Caddyfile; do
    mkdir -p "$tmp/$(dirname "$f")"
    curl -fsSL "$BASE/$f" -o "$tmp/$f" || fail "download failed: $BASE/$f"
done
head -1 "$tmp/panosphp-viewer" | grep -q '^#!/bin/bash' || fail "the download is not the start script - check the address / proxy"
for f in panosphp-viewer docker-compose.yml docker-compose.https.yml docker/Caddyfile; do
    mv "$tmp/$f" "$f"
done
chmod +x panosphp-viewer

# the image of this channel (kept in .env; an existing .env keeps its own value)
if [ ! -f .env ]; then
    printf 'VIEWER_IMAGE=swaschkut/pan-os-php:%s\n' "$TAG" > .env
    chmod 600 .env
    first=yes
else
    first=no
fi

# questions need the terminal also when this script comes through a pipe (curl … | bash)
if [ -t 0 ]; then in=/dev/stdin; elif ( exec < /dev/tty ) 2>/dev/null; then in=/dev/tty; else in=/dev/null; fi
if [ "$first" = yes ]; then
    ./panosphp-viewer start < "$in"
else
    ./panosphp-viewer update < "$in"
    ./panosphp-viewer start < "$in"
fi

echo
echo "Next time: cd $(pwd) && ./panosphp-viewer start | stop | status | help"
