#!/bin/bash
# pan-os-php config viewer - installation / update without internet. Needs Docker with "docker compose".
#
#   ./install.sh        asks the first time: only this computer (http://127.0.0.1:8080/) or HTTPS for several users
#                       (no questions: VIEWER_HTTPS=yes VIEWER_DOMAIN=viewer.example.com ./install.sh)
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

# images from images.tar.gz, settings (questions on the first time), start, address and the one-time code
chmod +x ./panosphp-viewer
./panosphp-viewer update
./panosphp-viewer start
echo
echo "Later: ./panosphp-viewer status | stop | start | license <file> | plugin <file.ppp> | help"
