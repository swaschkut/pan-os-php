#!/bin/bash
# Makes the bundle for an installation without internet (air gap): images + compose files + install.sh in one file.
# Run it on a computer with internet and Docker:
#
#   utils/develop/config-viewer/airgap/make-bundle.sh [image] [platform] [plug-in folder]
#       image          default swaschkut/pan-os-php:alpha
#       platform       linux/amd64 (Intel / AMD servers) or linux/arm64 (Apple silicon, ARM servers); default: this computer
#       plug-in folder optional: the licensed plug-ins (*.ppp) to ship with it - never plug-in source folders
#
# Result: panosphp-viewer-<tag>-<platform>-<date>.tar.gz in the current folder. At the customer:
#   tar xzf panosphp-viewer-….tar.gz && cd panosphp-viewer && ./install.sh
set -euo pipefail
IMAGE="${1:-swaschkut/pan-os-php:alpha}"
PLATFORM="${2:-}"
PLUGIN_SRC="${3:-}"
PROXY="caddy:2"
HERE="$(cd "$(dirname "$0")" && pwd)"
VIEWER="$(dirname "$HERE")"
if [ -z "$PLATFORM" ]; then
    case "$(uname -m)" in arm64|aarch64) PLATFORM="linux/arm64" ;; *) PLATFORM="linux/amd64" ;; esac
fi
TAG="${IMAGE##*:}"
NAME="panosphp-viewer-${TAG}-${PLATFORM##*/}-$(date +%Y%m%d)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
B="$WORK/panosphp-viewer"
mkdir -p "$B/docker/certs"

echo "images for $PLATFORM: $IMAGE, $PROXY"
docker pull --platform "$PLATFORM" "$IMAGE"
docker pull --platform "$PLATFORM" "$PROXY"
docker save "$IMAGE" "$PROXY" | gzip > "$B/images.tar.gz"

cp "$VIEWER/docker-compose.yml" "$VIEWER/docker-compose.https.yml" "$VIEWER/panosphp-viewer" "$B/"
cp "$VIEWER/docker/Caddyfile" "$B/docker/"
cp "$HERE/install.sh" "$HERE/README.txt" "$B/"
chmod +x "$B/install.sh" "$B/panosphp-viewer"
mkdir -p "$B/plugins"
if [ -n "$PLUGIN_SRC" ]; then
    n=0
    for f in "$PLUGIN_SRC"/*.ppp; do [ -f "$f" ] && cp "$f" "$B/plugins/" && n=$((n + 1)); done
    echo "licensed plug-ins in the bundle: $n"
fi
# the image this bundle was made with
printf 'VIEWER_IMAGE=%s\n' "$IMAGE" > "$B/.env"
printf 'image    %s\nproxy    %s\nplatform %s\nmade     %s\n' "$IMAGE" "$PROXY" "$PLATFORM" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$B/VERSION.txt"

tar -C "$WORK" -czf "$NAME.tar.gz" panosphp-viewer
echo "bundle: $NAME.tar.gz ($(du -h "$NAME.tar.gz" | cut -f1))"
