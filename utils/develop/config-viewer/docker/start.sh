#!/bin/bash
# Start of one part of the config viewer in a container: web | service | jobs  (see ../docker-compose.yml)
set -eu
cd "$(dirname "$0")/.."
RUNAS="${VIEWER_RUN_AS:-ubuntu}"

# as the runtime user; started as root only to hand over the data volume and (jobs) the group of the docker socket
as_user() {
    if [ "$(id -u)" != "0" ]; then exec "${@:2}"; fi
    exec setpriv --reuid "$RUNAS" --regid "$RUNAS" --groups "${1}" "${@:2}"
}
groups_default="$(id -g "$RUNAS" 2>/dev/null || echo 0)"
if [ "$(id -u)" = "0" ]; then chown "$RUNAS:$RUNAS" "$PANOSPHP_VIEWER_DATA"; fi
# the home of the runtime user, not the one of root (the docker client looks for its settings there)
if [ "$(id -u)" = "0" ]; then export HOME="$(getent passwd "$RUNAS" | cut -d: -f6)"; fi

case "${1:-web}" in
web)
    # first start: one admin user. Password from VIEWER_ADMIN_PASSWORD, otherwise a random one - shown once in the log.
    if [ "$(id -u)" = "0" ]; then
        users="$(setpriv --reuid "$RUNAS" --regid "$RUNAS" --clear-groups php bin/user.php list)"
        if [ -z "$users" ]; then
            name="${VIEWER_ADMIN_USER:-admin}"
            pw="${VIEWER_ADMIN_PASSWORD:-}"
            shown=""
            if [ -z "$pw" ]; then pw="$(php -r 'echo bin2hex(random_bytes(12));')"; shown="$pw"; fi
            VIEWER_PASSWORD="$pw" setpriv --reuid "$RUNAS" --regid "$RUNAS" --clear-groups php bin/user.php add "$name" admin >/dev/null
            echo "config-viewer: first start - user \"$name\" created."
            if [ -n "$shown" ]; then echo "config-viewer: password: $shown   (shown only now - change it under Account)"; fi
        fi
    fi
    echo "config-viewer: web part on port 8080"
    as_user "$groups_default" php -S 0.0.0.0:8080 -t .
    ;;
service)
    as_user "$groups_default" php bin/service.php
    ;;
jobs)
    g="$groups_default"
    # the group that owns the docker socket (differs per host; root on Docker Desktop)
    if [ -S /var/run/docker.sock ]; then g="$g,$(stat -c %g /var/run/docker.sock)"; fi
    as_user "$g" php bin/jobs.php
    ;;
*)
    echo "usage: start.sh web | service | jobs" >&2
    exit 2
    ;;
esac
