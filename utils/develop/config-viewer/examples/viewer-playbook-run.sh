#!/bin/bash
# pan-os-php config viewer: project -> upload a Panorama XML -> run a playbook -> download result XML + set commands
#
#   VIEWER_PASSWORD='...' ./viewer-playbook-run.sh panorama.xml visibility.json [bp.json]
#
# The playbook: a file here is uploaded into the project; a name that is no file here (visibility.json, or
# '$$playbook$$/visibility.json' as with the CLI) is a predefined playbook of pan-os-php - an administrator of the
# viewer turns them on (visibility.json is on by default).
#
# Environment: VIEWER_URL (default http://127.0.0.1:8080), VIEWER_USER (default admin), VIEWER_PASSWORD,
#              VIEWER_PROJECT (project name, default "api-<date>"), VIEWER_OUT (folder for the results, default .)
# Needs curl and jq.
set -euo pipefail
CONFIG="${1:?usage: $0 <panorama.xml> <playbook.json> [bp.json]}"
PLAYBOOK="${2:?usage: $0 <panorama.xml> <playbook.json> [bp.json]}"
BP="${3:-}"
API="${VIEWER_URL:-http://127.0.0.1:8080}/api.php"
USER_NAME="${VIEWER_USER:-admin}"
: "${VIEWER_PASSWORD:?set VIEWER_PASSWORD}"
OUT="${VIEWER_OUT:-.}"
JAR="$(mktemp)"; trap 'rm -f "$JAR"' EXIT

# every call: session cookie + CSRF token; stops with the error text of the API
call() {   # call <method> <route> [curl options...]
    local method="$1" route="$2"; shift 2
    local body status
    body="$(curl -sS -b "$JAR" -c "$JAR" -X "$method" ${CSRF:+-H "X-CSRF-Token: $CSRF"} -w '\n%{http_code}' "$@" "$API/$route")"
    status="${body##*$'\n'}"; body="${body%$'\n'*}"
    if [ "$status" -ge 400 ]; then echo "error $status at $method $route: $(echo "$body" | jq -r '.error // .' 2>/dev/null || echo "$body")" >&2; exit 1; fi
    echo "$body"
}

# 1. login
CSRF=""
CSRF="$(call POST login -H 'Content-Type: application/json' -d "$(jq -n --arg u "$USER_NAME" --arg p "$VIEWER_PASSWORD" '{user:$u,password:$p}')" | jq -r .csrf)"

# 2. project
PID="$(call POST projects -H 'Content-Type: application/json' -d "$(jq -n --arg n "${VIEWER_PROJECT:-api-$(date +%Y%m%d-%H%M%S)}" '{name:$n}')" | jq -r .pid)"
echo "project   $PID"

# 3. configuration, playbook, optional BP JSON
CID="$(call POST "projects/$PID/configs" -F "config=@$CONFIG;type=text/xml" | jq -r .cid)"
echo "version   $CID"
if [ -f "$PLAYBOOK" ]; then
    PB="$(call POST "projects/$PID/files?kind=playbook" -F "file=@$PLAYBOOK;type=application/json" | jq -r .fid)"
    RUN_BODY="$(jq -n --arg pb "$PB" '{playbook:$pb}')"
    echo "playbook  $PLAYBOOK (uploaded)"
else
    NAME="${PLAYBOOK#\$\$playbook\$\$/}"
    RUN_BODY="$(jq -n --arg n "$NAME" '{predefined:$n}')"
    echo "playbook  $NAME (predefined)"
fi
if [ -n "$BP" ]; then
    BPF="$(call POST "projects/$PID/files?kind=bp" -F "file=@$BP;type=application/json" | jq -r .fid)"
    RUN_BODY="$(echo "$RUN_BODY" | jq --arg bp "$BPF" '. + {bp:$bp}')"
fi

# 4. run (without "bp": the BP JSON shipped with pan-os-php)
JID="$(call POST "projects/$PID/configs/$CID/playbook/runs" -H 'Content-Type: application/json' -d "$RUN_BODY" | jq -r .jid)"
echo "run       $JID"
while :; do
    RUN="$(call GET "projects/$PID/runs/$JID")"
    STATE="$(echo "$RUN" | jq -r .state)"
    case "$STATE" in queued|running) sleep 2 ;; *) break ;; esac
done
echo "state     $STATE"

# 5. results: changed configuration, set commands, log
mkdir -p "$OUT"
for f in out.xml set-commands.txt run.log; do
    if echo "$RUN" | jq -e --arg f "$f" '.files[] | select(.name == $f)' >/dev/null; then
        curl -sS -f -b "$JAR" -o "$OUT/$f" "$API/projects/$PID/runs/$JID/files/$f"
        echo "saved     $OUT/$f ($(wc -c < "$OUT/$f") bytes)"
    fi
done
[ "$STATE" = "done" ] || { echo "the run did not finish: $(echo "$RUN" | jq -r '.error // ""') - see $OUT/run.log" >&2; exit 1; }
call POST logout >/dev/null
