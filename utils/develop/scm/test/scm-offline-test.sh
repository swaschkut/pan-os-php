#!/bin/bash
#
# Offline test of type=scm-changes and type=scm-apply, no SCM tenant needed.
#
#   utils/develop/scm/test/scm-offline-test.sh [workdir]
#
# 1. "download" an SCM configuration from fixtures with the real import code (scm-mock-download.php)
# 2. run the visibility playbook on it with outputformatscmjson=
# 3. single util changes (zone, rule, rename, delete, snippet) and type=scm-changes
# 4. type=scm-apply dry-run, then against a local SCM mock server (scm-mock-server.php)
# Each step checks its result; the script exits non-zero on the first failed check.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../../.." && pwd)
W=${1:-$(mktemp -d /tmp/scm-offline-test.XXXX)}
mkdir -p "$W"
P="php $REPO/utils/pan-os-php.php"
PORT=${SCM_MOCK_PORT:-8099}
FAILED=0

check() { # description, condition
    if eval "$2"; then echo "  ok    $1"; else echo "  FAIL  $1"; FAILED=1; fi
}
jq_() { python3 -c "import json,sys; d=json.load(open('$1')); print($2)"; }

echo "workdir: $W"

echo "1) offline download"
php "$HERE/scm-mock-download.php" "$REPO" "$HERE/scm-fixtures.json" "$W/scm.xml" > "$W/download.log" 2>&1
check "SCM XML written" "[ -s '$W/scm.xml' ]"
check "SCM ids stored as uuid" "grep -q 'uuid=\"r-1\"' '$W/scm.xml'"

echo "2) visibility playbook with outputformatscmjson="
mkdir -p "$W/pb"
(cd "$REPO" && $P type=playbook json=utils/api/v1/playbook/visibility.json in="$W/scm.xml" out="$W/scm-visibility.xml" projectfolder="$W/pb" outputformatscmjson=changes-visibility.json > "$W/playbook.log" 2>&1)
C="$W/pb/changes-visibility.json"
check "changes file written" "[ -s '$C' ]"
check "format pan-os-php-scm-changes" "[ \"\$(jq_ $C \"d['format']\")\" = pan-os-php-scm-changes ]"
check "POST before PUT before DELETE" "[ \"\$(jq_ $C \"''.join(r['method'][0] for r in d['requests'])\" | grep -cE '^P*$|^P+U*D*$')\" = 1 ]"
check "folder in the POST body, not in the query" "[ \"\$(jq_ $C \"all(('folder' in r['body'] or 'snippet' in r['body'] or 'device' in r['body']) and 'folder' not in r['query'] for r in d['requests'] if r['method']=='POST')\")\" = True ]"
check "AV profile with PAN-OS decoder needs review" "[ \"\$(jq_ $C \"[r['review'] for r in d['requests'] if r['object']['name']=='Alert-Only-AVWF'][0]\")\" = True ]"
check "profile group depending on it needs review" "[ \"\$(jq_ $C \"[r['review'] for r in d['requests'] if r['object']['name']=='Alert-Only'][0]\")\" = True ]"
check "zone referencing a missing ZPP needs review" "[ \"\$(jq_ $C \"[r['review'] for r in d['requests'] if r['object']['name']=='trust'][0]\")\" = True ]"
check "snippet members not duplicated" "[ \$(grep -c '<member>branch-snippet</member>' '$W/scm-visibility.xml') = 1 ]"

echo "3) single util changes"
cp "$W/scm.xml" "$W/s0.xml"
(cd "$REPO"
 $P type=zone location=ngfw-shared in="$W/s0.xml" out="$W/s1.xml" actions=zpp-set:zpp-existing 'filter=(name eq trust)'
 $P type=zone location=ngfw-shared in="$W/s1.xml" out="$W/s2.xml" actions=logsetting-set:lfp-existing 'filter=(name eq trust)'
 $P type=rule location=ngfw-shared in="$W/s2.xml" out="$W/s3.xml" actions=logsetting-set:lfp-existing 'filter=(name eq allow-web)'
 $P type=address location=ngfw-shared in="$W/s3.xml" out="$W/s4.xml" actions=name-rename:web-server-01 'filter=(name eq web-srv)'
 $P type=address location=ngfw-shared in="$W/s4.xml" out="$W/s5.xml" actions=delete 'filter=(name eq unused-addr)'
 $P type=rule location=Branches in="$W/s5.xml" out="$W/s6.xml" actions=disabled-set:true 'filter=(name eq branch-allow)'
 $P type=rule location=branch-snippet in="$W/s6.xml" out="$W/s7.xml" actions=description-append:changed-in-snippet 'filter=(name eq snip-allow)'
 $P type=scm-changes file1="$W/scm.xml" file2="$W/s7.xml" out="$W/changes-single.json"
) > "$W/single.log" 2>&1
S="$W/changes-single.json"
check "5 PUT, 1 DELETE, nothing to review" "[ \"\$(jq_ $S \"(d['summary']['PUT'],d['summary']['DELETE'],d['summary']['review'])\")\" = '(5, 1, 0)' ]"
check "rename is a PUT on the same id" "[ \"\$(jq_ $S \"[(r['method'],r['id'],r['body']['name']) for r in d['requests'] if r['object']['resource']=='addresses' and r['method']=='PUT'][0]\")\" = \"('PUT', 'a-1', 'web-server-01')\" ]"
check "zone PUT on /config/network/v1/zones/z-1" "grep -q '/config/network/v1/zones/z-1' '$S'"
check "rule follows the renamed address" "[ \"\$(jq_ $S \"[r['body'].get('destination') for r in d['requests'] if r['object']['name']=='allow-web'][0]\")\" = \"['web-server-01']\" ]"
check "snippet rule PUT" "grep -q '/config/security/v1/security-rules/r-20' '$S'"
check "DELETE last" "[ \"\$(jq_ $S \"d['requests'][-1]['method']\")\" = DELETE ]"

echo "4) scm-apply"
(cd "$REPO" && $P type=scm-apply changes="$S" dry-run > "$W/apply-dry.log" 2>&1)
check "dry-run: 6 ok" "grep -q 'dry-run: ok 6, failed 0' '$W/apply-dry.log'"

python3 - "$HERE/scm-fixtures.json" "$W/mock-state.json" <<'EOF'
import json, sys
fx = json.load(open(sys.argv[1])); st = {}
for key, objs in fx['res'].items():
    for o in objs:
        st.setdefault(key.split('|')[0], {})[o['id']] = o
json.dump(st, open(sys.argv[2], 'w'))
EOF
SCM_MOCK_STATE="$W/mock-state.json" SCM_MOCK_LOG="$W/mock-requests.log" php -S 127.0.0.1:$PORT "$HERE/scm-mock-server.php" > "$W/mock-server.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
sleep 1

mkdir -p "$W/home"
A="type=scm-apply tsg=1234567890 apiurl=http://127.0.0.1:$PORT tokenurl=http://127.0.0.1:$PORT/oauth2/access_token"
(cd "$REPO" && printf 'test-client-id\ntest-client-secret\n' | HOME="$W/home" $P $A changes="$S" > "$W/apply.log" 2>&1)
check "apply: 6 ok" "grep -q 'ok 6, failed 0' '$W/apply.log'"
check "PUT merged with the live object (description kept)" "grep -q '\"description\":\"web server\"' '$W/mock-requests.log'"
check "address renamed on the server" "[ \"\$(jq_ $W/mock-state.json \"d['addresses']['a-1']['name']\")\" = web-server-01 ]"
check "address deleted on the server" "[ \"\$(jq_ $W/mock-state.json \"'a-2' in d['addresses']\")\" = False ]"

(cd "$REPO" && HOME="$W/home" $P $A changes="$C" > "$W/apply-visibility.log" 2>&1)
check "visibility: review requests skipped, rest ok" "grep -qE 'ok [0-9]+, failed 0, skipped \(review\) [1-9]' '$W/apply-visibility.log'"
(cd "$REPO" && HOME="$W/home" $P $A changes="$C" > "$W/apply-again.log" 2>&1)
check "second run stops at the first 409" "grep -q 'HTTP 409' '$W/apply-again.log' && grep -q 'stopped; resume with from=1' '$W/apply-again.log'"

echo
if [ $FAILED = 0 ]; then echo "all checks passed"; else echo "some checks FAILED (logs in $W)"; fi
exit $FAILED
