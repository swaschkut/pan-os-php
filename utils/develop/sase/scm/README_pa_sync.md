# scm_pa_sync.php – sync the differences of two exports into a tenant


For a few folders / snippets / objects without editing an export by hand: [README_pa_change.md](README_pa_change.md)
(`scm_pa_change.php` - same plan / apply logic, one command).

Technical reference. Step-by-step usage: [CONSULTANT_GUIDE_pa_export_compare.md](CONSULTANT_GUIDE_pa_export_compare.md) §4.
Inputs come from [scm_pa_export.php](README_pa_export.md) and [scm_pa_compare.php](README_pa_compare.md).

```
export A ─┐
          ├─► scm_pa_compare.php ─► diff.json ─► scm_pa_sync.php plan ─► plan.json ─► scm_pa_sync.php apply ─► (push)
export B ─┘                                       (offline, reviewable)               (dry-run, then execute)
                                                                                         │
                                         re-export target ─► scm_pa_compare.php ◄────────┘  (should be identical)
```

Only the differences are sent: one request per created / changed / deleted entry, nothing for equal entries.

## 1. plan (offline)

```bash
php utils/develop/sase/scm/scm_pa_sync.php plan diff=<compare dir>/diff.json source=left mode=additive
php utils/develop/sase/scm/scm_pa_sync.php plan diff=<compare dir>/diff.json source=left mode=mirror allow-delete
php utils/develop/sase/scm/scm_pa_sync.php plan diff=<compare dir>/diff.json mode=merge
```

| argument | description |
|---|---|
| `diff=` | `diff.json` of `scm_pa_compare.php` |
| `source=left\|right` | the export that **wins**; the other one is the target. Reverse direction = other value, same diff |
| `mode=` | `additive` (default), `mirror`, `merge` – see below |
| `allow-delete` | `mirror` only: delete operations are executable (otherwise listed as blocked) |
| `allow-infra` | infrastructure singletons (shared infrastructure settings, BGP routing) may be updated |
| `allow-network` | config area: NGFW `network` and `device` groups (interfaces, routing, zones, IKE / IPsec, device settings) may be written |
| `area=` / `container=` / `config-types=` | restrict the plan (same meaning as in compare) |
| `out=` | output directory (default: directory of `diff.json`) |

| mode | only in source | only in target | changed | order |
|---|---|---|---|---|
| `additive` | create | keep | update (source wins) | move |
| `mirror` | create | delete (`allow-delete`) | update (source wins) | move |
| `merge` | create in the other tenant, **two plans** (`plan-left-to-right.json`, `plan-right-to-left.json`) | – | **conflict**, not sent | – |

Output: `plan.json` (merge: `plan-<side>-to-<side>.json`) and `PLAN_REPORT.md`.

### What the plan does

1. **Operations** from the diff: `create` (POST), `update` (PUT by id; singletons PUT without id), `delete`
   (DELETE by id), `move` (rule order).
2. **Request body** = the source object, name map applied (key and references), without `id` and the endpoint's
   `ignore` fields, owner set to the target container (config). **Secrets** are replaced by placeholders
   `{"__secret__": {list, key}}` – `plan.json` never contains a secret.
3. **Dependencies** (endpoint metadata `refs`): a referenced object must exist in the target, be created by the
   plan, or is **added from the source** as an extra create (`reason: dependency of op-…`). Objects in a folder /
   snippet that the plan creates depend on that create; a folder depends on its parent / attached snippets.
   References found nowhere (predefined / inherited objects) become a note.
4. **Delete check**: a delete is blocked while a remaining target object (not deleted, not updated by the plan) or
   the body of a create / update still references the object.
5. **backup_SC**: service connections that are created together and reference each other are created without
   `backup_SC`; a follow-up update sets it.
6. **Order of execution**: phase 1 create / update in import order (area order, endpoint order, parent folders
   first), phase 2 follow-ups, phase 3 moves, phase 4 deletes in **reverse** order; every operation after its
   `depends_on`.
7. **Blocked** operations (with reason) stay in the plan but are never executed:
   - `write: none` endpoints (IAM, locations, agent versions …)
   - Prisma Browser (rule / section API and draft publish not implemented yet)
   - infrastructure singletons without `allow-infra`
   - config `network` / `device` groups without `allow-network`
   - devices (`config/devices`): onboarding and folder assignment are done in SCM device management
   - deletes without `allow-delete`, deletes of referenced objects, singleton deletes
   - missing secret: the source export has no secret list / no value for the object

### plan.json

```jsonc
{
  "format_version": 1, "tool": "pan-os-php scm_pa_sync.php plan", "created_at": "...",
  "source": { "side": "left", "dir": "...", "tsg_id": "1111", ... },
  "target": { "side": "right", "dir": "...", "tsg_id": "2222", ... },
  "mode": "mirror", "options": { ... },
  "summary": { "operations", "enabled", "blocked", "by_action", "by_area", "conflicts" },
  "operations": [
    { "id": "op-0009", "seq": 5, "phase": 1, "action": "create|update|delete|move",
      "area": "remote-networks", "endpoint": "ike-gateways", "endpoint_key": "remote-networks/ike-gateways",
      "write": "collection", "container": null | "folder:Branch", "name": "GW-MUC", "source_name": "GW-MUC",
      "url": "/config/network/v1/ike-gateways", "query": { "folder": "Remote Networks" }, "position": null | "pre" | "post",
      "target_id": null, "target_hash": null | "<sha1 of the normalised target object>",
      "body": { ..., "authentication": { "pre_shared_key": { "key": { "__secret__": { "list": "remote-networks/psk-list.csv", "kind": "psk", "key": "GW-MUC" } } } } },
      "secrets": [ { "path", "list", "kind", "key" } ],
      "sequence": [ ... ],            // move only: target order of the rule names
      "depends_on": [ "op-0008" ], "reason": "only in left", "notes": [],
      "enabled": true, "blocked": null | "reason" }
  ],
  "conflicts": [ { "area", "container", "endpoint", "name", "fields" } ],   // merge
  "warnings": []
}
```

**Editing:** set `"enabled": false` to skip an operation (operations that depend on it are skipped as well). Do not
edit `blocked` to force an operation – fix the cause and plan again.

## 2. apply (target tenant)

```bash
# dry-run: reads the target (hash check), sends nothing
php utils/develop/sase/scm/scm_pa_sync.php apply in=scm-api://<target TSG> plan=<dir>/plan.json

# execute (asks to type the target TSG), then push the touched folders
php utils/develop/sase/scm/scm_pa_sync.php apply in=scm-api://<target TSG> plan=<dir>/plan.json execute push
```

| argument | description |
|---|---|
| `in=scm-api://<TSG>` | target tenant – must be the `target.tsg_id` of the plan |
| `plan=` | `plan.json` |
| `execute` | send the requests; without it: dry-run |
| `yes` | no confirmation prompt (scripts) |
| `push` | after the operations push the touched folders (`config-versions/candidate:push`) and poll the job |
| `continue-on-error` | continue after a failed / conflicting operation; operations depending on it are skipped |
| `ops=op-0001,op-0002` | only these operations |
| `source-dir=` | source export directory with the secret lists (default: `source.dir` of the plan) |
| `skip-hash-check` | do not verify that target objects are unchanged since the export |
| `debugapi` | print every API call (contains secrets in request bodies – do not share) |

The plan notes for every secret whether the value from the list is verified against the source tenant (SHA1 of the
exported encrypted value) or a new secret.

Per operation:

1. skipped if blocked, disabled, not in `ops=`, or a `depends_on` operation was not executed
2. secrets resolved from the source secret lists (`*_new`, else `*_current`) – missing value → `failed`
3. **hash check** (update / delete): the target object is read (`GET …/{id}`) and compared with the hash from the
   target export; changed → `conflict`, nothing sent ("re-export and re-plan")
4. request(s): `POST <path>[?folder=…][&position=pre|post]`, `PUT <path>/<id>`, `PUT <path>` (singleton),
   `DELETE <path>/<id>`, `POST <path>/<id>:move` (`destination` `top` / `after` + `destination_rule`, `rulebase`)
5. ids of created objects are remembered for later updates / moves (dry-run: placeholder `<new op-…>`)

Stops at the first `failed` / `conflict` unless `continue-on-error`. Result: console summary and
`apply-log-<dry-run|execute>-<timestamp>.json` next to the plan (per operation: status, requests with method, URL,
HTTP code, error – no bodies, no secrets) and the folders to push.

**Push only** (e.g. after an apply without `push`, or a re-run whose operations are already applied):
`scm_pa_sync.php push in=scm-api://<TSG> folders=<f1,f2> [execute [yes]]` – dry-run unless `execute`, asks for the
TSG, polls the job.

**Push targets:** only folders with a firewall below them (or the firewall folder itself) and the Prisma Access
folders can be pushed – SCM answers HTTP 400 `push-config -> push-to unexpected node` for others (in the UI the push
button is greyed out). `push` reads the folder / device list and pushes only those folders; the others are listed as
`not pushable`; their changes stay in the candidate configuration and go out with the next push of a folder with
firewalls / Prisma Access (verified on a live tenant with a folder without firewalls).

**Push:** `push` sends `POST /config/operations/v1/config-versions/candidate:push` with the touched folders
(config containers; `Remote Networks`, `Service Connections`, `Mobile Users`, `Prisma Access` for the other areas)
and polls `/config/operations/v1/jobs/<id>` up to 30 minutes. Without `push` the folders are listed – push in SCM.

**Afterwards:** export the target again and compare with the source export – only blocked / filtered / excluded
differences may remain.

## Safety summary

- plan is offline and reviewable; apply is dry-run by default; `execute` asks for the target TSG
- the target TSG of the plan must match `in=`
- deletes need `mode=mirror` **and** `allow-delete`; referenced objects are never deleted
- infrastructure singletons need `allow-infra`
- hash check prevents overwriting changes made after the export
- no secret in `plan.json`, `PLAN_REPORT.md` or the apply log

## Limitations / to verify on a live tenant

- request formats (POST bodies with `folder`, PUT by id, `:move` body, `candidate:push` body / job fields) follow the
  SCM API documentation but were only tested against a simulated tenant – see
  [NEXT_STEPS_pa_export.md](NEXT_STEPS_pa_export.md) §4.10
- Prisma Browser is planned but blocked (rule / section API + draft publish to be implemented)
- IAM, egress IPs, locations, agent versions: read-only
- secrets of endpoints without secret list (e.g. passwords in config server profiles) are sent as exported
  (encrypted) – a warning lists them
- `config` references are only partly in the metadata (groups, profile groups): rules referencing objects that are
  missing in the target are not detected as dependency
- folder / snippet **renames** are not executed (name map only aligns the compare)

## Code

- `scm_pa_sync.php` – CLI (`plan` offline without UTIL, `apply` with UTIL / `in=scm-api://`)
- `lib/SCMPrismaAccessSync.php` – `buildPlans()` / `buildPlan()`, `planCreate/Update/Delete/Move()`,
  `resolveDependencies()`, `checkDeletes()`, `splitBackupSC()`, `sortOps()`, `writePlan()`, `apply()`, `push()`
