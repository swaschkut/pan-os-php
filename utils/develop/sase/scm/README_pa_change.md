# scm_pa_change.php – change an SCM tenant from a small change request file

One command instead of the manual chain export → copy → edit JSON → compare → plan → dry-run → execute → re-export →
compare. The script only chains the existing building blocks (`scm_pa_export.php`, `scm_pa_compare.php`,
`scm_pa_sync.php`); all safety steps stay:

* without `execute` nothing is sent (dry-run, including the hash check of the target objects)
* `execute` asks for the TSG id (unless `yes`)
* `execute` is refused if the dry-run has blocked requests or conflicts
* push only with `push` (and only folders with a push target)
* after `execute`: export again and check every change against the tenant

```
php utils/develop/sase/scm/scm_pa_change.php in=scm-api://<TSG> changes=<file.json>             # dry-run
php utils/develop/sase/scm/scm_pa_change.php in=scm-api://<TSG> changes=<file.json> execute     # send + verify
    [outdir=change] [yes] [push] [continue-on-error] [config-parallel=8] [debugapi]
```

## Change request file

```json
{
  "description": "test: sub folder with one address",
  "folders": [
    { "name": "pan-os-php-sub", "parent": "pan-os-php-test", "description": "created by pan-os-php" }
  ],
  "tags": [
    { "folder": "pan-os-php-sub", "name": "pan-os-php-sub", "color": "Blue" }
  ],
  "addresses": [
    { "folder": "pan-os-php-sub",  "name": "h-10.1.1.1", "ip_netmask": "10.1.1.1/32", "tag": ["pan-os-php-sub"] },
    { "folder": "pan-os-php-test", "name": "pan-os-php-addr1", "_append": { "tag": ["pan-os-php"] } },
    { "folder": "pan-os-php-test", "name": "pan-os-php-old", "_delete": true }
  ]
}
```

| key | content |
|---|---|
| `folders` | `name`, `parent`, optional `description` / `labels`. New folders only below `ngfw-shared` (All Firewalls), max. 4 levels below it (as Panorama device-groups below shared); a new parent must come first in the list. Existing folder: fields are updated, moving (other `parent`) is refused. |
| `snippets` | `name`, optional `description` / `labels`. Predefined snippets cannot be changed. |
| `<config type>` | a list per type, e.g. `addresses`, `address-groups`, `tags`, `services`, `service-groups`, `external-dynamic-lists`, `url-categories`, security profiles, `profile-groups`, identity objects, rule bases (`security-rules`, `nat-rules` …) … (all types of the groups `objects`, `identity` and `policies` of `scm_pa_export.php`) |
| `objects` | the same as one list, with `"type": "<config type>"` per entry |

Per object:

* `name` and exactly one of `folder` / `snippet` – the container must exist or be created in the same file
* all other fields are SCM API fields (snake_case, as in the export). Object does not exist → created with these fields.
  Object exists → these fields **replace** the current values, all other fields stay.
* `_append`: `{ "field": [values] }` – add values to a list (e.g. a tag), existing values stay
* `_remove`: `{ "field": [values] }` – remove values from a list
* `_delete: true` – delete the object (only `name` + container in the entry)
* `id` is set by SCM and must not be in the file

The request is idempotent: a second run with the same file finds nothing to do ("unchanged" / "absent").

Rules (`security-rules`, `nat-rules`, `decryption-rules` …): `"position": "pre"` (default) or `"post"` in a folder, no
position in a snippet. New rules are added at the end of the rule base in file order; the verification also checks the
order of the rules of the file in the tenant. Moving existing rules is not part of this tool (sync workflow).

`_internal` (security profiles in folders): `{ "prefix": "profiles/vulnerability|spyware|dns-security|virus-and-wildfire-analysis", "entry": { PAN-OS structure as JSON } }`
– sections the public API does not have (inline ML, inline cloud analysis, decoder actions, rule action `default` …).
After the public requests the script reads the profile through the internal UI API
(`GET /api/config/v9.2/Objects/<type>?folder=&type=container|cloud&name=`) and, if a section differs, writes the
complete entry (`POST /api/config/v9.2/multiConfigure`, `command: edit`, `prefix`, `subPath: entry[@name='…']` – the
call of the SCM UI, HAR 2026-11-14) with the `@uuid` / `@loc` of the live entry. The dry-run shows `edit` /
`unchanged` / `after create`; the verification compares the sections; `push` pushes after these edits.
`ui-api-host=` sets the host of the tenant region (default `paas-3.prod.eu.panorama.paloaltonetworks.com`).

Zones (`zones`) are the only network type a change request can contain (they belong to the rules that use them).

Not supported (refused with a message; use the sync workflow): other network / device settings, Prisma Access
infrastructure, deleting folders / snippets.

Examples in `examples/` (lab folder `pan-os-php-test`, run in this order): `change-sub-folder.json` (sub folder, tag,
address – verified live), `change-append-tag.json` (`_append` of a tag from the parent folder),
`change-delete-address.json`, `change-delete-tag.json` (`_delete`; the tag after the address that uses it).

## What happens

| step | what | files in `<outdir>/<TSG>/change-<timestamp>/` |
|---|---|---|
| 1 | export of only the containers and types of the request (read only) | `ist/` |
| 2 | soll = ist + changes; checks: containers exist, folder below `ngfw-shared`, type allowed in the folder | `soll/` |
| 3 | compare soll ↔ ist, plan (`additive`, with `_delete`: `mirror` + allow-delete – only the deleted objects differ) | `compare/`, `plan.json`, `PLAN_REPORT.md` |
| 4 | apply dry-run: every request (method, URL, body), hash check of updated / deleted objects | `apply-log-dry-run.json` |
| 5 | `execute`: requests in plan order (new folder before its objects), optional push | `apply-log-execute.json` |
| 6 | export again, check each change (fields, `_append` / `_remove` values, deleted objects) | `verify/`, `verify.json`, `compare-verify/` |

Example output (dry-run):

```
 * [2/4] changes
   create    folder pan-os-php-sub
   create    addresses h-10.1.1.1 [folder pan-os-php-sub]
   update    addresses pan-os-php-addr1 [folder pan-os-php-test]
 * [3/4] requests (dry-run)
   op-0001  create  POST   /config/setup/v1/folders pan-os-php-sub
            body {"name":"pan-os-php-sub","parent":"pan-os-php-test","description":"created by pan-os-php"}
   op-0002  create  POST   /config/objects/v1/addresses h-10.1.1.1
   …
 * dry-run - nothing was sent. Same command with 'execute' to apply.
```

The folder / snippet list of the public API does not return `description` / `labels` (live 2026-11-13; the UI shows
them, the single `GET /config/setup/v1/folders/{id}` returns them): for the folders / snippets of the request these
fields are read with the single GET, in the first export and in the verification export.

`verify` reports `verified` per change, or `failed` with the field that differs. A newly created folder has no
firewall – push is neither possible nor needed (`not_pushable`); the candidate configuration is stored anyway.

## Relation to the other tools

* Panorama device-groups → SCM: [README_pa_panorama_import.md](README_pa_panorama_import.md)
  (`scm_pa_panorama_to_change.php` writes the change file)

* bigger changes, reordering rule bases, Prisma Access areas, tenant → tenant: export / edit / `scm_pa_compare.php` /
  `scm_pa_sync.php` ([README_pa_sync.md](README_pa_sync.md))
* gap remediation (best practice / visibility fixes for the CDSS portal): change file `pan-os-php-scm-changes`
  ([../../scm/CONCEPT_gap_remediation.md](../../scm/CONCEPT_gap_remediation.md)) – there the requests are generated
  from findings; here the consultant writes the wanted state of a few objects by hand. Both end in the same
  apply logic.
