# scm_pa_compare.php – compare two Prisma Access exports

Technical reference. For a step-by-step guide see
[CONSULTANT_GUIDE_pa_export_compare.md](CONSULTANT_GUIDE_pa_export_compare.md); for the export itself see
[README_pa_export.md](README_pa_export.md).

`scm_pa_compare.php` compares two export directories written by `scm_pa_export.php` – **offline**, no API access,
no credentials. The result is symmetric ("left" / "right", no direction) and is the input for the planned sync
(`scm_pa_sync.php`: plan → apply, see [README_pa_sync.md](README_pa_sync.md)).

## Usage

```bash
php utils/develop/sase/scm/scm_pa_compare.php left=<export dir A> right=<export dir B>
php utils/develop/sase/scm/scm_pa_compare.php left=export/1111/20261113-090000 right=export/2222/20261113-091500 \
    out=/share/compare/1111-vs-2222 area=remote-networks,service-connections name-map=names.csv
```

| argument | description |
|---|---|
| `left=` / `right=` | export directories `<outdir>/<TSG>/<timestamp>` (the folder that contains `manifest.json`) |
| `out=` | result directory; default `<outdir>/compare-<leftTSG>-vs-<rightTSG>-<timestamp>` next to the TSG folders |
| `area=` | only these areas (`infra`, `config`, `remote-networks`, `service-connections`, `mobile-users`, `prisma-browser`, `iam`) |
| `container=` | config area: only these folders / snippets |
| `config-types=` | config area: only these types, e.g. `addresses,security-rules` (`security-rules` covers `-pre` and `-post`) |
| `ignore-fields=` | additional dotted paths ignored for every endpoint, e.g. `description` |
| `name-map=` | CSV with entries that are named differently in right (see below) |
| `max-items=` | max. entries / changes per endpoint in `DIFF_REPORT.md` (default 50; `diff.json` is always complete) |
| `fail-on-diff` | exit code 2 if there are differences |
| `help` | usage |

Exit codes: `0` done (with `fail-on-diff`: no differences), `1` usage / input error, `2` differences (`fail-on-diff`).

Both exports should have `format_version` ≥ 6 (current `scm_pa_export.php`); older exports are compared as far as
possible and a hint is printed.

## What is compared

Every endpoint file listed in both `manifest.json` files (key: area + container + endpoint). Per endpoint:

| result | meaning |
|---|---|
| `only_left` | entry exists only in left (key not found in right) |
| `only_right` | entry exists only in right |
| `changed` | same key, different content – with a field level change list |
| `order` | ordered endpoints (rule bases): same entries, different sequence |
| `equal` | counted only |
| not comparable | endpoint missing in one export (area not exported) or `status` not `ok` on one side (error / unavailable); both `unavailable` is skipped silently |

A config container (folder / snippet) that exists on one side only is compared against an empty list – all its
entries are `only_left` / `only_right` – unless the other export excluded it with `container=` / `config-types=`
(then: not comparable).

Config hierarchy (`config/hierarchy.json`) is compared separately: folders only left / right, folder `parent` /
`type` changed, attached snippets changed or **order** changed, snippets only left / right.

### Identity (key)

Entries are matched by a **business key inside their owning container**, never by the tenant specific `id`.
Default key is `name`; exceptions are defined in the endpoint metadata (see below), e.g. `infra/locations` → `value`,
`iam/access-policies` → `principal` + `role` + `resource`, singletons (e.g. `shared-infrastructure-settings`,
`bgp-routing`, Prisma Browser policies) have no key and are compared as one object. Entries without key value are
compared by position (warning). Duplicate keys are reported, the first entry is compared.

Config objects are only stored at their owner by the export, so an object moved to another folder / snippet appears
as `only_left` in one container and `only_right` in the other.

### Normalisation

Before comparing, both sides are normalised:

1. removed everywhere: `id`, `folder`, `snippet` (`COMPARE_IGNORE_ALWAYS`)
2. removed per endpoint: `ignore` paths of the endpoint metadata (derived / read-only, e.g. remote network `details`,
   `loopback_ips`, `api_key`) and `ignore-fields=`
3. object keys sorted
4. lists of objects with a unique `name` become maps (`rules[Allow-DNS].action`) – element order is then irrelevant,
   except for `ordered` paths (e.g. Prisma Browser `rules` / `sections`), where the name sequence is compared as well
5. other lists keep their order; same elements in a different order are reported as type `order`
   (e.g. IKE crypto encryption preference), different elements as `changed`
6. left side only: the name map is applied to the key and to all reference fields of the endpoint metadata

### Change types (field level)

| type | meaning |
|---|---|
| `changed` | value differs |
| `left_only` / `right_only` | field present on one side only |
| `order` | same list elements, different order |
| `secret` | secret field differs – values shown as `***` |

Secrets: paths in the endpoint metadata `secret` (e.g. `authentication.pre_shared_key.key`, `protocol.bgp.secret`,
`bgp_peer.secret`, `bind_password`) and every field whose name matches the export's secret pattern (`secret`,
`password`, `passphrase`, `key`, `*_key` …, except `public_key` etc.) are compared (encrypted values are deterministic
for the same master key) but never written in clear text – in `diff.json`, `DIFF_REPORT.md` or on the console.

## Name map

For entries that are named differently in the two tenants (naming conventions, renamed folders):

```csv
area,endpoint,left,right
service-connections,service-connections,SC-HQ-OLD,SC-HQ-1
*,ipsec-tunnels,TUN-FRA-1,TUNNEL-FRA-1
config,container,Mobile Users,MU
```

* `area` / `endpoint` may be `*`; exact name match only (no prefixes / patterns).
* Applied to the **left** side: the key, the key field itself (an intended rename is no difference) and all
  reference fields of the endpoint (e.g. `backup_SC`, `ipsec_tunnel`, group members) that point to the mapped
  endpoint.
* `config,container,<left>,<right>` maps folder / snippet names (container of config objects, folder / snippet
  lists, hierarchy).

## Output

```
<out>/
    DIFF_REPORT.md      human readable report
    diff.json           complete machine readable result (input for scm_pa_sync.php)
    diff-summary.csv    one row per compared endpoint: area, container, endpoint, left, right, equal,
                        only_left, only_right, changed, order_changed
```

### diff.json

```jsonc
{
  "format_version": 1,
  "tool": "pan-os-php scm_pa_compare.php",
  "left":  { "dir": "...", "tsg_id": "...", "created_at": "...", "areas": [...], "format_version": 6 },
  "right": { ... },
  "options": { "filter": {...}, "extra_ignore": [...], "name_map": {...}, "container_map": {...} },
  "summary": { "areas": { "<area>": { "endpoints", "endpoints_with_differences", "equal", "only_left",
                                      "only_right", "changed", "order" } },
               "hierarchy_differences": 0, "not_comparable": 0, "identical": false },
  "hierarchy": { "folders_only_left": [], "folders_only_right": [], "folders_changed": [ { "folder", "changes": [] } ],
                 "snippets_only_left": [], "snippets_only_right": [] },
  "entries": [                                   // only endpoints with differences
    { "area", "container": "folder:Mobile Users" | null, "endpoint", "endpoint_key": "config/addresses",
      "singleton", "key_fields", "write": "collection|singleton|none",
      "counts": { "left", "right", "equal", "only_left", "only_right", "changed" },
      "only_left":  [ { "key", "left_id", "left_name" } ],
      "only_right": [ { "key", "right_id" } ],
      "changed":    [ { "key", "left_id", "right_id", "left_name",
                        "changes": [ { "path", "type", "left", "right" } ] } ],
      "order": null | { "left": [keys], "right": [keys] },
      "duplicates": [] }
  ],
  "equal_endpoints": [ "area/container/endpoint", ... ],
  "not_comparable": [ { "area", "container", "endpoint", "endpoint_key", "reason", "left_status", "right_status" } ],
  "warnings": []
}
```

`left_id` / `right_id` are the tenant ids from the exports (needed by the sync for update / delete); objects
themselves are not copied – the sync reads them from the export files.

## Endpoint metadata

Defined once in `lib/SCMPrismaAccessExport.php` (`ENDPOINT_META_DEFAULT`, `ENDPOINT_META`, `endpointMeta()`), used by
compare now and by the sync later:

| field | meaning | default |
|---|---|---|
| `key` | identity fields inside a container | `["name"]` |
| `singleton` | one object per endpoint, compared as a whole | `false` |
| `ignore` | dotted paths removed before compare | `[]` |
| `secret` | dotted paths compared but masked | `[]` |
| `ordered` | `true`: entry order matters (rule bases, auth settings, agent / tunnel profiles, traffic steering); list of paths: order of these named lists inside a singleton | `false`; all config `*-rules` are ordered |
| `refs` | `"path" => "area/endpoint"` references (`[]` = every list element) – name map now, dependency resolution in the sync | `[]` |
| `write` | `collection` (POST / PUT {id} / DELETE {id}), `singleton` (PUT), `none` (read-only / documentation) | `collection` |
| `compare` | `false`: not compared (pure context: `infra/egress-ip`, `prisma-browser/pending-changes`, `iam/permissions`) | `true` |

Changing the behaviour for an endpoint (e.g. ignoring another derived field) = one line in `ENDPOINT_META`.

## Limitations

* Exact name matching (plus name map); no fuzzy matching of renamed entries without map.
* `config` references (rules → addresses / services / profiles …) are only partly in the metadata
  (groups, profile groups); renamed config objects are therefore not mapped inside rules – add them to `refs` or
  compare with consistent names.
* Values of IPs that differ by design between tenants (e.g. remote network `details`) are ignored; differences in
  configured IPs (peer addresses, BGP) are reported.
* Large exports: `diff.json` contains every difference; `DIFF_REPORT.md` is limited by `max-items`.

## Code

* `scm_pa_compare.php` – CLI (no UTIL / API)
* `lib/SCMPrismaAccessCompare.php` – compare logic: `run()`, `compareEndpoint()`, `normalizeValue()`, `diffValues()`,
  `compareHierarchy()`, `write()`, `reportMarkdown()`
* `lib/SCMPrismaAccessExport.php` – endpoint metadata
