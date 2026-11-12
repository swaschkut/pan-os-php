# Consultant guide – Prisma Access export and compare with pan-os-php

This guide explains how to take a complete snapshot of a Prisma Access tenant (Strata Cloud Manager) and how to
compare two snapshots – for a tenant migration, a lab / production drift check, or a before / after check of a change.

| tool | what it does | needs API access |
|---|---|---|
| `scm_pa_export.php` | downloads the tenant configuration into a local directory | yes (read only) |
| `scm_pa_compare.php` | compares two export directories and writes a report | no |

Reference documentation: [README_pa_export.md](README_pa_export.md) (export), [README_pa_compare.md](README_pa_compare.md)
(compare), [NEXT_STEPS_pa_export.md](NEXT_STEPS_pa_export.md) (verification list, roadmap).

> **Status:** export and compare are in development (`beta_scm-extension`). Both only **read** from the tenant; nothing
> is changed. Writing the differences into a tenant (sync) is the next development step.

---

## 1. Before you start

### 1.1 What you need

- [ ] pan-os-php from branch `beta_scm-extension` (local checkout with the PHP version / extensions pan-os-php
      requires) – run all commands from the pan-os-php root directory
- [ ] the **TSG ID** of every tenant (shown in the tenant management of Strata Cloud Manager / Common Services)
- [ ] a **service account** per tenant (Identity & Access → service accounts, created in that TSG) with read access to the configuration;
      `client_id` and `client_secret` – for Prisma Browser and IAM the account needs the corresponding roles,
      otherwise these areas are reported as `unavailable`
- [ ] optional: the **egress-IP API key** of the tenant (Prisma Access → Infrastructure settings) – the export can
      also take it from the infrastructure settings automatically
- [ ] a working directory **outside of git / shared drives** for the exports (they may contain secrets, see 1.3)

### 1.2 Credentials (`~/.panconfkeystore`)

On the first run against a TSG pan-os-php asks for `client_id` and `client_secret` and stores them in
`~/.panconfkeystore` (entry `tsg_id<TSG>`). The egress-IP API key is stored as `egressip_tsg_id<TSG>`.
To change credentials, edit / remove the line in that file. Never commit or mail this file.

### 1.3 Handling of sensitive data

| file | content | share? |
|---|---|---|
| `manifest.json`, `MIGRATION_CHECKLIST.md`, `DIFF_REPORT.md`, `diff.json` | configuration summary, differences; secrets masked | internal project use |
| endpoint files (`*/NN_*.json`) | full configuration incl. **encrypted** PSKs / passwords (decryptable with the default master key) | treat as confidential |
| `psk-list.csv`, `bgp-secret-list.csv`, `secret-list.csv` (option `psk-list`) | **cleartext** secrets, file mode 600 | never; delete after use |
| console output with `debugapi` | bearer token, full API answers | never |

The `api_key` of the infrastructure settings is never written to disk.

---

## 2. Export a tenant

### 2.1 Full export

```bash
php utils/develop/sase/scm/scm_pa_export.php in=scm-api://<TSG> outdir=/data/pa-export egressip
```

Result: `/data/pa-export/<TSG>/<YYYYmmdd-HHMMSS>/` – one directory per run, nothing is overwritten.

| option | use it when |
|---|---|
| `area=infra,remote-networks,…` | only some areas are needed (default: all) |
| `egressip` | you need the public egress IPs (allow lists, IP mapping) |
| `psk-list` | you prepare a migration and need the PSKs / secrets (cleartext lists!) |
| `container="Mobile Users"` / `config-types=addresses,security-rules` | the tenant is large and you only need part of the objects / policies |
| `debugapi` | troubleshooting only |

Shortcuts for one area: `scm_rn_export.php`, `scm_sc_export.php`, `scm_mu_export.php`, `scm_pb_export.php`,
`scm_iam_export.php`, `scm_config_export.php` (same options).

### 2.2 Areas

| area | content |
|---|---|
| `infra` | infrastructure subnet, infra BGP AS, BGP routing, internal DNS, locations, egress IPs |
| `config` | folder / snippet hierarchy (incl. snippet order), objects, security profiles, rules (pre / post), zones – each object at its owning folder / snippet |
| `remote-networks` | IKE / IPsec crypto profiles, IKE gateways, IPsec tunnels, QoS, bandwidth allocations, remote networks |
| `service-connections` | the same chain for service connections, QoS, service connection groups, traffic steering |
| `mobile-users` | certificates, server / authentication profiles, local users, GlobalProtect settings |
| `prisma-browser` | user / device groups, applications, browser policies |
| `iam` | roles, service accounts, access policies – documentation only |

Not exported: Mobile Users Explicit Proxy, ZTNA connector, Cloud Identity Engine, Strata Logging Service, licenses,
certificate private keys – listed in `MIGRATION_CHECKLIST.md`.

### 2.3 Check the run

At the end the export prints a summary. Then open in the export directory:

1. **`manifest.json` → `errors`** must be 0. `unavailable` lists endpoints the tenant does not have or the service
   account may not read – check that this is expected.
2. **`MIGRATION_CHECKLIST.md`** – the to-do list for a migration, sorted `action_required` → `check` → `info`.
3. **`config/hierarchy.txt`** – the folder tree with the attached snippets in order; compare with SCM.
4. **`*/ip-mapping.csv`** – per remote network / service connection / MU location the Prisma Access and peer IPs.

### 2.4 Export directory at a glance

```
<TSG>/<timestamp>/
    manifest.json               what was exported, counts, errors, hints, checklist
    MIGRATION_CHECKLIST.md
    infra/ config/ remote-networks/ service-connections/ mobile-users/ prisma-browser/ iam/
        NN_<endpoint>.json      raw API data, NN = import order inside the area
        ip-mapping.csv/.json    (RN, SC, MU)
        psk-list.csv …          (only with psk-list)
    config/hierarchy.txt/.json
    config/folders/<folder>/NN_<type>.json, config/snippets/<snippet>/NN_<type>.json
```

---

## 3. Compare two exports

### 3.1 Run

```bash
php utils/develop/sase/scm/scm_pa_compare.php \
    left=/data/pa-export/<TSG-A>/<timestamp> \
    right=/data/pa-export/<TSG-B>/<timestamp>
```

`left` and `right` are the directories that contain `manifest.json`. The result goes to
`/data/pa-export/compare-<TSG-A>-vs-<TSG-B>-<timestamp>/` (or `out=<dir>`):

- `DIFF_REPORT.md` – read this
- `diff-summary.csv` – one row per endpoint, for Excel
- `diff.json` – complete result (input for the later sync)

Tip: export both tenants with the **same options** (areas, filters); otherwise endpoints are reported as
"not comparable".

### 3.2 Read the report

**Summary table** – per area: compared endpoints, endpoints with differences, entries equal / only left /
only right / changed, rule bases with a different order.

**Hierarchy** – folders / snippets only on one side, a different parent, different or re-ordered snippets.

**Per endpoint** (`### container / endpoint`):

- **Only in left / Only in right** – entries (by name) that exist on one side only
- **Order differs** – same rules, different sequence (shown as name sequences)
- **change table** – per entry the changed fields:

| type | meaning |
|---|---|
| `changed` | different value |
| `left_only` / `right_only` | field set on one side only |
| `order` | same list elements, different order (e.g. crypto preference) |
| `secret` | a PSK / password / secret differs – value shown as `***` |

**Not comparable** – endpoint missing in one export or with an error / not available on one side.

What is **not** reported as difference: ids, owner fields (`folder` / `snippet`), values Prisma Access derives
itself (loopbacks, tunnel monitor IP, service IPs in remote network `details`), the infrastructure `api_key`.

### 3.3 Typical questions

| question | how |
|---|---|
| Is tenant B a complete copy of tenant A? | compare A (left) with B (right); everything "only in left" is missing in B |
| What changed in my tenant since last week? | compare the old export (left) with a new export of the same TSG (right) |
| Only remote networks / service connections | `area=remote-networks,service-connections` |
| Only the objects of one folder | `area=config container="Mobile Users"` |
| Names follow another convention in B | name map, see 3.4 |
| Descriptions are irrelevant | `ignore-fields=description` |
| Use in a script / pipeline | `fail-on-diff` → exit code 2 if there are differences |

### 3.4 Different names in the two tenants (name map)

Create a CSV and pass it with `name-map=names.csv`:

```csv
area,endpoint,left,right
service-connections,service-connections,SC-HQ-OLD,SC-HQ-1
*,ipsec-tunnels,TUN-FRA-1,TUNNEL-FRA-1
config,container,Mobile Users,MU
```

Left names are translated before comparing – including references to them (e.g. the tunnel name inside a remote
network, `backup_SC`, group members). `config,container,…` renames folders / snippets.

---

## 4. Troubleshooting

| symptom | cause / action |
|---|---|
| `problem with SCM API connection - not possible to get 'access_token'` | wrong `client_id` / `client_secret` or TSG → fix the line in `~/.panconfkeystore`; QA tenant: add `shadow-saseapiqa` |
| many endpoints `unavailable` | product not licensed or service account without role → expected / add role |
| endpoint `error` with HTTP 400 / 404 | API path or parameter not valid for this tenant → note it in the verification list ([NEXT_STEPS](NEXT_STEPS_pa_export.md) §4) |
| egress IP error | try `egressip-env=prod6`; check the egress API key |
| `psk-list.csv` shows `DECRYPT_FAILED` | tenant uses a custom master key → `master-key=<key>` |
| export of `config` takes long | filter with `container=` / `config-types=` |
| compare: "not comparable – not exported in right" | the two exports used different areas / filters → export again with the same options |
| compare: "format_version …" hint | an export from an older version → export again |
| compare: everything "only in left / right" in one folder | the folder is named differently → name map `config,container,<left>,<right>` |

## 5. What comes next

- verification of the export against live tenants ([NEXT_STEPS_pa_export.md](NEXT_STEPS_pa_export.md) §4)
- `scm_pa_verify.php` – checks pan-os-php's own SCM loading against the raw export
- `scm_pa_sync.php` – turns `diff.json` into a reviewed plan (direction, mode `additive` / `mirror` / `merge`, delete
  only on request) and applies it to the target tenant (dry-run first), followed by push and a new compare
