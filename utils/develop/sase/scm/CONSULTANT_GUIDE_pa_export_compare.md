# Consultant guide – Prisma Access export, compare and sync with pan-os-php

This guide explains how to take a complete snapshot of a Prisma Access tenant (Strata Cloud Manager), how to
compare two snapshots – for a tenant migration, a lab / production drift check, or a before / after check of a change –
and how to write the differences into a tenant.

| tool | what it does | needs API access |
|---|---|---|
| `scm_pa_export.php` | downloads the tenant configuration into a local directory | yes (read only) |
| `scm_pa_compare.php` | compares two export directories and writes a report | no |
| `scm_pa_sync.php plan` | turns the differences into a reviewable list of operations | no |
| `scm_pa_sync.php apply` | sends the operations to the target tenant (dry-run unless `execute`) | yes (**write**) |

Reference documentation: [README_pa_export.md](README_pa_export.md) (export), [README_pa_compare.md](README_pa_compare.md)
(compare), [README_pa_sync.md](README_pa_sync.md) (sync), [NEXT_STEPS_pa_export.md](NEXT_STEPS_pa_export.md)
(verification list, roadmap).

> **Status:** in development (`beta_scm-extension`). Export and compare only **read**. `scm_pa_sync.php apply execute`
> **changes** the target tenant – it has been tested against a simulated tenant only: use it on lab tenants until
> the live verification ([NEXT_STEPS](NEXT_STEPS_pa_export.md) §4.10) is done.

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
| `config-devices` | NGFW: include the device folders (device specific interfaces, routing, settings) |
| `config-scope=objects,policies` | only some groups of the config area (`identity`, `objects`, `network`, `policies`, `device`) |
| `config-parallel=4` | the tenant answers with HTTP 429 (rate limit) – default is 8 concurrent requests |
| `config-mode=all` | only to cross-check: queries every folder instead of only the deepest ones (much slower) |
| `debugapi` | troubleshooting only |

Shortcuts for one area: `scm_rn_export.php`, `scm_sc_export.php`, `scm_mu_export.php`, `scm_pb_export.php`,
`scm_iam_export.php`, `scm_config_export.php` (same options).

### 2.2 Areas

| area | content |
|---|---|
| `infra` | infrastructure subnet, infra BGP AS, BGP routing, internal DNS, locations, egress IPs |
| `config` | the complete NGFW / SCM configuration: folder / snippet hierarchy (incl. snippet order), devices (serials), and per folder / snippet / device: certificates and auth profiles, objects and security profiles, interfaces / routing / zones / VPN, all rule bases (security, NAT, PBF, decryption, …), device settings – each object at its owning container |
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
3. **`config/hierarchy.txt`** – the folder tree with the attached snippets in order and the devices (model, version,
   connected, HA peer); compare with SCM.
4. **`config/devices.csv`** – all firewalls (serials) with folder, connection state, versions and HA peer.
5. **`*/ip-mapping.csv`** – per remote network / service connection / MU location the Prisma Access and peer IPs.

### 2.4 NGFW (firewalls managed by Strata Cloud Manager)

```bash
php utils/develop/sase/scm/scm_config_export.php in=scm-api://<TSG> outdir=/data/pa-export config-devices
```

- `config/devices.csv` – which serials are onboarded, in which folder, connected or not, software version, HA pairs.
  The license authcodes are not written.
- device specific configuration (interfaces, routing, device settings) lands in `config/folders/<serial>/`,
  shared configuration in the folders / snippets above it (`config/hierarchy.txt` shows where).
- for a big tenant start with one device / folder: `container=<serial>` or `container="ngfw-shared"`.
- `manifest.json` → `config.types_unavailable` lists types the tenant / API does not know.

### 2.5 Export directory at a glance

```
<TSG>/<timestamp>/
    manifest.json               what was exported, counts, errors, hints, checklist
    MIGRATION_CHECKLIST.md
    infra/ config/ remote-networks/ service-connections/ mobile-users/ prisma-browser/ iam/
        NN_<endpoint>.json      raw API data, NN = import order inside the area
        ip-mapping.csv/.json    (RN, SC, MU)
        psk-list.csv …          (only with psk-list)
    config/hierarchy.txt/.json, config/devices.csv
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

## 4. Sync the differences into a tenant

> Writes to a tenant. Lab tenants first. Always: plan → read the plan → dry-run → execute → push → compare again.

### 4.1 Decide direction and mode

- **source** = the export whose content should win (`left` or `right` of the compare); the other is the target.
- **NGFW network / device settings** (interfaces, routing, zones, VPN, device setup) are only written with
  `allow-network`; devices themselves (serials, folder assignment) are never written – onboard / move them in SCM.
- **mode**
  - `additive` – create what is missing in the target, update what differs; nothing is deleted. Safe default.
  - `mirror` + `allow-delete` – the target becomes a copy of the source (within the compared areas / filters);
    entries that exist only in the target are deleted.
  - `merge` – both tenants get what they are missing (two plans); entries that differ are listed as conflicts and
    not touched – decide them manually.
- Infrastructure settings (infrastructure subnet, AS, BGP routing) are only changed with `allow-infra` – this can
  interrupt traffic.

### 4.2 Prepare the source export

For gateways / connections with PSK or BGP secret and for MU server profiles / local users the cleartext is taken
from the source export's secret lists. Export the source with `psk-list`. To set **new** keys on the target, fill
`psk_new` / `secret_new` in those CSV files. Local user passwords (`HASHED`) always need `secret_new`.

**Strata Cloud Manager tenants use their own master key**, so `psk_current` is usually `DECRYPT_FAILED`. Then:

1. fill `psk_new` with the existing PSKs – the peer firewalls (branch / data center) have them; for PAN-OS peers
   pan-os-php can read them from their configuration
2. check the list – no secret is printed:
   ```bash
   php utils/develop/sase/scm/scm_pa_secret_check.php dir=<source export dir>
   ```
   `OK new = secret of the source tenant` → correct; `NEW` → this is a different PSK than in the source tenant
   (typo, or an intended new key – then the peer needs it too); `MISSING` → no value yet
3. plan again – the plan shows per secret "verified" or "new secret"

### 4.3 Create and read the plan

```bash
php utils/develop/sase/scm/scm_pa_sync.php plan diff=<compare dir>/diff.json source=left mode=additive
```

Open `PLAN_REPORT.md` next to `diff.json`:

- **Blocked operations** – never executed, with the reason (delete not allowed, still referenced, secret missing,
  read-only area, Prisma Browser, infrastructure without `allow-infra`). Fix the cause and plan again.
- **Operations in execution order** – create / update / move / delete, the reason (e.g. `changed: protocol.bgp.peer_as`),
  dependencies (`depends on`) and notes (e.g. "reference … not found – predefined or inherited?").
- **Conflicts** (merge) – handle manually.

To leave out single operations set `"enabled": false` in `plan.json` (operations depending on them are skipped too).

### 4.4 Dry-run, execute, push

```bash
# dry-run – reads the target, sends nothing, shows every request
php utils/develop/sase/scm/scm_pa_sync.php apply in=scm-api://<target TSG> plan=<compare dir>/plan.json

# execute – you are asked to type the target TSG
php utils/develop/sase/scm/scm_pa_sync.php apply in=scm-api://<target TSG> plan=<compare dir>/plan.json execute

# execute and push the changed folders
php utils/develop/sase/scm/scm_pa_sync.php apply in=scm-api://<target TSG> plan=<compare dir>/plan.json execute push
```

- `conflict` = the target object was changed after its export → export the target again, compare, plan again.
- `failed` = the API refused a request (HTTP code and message in the console / `apply-log-*.json`); apply stops
  unless `continue-on-error`.
- Without `push` the touched folders are listed – push them in Strata Cloud Manager.

### 4.5 Check the result

Export the target again and compare it with the **same** source export. Only blocked / excluded differences may
remain. Then work through `MIGRATION_CHECKLIST.md` (certificates, IPs on branch / DC firewalls, …).

## 5. Troubleshooting

| symptom | cause / action |
|---|---|
| `problem with SCM API connection - not possible to get 'access_token'` | wrong `client_id` / `client_secret` or TSG → fix the line in `~/.panconfkeystore`; QA tenant: add `shadow-saseapiqa` |
| many endpoints `unavailable` | product not licensed or service account without role → expected / add role |
| endpoint `error` with HTTP 400 / 404 | API path or parameter not valid for this tenant → note it in the verification list ([NEXT_STEPS](NEXT_STEPS_pa_export.md) §4) |
| egress IP error | try `egressip-env=prod6`; check the egress API key |
| `psk-list.csv` shows `DECRYPT_FAILED` | normal for SCM tenants (own master key) → fill `psk_new`, check with `scm_pa_secret_check.php` (4.2); a known master key: `master-key=<key>` |
| export of `config` takes long | default `config-mode=leaf` already queries only the deepest folders and runs 8 requests in parallel; further: `config-scope=` / `container=` / `config-types=`; try `config-parallel=16` if no HTTP 429 occurs |
| compare: "not comparable – not exported in right" | the two exports used different areas / filters → export again with the same options |
| compare: "format_version …" hint | an export from an older version → export again |
| compare: everything "only in left / right" in one folder | the folder is named differently → name map `config,container,<left>,<right>` |
| plan: `secret missing` | export the source with `psk-list` (or fill `*_new`) and compare / plan again |
| plan: `still referenced by …` | another target object uses it – delete / change that one first, or leave it |
| apply: `plan target TSG … does not match` | wrong `in=` – the plan belongs to another target |
| apply: `conflict` | target changed after its export → re-export, compare, plan |

## 6. What comes next

- verification of export, compare and sync against live tenants ([NEXT_STEPS_pa_export.md](NEXT_STEPS_pa_export.md) §4)
- Prisma Browser sync (rule / section API, draft publish)
- `scm_pa_verify.php` – checks pan-os-php's own SCM loading against the raw export
