# scm_pa_export.php – next steps and verification

Status: the export covers all planned areas (`infra`, `config`, `remote-networks`, `service-connections`,
`mobile-users`, `prisma-browser`, `iam`) and writes `MIGRATION_CHECKLIST.md`. It has only been tested offline against simulated API
answers. Before compare / import are built on top of it, the export format has to be verified against a live tenant.

Details of the export itself: [README_pa_export.md](README_pa_export.md). Compare: [README_pa_compare.md](README_pa_compare.md).
Sync: [README_pa_sync.md](README_pa_sync.md).
Step-by-step guide for consultants: [CONSULTANT_GUIDE_pa_export_compare.md](CONSULTANT_GUIDE_pa_export_compare.md).

---

## 1. Apply the patches (branch `beta_scm-extension`)

Order matters, each patch builds on the previous one:

```bash
git checkout beta_scm-extension
git am scm-rn-export_beta.patch \
       scm-rn-export-psk-list_beta.patch \
       scm-pa-export-infra_beta.patch \
       scm-pa-export-sc_beta.patch \
       scm-pa-export-mu_beta.patch \
       scm-pa-export-pb-iam-checklist_beta.patch \
       scm-pa-export-next-steps_beta.patch \
       scm-pa-export-config_beta.patch \
       scm-pa-compare_beta.patch \
       scm-pa-sync_beta.patch \
       scm-pa-export-ngfw_beta.patch \
       scm-pa-livefix-1_beta.patch
```

Quick check:

```bash
php -l utils/develop/sase/scm/scm_pa_export.php
php -l utils/develop/sase/scm/lib/SCMPrismaAccessExport.php
php -l lib/misc-classes/PanSCMAPIConnector.php
```

## 2. Prerequisites for the first live run

- [ ] **Test tenant** (TSG) with Prisma Access – ideally one with RN, SC and MU configured.
- [ ] **Service account** with read access to the tenant. For `iam` and `prisma-browser` the account needs the
      corresponding roles; without them these areas show `unavailable` (not an error).
- [ ] **`.panconfkeystore`**: entry `tsg_id<TSG>` exists or is created on the first run (client_id / client_secret prompt).
- [ ] **Egress-IP API key** (optional): either entry `egressip_tsg_id<TSG>` in `.panconfkeystore`, or the run takes
      `api_key` from `shared-infrastructure-settings`, or it asks once.
- [ ] Output directory outside of git (the secret lists contain cleartext).

## 3. First live run

Full export with all extras and API debug output (keep the log):

```bash
php utils/develop/sase/scm/scm_pa_export.php in=scm-api://<TSG> \
    outdir=/share/export egressip psk-list debugapi 2>&1 | tee /share/export/run-<TSG>.log
```

If the full run is too noisy, run the areas one by one:

```bash
php utils/develop/sase/scm/scm_pa_export.php in=scm-api://<TSG> area=infra egressip debugapi
php utils/develop/sase/scm/scm_rn_export.php  in=scm-api://<TSG> psk-list debugapi
php utils/develop/sase/scm/scm_sc_export.php  in=scm-api://<TSG> psk-list debugapi
php utils/develop/sase/scm/scm_mu_export.php  in=scm-api://<TSG> psk-list debugapi
php utils/develop/sase/scm/scm_pb_export.php  in=scm-api://<TSG> debugapi
php utils/develop/sase/scm/scm_iam_export.php in=scm-api://<TSG> debugapi
php utils/develop/sase/scm/scm_config_export.php in=scm-api://<TSG> debugapi
```

The `config` area queries every type for every container – on a large tenant start with a filter:

```bash
php utils/develop/sase/scm/scm_config_export.php in=scm-api://<TSG> container="Mobile Users" config-types=addresses,security-rules debugapi
```

Note: `debugapi` prints the bearer token and full API answers – do not share the raw log.

## 3a. Results of the first live run (Prisma Access tenant, areas infra, RN, SC, MU, IAM)

| finding | change |
|---|---|
| 0 errors, all endpoints of infra / RN / SC / MU answered; egress mapping matched for all RNs and MU locations | – |
| all PSKs `-AQ==…` (PAN-OS format v1, 77 chars), none decryptable with the default master key → SCM tenant key | SHA1 of the cleartext used: `psk_sha1` column, `scm_pa_secret_check.php`, compare by SHA1, plan notes; checklist item "PSKs not decryptable" |
| IAM lists come as `{"items": [...], "count": n}` → were stored as single object, IAM summary empty | list detection for `data` / `items` / top-level arrays (`PanSCMAPIConnector::listOfAnswer()`) |
| `locations`, `mobile-agent/locations` return a top-level array → counted as 1 entry | same fix |
| `area=config` too slow on a large tenant | `config-mode=leaf` (default) + skip of unavailable types |

## 4. Verification

Work through the list with the export directory `<outdir>/<TSG>/<timestamp>/`. For every item note **OK** or what
was found; wrong items are fixed in the code afterwards.

### 4.1 General

- [ ] `manifest.json` → `errors` is 0. For every endpoint with `status: error`: note `http_code` and `error`
      (wrong path, wrong folder, missing permission?).
- [ ] `manifest.json` → `unavailable`: only products that are really not licensed / not permitted.
- [ ] Log: does the "retry without limit/offset" line appear? For which endpoints? (They really reject
      `limit` / `offset`.)
- [ ] Endpoints with many objects (> 200): count in `manifest.json` = count in the SCM UI (pagination works).
- [ ] `infra/01_shared-infrastructure-settings.json`: `api_key` is `***REDACTED***`;
      `grep -r "<real api key>" <export dir>` finds nothing.
- [ ] Secret lists have mode 600: `ls -l */psk-list.csv */bgp-secret-list.csv */secret-list.csv`.

### 4.2 infra

- [ ] `shared-infrastructure-settings`: `infrastructure_subnet`, `infra_bgp_as`, `loopback_ips` match the UI.
- [ ] `bgp-routing`: field names as used in the `infra` summary of `manifest.json` (`routing_preference`,
      `backbone_routing`, `accept_route_over_SC`, `outbound_routes_for_services`, `add_host_route_to_ike_peer`,
      `withdraw_static_route`) – summary values not `null` where set in the UI.
- [ ] `internal-dns-servers`: field names `domain_name`, `primary`, `secondary`.
- [ ] `locations`: entries have `value` and `display` (used for all IP mappings).
- [ ] `92_egress-ip.json`: request worked; if HTTP error → try `egressip-env=prod6`.
- [ ] Egress API accepted the `api_key` of `shared-infrastructure-settings` (log line
      "using api_key of shared-infrastructure-settings").
- [ ] Egress `addrType=all` contains pre-allocated GlobalProtect addresses (`addressType` values in the file).

### 4.3 remote-networks

- [ ] `remote-networks` and `bandwidth-allocations` return data without a `folder` parameter.
- [ ] `05_qos-profiles.json`: path `/config/network/v1/qos-profiles?folder=Remote Networks` works.
- [ ] IKE / IPsec objects: folder `Remote Networks` returns the expected objects; predefined profiles are listed in
      `import_hints` as `inherited_or_predefined`.
- [ ] `ike-gateways`: PSK under `authentication.pre_shared_key.key`, format `-AQ==…`.
- [x] `ike-gateways` PSK format `-AQ==…` – confirmed; not decryptable with the default master key (3a).
- [ ] fill `psk_new` for a few gateways with known PSKs → `scm_pa_secret_check.php` reports `OK new = secret of the
      source tenant`; a deliberately wrong value reports `NEW`.
- [ ] `bgp-secret-list.csv`: BGP secret under `protocol.bgp.secret`, decrypted.
- [ ] `ip-mapping.csv`: `service_ip_address`, `fqdn`, `branch_peer_address` filled; `egress_match = location` for
      most rows (if `none`: compare `region` with `infra/90_locations.json` `value`).

### 4.4 service-connections

- [ ] `service-connections`, `service-connection-groups`, `traffic-steering-rules`: paths work, without `folder`
      parameter.
- [ ] `05_qos-profiles.json` for folder `Service Connections`.
- [ ] Field names in `ip-mapping.csv`: `backup_SC`, `subnets`, `nat_pool`, `source_nat`, `qos`, `bgp_peer.*`.
- [ ] `psk-list.csv` / `bgp-secret-list.csv`: decrypted; `bgp_peer.secret` uses the same encryption as the PSK.
- [ ] `import_hints` `intra_dependency` lists the service connections with `backup_SC`.

### 4.5 mobile-users

- [ ] Identity endpoints (`/config/identity/v1/*?folder=Mobile Users`): do they also return objects of parent
      folders (`Prisma Access`, `All`)? Compare e.g. authentication profiles with the UI.
- [ ] `mobile-agent/*`: `agent-versions`, `enable`, `global-settings` accept the `folder` parameter.
- [ ] `21_mobile-agent-locations.json`: structure (used only as fallback for the MU IP mapping).
- [ ] `20_mobile-agent-infrastructure-settings.json`: `name` = portal hostname, `ip_pools`, `deployment.region[]`.
- [ ] `secret-list.csv`: which fields are really found (LDAP `bind_password`, RADIUS `secret`, local user
      `password` = `HASHED`, GP app passwords in `gp_app_config`)? Any false positives (non-secret values)?
      Any secret that is missing?
- [ ] `ip-mapping.csv`: gateway / portal egress IPs per location, active and pre-allocated split correctly.
- [ ] `import_hints` `certificate_private_key`: does the certificate list contain private key fields at all?

### 4.6 prisma-browser

- [ ] The SCM service account token is accepted on `api.sase.paloaltonetworks.com/seb-api/v1` (no 401).
- [ ] Lists: response key (`data` / `items` / `results`) and cursor field in `pageInfo` – a list with more than
      1000 entries is complete.
- [ ] Policy GETs return the active configuration without `configurationVersion=active` (otherwise the parameter
      has to be added).
- [ ] `user-groups`: field / values for IdP-synced groups (`source`, `type`, …) → `idp_synced_groups` hint correct.
- [ ] `applications`: field / value for catalog applications (`type: catalog`?).
- [ ] `prisma_browser` summary in `manifest.json`: rule / section counts match the UI.

### 4.7 iam

- [ ] Paths `/iam/v1/custom_roles` and `/iam/v1/permission_sets` (derived from the documentation structure, not
      confirmed).
- [x] List format of the IAM endpoints: `items` / `count` (3a) – re-run `area=iam`: access policies / service accounts
      counted in `manifest.json` → `iam`.
- [ ] Pagination of the IAM endpoints (more than 200 access policies complete?).
- [ ] `access-policies.csv`: `principal`, `role`, `resource` filled (field names of the access policy objects).

### 4.8 config

- [ ] **`config-mode=leaf` vs `all`**: export a part of the tenant twice (e.g. `config-scope=objects,policies`, once
      with `config-mode=all`) and compare the two exports → **no differences** expected. A difference means a folder
      answer does not contain all inherited objects (→ use `all` and report).
- [ ] `manifest.json` → `config.api_queries` / runtime of `leaf` acceptable; `config.warnings` empty (objects
      without owner field).
- [ ] `config/hierarchy.txt` matches the folder tree in SCM, incl. the order of the attached snippets per folder.
- [ ] Every object returned for a container carries `folder` or `snippet` (otherwise it stays in the queried container
      – check files with `data` entries without these fields).
- [ ] No object appears twice on disk: per type, the names over all `config/*/*/NN_<type>.json` files are unique
      per owner.
- [ ] Owned counts per container (`manifest.json` → `config.owned_objects_by_container`) match the UI for a few
      containers / types.
- [ ] `config.types_unavailable`: only types that really do not exist / are not licensed (e.g. `ai-security-profiles`).
      A type that exists in the UI but is listed there has a wrong path.
- [ ] Rules: `-pre` / `-post` split as in the UI; order of the rules inside a file = rule order in the UI.
- [ ] Predefined objects (applications, profiles): owner value (`snippet: predefined`?) → counted under
      `config.owners_not_exported`, not stored.
- [ ] Runtime / number of API calls acceptable on a large tenant (containers × types) – the config area has now
      ~110 types; use `config-scope=` / `container=` for the first runs.
- [ ] NGFW groups: which of the derived paths answer 404 (`config.types_unavailable`) although the type exists in the
      UI → correct the path in `getConfigTypes()`. Especially: `layer2-subinterfaces`, `layer3-subinterfaces`,
      `ospf-auth-profiles`, `bgp-*`, `route-*-lists`, `sdwan-*`, all `/config/device/v1/*` and `*-match-list`.
- [ ] `nat-rules`, `pbf-rules`, `qos-policy-rules`, `sdwan-rules` accept `position=pre|post` (otherwise: one rule base).
- [ ] Device folders: does `folder=<serial>` work, or is the `device=<serial>` fallback used (see the `url` in
      `config/folders/<serial>/*.json`)? Which owner field do device objects carry (`folder` / `device`)?
- [ ] Device settings (`general-settings` …): list with `name` or single object? (key in `ENDPOINT_META`)
- [ ] `config/devices.csv` matches SCM device management (serials, folder, connected, version, HA peer);
      `grep` for a known authcode in the export finds nothing.
- [ ] Prisma Access folders: no network / identity files in `config/folders/<PA folder>/` (covered by the PA areas).

### 4.9 compare (two real exports)

- [ ] Export the same tenant twice without changes in between and compare: **no differences** expected. Every
      difference is a field that changes by itself (timestamps, counters, runtime state) → add it to `ignore` in
      `ENDPOINT_META` (or report it).
- [ ] Change one known value in the UI (e.g. a remote network BGP peer AS, an address, rule order), export again,
      compare: exactly these changes are reported.
- [ ] Compare two different tenants: are the keys right (no mass "only left / only right" for objects that exist on
      both sides)? Endpoints without a `name` field show up in the warnings.
- [ ] Secrets: a changed PSK shows `secret` with `***`; `grep` for a known PSK in the compare output finds nothing.
- [ ] Lists reported as `order` where the order is irrelevant in SCM → note the path (candidate for normalisation).

### 4.10 sync on a lab tenant

Use two lab tenants (or one lab tenant and an export of another tenant). Export both with `psk-list`.

- [ ] `plan` with `mode=additive`: `PLAN_REPORT.md` lists exactly the expected operations; dependencies are in the
      right order (crypto profile → gateway → tunnel → RN / SC; parent folder → folder → objects).
- [ ] `apply` dry-run: no write request in the SCM audit log; hash check reads work (no `conflict` on unchanged
      objects – otherwise the single object GET returns another shape than the list → report).
- [ ] `apply execute` for **one** operation (`ops=op-…`) per action type and endpoint family, check the result in SCM:
      - [ ] create config object (`POST /config/objects/v1/addresses` with `folder` in the body)
      - [ ] create security rule with `?position=pre`
      - [ ] update by id (`PUT …/{id}`), incl. one with folder query (`ike-gateways?folder=Remote Networks`)
      - [ ] PSK / BGP secret sent in cleartext from the list → tunnel comes up with the expected key
      - [ ] singleton update (`PUT /config/mobile-agent/v1/global-settings?folder=Mobile Users`)
      - [ ] create folder (`POST /config/setup/v1/folders` with `parent`)
      - [ ] rule move (`POST …/security-rules/{id}:move`, body `destination` / `destination_rule` / `rulebase`)
      - [ ] delete (`DELETE …/{id}`)
      - [ ] NGFW (with `allow-network`, lab firewall only): update of an interface / zone / NAT rule in a device
            folder (owner field `folder` or `device`), push to the device
      - [ ] service connection with `backup_SC` (create + follow-up update)
- [ ] `push`: job id field of `candidate:push`, job status values (`FIN` / …) – adjust `push()` if different.
- [ ] full `mirror allow-delete` run on the lab tenant, re-export, compare: identical except blocked / excluded.
- [ ] merge: both plans and the conflict list are plausible.

### 4.11 MIGRATION_CHECKLIST.md

- [ ] All `action_required` items are plausible for this tenant.
- [ ] License item shows the RN bandwidth sum of the source tenant.
- [ ] ZTNA connector item: lists the connector blocks if ZTNA is used.
- [ ] Anything missing that you would do manually during a migration?

## 5. What to send back for the fixes

Safe to share (no secrets):

- `manifest.json`
- `MIGRATION_CHECKLIST.md`
- the filled-in verification list (section 4)
- one endpoint file per failing or suspicious endpoint – names / IPs may be anonymised

Never share: `psk-list.csv`, `bgp-secret-list.csv`, `secret-list.csv`, the raw `debugapi` log.

## 6. Explicit Proxy (internal SCM API)

No documented public API exists. To add it as an area:

1. Log in to Strata Cloud Manager, open Prisma Access → Mobile Users → Explicit Proxy.
2. Browser developer tools → Network, filter `Fetch/XHR`, reload and open each Explicit Proxy page / tab.
3. Note per request: method, path, query parameters, response structure (or save a HAR file).
4. Remove `Authorization` headers and cookies from the HAR before sharing.
5. The calls are added as area `mobile-users-explicit-proxy` with endpoints marked `internal`
   (may change without notice).

Alternative: open SCM in the Claude browser pane and capture the calls together.

## 7. Next development steps

| step | what | depends on |
|---|---|---|
| 1 | fixes from the verification (section 4) | live run |
| 2a | `scm_pa_verify.php`: verify pan-os-php's SCM loading against the raw export – input: export directory + XML written by `pan-os-php in=scm-api://<TSG> out=…`; per container and type: count, names, selected fields; report: types pan-os-php does not load, missing / extra objects, field differences, wrong owner (folder / snippet) | export format verified (4.8) |
| 2 | ✅ endpoint metadata (`ENDPOINT_META`) + `scm_pa_compare.php` – offline diff per area / container / endpoint, hierarchy diff, name map, `diff.json` / `DIFF_REPORT.md` / `diff-summary.csv` ([README_pa_compare.md](README_pa_compare.md)) | done – verify with 4.9 |
| 3 | ✅ `scm_pa_sync.php plan`: `diff.json` + direction + mode (`additive` / `mirror` + `allow-delete` / `merge`) → `plan.json` / `PLAN_REPORT.md`; dependency closure, delete check, `backup_SC` follow-up, secrets as placeholders ([README_pa_sync.md](README_pa_sync.md)) | done – verify with 4.10 |
| 4 | ✅ `scm_pa_sync.php apply`: dry-run by default, TSG check + confirmation, hash check, secrets from the lists, create / update / delete / move, ids of created objects, `push` + job polling, apply log | done – verify with 4.10 |
| 4a | migration into a **new** tenant = export the new (empty) tenant, compare with the source, plan `additive`, apply – no separate import tool | steps 3 + 4 |
| 5 | Prisma Browser sync (rule / section API, draft publish) | 4.10 |
| 6 | Explicit Proxy area (internal API) | section 6 |

## 8. Known limitations

- Private keys of certificates are not exported (manual import on the target tenant).
- Service account secrets cannot be read (new service accounts on the target tenant).
- IAM is documentation / compare only.
- Not exported: Explicit Proxy, ZTNA connector, Cloud Identity Engine, Strata Logging Service, license allocation,
  Prisma Browser assets (logos).
- `config` references in the endpoint metadata are partial (groups, profile groups) – dependencies of rules on
  objects are not resolved by the sync plan yet.
- Sync of Prisma Browser is blocked in the plan; IAM is never written.
