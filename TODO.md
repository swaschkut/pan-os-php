# TODO – open work and concepts

Central list of planned work. One file per topic in [todo/](todo/), named `<area>-<topic>.md`, with status, code
reference, plan and open decisions. Finished topics move to [todo/done/](todo/done/). Small items without their own
file are listed below.

Known bugs and limitations (open GitHub issues and limitations without issue): [KNOWN_ISSUES.md](KNOWN_ISSUES.md).
Loose scripts in `utils/develop/`: [TODO-develop-scripts.md](TODO-develop-scripts.md).

Documentation of an existing tool (`README_*.md`, guides) stays next to its code; `utils/develop/` keeps the code
under development.

## Topics

| Area | Topic | Status | File |
|---|---|---|---|
| rule-compare | switch `type=rule-compare` to `RuleResolver` (more fields, IPv6, EDL, other rule types) | planned, open decisions | [todo/rule-compare-ruleresolver.md](todo/rule-compare-ruleresolver.md) |
| panorama-move | move device groups from one Panorama to another (`type=panorama-move`) | implemented on `alpha`; scheduled config push and `auto-push` / `to-sw-version` of moved firewalls: not transferred, report only (2026-11-19, xpath of the scheduled config push to verify with a real configuration); open items: predefined profile names, name length / characters (concept section 11) | [todo/panorama-move-concept.md](todo/panorama-move-concept.md) |
| SCM | Panorama → SCM migration firewall by firewall | concept; step 2 (onboarding) is new | [todo/scm-panorama-migration.md](todo/scm-panorama-migration.md) |
| SCM | gap remediation: visibility / best practice fixes as reviewable API change files | draft for discussion | [todo/scm-gap-remediation.md](todo/scm-gap-remediation.md) |
| SCM / Prisma Access | lifecycle from requirements to maturity report | draft; steps A + B as first version (`type=scm-report`) | [todo/scm-prisma-access-lifecycle.md](todo/scm-prisma-access-lifecycle.md) |
| SCM / Prisma Access | **licences of the Prisma Access tenant** for the as-built report: Subscription Service / Tenancy API of SCM with the service account (read only) - new area of `scm-export`, table *Subscriptions* (today "not in export") and units in use vs. licensed in `type=scm-report` | wish 2026-11-21, not built | [todo/scm-prisma-access-lifecycle.md](todo/scm-prisma-access-lifecycle.md) (6b) |
| SCM / Prisma Access | `scm_pa_export.php`: next steps, verification against a live tenant | open: live verification | [todo/scm-pa-export-next-steps.md](todo/scm-pa-export-next-steps.md) |
| SCM | API coverage: single scripts (pan.dev endpoints) vs. integrated `scm-*` types – superseded scripts, endpoints not integrated (config versions / jobs list, snippet audit logs, shared snippets, trusted tenants, deployment sites, fetch-scm-config, AIOps BPA) | inventory, decisions open | [todo/scm-api-coverage.md](todo/scm-api-coverage.md) |
| master key | script: input configuration + custom master key → output with **all** secrets re-encrypted with the default master key (generic old key → new key); based on `PanosCrypto`; also for panorama-move 7a (`master-key=rekey` instead of removing the fields) | implemented: `type=master-key` – display (flags `hashes`, `cleartext`), `actions=rekey` (level 1), `actions=scrub` (lab copy); open: lab verification of scrub / rekey, panorama-move `master-key=rekey`, small cleanups (see file) | [todo/master-key-rekey.md](todo/master-key-rekey.md) |
| ssh-connector | `type=ssh-connector` / `RUNSSH` (also `gratuitous-arp`): switch from the edited phpseclib 1.0.19 copy in `phpseclib/` to a current release (3.0 / 4.0) used unchanged | planned, decisions open | [todo/ssh-connector-phpseclib.md](todo/ssh-connector-phpseclib.md) |
| merger | set the single `xyz-merger` types (address, addressgroup, service, servicegroup, tag, custom-url-category, securityprofile, securityprofilegroup) to deprecated → `type=object-merger objecttype=` | planned | [todo/merger-deprecate-single-types.md](todo/merger-deprecate-single-types.md) |
| framework | `utils/lib/UTIL.php` review: type chains maintained twice (`supportedActions()` / `extracting_actions()`), about 60 `require_once` on every call, very long methods (`location_filter*`), `exit()` instead of exceptions | review done, nothing implemented | [todo/util-class-refactoring.md](todo/util-class-refactoring.md) |
| autocompletion | bash / zsh completion (`utils/bash_autocompletion/pan-os-php.sh`): bash loads only with `extglob`; missing: several actions / action arguments, filter operators, type specific arguments (108 of 164 unknown); lists by hand, bash ↔ zsh differences | review done, nothing implemented | [todo/shell-autocompletion.md](todo/shell-autocompletion.md) |
| review | check types `session-browser`, `traffic-log`, `threat-log`, `xml-op-json`, `xpath` (function, help, limits, tests) | review needed | [todo/types-review-logs-xpath.md](todo/types-review-logs-xpath.md) |
| Prisma Access | Panorama cloud plugin (`cloud_services`) and SCM API (infra / SC / RN / MU): understand, output, adapt via scripts, write to Panorama XML offline / Panorama XML API / SCM API / SCM web UI API | concept / inventory | [todo/prisma-access-config.md](todo/prisma-access-config.md) |
| UI | keep the config in the browser / in memory, change and check it in the UI instead of the CLI; possible common way with pan-config-viewer (github.com/fahadysf/pan-config-viewer) | **prototype implemented** (`utils/develop/config-viewer/`, [README](utils/develop/config-viewer/README.md)): login, projects, members read / write, load once, change in memory, save as version, auto save; open: large Panorama config, macOS / Apache / Docker, single-object changes, more types, diff, allow list of actions | [todo/ui-config-in-browser.md](todo/ui-config-in-browser.md) |
| UI / API | **config-viewer: all open points in one list** (state 2026-11-21) - windows (missing pan-os-php actions, types with the generic window only), object-merger, git step 4b, pan.dev APIs, devices, data at rest, limits, licences, migration, API | overview | [utils/develop/config-viewer/TODO.md](utils/develop/config-viewer/TODO.md) |
| UI / API | config-viewer as secured pan-os-php API: **all types** (today 8 of 99), API tokens for scripts (CDSS), result files and jobs, allow list per action, permissions per user (read / write, types, scope DG / template / stack / SCM folder), container per job, REST per type, secrets, audit log; the viewer stays next to `tool.php` / `utils/develop/ui/` | planned, decisions taken 2026-11-20 | [todo/config-viewer-api.md](todo/config-viewer-api.md) |
| UI / API | config-viewer licences: basic (everything built until 2026-11-20) without a licence; future features (`migration`, `cdss`, …) unlocked by a signed licence file, air-gapped customers, bound to the customer, run time | planned, decisions taken 2026-11-20 | [todo/config-viewer-license.md](todo/config-viewer-license.md) |
| UI / API | config-viewer project inputs (PAN-OS file, XML API, SCM API, 3rd party file) and **3rd party migration** as a licensed plug-in (estimate, import by object kind, result into another project, licence per vendor) | requirements 2026-11-20, design proposal, decisions open | [todo/config-viewer-migration.md](todo/config-viewer-migration.md) |
| UI / API | config-viewer data at rest: who can read the Docker volume today (Docker admin = everything, administrator in the browser only via a new password), encryption in the viewer bound to administrators or per project, emergency data key, backup command; encryption does not protect against a determined Docker admin | open, analysis 2026-11-21, decisions open | [todo/config-viewer-encryption.md](todo/config-viewer-encryption.md) |
| UI / API | config-viewer limits per run (memory, CPUs, time) set by an administrator in the browser instead of `.env`: stored in the viewer, read before every run (no restart), upper bound from `docker info` / `VIEWER_RUN_MEMORY_MAX` | idea 2026-11-21, not built | [todo/config-viewer-run-limits.md](todo/config-viewer-run-limits.md) |
| UI / API | config-viewer access to devices: import (read only) from firewall / Panorama / SCM with personal API keys, network for runs (admin switch + per project, allow / deny list); later writing and set commands per SSH | step 1 built 2026-11-21 | [todo/config-viewer-device-access.md](todo/config-viewer-device-access.md) |
| UI / API | config-viewer App-ID database and MaxMind data: installation (admin) and App-ID per project; download (own key, network rules) or upload (air gap); pan-os-php: `PANOSPHP_PREDEFINED_XML`, `PANOSPHP_GEOIP_DIR`, `predefined-out=`, `maxmind-zip=` | built 2026-11-21 | [todo/config-viewer-device-access.md](todo/config-viewer-device-access.md) |
| UI / API | config-viewer LDAP: saved queries per user (own LDAP account: key store entry `ldap_user<bind user>`), project tab LDAP, cleanup check of the rule users (`user-check-ldap`); pan-os-php `type=ldap-query` (the scripts of `utils/develop/ldap` without questions); keys editable (label) | built 2026-11-21 | [todo/config-viewer-device-access.md](todo/config-viewer-device-access.md) |
| UI / API | config-viewer: the APIs documented on **pan.dev** with the user's own service account (key store `scm`): catalogue from the OpenAPI specs of pan.dev (GitHub `PaloAltoNetworks/pan.dev` `openapi-specs`, download or upload for air gap) - which APIs exist is given by pan.dev, not hard-coded; SCM (tenancy, IAM, subscription, config SASE / NGFW / Cloud NGFW, insights, monitoring, incidents, posture …), Prisma SASE; other products (Threat Vault, Prisma Cloud, …) with own key kinds later; read only (GET, reviewed POST queries), as a run with network to the spec's server only; coverage report of the SCM import | idea 2026-11-21, not built | [todo/config-viewer-pandev-api.md](todo/config-viewer-pandev-api.md) |
| UI / API | config-viewer: **public PANW data** as tables with filters - EoL (hardware / software), release notes of the PANW products (start: `panos-release-notes`), CVE / security advisories, firewall compare (core data, front / back panel, link to the documentation, ports copper / fibre for a migration e.g. PA-3250 → PA-1450 / PA-3410), IANA protocol numbers (`type=protocoll-number-download`, admin) | list of Sven 2026-11-21, not built | [todo/config-viewer-panw-data-and-live.md](todo/config-viewer-panw-data-and-live.md) (A) |
| UI / API | config-viewer: **support portal** with the user's login (2FA / mail code): per CSP account the registered serials, search, register firewalls with auth codes (also batch, with address), download licences per serial - check first: official API / terms of use | list of Sven 2026-11-21, not built | [todo/config-viewer-panw-data-and-live.md](todo/config-viewer-panw-data-and-live.md) (B) |
| UI / API | config-viewer: **live data of a device** (XML API, read only, personal key): `session-browser` (also through Panorama?), `system-log`, `traffic-log`, `threat-log`, `custom-report`, `xml-op-json` - as tables; no `actions=delete` / write commands | list of Sven 2026-11-21, not built (review of the types first) | [todo/config-viewer-panw-data-and-live.md](todo/config-viewer-panw-data-and-live.md) (C) |
| UI / API | config-viewer DNS servers per project and per user: for FQDN address objects and everything else that needs DNS (LDAP servers, device names) - the customer's internal DNS; today only installation-wide `VIEWER_RUN_DNS` | open | [todo/config-viewer-device-access.md](todo/config-viewer-device-access.md) (H) |
| UI / API | config-viewer like PAN-OS: menu on the left (no store type select), every object in a window with its fields editable one by one; each change = one pan-os-php action (filter + action) in a change list → multi-edit with a wider filter, export as playbook; history / undo / versions with git on object level (bare repository fed from the DOM, one entry per object); menu Objects / Policies / Network / Device for Panorama and firewall; missing actions (`description-set`, `value-set`, `remove-member`, …) | steps 1-4, playbook export, Network / Device windows, NAT translations, description aliases, tag rename built 2026-11-21; git step 1 (split / join per object, `type=config-split`) , step 2 (a commit per change, `history.git` per project) , step 3 (undo of one change) and step 4a (merge per field, XML + history per object) built; open: git step 4b (branches: device import, per user); Merger tab built (object-merger / rule-merger / merger-possible-report, reports as tables from exportJSON); open also: merge applied to the loaded version (one commit, undo), the list of fields / types not editable yet (missing pan-os-php actions vs. windows), run.log in a window, XML snippet per object, text search in the whole XML (as type=xpath) | [todo/config-viewer-panos-style-edit.md](todo/config-viewer-panos-style-edit.md) |
| API | JSON object model for the API items = the SCM API schema (`scm-ngfw-config-schema.json`); what SCM does not have (PAN-OS locations, separate antivirus / WildFire profiles, computed values) is defined by pan-os-php until PANW defines it | decided 2026-11-20; implemented (`ApiObjectModel`): tags, addresses, address-groups, services, service-groups, schedules, url-categories, external-dynamic-lists, log-forwarding-profiles, security profiles, profile-groups, zones, all rule resources, `?computed=1` (references, visibility, best practice, checks); with the BP JSON of the project (`?bp=`); next: own definitions file | [todo/json-object-model.md](todo/json-object-model.md) |
| API | pan-os-php API (`utils/api/v1/tool.php`, `Dockerfile-API`, docker-compose with DB / users): security findings (no auth, path traversal, MD5 logins), REST / OpenAPI, JSON model, async jobs | review / hardening needed | [todo/api-rest.md](todo/api-rest.md) |
| config-section | device / Panorama settings without object model (`deployment-update-schedule`, `config-bundle-export-schedule`, `permitted-ip`): `type=config-section` with registry, generic display / get / set / delete / exportToHtml | first version implemented (`deployment-update-schedule` = dynamic update schedules, verified); open: xpath of scheduled config push, more sections | [todo/panorama-config-sections.md](todo/panorama-config-sections.md) |
| develop / release notes | PAN-OS release notes (known / addressed issues) as `type=`; script + library + cache exist (`utils/develop/panos-release-notes`, `lib/resources/panos_release_notes`) | standalone script, not connected; known issues cache outdated (newest 11.2.5) | [todo/develop-areas.md](todo/develop-areas.md) (1.1) |
| develop / CVE | security advisory / CVE search for a PAN-OS version (security.paloaltonetworks.com) | **new**, does not exist | [todo/develop-areas.md](todo/develop-areas.md) (1.2) |
| develop / hardware | firewall hardware compare / platform limits: check a config against the limits of its model or a target model (HW refresh); data in `utils/develop/panos-hw-compare` + `info_json/pan_max_values.json` (2021, newer models missing) | not connected, data outdated | [todo/develop-areas.md](todo/develop-areas.md) (1.4) |
| iron-skillet / URL | PAN-OS 12.2 HTTP request / response header logging in the URL Filtering profile (*Log all HTTP headers*, response code, *Max Header Length*): XML element names, decide what goes into the 12.2 URL snippet / best practice | open – needs a 12.2 URL profile with these options set | [todo/ironskillet-url-http-header-logging-12.2.md](todo/ironskillet-url-http-header-logging-12.2.md) |
| best practice / device settings | best-practice device settings: **create** with the initial configuration (like `sp_spg-create-bp`) and **validate** for firewall, Panorama, template and template stack (general / shared template, overrides); today `utils/develop/bp_config_validation` (firewall only) | concept | [todo/bp-config-validation.md](todo/bp-config-validation.md) |
| develop / LDAP | read AD users / groups (nested, account status); compare with firewall group mapping | 5 interactive scripts, not connected | [todo/develop-areas.md](todo/develop-areas.md) (1.3) |
| develop | other `utils/develop` folders not connected to `type=`: `migration` (vendor converters), `create`, `certificate`, `cleanup_customer`, `cisco_aci`, `mapper`, `playbook`, `ironskillet`, `appid`, `power` | inventory, decisions open | [todo/develop-areas.md](todo/develop-areas.md) (2) |
| develop | 26 loose scripts directly in `utils/develop/`: remove (covered by a type) / action / new type / keep | inventory, decisions open | [TODO-develop-scripts.md](TODO-develop-scripts.md) |
| anonymise | `type=config-anonymize`: anonymise a Panorama / firewall / SCM configuration – config logic kept (types, counts, references, rule logic, hierarchy), nothing customer specific left (secrets, certificates, logos / response pages, FQDN / URLs, IPs prefix-preserving, names, free text, users / DNs, serials / host names); allow-list approach, consistent pseudonyms (salt), leak scan + `type=stats` comparison | **first version implemented** ([README](utils/README_config-anonymize.md)); open: lab commit, certificate chains, more real configs, real SCM export | [todo/config-anonymize.md](todo/config-anonymize.md) |
| object merger | remaining object types: section B items 9 (data objects) and 10 (GTP, SCEP, packet broker, SD-WAN profiles) – only when needed; section D: duplicate report for template objects (certificates, certificate profiles, SSL/TLS service profiles) | open | [todo/done/merger-missing-object-types.md](todo/done/merger-missing-object-types.md) (sections B, D) |

## Done

| Area | Topic | Result | File |
|---|---|---|---|
| object merger | missing object mergers, section A + item 8 | `type=object-merger` (`objecttype=`), `securityprofile-merger` SCM profile types | [todo/done/merger-missing-object-types.md](todo/done/merger-missing-object-types.md) |
| best practice | Iron-Skillet / BP day one config (also via API) | iron-skillet XML in the profile classes (`ironSkilletXml()`: antivirus, anti-spyware, vulnerability, URL, file blocking, WildFire, virus-and-wildfire-analysis, DNS security, log forwarding, zone protection); `type=device` actions `sp_spg-create-BP`, `sp_spg-create-alert-only-BP`, `LogForwardingProfile-create-BP`, `ZPP-create-BP`, `CleanUpRule-create-BP`, `DefaultSecurityRule-create-BP`; with `in=api://` the objects are sent by `API_sync()` | – |
| best practice | security profile best practice filter | `type=securityprofile securityprofiletype=<type> 'filter=(<field> is.best-practice)'`, field per profile type: `av`, `as`, `vp`, `wf`, `url`, `fb`, `avwf`, `dnssec`, `dns-security`, `dns-list`, `cloud-inline-analysis` and sub fields (`av.action`, `as.rules`, `vp.mica-engine`, …); also `is.visibility` / `is.adoption`; data filtering (`df`): `is.visibility` / `is.adoption` only | – |
| best practice | security profile export with best practice | `type=securityprofile actions=exportToExcel:file.html,BestPractice\|Visibility\|Adoption` – columns `BP SP`, `BP rules`, `BP mica-engine`, … | – |
| SCM / Prisma Access | Prisma Access public IPs (`getPrismaAccessIP/v2`) | `scm-export` area `infra`, `92_egress-ip.json` (`egressip-env=`, API key) | [todo/scm-api-coverage.md](todo/scm-api-coverage.md) |

## Small items

### General (former `lib/todo.txt`)

- optimisation:
  - template HA / device / local FW config import
  - rule-merger – Panorama based on serial – upper / lower DG
  - partial usage of address / address-group / service / service-group / application-group / application-container
  - display threat-log
  - `type=rule threat-log-hit.count == 0`

### IPv6

- zone calculation of rules (`Rule.php`, from / to) uses only the `ipv4` part of `getIPtoZoneRouteMapping()`; the
  `ipv6` part exists since `b8381c9` – using it changes rule results
- IPv6 address as action argument: see "Action arguments"

### Action arguments (`UTIL::extracting_actions()`)

- `/` separates actions, a `/` inside an argument has to be written as `//` – works, but is not documented
  (README, `READMEutil.md`, help text): `actions=exportToExcel://tmp//out.html` writes `/tmp/out.html`;
  `exportToExcel:/tmp/out.html` fails with "argument#0 'filename' requires a value", `exportToExcel:sub/out.html` with
  "unsupported Action"
- `:` separates the action name from its arguments, more than one `:` is "illegal syntax" and there is no escape:
  an IPv6 address cannot be passed, e.g. `actions=find-zone-from-ip:2001:db8::1`

### appid-toolbox

- `location=` argument help not available / if `location=` is not used, load config and display available DG / vsys
- p1 with rule filter
- p2 rule filter
- p5 rule activation – what about rule renaming and clear of rule hit count? In the past a rule rename cleared
  hit.count, nowadays not

### SCM API (former `utils/develop/sase/scm/todo`, `utils/develop/sase/prisma_access/todo`)

Moved to [todo/scm-api-coverage.md](todo/scm-api-coverage.md): list jobs (`/config/operations/v1/jobs`), list config
versions (`/config/operations/v1/config-versions`), `/config/setup/v1/snippet-audit-logs`; Prisma Access public IPs
are done (see Done).

### UI diagram (former `utils/develop/ui/html/diagram/todo`)

- JavaScript libraries: https://d3js.org/d3.v7.min.js, https://html2canvas.hertzen.com/dist/html2canvas.min.js
