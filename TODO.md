# TODO – open work and concepts

Central list of planned work. One file per topic in [todo/](todo/), named `<area>-<topic>.md`, with status, code
reference, plan and open decisions. Finished topics move to [todo/done/](todo/done/). Small items without their own
file are listed below.

Documentation of an existing tool (`README_*.md`, guides) stays next to its code; `utils/develop/` keeps the code
under development.

## Topics

| Area | Topic | Status | File |
|---|---|---|---|
| rule-compare | switch `type=rule-compare` to `RuleResolver` (more fields, IPv6, EDL, other rule types) | planned, open decisions | [todo/rule-compare-ruleresolver.md](todo/rule-compare-ruleresolver.md) |
| panorama-move | move device groups from one Panorama to another (`type=panorama-move`) | implemented on `alpha`; concept kept for decisions and limits | [todo/panorama-move-concept.md](todo/panorama-move-concept.md) |
| SCM | Panorama → SCM migration firewall by firewall | concept; step 2 (onboarding) is new | [todo/scm-panorama-migration.md](todo/scm-panorama-migration.md) |
| SCM | gap remediation: visibility / best practice fixes as reviewable API change files | draft for discussion | [todo/scm-gap-remediation.md](todo/scm-gap-remediation.md) |
| SCM / Prisma Access | lifecycle from requirements to maturity report | draft; steps A + B as first version (`type=scm-report`) | [todo/scm-prisma-access-lifecycle.md](todo/scm-prisma-access-lifecycle.md) |
| SCM / Prisma Access | `scm_pa_export.php`: next steps, verification against a live tenant | open: live verification | [todo/scm-pa-export-next-steps.md](todo/scm-pa-export-next-steps.md) |
| SCM | API coverage: single scripts (pan.dev endpoints) vs. integrated `scm-*` types – superseded scripts, endpoints not integrated (config versions / jobs list, snippet audit logs, shared snippets, trusted tenants, deployment sites, fetch-scm-config, AIOps BPA) | inventory, decisions open | [todo/scm-api-coverage.md](todo/scm-api-coverage.md) |
| develop / release notes | PAN-OS release notes (known / addressed issues) as `type=`; script + library + cache exist (`utils/develop/panos-release-notes`, `lib/resources/panos_release_notes`) | standalone script, not connected | [todo/develop-areas.md](todo/develop-areas.md) (1.1) |
| develop / CVE | security advisory / CVE search for a PAN-OS version (security.paloaltonetworks.com) | **new**, does not exist | [todo/develop-areas.md](todo/develop-areas.md) (1.2) |
| develop / LDAP | read AD users / groups (nested, account status); compare with firewall group mapping | 5 interactive scripts, not connected | [todo/develop-areas.md](todo/develop-areas.md) (1.3) |
| develop | other `utils/develop` folders and loose scripts not connected to `type=` (migration vendors, create, certificate import, superseded scripts, `power/`) | inventory, decisions open | [todo/develop-areas.md](todo/develop-areas.md) (2, 3) |
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

### panos-hw-compare (former `utils/develop/panos-hw-compare/todo.txt`)

The plain download does not show the product information, it is loaded by JavaScript
(`class="table table-condensed table-hover table-striped table-bordered`).

- comparison pages: https://www.paloaltonetworks.com/products/product-comparison?chosen=pa-3410 ,
  `?chosen=pa-1410,pa-1420`, `?chosen=pa-3410,pa-3420,pa-3430,pa-3440`,
  `?chosen=pa-5410,pa-5420,pa-5430,pa-5440,pa-5445,pa-5450`
- PDF: https://www.paloaltonetworks.com/apps/productcompare/createpdf?language=en_US&corename=productcompare&q=product_id:%22pa-5410%22&rows=3&json.nl=map&sort=position+asc&wt=json&chosen=pa-5410
- HW EoL: https://www.paloaltonetworks.com/services/support/end-of-life-announcements/hardware-end-of-life-dates
- SW EoL: https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-life-summary#pan-os-panorama

### SCM API (former `utils/develop/sase/scm/todo`, `utils/develop/sase/prisma_access/todo`)

Moved to [todo/scm-api-coverage.md](todo/scm-api-coverage.md): list jobs (`/config/operations/v1/jobs`), list config
versions (`/config/operations/v1/config-versions`), `/config/setup/v1/snippet-audit-logs`; Prisma Access public IPs
are done (see Done).

### UI diagram (former `utils/develop/ui/html/diagram/todo`)

- JavaScript libraries: https://d3js.org/d3.v7.min.js, https://html2canvas.hertzen.com/dist/html2canvas.min.js
