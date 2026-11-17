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
| object merger | remaining object types: section B items 9 (data objects) and 10 (GTP, SCEP, packet broker, SD-WAN profiles) – only when needed; section D: duplicate report for template objects (certificates, certificate profiles, SSL/TLS service profiles) | open | [todo/done/merger-missing-object-types.md](todo/done/merger-missing-object-types.md) (sections B, D) |

## Done

| Area | Topic | Result | File |
|---|---|---|---|
| object merger | missing object mergers, section A + item 8 | `type=object-merger` (`objecttype=`), `securityprofile-merger` SCM profile types | [todo/done/merger-missing-object-types.md](todo/done/merger-missing-object-types.md) |

## Small items

### General (former `lib/todo.txt`)

- Ironskillet / BP – extend to configure day one config via API
- `type=securityprofile 'filter=(object is.bestpractice)'`
- `type=securityprofile actions=exporttoexcel:file.html,checkBestPractice`
- optimisation:
  - template HA / device / local FW config import
  - rule-merger – Panorama based on serial – upper / lower DG
  - partial usage of address / address-group / service / service-group / application-group / application-container
  - display threat-log
  - `type=rule threat-log-hit.count == 0`

### IPv6

- zone calculation of rules (`Rule.php`, from / to) uses only the `ipv4` part of `getIPtoZoneRouteMapping()`; the
  `ipv6` part exists since `b8381c9` – using it changes rule results
- action arguments cannot take an IPv6 address: `actions=find-zone-from-ip:2001:db8::1` → "illegal syntax" (the
  colons are the argument separator)

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

- list jobs: https://api.strata.paloaltonetworks.com/config/operations/v1/jobs
- list config versions: https://api.strata.paloaltonetworks.com/config/operations/v1/config-versions
- `/config/setup/v1/snippet-audit-logs`
- Prisma Access public IPs – API examples:
  https://docs.paloaltonetworks.com/prisma-access/administration/prisma-access-setup/api-examples-for-retrieving-prisma-access-ip-addresses
  and https://docs.paloaltonetworks.com/prisma-access/administration/prisma-access-setup/retrieve-ip-addresses-for-prisma-access
  – Prisma Access (managed by Strata Cloud Manager): Configuration › NGFW and Prisma Access › Configuration Scope
  Prisma Access › Prisma Access Infrastructure › Infrastructure Settings:

  ```
  curl -X POST -d @option.txt -H "header-api-key: {API-KEY}" "https://api.lab.datapath.prismaaccess.com/getPrismaAccessIP/v2"

  option.txt
  {
    "serviceType": "all",
    "addrType": "all",
    "location": "all"
  }
  ```

### UI diagram (former `utils/develop/ui/html/diagram/todo`)

- JavaScript libraries: https://d3js.org/d3.v7.min.js, https://html2canvas.hertzen.com/dist/html2canvas.min.js
