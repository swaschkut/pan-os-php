# Prisma Access configuration – Panorama cloud plugin and SCM API

**Status:** concept / inventory (2026-11-17)
**Code reference:** `alpha` `b109255`
**Related:** [scm-prisma-access-lifecycle.md](scm-prisma-access-lifecycle.md),
[scm-pa-export-next-steps.md](scm-pa-export-next-steps.md), [scm-panorama-migration.md](scm-panorama-migration.md),
[scm-api-coverage.md](scm-api-coverage.md)

Prisma Access is configured in two places:

- **Panorama managed:** Panorama plugin `cloud_services`
  (`/config/devices/entry[@name='localhost.localdomain']/plugins/cloud_services`) plus the device groups / templates of
  the plugin (Service Connection, Remote Network, Mobile User, Explicit Proxy)
- **SCM managed:** Strata Cloud Manager API – areas infrastructure, service connections (SC), remote networks (RN),
  mobile users (MU: GlobalProtect, Explicit Proxy, Prisma Access Agent) in the folders `Service Connections`,
  `Remote Networks`, `Mobile Users`, …

Both describe the same things (infrastructure subnet, locations, tunnels, BGP / routing, IP pools, onboarding …).
The goal: **one way of working for both sources**, built from four common building blocks.

## Common building blocks

| # | Building block | Panorama plugin (`cloud_services`) | SCM API |
|---|---|---|---|
| 1 | **understand** the config: elements, dependencies, mapping Panorama ↔ SCM | not documented in the repo | partly: `README_pa_export.md`, `CONSULTANT_GUIDE_pa_export_compare.md` |
| 2 | **output** via scripts (display, Excel / HTML, JSON) | `utils/develop/sase/panorama_managed/plugin_cloud_services.php` (partial, display only) | `type=scm-export` (areas `infra`, `sc`, `rn`, `mu`, `ep`, `pb`, `iam`), `scm-report`, `scm-compare` |
| 3 | **adapt** via scripts (actions: add / change / remove) | none | `type=scm-change` / `scm-xml-to-change` (change.json, dry-run, verify) |
| 4 | **write** the change | offline XML (`out=`) / Panorama XML API: none | SCM public API: `scm-change`, `scm-sync`; SCM internal (web UI) API: read only today |

Same normalised model in the middle: read from Panorama XML **or** SCM → common structure → output / actions →
write to Panorama XML (offline), Panorama XML API (online), SCM public API or SCM internal UI API.

```
Panorama XML (file) ─┐                                         ┌─► Panorama XML (out=)
Panorama XML API  ───┼─► reader ─► PA model ─► output          ├─► Panorama XML API (set / edit, commit, push)
SCM public API    ───┤                     └─► actions ─► writer┼─► SCM public API (change.json)
SCM internal UI API ─┘                                          └─► SCM internal UI API (only where no public API)
```

## 1. Understand

### Panorama plugin – what exists today

`plugin_cloud_services.php` reads (display only, old argument parsing, own Todo 2025-01-02: "all these parts are now
separately available as utility e.g. type=ike-gateway"):

| Plugin element | Read today |
|---|---|
| `service-connection` | yes (`internal-dns-list` removed for display) |
| `remote-networks/onboarding/entry` | name, `protocol/bgp/enable`, `subnets`, `region`, `license-type`, `ipsec-tunnel`, `secondary-ipsec-tunnel`, `spn-name`, `ecmp-load-balancing` |
| `routing-preference` | yes |
| `mobile-users/onboarding/entry` | no (only known from `DIFF.php` exclude example and `XMLISSUE.php` duplicate check of the readonly part) |
| infrastructure settings, Explicit Proxy, other plugin parts | no |

Other code touching the plugin:
- `utils/lib/XMLISSUE.php`: removes duplicate `readonly/…/plugins/cloud_services/mobile-users/onboarding/entry`
- `utils/develop/panorama-PA_cleanup.php`, `panorama-PA_multi2singleTenant.php`: keep / rename Prisma Access device
  groups and template stacks, multi tenant → single tenant (see [TODO-develop-scripts.md](../TODO-develop-scripts.md))
- the plugin device groups / templates are normal device groups / templates – objects, rules, IKE / IPsec, zones work
  with the existing types (`type=address`, `rule`, `ike-gateway`, `ipsec-tunnel`, …); the plugin part itself
  (onboarding, locations, IP pools, BGP, routing preference) has **no class in `lib/`**

### SCM API – what exists today

- `type=scm-export` with `SCMPrismaAccessExport` (`utils/develop/sase/scm/lib/`): areas `infra`, `sc`, `rn`, `mu`
  (incl. GlobalProtect mobile agent, Prisma Access Agent), `ep` (Explicit Proxy), `pb` (Prisma Browser), `iam`;
  endpoints without public API are read from the internal UI API (`'internal' => true`: GP portal, clientless VPN,
  trusted zones, PA agent, Explicit Proxy, forwarding profiles) – documentation / compare only
- `scm-compare`, `scm-report`, `scm-change`, `scm-sync`, `scm-xml-to-change`
- older single scripts `utils/develop/sase/prisma_access/pa_*.php` (superseded, see [scm-api-coverage.md](scm-api-coverage.md))
- `scm-panorama-to-change` (Panorama → SCM) covers shared, device groups, templates – **not the plugin**

### To do

- mapping table per area: Panorama plugin xpath ↔ SCM endpoint / field (infra, SC, RN, MU GlobalProtect, MU Explicit
  Proxy, routing, IP pools, DNS, egress), incl. what exists on one side only
- dependencies: plugin onboarding entry → IKE gateway / IPsec tunnel in the plugin template, zones, device group
  of the plugin, regions / locations, bandwidth / license
- collect real plugin XML from lab / customer exports (several plugin versions) as test fixtures

## 2. Output

- one type for both sources, e.g. `type=prisma-access` (name open) with `in=panorama.xml`, `in=api://<panorama>` or
  `in=scm-api://<TSG>`, `area=infra|sc|rn|mu|ep|any`
- `actions=display`, `exportToExcel:file.html`, JSON (`shadow-json`) – same columns for both sources, so the result
  of Panorama and SCM can be compared directly
- Panorama: replace `plugin_cloud_services.php` by a class in `lib/` (reader for the plugin XML)
- SCM: reuse `SCMPrismaAccessExport` (already writes the areas as files)
- compare Panorama plugin ↔ SCM export: same model → `scm-compare` logic

## 3. Adapt

Actions on the model, e.g.:
- RN / SC: add / remove subnets, change BGP (peer AS, enable), change region / SPN / license type, change IPsec tunnel
  (primary / secondary), ECMP
- MU: IP pools per region, locations, DNS servers, portal / gateway settings
- routing preference, infrastructure settings
- bulk input from CSV / JSON (many remote networks at once)
- placeholders and validation (overlapping subnets / IP pools, names max. 31 characters – see
  [KNOWN_ISSUES.md](../KNOWN_ISSUES.md) #121)

## 4. Write

| Target | Today | To do |
|---|---|---|
| Panorama offline (XML file, `out=`) | – | write the plugin XML (keep element order / `__recordInfo` of readonly parts) |
| Panorama online (XML API) | – | `set` / `edit` on the plugin xpath, commit, then push to Prisma Access (command to be verified) |
| SCM public API | `scm-change` (change.json, dry-run, execute, verify) | add the PA areas (SC / RN / MU) to the change generator where the public API allows writes |
| SCM internal (web UI) API | read only (export) | write only where no public API exists; marked "may change without notice", opt-in argument |

## Related migration path

Panorama managed → SCM managed Prisma Access = building blocks 1 + 2 (Panorama) → mapping → 3 + 4 (SCM). This extends
`scm-panorama-to-change` (today without the plugin). Secrets (IKE pre-shared keys, …) as in the other migrations:
same master key or re-enter.

## Open decisions

1. One type for both sources (`type=prisma-access`) or extend `scm-*` types with a Panorama reader.
2. Order: understand + output first (read only, low risk), write later?
3. Panorama push to Prisma Access via XML API: part of the type or left to the user.
4. Use of the SCM internal UI API for writing – yes / no / only with explicit argument.
5. Which plugin versions have to be supported (fixtures).
