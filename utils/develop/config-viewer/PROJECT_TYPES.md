# config viewer: project types (SCM import scope, tenant migration, tenant sync, Panorama → SCM) - concept

Status: concept 2026-11-22 (Sven); built: 1 (scope of the SCM import). It puts together what already exists on the CLI
(`utils/develop/sase/scm/`) and what a project of the viewer needs for it. Related:

* [SCM_TAB.md](SCM_TAB.md) - SCM tab, binding of a project, compare / change with review and live compare
* [CONSULTANT_GUIDE_pa_export_compare.md](../sase/scm/CONSULTANT_GUIDE_pa_export_compare.md) - export → compare → sync
  (tenant migration on the CLI), PSK lists, `allow-infra`
* [README_pa_sync.md](../sase/scm/README_pa_sync.md) - plan / apply, modes additive / mirror / merge, secret lists
* [todo/scm-panorama-migration.md](../../../todo/scm-panorama-migration.md) - Panorama → SCM firewall by firewall
* [todo/scm-prisma-access-lifecycle.md](../../../todo/scm-prisma-access-lifecycle.md) - design JSON = export format,
  report generator

## 1. Scope of the SCM import (choice when the project is started)

Today the SCM import reads `area=config` + every area of the Prisma Access pages + the egress IPs (2.1.63). On a large
tenant that takes long, and a service account may not see every area (IAM, Prisma Browser: HTTP 403 → "not
available"). Proposal: a setting of the project, asked at the first SCM import, changeable later by the owner:

| choice | `scm-export area=` | for |
|---|---|---|
| configuration only | `config` | objects / policies / NGFW (as before 2.1.63) |
| selected areas | `config` + the areas ticked (infra, service-connections, remote-networks, mobile-users, explicit-proxy, prisma-browser, iam; egress IPs yes / no) | a project that needs only a part |
| all (default) | `config` + every area the viewer knows **now** | as today |
| all, also future areas | `config` + every area of the viewer version that runs the import (a new area of a later version is read without a change of the project) | long running projects |

Difference of the last two: "all" keeps the list of the day it was chosen (a later version does not read more on
its own); "also future areas" follows the viewer. Additionally for the config area the existing filters of
`scm_pa_export.php`: `config-scope=` (objects, policies, network, identity, device) and `config-types=`.

Built: stored with the project (`import_scope`: kind + areas + egress yes / no + config scope), in the card "Import
from a device" (block "SCM import: scope", also without an import now: "Save scope"; `PUT projects/<pid>/import-scope`).
Chosen by a writer while there is none (also with the first SCM import: `scope` of `POST …/import/runs`), changed later
by the owner. Fixed per run in its arguments (`x-import-areas`, `x-import-egress`, `x-import-cscope`): a run started
before a change keeps its scope. The egress IPs need Infrastructure (the API key is in its settings) - it is added.
"Read all live" of the SCM tab reads every area (an explicit read).

## 2. Project types

A project gets a **type** when it is created (today every project is "standard"; the binding of 2.1.63 decides PAN-OS
or SCM by the first import):

| type | bound to | what it is for |
|---|---|---|
| standard PAN-OS | PAN-OS (firewall / Panorama) | as today |
| standard SCM | one SCM tenant (TSG) | as today (+ SCM tab) |
| **tenant migration** | source tenant TSG a, target tenant TSG b | copy everything of tenant a into the new tenant b (Prisma Access rebuilt by PANW) |
| **tenant sync** | tenant a, tenant b | keep objects / policies (and further areas) of two tenants in step |
| **Panorama → SCM** | Panorama (PAN-OS) and one SCM tenant | objects / policies and the mapping device-group / template-stack / template → folder / snippet |

The binding of 2.1.63 becomes a list of **roles**: `source` / `target` (migration, Panorama → SCM) or `a` / `b`
(sync), each with kind + target. Every import / read of the project says which role it is for; a key of another
tenant / kind is refused as today. Writing only into the role `target` (migration) or the side chosen per plan
(sync), always through compare / change with review per area and a live compare right before the upload
(SCM_TAB.md "Changes").

Open: does a migration / sync project import both tenants itself (own versions per role - simple, the keys stay
personal), or does it refer to the versions of project A and project B (no double imports, but members / rights of
two projects)? Proposal: own imports per role; "take the latest version of project A" as a copy, if wanted.

## 3. Tenant migration (A → B)

Situation: tenant b is new; PANW builds the Prisma Access nodes new, so everything that Prisma Access derives
(egress IPs, loopbacks, tunnel monitor IP, service IPs, portal host name) is **new**. The configuration is copied, the
infrastructure is set up again with new values.

### 3.1 Steps

| # | step | source of the data | tool today | missing |
|---|---|---|---|---|
| 1 | export tenant a (all areas, egress IPs, secret lists) | API a | `scm_pa_export.php egressip psk-list` ✅ | viewer: import role source with `psk-list` (cleartext lists only in the run, never in the project - see 3.3) |
| 2 | **migration settings**: the values that are new in b | consultant | - | form: infrastructure subnet (IPv4 / IPv6), infra BGP AS, GlobalProtect portal host name (`xyz.gpcloudservice.com`), MU IP pools (same / new), DNS, … - stored with the project |
| 3 | infrastructure of b | settings of step 2 | `scm_pa_sync.php allow-infra` ✅ (writes the source values) | **transform** step: the plan of a with the values of step 2 instead of those of a (AS, subnet, portal, pools); derived values (`derived_read_only`) never |
| 4 | SC-CAN: service connections new | export a | sync ✅ (crypto, IKE gateways, tunnels, QoS, SC, groups, traffic steering) | PSK: see 3.3 |
| 5 | RN-SPN: remote networks new, **old tunnel names** | export a | sync ✅ (crypto, IKE gateways, tunnels, QoS, bandwidth allocations, RN) | region / SPN names of b (bandwidth allocation per region may differ) |
| 6 | MU-SPN: mobile users new (all MU settings, identity objects, GP / PAA) | export a | sync ✅ (mobile-agent, identity), GP portal / clientless / PAA only internal UI API (read) | write of the internal-API parts (portal, PAA) - manual list in the report |
| 7 | explicit proxy (if there is one) | export a | read ✅ (internal UI API) | write - manual list in the report |
| 8 | objects / policies (config area) | export a | sync ✅ (`area=config`, `allow-network` for NGFW parts) | - |
| 9 | push in b, then **export b** | API b | export ✅, push: `scm-change` / UI | - |
| 10 | **check the tunnels**: per tunnel name old ↔ new | `ip-mapping.json` a and b, egress IPs a and b | `ip-mapping` ✅ (per RN / SC / MU location: Prisma Access + peer IPs) | compare by tunnel **name**: old egress / service IP → new one, tunnel state (up / down: live) |
| 11 | **report** | everything above | report generator (lifecycle concept) | migration report (3.2) |

### 3.2 Migration report

* per remote network / service connection: tunnel name, peer IP, old Prisma Access IP (egress / service IP of a) →
  new IP of b, PSK (same / new - never the value), state after the migration
* infrastructure: old → new (subnet, AS, portal host name, pools), the derived values of b (loopbacks, tunnel monitor)
* egress IPs: old list → new list (for the allow lists of the customer: SaaS, partners) - the existing compare of
  Egress IP between two tenants
* what was not migrated automatically (internal API parts, values PANW sets) - a checklist
* as document (Docs) and CSV per table

### 3.3 PSKs and secrets

* SCM tenants have their own master key: the exported PSKs (`-AQ==…`) usually can not be decrypted
  (`psk_current = DECRYPT_FAILED`) and can not be copied 1:1 into another tenant.
* Ways (existing on the CLI: `psk-list.csv` with `psk_new`, `scm_pa_secret_check.php`):
  1. the PSKs are known (peer firewalls) → filled in `psk_new`
  2. **new PSKs generated** per tunnel (random, length / characters as wanted) → in the plan and in the report
     (the report gets them only as a separate file for the customer, chmod 600, never in the project)
  3. later, per tunnel or a list of tunnels: set a new PSK by script (`scm-change` of the IKE gateway) - also after
     the migration
* in the viewer: the cleartext lists exist only in the folder of the run while it runs (as the egress key); the user
  gets them as a download once, then they are deleted.

## 4. Tenant sync (A ↔ B)

After a migration (or for lab / production): objects / policies of a with b, further areas when needed.

* compare a ↔ b: `scm_pa_compare.php` ✅ (name map for different names ✅)
* plan: `scm_pa_sync.php` ✅ - `additive` (a wins, nothing deleted), `mirror` (+ delete with `allow-delete`), `merge`
  (two plans, conflicts not sent)
* viewer: areas to sync chosen per project (config: containers / types; Prisma Access areas), the plan as a review
  per area, live compare before the upload (SCM_TAB.md); a run per direction
* recurring: as a scheduled run that only plans and reports (no write without review)

## 5. Panorama → SCM

Concept and tools: [todo/scm-panorama-migration.md](../../../todo/scm-panorama-migration.md) -
`scm_pa_panorama_to_change.php` ✅ + `scm_pa_change.php` ✅ (folders, snippets, objects, profiles, rules, zones,
interface variables), onboarding per firewall (planned), delta sync (planned: deletes by state file, renames, moves).

For the project type:

* sources: Panorama (import role source, XML API or file) and the SCM tenant (role target)
* **mapping** stored with the project: device-group → folder, template-stack / template → snippet (order of the
  snippets of a folder = order of the templates of the stack), shared → folder / snippet of choice; proposed from the
  names, changed by the consultant; used by every run (import, sync)
* views: per device-group / folder side by side (objects, rules, effective view of both), differences, what is
  missing in SCM; the firewalls with their folder / snippets / variables
* runs: import (change file → review → upload), sync (delta), onboarding per firewall

## 6. Order (proposal)

1. import scope of the SCM import (1) - small, helps every SCM project
2. roles of the binding + project type (2) - the base of the others
3. tenant migration (3): migration settings, transform, ip-mapping by tunnel name, report, PSK handling
4. tenant sync (4) in the viewer (the CLI exists)
5. Panorama → SCM (5): mapping in the project, views, runs
