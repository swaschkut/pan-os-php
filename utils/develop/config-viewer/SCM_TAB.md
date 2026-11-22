# config viewer: SCM tab (Prisma Access, Identity, CIE, …) - concept

Status: concept 2026-11-22 (agreed with Sven). Built: Prisma Access > Egress IP (CLI `scm_egress_ip.php` + library
`SCMEgressIP`), the other Prisma Access pages and Service accounts (see below). The rest is in `TODO.md` ("SCM tab").

## Goal

A project gets a tab **SCM** next to the configurations - for the Strata Cloud Manager tenant (TSG) the project is
about. The configuration itself (folders, snippets, objects, rules, variables, device settings) stays where it is
today: an SCM configuration version of the project, shown like Panorama / firewall (Location = folder / snippet,
effective view, System settings). The tab is for everything that is **not** the object configuration: Prisma Access
infrastructure and connections, identity, deployment, licences, monitoring.

## Menu (left side of the tab)

| section | entries | source (scm_pa_export / script) |
|---|---|---|
| **Prisma Access** | Egress IP | `infra/92_egress-ip.json` (egress-IP API), `scm_egress_ip.php` |
| | Infrastructure | `infra/*` (shared-infrastructure-settings, …) |
| | Service Connection | `service-connections/*`, IP mapping |
| | Remote Networks (RN-SPN) | `remote-networks/*`, IP mapping |
| | Mobile User Gateway | `mobile-users/*` (gateways / locations) |
| | Mobile User GlobalProtect | `mobile-users/*` |
| | Mobile User PAA | `mobile-users/*` (agent) |
| | Mobile User Explicit Proxy | `explicit-proxy/*` |
| | Prisma Browser | `prisma-browser/*` |
| **Identity & Access** | Service accounts | `iam/*` (`scm_iam_export.php`) - never a secret |
| **Cloud Identity Engine (CIE)** | (later) | CIE API |
| **Configuration** | Config versions and push status | `scm_config-versions.php` |
| | Variables | folder / snippet / device (pan-os-php `DeviceVariables`, already in the configuration) |
| **Deployment** | Locations, bandwidth, BGP, traffic steering | `scm_deployment_*.php` |
| **Tenant** | Trusted tenants | `scm_trusted_tenants.php` |
| | Licences and instances | `instances.php` |
| **Monitoring** | Insights | `insights.php` |
| | Audit logs (snippets) | `scm_snippets_audit_logs.php` |
| **Best practice** | BPA | `scm_bpa.php` |

Folders / snippets / hierarchy are not a menu entry here: they are the SCM configuration version of the project
(Location, hierarchy window, effective view).

## Data

1. **The SCM import of the project** (Configurations: import with the SCM key of the user, service account + TSG, as
   the XML API import of Panorama / firewall) - it runs `scm_pa_export.php area=config,<areas of the pages>`; the
   config area becomes the Buckbeak XML (objects / policies), the other areas a state of their Prisma Access page -
   as the SCM API gives them (only what scm_pa_export.php itself redacts: api_key of shared-infrastructure-settings).
   The egress-IP API key (that api_key) goes into the key store of the user (kind egress IP, target TSG):
   `scm_pa_export.php egressip-key-out=<file>`.
   With that key the import reads the egress IPs as well (`egressip egressip-env=auto`: prod8, on HTTP 401 / 403
   prod6, then prod; any other environment prod<N> can be given): a state of Prisma Access > Egress IP (source "SCM import", the environment that answered).
2. **Live refresh** - a button per page: the same call as the export, with the personal key of the user (key store,
   kind SCM / egress IP; network for runs per user, as today). The result is a new version of that area.
3. **Compare** - every page shows what changed between two versions (default: the last import against the live
   refresh): added / removed / changed entries. For the egress IPs: new and removed addresses per service type and
   location (`SCMEgressIP::compare`).
4. Later: an **as-is report** of the pages (export documentation).

## Binding of a project

The first import / read from an API binds the project (shown next to its name):

- a firewall / Panorama (XML API) -> **PAN-OS**: imports with an SCM key are refused, no SCM tab;
- an SCM tenant -> **SCM, TSG <id>**: imports / SCM tab reads / egress IPs only for this TSG (keys of other tenants are
  not offered, a file of egress IPs of another TSG is refused), no import from a firewall / Panorama.

Projects that existed before: bound by the runs they have done when these agree (all PAN-OS or one tenant). An
administrator can release the binding ("Release binding"; the next import binds again).

## Filling the pages

- **From the SCM imports** (button on top of the tab): the Prisma Access pages and Egress IP from the SCM imports /
  reads of the project whose export is still there. Imports before 2.1.63 read only the configuration (area config) -
  for them "Read all live".
- **Read all live**: one run with the SCM key of the user - every area of the pages and the egress IPs (as the import,
  without the configuration).

## Changes (setter) - only through compare and change

Nothing is written to SCM directly from the viewer (neither the SCM API nor the internal API). The way is the one of
`scm_pa_compare.php` / `scm_pa_change.php`:

1. a change in a page (setter) goes into a **change file** of the project (one per area);
2. **review**: every area is checked and approved by a reviewer (like the review of action classes) before it can be
   uploaded;
3. **live compare before the upload**: right before the upload the areas that are changed are read live again and
   compared with the state the change was made on - a conflict (e.g. an address object of the same name created in the
   meantime, an entry changed by someone else) stops the upload of that area;
4. **upload** with `scm_pa_change.php` (dry run first, then apply), the result and the new state as a new version.

## Rules

- personal keys only (SCM: client id / secret; egress IP: header-api-key), encrypted, never back to the browser, never
  in the audit log; read only import is the default ("nur import");
- the pages show what the SCM API gives (encrypted PSKs / secrets as the API returns them); the cleartext lists of
  the export (psk-list) are not used; the egress-IP API key only in the key store of the user (encrypted, never shown);
- every script works on the CLI the same way (one method for CLI and viewer).

## Egress IP (built)

CLI: `php utils/develop/sase/scm/scm_egress_ip.php tsg=<TSG> [servicetype=all] [addrtype=all] [location=all]
[env=prod8|prod6|prod|prod<N>] [option=option.txt] [format=table|csv|json|list] [out=file] [save=snapshot.json]
[compare=previous.json|export-dir] [in=export-dir|92_egress-ip.json]`

- `option=` reads the request body of the Palo Alto documentation ("API examples for retrieving Prisma Access IP
  addresses": a `.txt` file with `{"serviceType": "...", "addrType": "...", "location": "..."}`); arguments override it;
- `in=` works offline on an export (`infra/92_egress-ip.json`) or a saved snapshot;
- `compare=` shows added / removed addresses against a snapshot or export;
- `format=list`: one address per line (e.g. as an external dynamic list).

Values (documentation): serviceType `all`, `gp_gateway` (mobile users), `gp_portal`, `remote_network`, `clean_pipe`,
`swg_proxy` (explicit proxy: egress IPs, authentication cache service, network load balancers), `rbi`; addrType `all`,
`active` (and the special types of swg_proxy); location `all`, `deployed` (gp_gateway; not for remote_network /
clean_pipe).

Viewer (built): project tab SCM > Prisma Access > Egress IP - import (zip of an export: only infra/92_egress-ip.json is
read; the file; a snapshot; the answer of the API), "Read live" (run egress-ip with the egress-IP key of the user - kind
egress IP, target TSG; network: tsg:<TSG> on the allow list, network of the project on), the states with their rows,
compare with the state before, filter, address list / CSV download. States: projects/<pid>/scm/egress/<id>.json.

## Prisma Access pages from scm_pa_export.php (built: Infrastructure)

A page shows endpoints of one area of `scm_pa_export.php` (`ViewerApp::SCM_PA_PAGES`, `SCM_PA_VIEWS` of app.js):

| page | area | endpoints |
|---|---|---|
| Infrastructure | infra | shared-infrastructure-settings, bgp-routing, internal-dns-servers, locations |
| Service Connection | service-connections | all of the area (IKE / IPSec crypto, IKE gateways, IPSec tunnels, QoS, service connections, groups, traffic steering) |
| Remote Networks (RN-SPN) | remote-networks | all of the area (crypto, IKE gateways, IPSec tunnels, QoS, bandwidth allocations, remote networks) |
| Mobile User Gateway | mobile-users | mobile-agent infrastructure settings, locations, enable |
| Mobile User GlobalProtect | mobile-users | authentication settings, tunnel / agent profiles, global settings, agent versions, GP portal, clientless apps / groups, trusted zones, identity objects of the folder |
| Mobile User PAA | mobile-users | pa-agent-* (internal UI API) |
| Mobile User Explicit Proxy | explicit-proxy | all of the area (internal UI API) |
| Prisma Browser | prisma-browser | all of the area |
| Service accounts (Identity & Access) | iam | all of the area |

- **States**: from the SCM import of the project (`scm-export area=config,infra`) and from "Read live" (run `scm-pa`:
  `pan-os-php type=scm-export in=scm-api://<TSG> area=<area>` with the SCM key of the user - network as for an import,
  `tsg:<TSG>` on the allow list, network of the project on). A state = the files of the endpoints of the page + a
  manifest (`projects/<pid>/scm/pa/<page>/<id>/`), as the SCM API gave them. A live read of a page gives a state to
  every page of its area (mobile-users: Gateway, GlobalProtect, PAA).
- **View**: one state - an object as setting / value, a list as a table (a filter field under every header, sort).
- **Compare** (button tab): two states with `SCMPrismaAccessCompare` - the same as `scm_pa_compare.php` on the CLI:
  added / removed entries (by their key field), changed fields (path: old -> new).
- the internal UI API (PAA, explicit proxy, GP portal / clientless) is region specific: scm_pa_export.php
  `ui-api-host=` (default the EU host); otherwise these endpoints are "not available".
