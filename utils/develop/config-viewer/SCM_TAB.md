# config viewer: SCM tab (Prisma Access, Identity, CIE, …) - concept

Status: concept 2026-11-22 (agreed with Sven), first part built: egress IP (CLI `scm_egress_ip.php` + library
`SCMEgressIP`). The rest is in `TODO.md` ("SCM tab").

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

1. **Import of an export** - a `scm_pa_export.php` directory (zip) is imported into the project, versioned like
   configurations (each import is a version; secrets of the export - PSK lists, keys - are never imported).
2. **Live refresh** - a button per page: the same call as the export, with the personal key of the user (key store,
   kind SCM / egress IP; network for runs per user, as today). The result is a new version of that area.
3. **Compare** - every page shows what changed between two versions (default: the last import against the live
   refresh): added / removed / changed entries. For the egress IPs: new and removed addresses per service type and
   location (`SCMEgressIP::compare`).
4. Later: an **as-is report** of the pages (export documentation).

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
- secrets of the export (PSK, BGP secrets, API keys) are never shown or stored in the project;
- every script works on the CLI the same way (one method for CLI and viewer).

## Egress IP (built)

CLI: `php utils/develop/sase/scm/scm_egress_ip.php tsg=<TSG> [servicetype=all] [addrtype=all] [location=all]
[env=prod|prod6] [option=option.txt] [format=table|csv|json|list] [out=file] [save=snapshot.json]
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
