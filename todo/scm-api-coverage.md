# SCM API – single scripts vs. integrated scm types

**Status:** inventory (2026-11-17), decisions open
**Code reference:** `alpha` `fa46d1b`
**Single scripts** (one pan.dev endpoint each): `utils/develop/sase/scm/scm_*.php`, `utils/develop/sase/prisma_access/*.php`
**Integrated:** `type=scm-export|scm-xml-to-change|scm-change|scm-panorama-to-change|scm-compare|scm-sync|scm-report`
(`utils/develop/sase/scm/scm_pa_*.php`, `utils/develop/sase/scm/lib/SCMPrismaAccess*.php`), `in=scm-api://`
(`lib/misc-classes/PanSaseAPIConnector.php`)

How the list was built: the endpoint strings of every file compared with the export / sync classes – a code inventory,
not a run against a tenant (live verification of the export: [scm-pa-export-next-steps.md](scm-pa-export-next-steps.md)).

## 1. Former TODO items "SCM API"

| Item | Endpoint | Status | Where |
|---|---|---|---|
| Prisma Access public IPs | `getPrismaAccessIP/v2` (egress-IP API, `header-api-key`) | **done** | `scm-export` area `infra`, file `92_egress-ip.json` (argument `egressip-env=`, API key) |
| config versions | `/config/operations/v1/config-versions` | partial | `scm-sync` pushes (`config-versions/candidate:push`); a list only in the single script `scm_config-versions.php` |
| jobs | `/config/operations/v1/jobs` | partial | `scm-sync` polls the push job by id (`jobs/<id>`); listing jobs: not implemented |
| snippet audit logs | `/config/setup/v1/snippet-audit-logs` | single script only | `scm_snippets_audit_logs.php` |

## 2. Single scripts covered by `scm-export` (same endpoint / resource)

| Single script | Endpoint / resource | In `scm-export` |
|---|---|---|
| `scm_deployment_bandwidth.php` | `/config/deployment/v1/bandwidth-allocations` | yes |
| `scm_deployment_bgp.php` | `/config/deployment/v1/bgp-routing` | yes |
| `scm_deployment_locations.php` | `/config/deployment/v1/locations` | yes |
| `scm_deployment_rn.php` | `/config/deployment/v1/remote-networks` | yes |
| `scm_deployment_sc.php` | `/config/deployment/v1/service-connections` | yes |
| `scm_deployment_shared-infra.php` | `/config/deployment/v1/shared-infrastructure-settings` | yes |
| `scm_deployment_traffic-steering.php` | `/config/deployment/v1/traffic-steering-rules` | yes |
| `scm_mobile-agent_infra.php`, `_locations.php`, `_tunnel.php` | `/config/mobile-agent/v1/infrastructure-settings`, `locations`, `tunnel-profiles` | yes |
| `scm_folders.php`, `scm_snippets.php`, `scm_variables.php` | `/config/setup/v1/folders`, `snippets`, `variables` | yes |
| `scm_security-service_url-access.php` | `/config/security/v1/url-access-profiles` | yes (also `in=scm-api://`) |
| `prisma_access/pa_auth.php` | authentication portals / profiles / sequences, SAML server profiles | yes |
| `prisma_access/pa_cert.php` | certificates, certificate profiles | yes |
| `prisma_access/pa_folders.php`, `pa_infra.php` | folders, shared infrastructure settings | yes |
| `prisma_access/pa_mu.php` | mobile agent: agent profiles, global settings, infrastructure settings, locations, … | yes |
| `prisma_access/pa_rn.php`, `pa_sc.php` | remote networks; service connections, BGP routing, IPsec / IKE | yes |
| `prisma_access/sase.php` | older Prisma Access config API `api.sase.paloaltonetworks.com/sse/config/v1` (token, config versions running) | replaced by the SCM API |

## 3. Only in single scripts (not integrated)

| Single script | Endpoint | Note |
|---|---|---|
| `scm_config-versions.php` | `/config/operations/v1/config-versions` | list of versions |
| `scm_snippets_audit_logs.php` | `/config/setup/v1/snippet-audit-logs` | |
| `scm_shared_snippets.php` | `/config/setup/v1/shared-snippets` | |
| `scm_trusted_tenants.php` | `/config/setup/v1/trusted-tenant-overview` | multi-tenant |
| `scm_deployment_sites.php` | `/config/deployment/v1/sites` | the other `deployment/v1` endpoints are in `scm-export` |
| `scm_fetch-confg.php` | `fetch-scm-config` (`/config/v1/operations/…`, `/api/sase/config/v1/…`, `/api/migration/v1/customer/…`) | migration / internal endpoints |
| `scm_bpa.php` | `api.stratacloud.paloaltonetworks.com/aiops/bpa/v1/requests` | AIOps BPA – another API |
| – | `/config/operations/v1/jobs` (list) | no script |

## 4. Helpers, not API coverage

* `scm_mu_export.php`, `scm_rn_export.php`, `scm_sc_export.php`, `scm_pb_export.php`, `scm_iam_export.php`,
  `scm_config_export.php`: shortcuts for `scm_pa_export.php area=…`
* `scm_internal_api_probe.php`, `scm_internal_api_get.php`: read-only checks of the internal SCM UI API (used by the
  export for areas without public API)
* `scm_pa_secret_check.php`: offline check of the secret lists of an export

## 5. Proposal

1. read-only operations data: config versions (running / candidate / history), jobs (last n), snippet audit logs –
   as an `scm-export` area (e.g. `area=operations`) or as a section of `scm-report`
2. add `/config/deployment/v1/sites`, `/config/setup/v1/shared-snippets` and `trusted-tenant-overview` to the matching
   `scm-export` areas
3. superseded single scripts (section 2): decide what happens with them
4. `fetch-scm-config`, AIOps BPA: decide whether they are in scope

## Open decisions

* superseded single scripts: delete, move to an archive folder, or keep as minimal examples
* operations data: `scm-export` area or `scm-report` section – and the area name
* `fetch-scm-config` / AIOps BPA: keep standalone, integrate, or drop
