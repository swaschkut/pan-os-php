# scm_pa_export.php – Prisma Access export (infrastructure, config, RN, SC, Mobile Users, Prisma Browser, IAM)

Downloads the Prisma Access configuration of one tenant (TSG) into a local directory, per **area**.
The export is the input for the later steps:

1. **export** (this script)
2. **compare** two exports offline (planned)
3. **import** into a new tenant in dependency order (planned)

| area | content |
|---|---|
| `infra` | Prisma Access infrastructure: infrastructure subnet, infra BGP AS, loopbacks, BGP routing, internal DNS servers, locations, egress IPs |
| `config` | folder / snippet hierarchy (with snippet order) and per container all objects, security profiles, rules (pre / post) and zones – stored at the owning container |
| `remote-networks` | IKE/IPsec crypto profiles, IKE gateways, IPsec tunnels, QoS profiles, bandwidth allocations, remote networks (RN / RN-SPN) |
| `service-connections` | IKE/IPsec crypto profiles, IKE gateways, IPsec tunnels, QoS profiles, service connections (SC-CAN), service connection groups, traffic steering rules |
| `mobile-users` | identity dependencies (certificates, trusted CAs, certificate / TLS service profiles, SAML / LDAP / RADIUS / TACACS+ / Kerberos server profiles, MFA servers, local users / groups, authentication profiles / sequences) and GlobalProtect (`/config/mobile-agent/v1/*`) |

| `prisma-browser` | Prisma Browser (`/seb-api/v1`): user / device groups, applications, application groups / plugins, sign-in / access-and-data / security / customization policy, pending draft changes |
| `iam` | IAM (`/iam/v1`): roles, custom roles, permission sets, service accounts, access policies, permissions – **documentation / compare only, not imported** |

Every export also writes `MIGRATION_CHECKLIST.md` (see below).

Next steps and the verification list for the first live run: [NEXT_STEPS_pa_export.md](NEXT_STEPS_pa_export.md).
Comparing two exports: [README_pa_compare.md](README_pa_compare.md); syncing differences: [README_pa_sync.md](README_pa_sync.md).
Step-by-step guide for consultants:
[CONSULTANT_GUIDE_pa_export_compare.md](CONSULTANT_GUIDE_pa_export_compare.md).

Not covered: Mobile Users Explicit Proxy (no documented public API), ZTNA connector (separate API), license
allocation – all three are listed in the migration checklist.

## Usage

```bash
php utils/develop/sase/scm/scm_pa_export.php in=scm-api://<TSG_ID>
php utils/develop/sase/scm/scm_pa_export.php in=scm-api://<TSG_ID> area=infra egressip
php utils/develop/sase/scm/scm_pa_export.php in=scm-api://<TSG_ID> outdir=/share/export egressip psk-list

# shortcuts
php utils/develop/sase/scm/scm_rn_export.php in=scm-api://<TSG_ID>     # area=remote-networks
php utils/develop/sase/scm/scm_sc_export.php in=scm-api://<TSG_ID>     # area=service-connections
php utils/develop/sase/scm/scm_mu_export.php in=scm-api://<TSG_ID>     # area=mobile-users
php utils/develop/sase/scm/scm_pb_export.php in=scm-api://<TSG_ID>     # area=prisma-browser
php utils/develop/sase/scm/scm_iam_export.php in=scm-api://<TSG_ID>    # area=iam
php utils/develop/sase/scm/scm_config_export.php in=scm-api://<TSG_ID> container="Mobile Users" config-types=addresses,security-rules
```

| argument | description |
|---|---|
| `in=scm-api://<TSG_ID>` | tenant; service account `client_id` / `client_secret` are taken from `~/.panconfkeystore` (`tsg_id<TSG_ID>`) or asked for and stored |
| `area=` | comma separated: `infra`, `config`, `remote-networks`, `service-connections`, `mobile-users`, `prisma-browser`, `iam`; default: all |
| `container=` | config: comma separated folder / snippet names (default: all containers; the hierarchy is always exported) |
| `config-types=` | config: comma separated types, e.g. `addresses,security-rules` (default: all) |
| `config-devices` | config: also device folders (type `cloud` / `on-prem`) |
| `config-predefined-snippets` | config: also predefined snippets (large) |
| `outdir=` | base directory, default `export` |
| `folder=` | SCM folder of the Remote Network IKE/IPsec objects, default `Remote Networks` |
| `sc-folder=` | SCM folder of the Service Connection IKE/IPsec/QoS objects, default `Service Connections` |
| `mu-folder=` | SCM folder of the Mobile Users identity / mobile-agent objects, default `Mobile Users` |
| `egressip` | also download egress IPs via the Prisma Access egress-IP API (`serviceType=all`) |
| `egressip-env=prod\|prod6` | egress-IP API host (`api.prod…` default, `api.prod6…` for some SCM tenants) |
| `psk-list` | write the secret lists with the decrypted values: `psk-list.csv` + `bgp-secret-list.csv` (RN, SC), `secret-list.csv` (MU) – see below |
| `master-key=` | master key to decrypt the secrets; default: PAN-OS default master key |
| `debugapi` | print every API call |

### Egress-IP API key

The egress-IP API (`getPrismaAccessIP/v2`) does not use OAuth but its own API key (`header-api-key`).
With `egressip` the key is taken from, in this order:

1. `~/.panconfkeystore` entry `egressip_tsg_id<TSG_ID>`
2. `api_key` of `shared-infrastructure-settings`, if the `infra` area is exported (used, not stored)
3. asked for once and stored as `egressip_tsg_id<TSG_ID>`

## Output

```
<outdir>/<TSG_ID>/<YYYYmmdd-HHMMSS>/
    manifest.json
    infra/
        01_shared-infrastructure-settings.json  /config/deployment/v1/shared-infrastructure-settings  (api_key redacted)
        02_bgp-routing.json                     /config/deployment/v1/bgp-routing
        03_internal-dns-servers.json            /config/deployment/v1/internal-dns-servers
        90_locations.json                       /config/deployment/v1/locations                       (context)
        92_egress-ip.json                       getPrismaAccessIP/v2, serviceType=all               (only with egressip)
    remote-networks/
        01_ike-crypto-profiles.json             /config/network/v1/ike-crypto-profiles?folder=Remote Networks
        02_ipsec-crypto-profiles.json           /config/network/v1/ipsec-crypto-profiles?folder=Remote Networks
        03_ike-gateways.json                    /config/network/v1/ike-gateways?folder=Remote Networks
        04_ipsec-tunnels.json                   /config/network/v1/ipsec-tunnels?folder=Remote Networks
        05_qos-profiles.json                    /config/network/v1/qos-profiles?folder=Remote Networks
        06_bandwidth-allocations.json           /config/deployment/v1/bandwidth-allocations
        07_remote-networks.json                 /config/deployment/v1/remote-networks
        ip-mapping.json / ip-mapping.csv
        psk-list.csv / bgp-secret-list.csv      (only with psk-list, chmod 600, cleartext)
    service-connections/
        01_ike-crypto-profiles.json             /config/network/v1/ike-crypto-profiles?folder=Service Connections
        02_ipsec-crypto-profiles.json           /config/network/v1/ipsec-crypto-profiles?folder=Service Connections
        03_ike-gateways.json                    /config/network/v1/ike-gateways?folder=Service Connections
        04_ipsec-tunnels.json                   /config/network/v1/ipsec-tunnels?folder=Service Connections
        05_qos-profiles.json                    /config/network/v1/qos-profiles?folder=Service Connections
        06_service-connections.json             /config/deployment/v1/service-connections
        07_service-connection-groups.json       /config/deployment/v1/service-connection-groups
        08_traffic-steering-rules.json          /config/deployment/v1/traffic-steering-rules
        ip-mapping.json / ip-mapping.csv
        psk-list.csv / bgp-secret-list.csv      (only with psk-list, chmod 600, cleartext)
    mobile-users/
        01_certificates.json                    /config/identity/v1/certificates?folder=Mobile Users
        02_trusted-certificate-authorities.json /config/identity/v1/trusted-certificate-authorities
        03_certificate-profiles.json            /config/identity/v1/certificate-profiles
        04_tls-service-profiles.json            /config/identity/v1/tls-service-profiles
        05_saml-server-profiles.json            /config/identity/v1/saml-server-profiles
        06_ldap-server-profiles.json            /config/identity/v1/ldap-server-profiles
        07_radius-server-profiles.json          /config/identity/v1/radius-server-profiles
        08_tacacs-server-profiles.json          /config/identity/v1/tacacs-server-profiles
        09_kerberos-server-profiles.json        /config/identity/v1/kerberos-server-profiles
        10_mfa-servers.json                     /config/identity/v1/mfa-servers
        11_local-users.json                     /config/identity/v1/local-users
        12_local-user-groups.json               /config/identity/v1/local-user-groups
        13_authentication-profiles.json         /config/identity/v1/authentication-profiles
        14_authentication-sequences.json        /config/identity/v1/authentication-sequences
        20_mobile-agent-infrastructure-settings.json  /config/mobile-agent/v1/infrastructure-settings?folder=Mobile Users
        21_mobile-agent-locations.json          /config/mobile-agent/v1/locations
        22_mobile-agent-authentication-settings.json  /config/mobile-agent/v1/authentication-settings
        23_mobile-agent-tunnel-profiles.json    /config/mobile-agent/v1/tunnel-profiles
        24_mobile-agent-agent-profiles.json     /config/mobile-agent/v1/agent-profiles
        25_mobile-agent-global-settings.json    /config/mobile-agent/v1/global-settings
        26_mobile-agent-agent-versions.json     /config/mobile-agent/v1/agent-versions
        27_mobile-agent-enable.json             /config/mobile-agent/v1/enable
        ip-mapping.json / ip-mapping.csv
        secret-list.csv                         (only with psk-list, chmod 600, cleartext)
    prisma-browser/                             https://api.sase.paloaltonetworks.com/seb-api/v1/...
        01_user-groups.json                     user-groups
        02_device-groups.json                   device-groups
        03_applications.json                    applications
        04_application-groups.json              application-groups
        05_application-plugins.json             applications/plugins
        06_policy-sign-in.json                  policy/sign-in
        07_policy-access-and-data.json          policy/access-and-data
        08_policy-security.json                 policy/security
        09_policy-customization.json            policy/customization
        90_pending-changes.json                 configuration-management/draft/pending-changes   (context)
    iam/                                        https://api.sase.paloaltonetworks.com/iam/v1/...
        01_roles.json                           roles
        02_custom-roles.json                    custom_roles
        03_permission-sets.json                 permission_sets
        04_service-accounts.json                service_accounts
        05_access-policies.json                 access_policies
        90_permissions.json                     permissions                                      (context)
        access-policies.csv
    config/
        01_folders.json                         /config/setup/v1/folders
        02_snippets.json                        /config/setup/v1/snippets
        hierarchy.json / hierarchy.txt
        folders/<container>/NN_<type>.json      ?folder=<container>   (only objects owned by <container>)
        snippets/<snippet>/NN_<type>.json       ?snippet=<snippet>
    MIGRATION_CHECKLIST.md
```

All `mobile-users` endpoints are queried with `?folder=Mobile Users` (`mu-folder=`). Identity objects defined in a
parent folder (e.g. `Prisma Access`, `All`) are reported as `inherited_or_predefined`.

* **Import order**: `infra` → `config` → `remote-networks` → `service-connections` → `mobile-users` → `prisma-browser`; `iam` is not imported (category `documentation`); inside an area the files `01`… are in import order
  (an entry only references entries with a lower number or of an earlier area).
  `manifest.json` lists the full order in `import_order` (`area/endpoint`).
* `infra/90_locations.json` is also fetched with `area=remote-networks` / `service-connections` / `mobile-users` alone (needed for the IP mapping);
  `manifest.json` marks it `fetched_as: context`.
* Every endpoint file keeps the API data (`data`) plus `endpoint`, `url`, `tsg_id`, `fetched_at`, `http_code`,
  `status`, `error`. Normalisation (dropping `id`, read-only fields, sorting) is done by compare/import.
* **Secrets are redacted** before writing: `shared-infrastructure-settings.api_key` → `***REDACTED***`
  (listed in the file under `redacted`). The value is only kept in memory for the egress-IP call.
* A failing endpoint does not stop the export; it is recorded with `status: error` in its file and in `manifest.json`.
  Prisma Browser and IAM endpoints are optional: HTTP 401/403/404 (product not licensed, no permission) gives
  `status: unavailable` and is listed under `unavailable`, not counted as error.

### manifest.json

`format_version` (6), `tool`, `areas`, `tsg_id`, `api_url`, `folders` (RN, SC, MU), `created_at`, `import_order`,
per-endpoint `area`/status/count/http_code, `infra` summary, `mobile_users` summary, `ip_mapping` (summary per area),
`secret_lists` (counts per area: `psk`, `bgp_secret`, `secret`), `prisma_browser`, `iam` and `config` summaries, `unavailable`,
`migration_checklist` and `import_hints` (each with `area`).

`mobile_users` summary (null without area `mobile-users`): `portal_hostname`, `ip_pools` per pool name,
`deployment_regions` (number of locations per region), number of `dns_servers`, `agent_profiles`, `tunnel_profiles`,
`authentication_profiles_used` (mobile-agent authentication settings), `authentication_profiles`, `certificates`,
number of `local_users`.

`infra` summary (null without area `infra`): `infrastructure_subnet`, `infrastructure_subnet_ipv6`, `ipv6`,
`infra_bgp_as`, `tunnel_monitor_ip_address`, `loopback_ips`, `bgp_routing` (routing preference, backbone routing,
accept route over SC, outbound routes for services, host route to IKE peer, withdraw static route),
`internal_dns_servers` (name, domain, primary, secondary), number of `locations`.

`import_hints`:

* `redacted` – secret fields not written to disk; tenant specific, never imported.
* `derived_read_only` – `loopback_ips`, `tunnel_monitor_ip_address`, `captive_portal_redirect_ip_address`,
  `egress_ip_notification_url`: derived by Prisma Access, compare only, not imported.
* `pre_shared_key` – IKE gateways using a PSK. No key value is written to the manifest; use `psk-list` for the import.
* `bgp_secret` – remote networks / service connections with a BGP authentication secret
  (`protocol.bgp.secret`, for service connections also `bgp_peer.secret`); see `bgp-secret-list.csv`.
* `intra_dependency` – service connections referencing another service connection as `backup_SC`: import all service
  connections without `backup_SC` first, then set it.
* `certificate_private_key` – certificates of the MU area: private keys are not exported by the API; import them
  manually (PKCS12 / PEM with key) on the target tenant before the mobile-agent settings.
* `secret` – MU passwords / shared secrets (see `secret-list.csv`).
* `owner_not_exported` – config: inherited objects whose owner container is not exported (predefined / filtered).
* `idp_synced_groups` – Prisma Browser user groups from an identity provider (not created by import).
* `unpublished_draft` – the source tenant has unpublished Prisma Browser changes (export = active configuration).
* `publish_required` – Prisma Browser import writes a draft, publish afterwards.
* `service_account_secret` / `iam_documentation` – IAM is documentation only; new service accounts on the target.
* `inherited_or_predefined` – entries not defined in the export folder itself (`snippet` set, e.g. `predefined`, or a
  parent folder). Import references them but does not create them.

### remote-networks/ip-mapping.json / ip-mapping.csv

One row per remote network:

| column | source |
|---|---|
| `region`, `spn_name`, `license_type`, `ipsec_tunnel`, `secondary_ipsec_tunnel` | remote network |
| `service_ip_address`, `fqdn`, `loopback_ip_address` | remote network `details` (Prisma Access side) |
| `bgp_*` | remote network `protocol.bgp` |
| `branch_peer_address` | remote network → IPsec tunnel → IKE gateway `peer_address` (branch side) |
| `location_display`, `egress_ip_addresses`, `egress_match` | region → `infra/90_locations.json` `value/region` → `display` → egress-IP `zone`; only addresses with `serviceType=remote_network` |

`egress_match: none` means no automatic match; check `infra/92_egress-ip.json`.
`egress_zones_without_remote_network` lists egress zones no remote network was mapped to.

A new tenant gets new Prisma Access IPs, so this file is also the checklist for the branch firewall changes
(peer address, allow lists).

### service-connections/ip-mapping.json / ip-mapping.csv

One row per service connection:

| column | source |
|---|---|
| `region`, `onboarding_type`, `ipsec_tunnel`, `secondary_ipsec_tunnel`, `backup_SC` | service connection |
| `subnets`, `nat_pool`, `source_nat`, `qos_profile` (only if `qos.enable`), `no_export_community` | service connection |
| `bgp_*` | service connection `protocol.bgp` |
| `bgp_peer_*` | service connection `bgp_peer` (local / peer IPv4 and IPv6) |
| `peer_address` | service connection → IPsec tunnel → IKE gateway `peer_address` (data center / CAN side) |
| `location_display` | region → `infra/90_locations.json` → `display` |

The egress-IP API has no service type for service connections, so there are no egress columns.

### <area>/psk-list.csv

One row per IKE gateway with a pre-shared key (`remote-networks` and `service-connections`):

| column | content |
|---|---|
| `ike_gateway` | gateway name – key for the import |
| `ipsec_tunnel`, `remote_network` / `service_connection`, `branch_peer_address` / `peer_address` | context only, to find the right key |
| `psk_current` | decrypted PSK from the export (`PanosCrypto`, default or `master-key=`); `DECRYPT_FAILED` if not possible |
| `psk_new` | empty – fill in to set a new PSK on the target tenant |

Import rule (`SCMPrismaAccessExport::loadPSKList()`): `psk_new` if filled, otherwise `psk_current`.
`psk_new` is optional. A gateway with empty `psk_new` and empty / `DECRYPT_FAILED` `psk_current`, or a duplicate
gateway name, is reported as error, so the import can stop in dry-run before creating anything.
Values are used exactly as written (no trimming). Gateways using certificates are not listed.

The file holds cleartext secrets: it is created with mode 0600, is not referenced by name in `manifest.json`
(only counts under `psk_list`) and should be kept out of git and tickets. Rotate keys if it leaks.

Note: `PanosCrypto::decrypt()` returns `""` instead of throwing on a wrong master key; the export treats an empty
result as `DECRYPT_FAILED`.

### <area>/bgp-secret-list.csv

One row per connection and BGP secret field:

| column | content |
|---|---|
| `object` | remote network / service connection name |
| `field` | `protocol.bgp.secret` or `bgp_peer.secret` |
| `bgp_peer_ip_address` | context only |
| `secret_current` | decrypted secret; `DECRYPT_FAILED` if not possible |
| `secret_new` | empty – fill in to set a new secret on the target tenant |

Import rule (`SCMPrismaAccessExport::loadBGPSecretList()`, key `object|field`): `secret_new` if filled, otherwise
`secret_current`; same error handling and file protection as `psk-list.csv`.

### mobile-users/ip-mapping.json / ip-mapping.csv

One row per MU location (`mobile-agent-infrastructure-settings` → `deployment.region[].locations[]`, fallback
`mobile-agent-locations`): `deployment_region`, `location`, `location_display`, `gp_gateway_active`,
`gp_gateway_pre_allocated`, `gp_portal_active`, `gp_portal_pre_allocated`, `egress_match`.
The egress IPs come from `infra/92_egress-ip.json` (`address_details` with `serviceType` `gp_gateway` / `gp_portal`,
split by `addressType`); the JSON also holds `portal_hostname`. A new tenant gets new GlobalProtect IPs – allow lists
of SaaS applications and partners have to be updated.

### mobile-users/secret-list.csv

Generic list of all secret fields found in the MU area – one row per value:

| column | content |
|---|---|
| `endpoint`, `object`, `path` | where the value is, e.g. `ldap-server-profiles`, `AD`, `bind_password` |
| `secret_current` | decrypted value (`-…` master-key format), `HASHED` for hashes (`$…`, e.g. local user passwords), `DECRYPT_FAILED`, or the value as returned |
| `secret_new` | empty – fill in for the target tenant |

Detected: fields named `secret`, `password`, `passwd`, `passphrase`, `key` or `*_password` / `*_secret` / `*_key`
(except `public_key`, `key_type`, `key_size`, `key_usage`), and name/value entries like
`gp_app_config.config[]` whose name contains `password`, `passcode`, `override-key` or `secret`.

Import rule (`SCMPrismaAccessExport::loadSecretList()`, key `endpoint|object|path`): `secret_new` if filled, otherwise
`secret_current`; `HASHED` and `DECRYPT_FAILED` require `secret_new`. Same file protection as `psk-list.csv`.

### config

**Hierarchy.** `config/hierarchy.json` is built from `/config/setup/v1/folders` and `/config/setup/v1/snippets`:
folders in depth-first order with `parent`, `depth`, `path` (root → folder), `snippets` (attached snippets **in API
order**), `children` and `inheritance_chain` (for every level root → folder: the folder, then its snippets in order).
Snippets list `attached_to` (folder + position). `hierarchy.txt` shows the same as an indented tree. Folders are
ordered by parent, independent of the response order.

**Owned objects only.** A query for a container also returns the objects of its parent folders and attached snippets.
Every object is stored only at its owner (field `snippet`, else `folder` of the object): in
`folders/<container>/` or `snippets/<snippet>/` (`<container>` with unsafe characters replaced by `_`). Each file
contains `container`, `container_kind`, `inherited_skipped` (objects of other owners in that answer) and `data`
(owned objects). Objects without owner field are kept. Inherited objects whose owner is not exported (predefined
snippet, `container=` filter, device folders, predefined snippets) are counted per owner in
`manifest.json` → `config.owners_not_exported` (each object once).

**Containers.** Folders of type `container` (devices with `config-devices`), then snippets (predefined ones with
`config-predefined-snippets`). **Types** (pan.dev, not pan-os-php's own list – so the verification can find gaps):
`variables`, tags, addresses, address groups, regions, services, service groups, schedules, external dynamic lists,
dynamic user groups, applications, application filters / groups, URL categories, HIP objects / profiles, HTTP / syslog
server profiles, log forwarding profiles, auto-tag actions, zone protection profiles, zones, security profiles
(anti-spyware, vulnerability, WildFire / AV, DNS security, file blocking, URL access, decryption, SaaS, AI), profile
groups, and the rule bases security / decryption / authentication / app-override / QoS as `-pre` and `-post`. A type
that answers 401/403/404 is `unavailable` (`config.types_unavailable`), not an error.

`manifest.json` → `config`: number of folders / snippets, exported containers, owned objects per type and per
container, `owners_not_exported`, `types_unavailable`, options.

### prisma-browser

Lists use cursor pagination (`limit=1000`, `cursor` from `pageInfo`); the four policies are single objects with
`rules` and `sections`. The export reads the active configuration. Catalog applications are predefined
(`inherited_or_predefined`), IdP-synced user groups need the IdP integration on the target tenant. After an import the
draft must be published (`POST /seb-api/v1/configuration-management/draft/publish`); logos / assets are not exported.

### iam/access-policies.csv

One row per access policy: `principal`, `principal_type`, `role`, `resource`, plus empty `principal_new` /
`resource_new` to fill in for the target tenant (principals and the TSG in `resource` differ). Service account secrets
cannot be read – create new service accounts on the target tenant and update `.panconfkeystore` / automation.

### MIGRATION_CHECKLIST.md

Generated from the export (hints, counts, failed / unavailable endpoints) plus fixed items, sorted by status
`action_required` → `check` → `info`. Also in `manifest.json` as `migration_checklist`
(`id`, `status`, `area`, `title`, `detail`, `objects`). Items include: license / units (with the source RN bandwidth),
export errors, secrets (PSK, BGP, MU), certificates with private key, new IPs for branch / DC / allow lists,
`backup_SC`, ZTNA connector, Explicit Proxy, CIE / logging, objects / policies, Prisma Browser publish, IAM, push.

### Explicit Proxy

There is no documented public API for Mobile Users Explicit Proxy (only the admin guide). Next step: capture the
internal SCM API calls of the Explicit Proxy pages (browser developer tools / network log) and add them as an area
marked `internal`. Until then it is a manual item in the migration checklist.

## Connector changes (`lib/misc-classes/PanSCMAPIConnector.php`)

* `sendSCMAPIRequest($method, $url, $body = false, $exitOnError = TRUE)` now returns
  `['http_code', 'response', 'json', 'errors']` and sets `Content-Type: application/json` when a body is sent.
  Default behaviour (derr on `_errors`) is unchanged.
* `getSCMResourceAll($url_config, $limit = 200)` – GET with limit/offset pagination, returns errors instead of exiting;
  handles single-object endpoints (`is_list = false`). If the first page fails with HTTP 400/403, the request is
  repeated once without `limit`/`offset` (some deployment endpoints answer "Access denied" to them).
* `getSCMResourceAll()` also accepts an absolute URL (other host, e.g. `https://api.sase.paloaltonetworks.com/iam/v1/...`).
* `getCursorResourceAll($url, $limit = 1000)` – cursor pagination (list in `data` / `items` / `results`, next cursor in
  `pageInfo.nextCursor` / `endCursor` / `cursor` or `next_cursor`, stops on `hasNextPage = false`).
* `getEgressIPApiKey($TSGid)` / `getPrismaAccessEgressIP($apiKey, $serviceType, $addrType, $location, $environment)`.
* Keystore lookup in `findOrCreateConnectorFromHost()` (SCM and SASE) now matches `tsg_id<TSG>` only at the start of
  the entry, so the `egressip_tsg_id<TSG>` entry is never taken as OAuth credential.

## To verify against a live tenant

* `internal-dns-servers` field names (`domain_name`, `primary`, `secondary`) and `bgp-routing` field names.
* Whether `api_key` of `shared-infrastructure-settings` is accepted by the egress-IP API.
* Which deployment endpoints really need the limit/offset fallback (`debugapi` shows the retry).
* `pre_shared_key` format returned by `ike-gateways`.
* Whether `remote-networks` and `bandwidth-allocations` need a `folder` parameter in your tenant.
* Region → location → egress zone matching (`egress_match`).
* `service-connections` / `service-connection-groups` / `traffic-steering-rules` field names; whether
  `service-connections` needs a `folder` parameter.
* `qos-profiles` endpoint path (`/config/network/v1/qos-profiles`) for folder `Service Connections`.
* BGP secret format (`protocol.bgp.secret`, `bgp_peer.secret`) – same master-key encryption as the PSK?
* `mobile-users`: whether identity endpoints return objects of parent folders with `folder=Mobile Users`;
  whether `agent-versions` / `enable` / `global-settings` accept the `folder` parameter; structure of
  `mobile-agent/locations`; which secret fields the API really returns (bind password, RADIUS secret, GP app passwords).
* Whether egress-IP `addrType=all` includes pre-allocated GlobalProtect addresses.
* `remote-networks/qos-profiles` path for folder `Remote Networks`.
* Prisma Browser: OAuth token of the SCM service account accepted on `api.sase…/seb-api`; `pageInfo` cursor field
  name; whether the policy GETs need `configurationVersion=active`; user group `source` / application `type` values.
* config: which types answer 404 in your tenant; whether objects of the queried container always carry `folder` /
  `snippet`; rule `position` values; how predefined objects are marked.
* IAM: `custom_roles` / `permission_sets` paths (derived from the doc structure), access policy field names
  (`principal`, `role`, `resource`), list format / pagination of the IAM endpoints.

## Endpoint metadata

`ENDPOINT_META` / `endpointMeta()` in `lib/SCMPrismaAccessExport.php` describe per endpoint the identity key,
singleton, ignored / secret fields, ordered lists, references and write mode – used by `scm_pa_compare.php` and the
planned sync, see [README_pa_compare.md](README_pa_compare.md#endpoint-metadata).

## Code

* `scm_pa_export.php` – CLI; `scm_rn_export.php` / `scm_sc_export.php` / `scm_mu_export.php` / `scm_pb_export.php` /
  `scm_iam_export.php` / `scm_config_export.php` – wrappers with one area
* `lib/SCMPrismaAccessExport.php` – export logic; area/endpoint list in `getAllEndpoints()`, connection areas
  (folder, connection endpoint) in `CONNECTION_AREAS`; results are keyed `area/endpoint`
  (`SCMRemoteNetworkExport` remains as class alias)
