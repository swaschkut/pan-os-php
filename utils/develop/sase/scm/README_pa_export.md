# scm_pa_export.php – Prisma Access export (infrastructure, Remote Networks, Service Connections)

Downloads the Prisma Access configuration of one tenant (TSG) into a local directory, per **area**.
The export is the input for the later steps:

1. **export** (this script)
2. **compare** two exports offline (planned)
3. **import** into a new tenant in dependency order (planned)

| area | content |
|---|---|
| `infra` | Prisma Access infrastructure: infrastructure subnet, infra BGP AS, loopbacks, BGP routing, internal DNS servers, locations, egress IPs |
| `remote-networks` | IKE/IPsec crypto profiles, IKE gateways, IPsec tunnels, bandwidth allocations, remote networks (RN / RN-SPN) |
| `service-connections` | IKE/IPsec crypto profiles, IKE gateways, IPsec tunnels, QoS profiles, service connections (SC-CAN), service connection groups, traffic steering rules |

Mobile Users follow as a further area.

## Usage

```bash
php utils/develop/sase/scm/scm_pa_export.php in=scm-api://<TSG_ID>
php utils/develop/sase/scm/scm_pa_export.php in=scm-api://<TSG_ID> area=infra egressip
php utils/develop/sase/scm/scm_pa_export.php in=scm-api://<TSG_ID> outdir=/share/export egressip psk-list

# shortcuts
php utils/develop/sase/scm/scm_rn_export.php in=scm-api://<TSG_ID>     # area=remote-networks
php utils/develop/sase/scm/scm_sc_export.php in=scm-api://<TSG_ID>     # area=service-connections
```

| argument | description |
|---|---|
| `in=scm-api://<TSG_ID>` | tenant; service account `client_id` / `client_secret` are taken from `~/.panconfkeystore` (`tsg_id<TSG_ID>`) or asked for and stored |
| `area=` | comma separated: `infra`, `remote-networks`, `service-connections`; default: all |
| `outdir=` | base directory, default `export` |
| `folder=` | SCM folder of the Remote Network IKE/IPsec objects, default `Remote Networks` |
| `sc-folder=` | SCM folder of the Service Connection IKE/IPsec/QoS objects, default `Service Connections` |
| `egressip` | also download egress IPs via the Prisma Access egress-IP API (`serviceType=all`) |
| `egressip-env=prod\|prod6` | egress-IP API host (`api.prod…` default, `api.prod6…` for some SCM tenants) |
| `psk-list` | per connection area write `psk-list.csv` and `bgp-secret-list.csv` with the decrypted values (see below) |
| `master-key=` | master key to decrypt PSKs and BGP secrets; default: PAN-OS default master key |
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
        05_bandwidth-allocations.json           /config/deployment/v1/bandwidth-allocations
        06_remote-networks.json                 /config/deployment/v1/remote-networks
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
```

* **Import order**: `infra` → `remote-networks` → `service-connections`; inside an area the files `01`… are in import order
  (an entry only references entries with a lower number or of an earlier area).
  `manifest.json` lists the full order in `import_order` (`area/endpoint`).
* `infra/90_locations.json` is also fetched with `area=remote-networks` / `service-connections` alone (needed for the IP mapping);
  `manifest.json` marks it `fetched_as: context`.
* Every endpoint file keeps the API data (`data`) plus `endpoint`, `url`, `tsg_id`, `fetched_at`, `http_code`,
  `status`, `error`. Normalisation (dropping `id`, read-only fields, sorting) is done by compare/import.
* **Secrets are redacted** before writing: `shared-infrastructure-settings.api_key` → `***REDACTED***`
  (listed in the file under `redacted`). The value is only kept in memory for the egress-IP call.
* A failing endpoint does not stop the export; it is recorded with `status: error` in its file and in `manifest.json`.

### manifest.json

`format_version` (3), `tool`, `areas`, `tsg_id`, `api_url`, `folders` (per connection area), `created_at`, `import_order`,
per-endpoint `area`/status/count/http_code, `infra` summary, `ip_mapping` (summary per area), `secret_lists`
(counts per area: `psk`, `bgp_secret`) and `import_hints` (each with `area`).

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

## Connector changes (`lib/misc-classes/PanSCMAPIConnector.php`)

* `sendSCMAPIRequest($method, $url, $body = false, $exitOnError = TRUE)` now returns
  `['http_code', 'response', 'json', 'errors']` and sets `Content-Type: application/json` when a body is sent.
  Default behaviour (derr on `_errors`) is unchanged.
* `getSCMResourceAll($url_config, $limit = 200)` – GET with limit/offset pagination, returns errors instead of exiting;
  handles single-object endpoints (`is_list = false`). If the first page fails with HTTP 400/403, the request is
  repeated once without `limit`/`offset` (some deployment endpoints answer "Access denied" to them).
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

## Code

* `scm_pa_export.php` – CLI; `scm_rn_export.php` / `scm_sc_export.php` – wrappers with `area=remote-networks` /
  `area=service-connections`
* `lib/SCMPrismaAccessExport.php` – export logic; area/endpoint list in `getAllEndpoints()`, connection areas
  (folder, connection endpoint) in `CONNECTION_AREAS`; results are keyed `area/endpoint`
  (`SCMRemoteNetworkExport` remains as class alias)
