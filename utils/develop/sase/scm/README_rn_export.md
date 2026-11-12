# scm_rn_export.php – Remote Network export

Downloads all Prisma Access Remote Network (RN / RN-SPN) related configuration of one tenant (TSG)
into a local directory. The export is the input for the later steps:

1. **export** (this script)
2. **compare** two exports offline (planned)
3. **import** into a new tenant in dependency order (planned)

## Usage

```bash
php utils/develop/sase/scm/scm_rn_export.php in=scm-api://<TSG_ID>
php utils/develop/sase/scm/scm_rn_export.php in=scm-api://<TSG_ID> outdir=/share/export egressip
```

| argument | description |
|---|---|
| `in=scm-api://<TSG_ID>` | tenant; service account `client_id` / `client_secret` are taken from `~/.panconfkeystore` (`tsg_id<TSG_ID>`) or asked for and stored |
| `outdir=` | base directory, default `export` |
| `folder=` | SCM folder of the IKE/IPsec objects, default `Remote Networks` |
| `egressip` | also download egress IPs via the Prisma Access egress-IP API |
| `egressip-env=prod\|prod6` | egress-IP API host (`api.prod…` default, `api.prod6…` for some SCM tenants) |
| `psk-list` | write `psk-list.csv` with the decrypted PSK per IKE gateway (see below) |
| `master-key=` | master key to decrypt the PSKs; default: PAN-OS default master key |
| `debugapi` | print every API call |

### Egress-IP API key

The egress-IP API (`getPrismaAccessIP/v2`) does not use OAuth but its own API key
(`header-api-key`, created in Prisma Access › Infrastructure Settings). With `egressip` the key is read from
`~/.panconfkeystore` entry `egressip_tsg_id<TSG_ID>`; if missing, it is asked for once and stored there.

## Output

```
<outdir>/<TSG_ID>/<YYYYmmdd-HHMMSS>/
    manifest.json
    01_ike-crypto-profiles.json     /config/network/v1/ike-crypto-profiles?folder=Remote Networks
    02_ipsec-crypto-profiles.json   /config/network/v1/ipsec-crypto-profiles?folder=Remote Networks
    03_ike-gateways.json            /config/network/v1/ike-gateways?folder=Remote Networks
    04_ipsec-tunnels.json           /config/network/v1/ipsec-tunnels?folder=Remote Networks
    05_bandwidth-allocations.json   /config/deployment/v1/bandwidth-allocations
    06_remote-networks.json         /config/deployment/v1/remote-networks
    90_locations.json               /config/deployment/v1/locations        (context)
    91_bgp-routing.json             /config/deployment/v1/bgp-routing      (context)
    92_egress-ip.json               getPrismaAccessIP/v2, serviceType=remote_network (only with egressip)
    ip-mapping.json / ip-mapping.csv
    psk-list.csv                    (only with psk-list, chmod 600, cleartext)
```

* Files `01`–`06` are in **import order**: an entry only references entries with a lower number
  (IKE crypto → IKE gateway → IPsec tunnel → remote network; bandwidth allocation before remote network).
* Every endpoint file keeps the **unmodified API data** (`data`) plus `endpoint`, `url`, `tsg_id`, `fetched_at`,
  `http_code`, `status`, `error`. Normalisation (dropping `id`, read-only fields, sorting) is done by compare/import.
* A failing endpoint does not stop the export; it is recorded with `status: error` in its file and in `manifest.json`.

### manifest.json

`format_version`, `tsg_id`, `api_url`, `folder`, `created_at`, `import_order`, per-endpoint status/count/http_code,
`ip_mapping` summary and `import_hints`:

* `pre_shared_key` – IKE gateways using a PSK. No key value is written to the manifest; use `psk-list` for the import.
* `inherited_or_predefined` – entries not defined in the export folder itself (`snippet` set, e.g. `predefined`, or a
  parent folder). Import references them but does not create them.

### ip-mapping.json / ip-mapping.csv

One row per remote network:

| column | source |
|---|---|
| `region`, `spn_name`, `license_type`, `ipsec_tunnel`, `secondary_ipsec_tunnel` | remote network |
| `service_ip_address`, `fqdn`, `loopback_ip_address` | remote network `details` (Prisma Access side) |
| `bgp_*` | remote network `protocol.bgp` |
| `branch_peer_address` | remote network → IPsec tunnel → IKE gateway `peer_address` (branch side) |
| `location_display`, `egress_ip_addresses`, `egress_match` | region → `locations[].value/region` → `display` → egress-IP `zone` |

`egress_match: none` means no automatic match; check `92_egress-ip.json`.
`egress_zones_without_remote_network` lists egress zones no remote network was mapped to.

A new tenant gets new Prisma Access IPs, so this file is also the checklist for the branch firewall changes
(peer address, allow lists).

### psk-list.csv

One row per IKE gateway with a pre-shared key:

| column | content |
|---|---|
| `ike_gateway` | gateway name – key for the import |
| `ipsec_tunnel`, `remote_network`, `branch_peer_address` | context only, to find the right key |
| `psk_current` | decrypted PSK from the export (`PanosCrypto`, default or `master-key=`); `DECRYPT_FAILED` if not possible |
| `psk_new` | empty – fill in to set a new PSK on the target tenant |

Import rule (`SCMRemoteNetworkExport::loadPSKList()`): `psk_new` if filled, otherwise `psk_current`.
`psk_new` is optional. A gateway with empty `psk_new` and empty / `DECRYPT_FAILED` `psk_current`, or a duplicate
gateway name, is reported as error, so the import can stop in dry-run before creating anything.
Values are used exactly as written (no trimming). Gateways using certificates are not listed.

The file holds cleartext secrets: it is created with mode 0600, is not referenced by name in `manifest.json`
(only counts under `psk_list`) and should be kept out of git and tickets. Rotate keys if it leaks.

Note: `PanosCrypto::decrypt()` returns `""` instead of throwing on a wrong master key; the export treats an empty
result as `DECRYPT_FAILED`.

## Connector changes (`lib/misc-classes/PanSCMAPIConnector.php`)

* `sendSCMAPIRequest($method, $url, $body = false, $exitOnError = TRUE)` now returns
  `['http_code', 'response', 'json', 'errors']` and sets `Content-Type: application/json` when a body is sent.
  Default behaviour (derr on `_errors`) is unchanged.
* `getSCMResourceAll($url_config, $limit = 200)` – GET with limit/offset pagination, returns errors instead of exiting;
  handles single-object endpoints (`is_list = false`).
* `getEgressIPApiKey($TSGid)` / `getPrismaAccessEgressIP($apiKey, $serviceType, $addrType, $location, $environment)`.
* Keystore lookup in `findOrCreateConnectorFromHost()` (SCM and SASE) now matches `tsg_id<TSG>` only at the start of
  the entry, so the `egressip_tsg_id<TSG>` entry is never taken as OAuth credential.

## To verify against a live tenant

* `pre_shared_key` format returned by `ike-gateways`.
* Whether `remote-networks` and `bandwidth-allocations` need a `folder` parameter in your tenant.
* Region → location → egress zone matching (`egress_match`).
