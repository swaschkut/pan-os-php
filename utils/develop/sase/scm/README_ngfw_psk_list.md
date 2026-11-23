# scm_ngfw_psk_list.php – the IKE pre-shared keys of every firewall managed by SCM

Read only. For every firewall of the tenant (`GET /config/setup/v1/devices`) the newest version of its configuration
(SCM NGFW operations API `GET /local-config/versions`, `GET /local-config/download`) and its IKE gateways: peer, local
address, IKE version and whether the pre-shared key can be decrypted (PAN-OS default master key first, then
`master-key=`).

```bash
pan-os-php type=scm-ngfw-psk-list in=scm-api://<TSG>                                  # every firewall, no clear text
pan-os-php type=scm-ngfw-psk-list in=scm-api://<TSG> psk-list=psk-list.csv            # + the PSK list (chmod 600)
pan-os-php type=scm-ngfw-psk-list in=scm-api://<TSG> serial=<s1>,<s2> [master-key=<key>] [save-dir=<dir>] [base=<url>] [debugapi]
```

| Argument | |
|---|---|
| `serial=` | comma separated serial numbers (default: every firewall of the tenant) |
| `master-key=` | master key of the firewalls, if not the default one |
| `psk-list=` | CSV file with one row per IKE gateway and the clear text of the decryptable pre-shared keys (chmod 600) |
| `save-dir=` | the downloaded configurations as `<serial>-<version>.xml` (chmod 600 - they hold the encrypted secrets) |
| `base=` | URL of the operations API; default: the probable ones are tried (the documentation gives only the paths) |

PSK list columns: `serial, firewall, config_version, config_timestamp, location, ike_gateway, peer_address,
local_address, ike_version, psk_status, psk_current, psk_sha1`.

`psk_status`: `default-master-key` / `given-master-key` (clear text in `psk_current`), `not-decryptable`,
`other-format` (e.g. master key encryption level 2 - not readable by pan-os-php), `no-psk` (e.g. certificate).
`psk_sha1` is the base64 SHA-1 of the clear text that PAN-OS keeps in the encrypted value: also known when the value
can not be decrypted - e.g. to check a PSK given by the customer without knowing the master key.

The output of the script names gateways, peers and the status only - never a secret (the config viewer writes the
output of a run into its log). The clear text exists only in the `psk-list=` file: never put it into a repository.

Exit code: 0 every pre-shared key decrypted, 1 not every one, 2 an API / download error.

The API logic (devices, versions, download, IKE gateways, PSK list) is `lib/SCMLocalConfig.php`, used by this script and
`scm_local_config_probe.php` (one firewall, one version, with details about the API).
