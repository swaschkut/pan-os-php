# scm_ngfw_psk_list.php – the IKE pre-shared keys of every firewall managed by SCM, or of a configuration file

Read only. For every firewall of the tenant (`GET /config/setup/v1/devices`) the newest version of its configuration
(SCM NGFW operations API `GET /local-config/versions`, `GET /local-config/download`) and its IKE gateways: peer, local
address, IKE version and whether the pre-shared key can be decrypted (PAN-OS default master key first, then
`master-key=`).

`in=<file.xml>`: offline, the IKE gateways of a configuration file - firewall, Panorama (templates) or SCM (folders,
snippets, devices: below `devices/entry[@name='localhost.localdomain']/network`); `location` names the place.

```bash
pan-os-php type=scm-ngfw-psk-list in=fw.xml psk-list=psk.csv sha1-list=psk-sha1.csv    # a configuration file
pan-os-php type=scm-ngfw-psk-list in=scm-api://<TSG> compare=psk-sha1.csv compare-out=compare.csv   # firewalls vs. file
pan-os-php type=scm-ngfw-psk-list in=scm-api://<TSG>                                  # every firewall, no clear text
pan-os-php type=scm-ngfw-psk-list in=scm-api://<TSG> psk-list=psk-list.csv            # + the PSK list (chmod 600)
pan-os-php type=scm-ngfw-psk-list in=scm-api://<TSG> serial=<s1>,<s2> [master-key=<key>] [save-dir=<dir>] [base=<url>] [debugapi]
```

| Argument | |
|---|---|
| `serial=` | comma separated serial numbers (default: every firewall of the tenant) |
| `master-key=` | master key of the firewalls, if not the default one |
| `psk-list=` | CSV file with one row per IKE gateway and the clear text of the decryptable pre-shared keys (chmod 600) |
| `sha1-list=` | the list without clear text (SHA-1 of the pre-shared key) - for `compare=` |
| `compare=` | a SHA-1 list (or PSK list - its clear text is not read): side a; this run: side b |
| `compare-out=` | the comparison as CSV: `ike_gateway, result, a_where, a_peer_address, a_psk_status, b_where, b_peer_address, b_psk_status` - result `same`, `different`, `only-a`, `only-b`, `unknown` (no PSK / other format) |
| `save-dir=` | the downloaded configurations as `<serial>-<version>.xml` (chmod 600 - they hold the encrypted secrets) |
| `base=` | URL of the operations API; default: the probable ones are tried (the documentation gives only the paths) |

PSK list columns: `serial, firewall, config_version, config_timestamp, location, ike_gateway, peer_address,
local_address, ike_version, psk_status, psk_current, psk_encrypted, psk_sha1`.

* `psk_current`: the clear text (when it could be decrypted)
* `psk_encrypted`: the whole value of the configuration, as it is (SCM: as the API gave it), e.g. `-AQ==…`
* `psk_sha1`: **not the key** - only the SHA-1 of the clear text that PAN-OS keeps in an encrypted value of level 1
  (the 28 characters after `-AQ==`, ending with `=`); the same for the same key with any master key

The SHA-1 list (`sha1-list=`) has neither `psk_current` nor `psk_encrypted` (with the default master key the encrypted
value is as good as the clear text).

`psk_status`: `default-master-key` / `given-master-key` (clear text in `psk_current`), `not-decryptable`,
`other-format` (e.g. master key encryption level 2 - not readable by pan-os-php), `no-psk` (e.g. certificate).
`psk_sha1` is the base64 SHA-1 of the clear text that PAN-OS keeps in the encrypted value: also known when the value
can not be decrypted - e.g. to check a PSK given by the customer without knowing the master key.

The output of the script names gateways, peers and the status only - never a secret (the config viewer writes the
output of a run into its log). The clear text exists only in the `psk-list=` file: never put it into a repository.

Exit code: 0 done (also with keys that can not be decrypted - see the summary), 2 an API / download error.

The API logic (devices, versions, download) is `lib/SCMLocalConfig.php`; the IKE gateways, PSK / SHA-1 lists and the
comparison are `lib/misc-classes/IKEPSKList.php` - used by this script, `scm_local_config_probe.php` and the config
viewer (run *IKE gateways / PSK list*).
