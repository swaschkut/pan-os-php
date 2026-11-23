# scm_local_config_probe.php – configuration of an SCM managed firewall, and its pre-shared keys

Read only. Checks what the SCM NGFW operations API gives of the configuration of a firewall managed by Strata Cloud
Manager (`GET /local-config/versions`, `GET /local-config/download`: "the XML configuration file pushed to a device"),
and whether the pre-shared keys of its IKE gateways can be decrypted - e.g. to keep the PSKs of the tunnels of the
customer firewalls when a tenant is moved (the PSKs of a Prisma Access tenant itself can not be decrypted).

```bash
pan-os-php type=scm-local-config-probe in=scm-api://<TSG>                         # the managed firewalls (serials)
pan-os-php type=scm-local-config-probe in=scm-api://<TSG> serial=<serial>         # newest version
    [config-version=<id>] [master-key=<key>] [save=<file>] [base=<url>] [debugapi]
pan-os-php type=scm-local-config-probe file=<config.xml> [master-key=<key>]       # offline: downloaded in SCM
```

| Output | Meaning |
|---|---|
| `try GET …: HTTP …` | the URL of the operations API is not documented (only the paths): the probable ones are tried; `base=` sets it (look at the request of Device Management > Local Config Management in the browser developer tools) |
| versions | id, local_version, xfmed_version, time, md5 |
| per IKE gateway | `level 1, decryptable with the DEFAULT master key` / `… with the given master key` / `NOT decryptable` / `other format (prefix …)` (e.g. master key encryption level 2 - not readable by pan-os-php yet) |

Never prints a secret - only names of IKE gateways, yes / no and counts. The downloaded configuration is written only
with `save=` (chmod 600: it holds the encrypted secrets of the firewall). Exit code of `file=`: 0 when every pre-shared
key can be decrypted.

To verify on a lab tenant: base URL and parameter names, the permission the service account needs, whether the file
holds the local configuration of the firewall as well, and with which master key its secrets are encrypted (the one of
the firewall - default unless SCM / the administrator deployed another one - or another).
