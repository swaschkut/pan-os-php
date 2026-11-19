# `type=config-anonymize` – anonymise a Panorama / firewall / SCM configuration

Makes a customer configuration shareable (test data, bug reports, training) **without changing its logic**.

```
pan-os-php type=config-anonymize in=customer.xml out=anon.xml [salt-file=salt.txt] [mapping=map.json] [ip=keep-private]
pan-os-php type=config-anonymize in=panorama.xml,fw1.xml,fw2.xml out=<folder> salt-file=salt.txt
pan-os-php type=config-anonymize in=scm-export://<export folder> out=<folder>
```

| Argument | |
|---|---|
| `in=` | one or more XML files (Panorama, firewall, SCM XML from `type=scm-export-xml`), separated by `,`; or an SCM export folder (`scm-export://<folder>` or the folder itself – all `*.json` files) |
| `out=` | output file (one XML input) or folder (several files / SCM export) |
| `salt=` / `salt-file=` | secret salt. Same salt → same pseudonyms (Panorama and its firewalls, several runs). Without a salt a random one is used: nothing can be linked to other runs |
| `mapping=` | writes original → pseudonym as JSON. **Sensitive** – it de-anonymises the output; keep it with the customer data, never share it |
| `ip=keep-private` | private addresses (RFC 1918, RFC 6598, IPv6 ULA) unchanged; default `remap` |
| `allow-leaks` | write the output even when the leak scan finds an original value |

## What is kept (logic)

- The XML structure: same elements, same order, same counts (checked after every run: "structure unchanged").
- **Every name gets one pseudonym everywhere** (`addr-…`, `rule-…`, `dg-…`, `tpl-…`, `zone-…`, `$var-…`), so all references,
  same-name overrides between shared / device groups, shadowing and template / template-stack relations stay as they are.
- Predefined names: applications, services (`service-http` …), URL categories, threats, predefined profiles / EDLs / DNS
  categories, interface names (`ethernet1/1`, `ae1.100`, `tunnel.3`), `vsys1`, SCM folders `All` / `Shared` /
  `ngfw-shared` / Prisma Access containers, iron-skillet names (`Alert-Only-*`, `Outbound-*`, …), PAN-OS keywords.
- IP addresses are mapped **prefix preserving** (keyed with the salt): a host stays inside its subnet, the netmask is
  unchanged, a network address stays a network address, private stays private, public stays public, link-local /
  multicast / loopback / `0.0.0.0/0` / netmasks are unchanged.
- All settings (actions, severities, inline ML, log settings, …), numbers, threat IDs.

## What is replaced

| | |
|---|---|
| secrets | encrypted values (`-AQ==…`), PSKs, passwords, SNMP communities, API keys → `Dummy-1234567890`, encrypted with the default master key; `phash` → hash of that placeholder |
| certificates | new self-signed certificate + key, CN = pseudonym of the certificate name; subject / issuer / hashes accordingly |
| FQDN / URL / email | `a.b.customer.com` → `l<hash>.l<hash>.d<hash>.example` (label structure kept, reserved TLD `.example`); URL paths hashed |
| users / groups / LDAP DN | `user-…`, `domain\user` and DN structure kept |
| serial numbers, MAC addresses, host names | same format, other value |
| free text | descriptions, comments, banners, display names, SNMP contact / location → `anonymized`; timezone → `UTC` |
| response pages / logos / images | neutral HTML page / 1×1 PNG |
| match patterns | custom application / threat / data pattern values → `pattern<hash>` |

SCM export: the JSON files are anonymised the same way (keys like `addresses|folder|<folder>|pre` included); other
files of the export folder (reports) are **not** copied; folder names in paths are replaced.

## Checks

- **Leak scan:** every replaced original value (names, FQDNs, domains, public IPs, users, serials, free text) is
  searched in the output. A hit stops the run (nothing written) unless `allow-leaks` is given.
- **Structure:** element paths and counts before / after must be the same.
- Recommended after a run: `type=stats` on input and output – the figures must be the same (names in the keys differ).
  Tested: `baseconfigpano-11_2-test-vcp5.xml` (1,100 figures) and a Panorama with templates / stacks (1,782 figures):
  all equal; the CDSS visibility playbook makes the same 924 changes on the original and on the anonymised config.

## Limits

- Certificates: every certificate becomes self-signed – issuer chains are not rebuilt.
- A value of an unknown element that is a single word (no FQDN / IP / user …) is kept; check the output before sharing
  a configuration with unusual content (`mapping=` + manual review).
- Customer objects whose name is a PAN-OS keyword or predefined name (e.g. a custom URL category `Block`) keep their name.
- `in=api://` is not supported – export the configuration first.

Concept and open items: [todo/config-anonymize.md](../todo/config-anonymize.md). Test: `php tests/test_config_anonymize.php`.
