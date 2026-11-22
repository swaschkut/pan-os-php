# Anonymise a Panorama / firewall / SCM configuration

**Status:** first version implemented (2026-11-19): `type=config-anonymize` –
[utils/README_config-anonymize.md](../utils/README_config-anonymize.md), `utils/lib/CONFIG_ANONYMIZE__.php`,
`utils/common/ConfigAnonymizer.php`, `tests/test_config_anonymize.php`. Open items: see "Open items" at the end
**Code reference:** `alpha` `76e6a0d4`
**Related:** `type=master-key actions=scrub` (`utils/common/ConfigSecretsScrub.php`, `utils/common/ConfigSecrets.php`,
[master-key-rekey.md](master-key-rekey.md)), `in=scm-export://` (`PanSCMExportConnector`), `type=stats`,
`type=playbook`, `type=diff`

## Goal

Input: a customer configuration (Panorama XML, firewall XML, SCM export folder / `type=scm-export-xml` file).
Output: a configuration that

1. **keeps the configuration logic**: same object types, counts, references, rule order, rule logic (source /
   destination / zone / application / service / action / profiles), group membership, device group / template /
   template-stack / container / snippet hierarchy, PAN-OS version, profile settings (actions, severities, inline ML,
   …), so pan-os-php gives the same results on it (stats, BPA / visibility figures, playbook changes, merger results,
   xml-issue findings), and it still loads in pan-os-php (ideally also commits on a lab device);
2. **allows no conclusion about the customer**: no secret, no name, no FQDN / domain, no IP that identifies the
   customer, no certificate, no logo, no free text.

Use: test configurations for pan-os-php (`tests/`, the 31 test configs, bug reports to the maintainer), sharing
configurations with Palo Alto Networks / partners, training, CDSS test data.

## What must be replaced

| Area | Examples (XML / SCM) | Replacement |
|---|---|---|
| **Secrets** | every master-key encrypted value (`-AQ==…`), `phash`, `password`, pre-shared keys (IKE, GP, RADIUS / TACACS+ / LDAP bind), SNMP community / v3 auth / priv, API keys, `auth-key` (BGP / OSPF), HA keys, `secret` | as `type=master-key actions=scrub`: placeholder encrypted with the default master key, hashes replaced by the hash of a fixed placeholder |
| **Certificates / keys** | `certificate` / `certificate-profile` / `ssl-tls-service-profile` names, `common-name`, `subject`, `issuer`, `public-key`, `private-key`, CA chains, SCEP, `ocsp-responder`, SAML IdP metadata (certificate, entity ID, SSO URL) | new self-signed certificate / key with the pseudonym name (as scrub), subject / CN pseudonymised; SAML metadata replaced by a generic dummy |
| **Logos / images / HTML** | custom response pages (`response-page` HTML, block / continue / GP / captive portal pages), custom logos (`custom-logo`, GP app / portal logos, base64 images), login banner, `motd` | default PAN-OS page / empty / fixed neutral text; base64 images removed |
| **FQDN / domains / URLs** | address objects `fqdn`, EDL `url`, custom URL category entries, DNS proxy / DNS server, NTP, syslog / SNMP / email / LDAP / RADIUS server, Panorama server, GP portal / gateway addresses, `domain`, `search-domain`, SAML / OAuth URLs, update server, proxy | consistent pseudonym under a reserved domain (`example.com`, `example.net`, `example.org`, `.test`, `.invalid`; RFC 2606 / 6761), same label structure (`a.b.example.com` stays 3 labels); wildcards (`*.`) and paths kept as structure only |
| **IP addresses / networks** | address objects (ip-netmask / range / wildcard), interfaces, routes, NAT, VPN peers, IKE IDs, DHCP, HA, management, services (DNS, NTP, syslog, Panorama …), BGP / OSPF neighbours, User-ID agents | consistent, **prefix-preserving** mapping: same subnet relations (contains / overlaps / equal / adjacent), same netmask, private stays private (RFC 1918 / 6598 / ULA), public → documentation / benchmark ranges or a stable remap; special addresses kept (`0.0.0.0/0`, `::/0`, loopback, link-local, multicast, `any`) |
| **Object / container names** | address, address group, service, service group, application group / filter, custom application / threat / URL category, tag, EDL, schedule, region, security profile, profile group, log forwarding, zone, interface descriptions, device group, template, template stack, vsys display names, SCM folders / snippets, rules (all rulebases), NAT pools, VR / LR, IKE / IPsec / GP / tunnel objects, admin roles, auth profiles | consistent pseudonym per name (`addr-0001`, `rule-0042`, `dg-03` …), kind visible, same name → same pseudonym in every scope (keeps same-name override / shadowing / `ancestor-objects-take-precedence` logic) |
| **Predefined / default names** | applications, `service-http` / `service-https`, `application-default`, predefined URL categories, predefined profiles (`default`, `strict`), predefined tags / EDLs, `any`, interface names (`ethernet1/1`, `ae1.100`, `tunnel.3`), zone types, `vsys1` | **kept** (needed for the logic, not customer specific) |
| **Free text** | `description`, `comment`, `display-name`, rule `description`, tag `comments`, audit comments, `group-tag` | removed or replaced by a fixed text |
| **Identity** | users / groups in rules, User-ID / group mapping (`group-include-list`, LDAP base / bind DN, `domain`), admin users, local users / user groups, Kerberos realm, email addresses, certificate profile `username-field`, GP / auth profile names | consistent pseudonyms (`user-0001`, `cn=group-0007,dc=example,dc=com`), DN structure kept |
| **Device identity** | serial numbers (device groups, templates, collector groups, HA), `hostname`, device names, `ip-address` of management, MAC addresses, SNMP `contact` / `location`, `timezone`, `domain`, Panorama `panorama-server`, licence / auth codes, `vm-auth-key`, cloud / tenant / TSG IDs, CSP IDs | pseudonym serials (same length / format, `0000000000000001` …), host names / MACs remapped, contact / location removed |
| **Numbers with meaning** | BGP AS numbers, IKE IDs, VLAN tags, tunnel IDs | optional remap (private AS 64512–65534 / 4200000000+), default keep (logic only) |
| **SCM specific** | TSG ID, tenant name, folder names, Prisma Access locations / remote network names / service connection names, mobile user domains, IAM users / service accounts, API client IDs | as above; locations / regions kept (logic) |

Rule: **allow-list, not block-list.** Every text value and every `name` attribute is replaced **unless** it is on the
list of kept values (predefined names, enum values like `yes` / `no` / `reset-both` / `alert`, numbers that are
logic, PAN-OS keywords). A field nobody thought of is then anonymised by default, not leaked.

## Proposal

New type `type=config-anonymize` (`utils/lib/CONFIG_ANONYMIZE__.php`, class `ConfigAnonymizer` in `utils/common/`):

```
pan-os-php type=config-anonymize in=customer.xml out=anon.xml [salt=<secret>] [mapping=<file.json>] [ip=keep-private|remap-all]
pan-os-php type=config-anonymize in=scm-export://<folder> out=<folder-anon>
pan-os-php type=config-anonymize in=panorama.xml,fw1.xml,fw2.xml out=<folder>   # one mapping for all files
```

Steps:

1. **Load** with the normal pan-os-php loaders (Panorama / firewall / SCM), so references are known.
2. **Secrets / certificates**: reuse `ConfigSecretsScrub` (master-key scrub) + extra list for plain-text secrets and
   hashes.
3. **Names**: walk all stores; build the dictionary original → pseudonym (deterministic: HMAC-SHA256(salt, kind +
   original), shortened, collision-checked). Rename through pan-os-php (`setName()`), so every reference (rules, groups,
   profiles, SPGs, zones, NAT, PBF, decryption, templates / variables `$var`, SCM folder references) follows.
4. **Generic XML pass** after the object pass: every element text / attribute not on the allow-list and not yet mapped
   → replaced by kind (IP, FQDN, URL, DN, email, serial, free text) through the same dictionary. Catches areas without
   an object model (device config, plugins, `cloud_services`, response pages, `config-section` areas).
5. **IPs**: prefix-preserving mapping (Crypto-PAn style, keyed with the salt) per address family; ranges /
   wildcards mapped consistently; netmask / prefix length unchanged.
6. **Output** the anonymised config; optional mapping file (original → pseudonym) for the consultant only. The
   mapping is sensitive: never written by default, warning when written.
7. **Self-check (leak scan)**: search the output for every original token from the dictionary (names, FQDNs, IPs,
   serials, DNs, emails, certificate subjects) and for typical patterns (`-----BEGIN`, base64 images, `@`, customer
   domain parts). Any hit → report and exit with an error.
8. **Logic check**: run `type=stats` (and optionally `type=playbook visibility.json`, `type=xml-issue`) on input and
   output and compare the figures; they must be the same.

## Open decisions

1. **Determinism:** same salt → same pseudonyms across runs and across Panorama + firewalls (needed for
   Panorama ↔ firewall comparisons). Without `salt=` a random salt per run (no linking possible).
2. **IPs:** keep private ranges as they are (often not customer-identifying, easier troubleshooting) or remap
   everything. Proposal: default remap all; option `ip=keep-private`.
3. **Commit-ability:** should the output commit on a lab device (certificates regenerated, secrets valid) or only load
   in pan-os-php? Proposal: as scrub, commit-able.
4. **Names that carry logic:** EDL / URL category entries used in rules (pattern matching), regex in custom
   applications / threats / data patterns (may contain customer strings) → replaced by neutral patterns, which changes
   match behaviour, but not config logic.
5. **SCM export JSON:** anonymise the JSON files directly (same dictionary) or go through `type=scm-export-xml` and
   back.
6. **Comparison with existing tools:** Palo Alto Networks / community "config sanitizer" scripts (e.g. used for BPA
   uploads) – check whether one can be reused or what they miss.

## Tests

- `tests/test_config_anonymize.php`: small Panorama + firewall config with every area in the table; check that
  - no original token is left (leak scan),
  - `type=stats` before and after are the same,
  - references still resolve (no `not found` warnings),
  - same name in shared + device group → same pseudonym (override logic kept),
  - predefined names unchanged.
- Run on the 31 test configs and compare `type=stats` / playbook output.

## Implementation (first version) – decisions taken

| Decision | Taken |
|---|---|
| 1. determinism | `salt=` / `salt-file=`: same pseudonyms; without: random salt |
| 2. IPs | default `remap` (prefix preserving, private stays private, public stays public); `ip=keep-private` |
| 3. commit-ability | loads in pan-os-php (type=stats / playbook identical); secrets are valid default-master-key values, certificates are valid self-signed certificates – lab commit not verified yet |
| 4. patterns | custom application / threat / data pattern values → `pattern<hash>` (match behaviour changes, config logic not) |
| 5. SCM | JSON files of the export folder directly (same dictionary) |

Approach: XML / JSON level (no object model), so every area is covered, also those pan-os-php does not model. Names:
every `name` attribute (except predefined / keyword / interface / structural model names) gets one pseudonym, and every
text value equal to a name is replaced by it – this keeps all references.



## Open items

- lab commit of an anonymised firewall / Panorama configuration
- certificate chains (issuer → certificate) rebuilt instead of all self-signed
- review of the allow-list with more configurations (GlobalProtect, SAML, cloud plugin, SD-WAN, Prisma Access)
- SCM: check with a real `scm_pa_export` folder (only the mock fixtures tested)
- single-word values in unknown elements are kept – collect such fields from real configurations
