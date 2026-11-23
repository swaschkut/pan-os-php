# JSON object model for the API: the SCM API schema

**Status:** decided 2026-11-20 – the model is the Strata Cloud Manager (SCM) API schema; first five resources implemented
**Code reference:** `alpha` – `lib/resources/scm/scm-ngfw-config-schema.json` (49 resources, request schema per
resource, generated from the official SCM API description), `SCMChangeGenerator`; REST resources of the config-viewer (`ViewerApp::resourceList()`,
today `model: display-v0`)
**Related:** [config-viewer-api.md](config-viewer-api.md) (decision 4), [ui-config-in-browser.md](ui-config-in-browser.md)
(open decision 3), [api-rest.md](api-rest.md)

## Decision

- An item of the API has the **shape of the SCM API** for that resource: resource names, field names (`snake_case`),
  types and structure as in `scm-ngfw-config-schema.json`. Nothing own is designed where PANW has defined it.
- **What the SCM API does not have is defined by pan-os-php**, in the same style, until PANW defines it; then the own
  definition is replaced by the PANW one.
- The same model for PAN-OS / Panorama XML and SCM input, so a client (CDSS, UI) reads one format.

Why not the `display` fields (`display-v0`): made for reading – text instead of structure (address `tag`:
`"tag: 'grp.shared-group1'"`), booleans / null as text (`"false"`, `"null"`), names from the display code
(`count values`, `ALLOW`), configured and computed values mixed.

## What this means

| | Today (`display-v0`) | With the SCM schema |
|---|---|---|
| resource names | one per pan-os-php type: `addresses`, `services`, `rules`, `security-profiles`, `security-profile-groups` | as SCM: `addresses`, `address-groups`, `services`, `service-groups`, `tags`, `security-rules`, `nat-rules`, `decryption-rules`, `app-override-rules`, `authentication-rules`, `pbf-rules`, `qos-policy-rules`, `zones`, `schedules`, `profile-groups`, `anti-spyware-profiles`, `vulnerability-protection-profiles`, `url-access-profiles`, `file-blocking-profiles`, `wildfire-anti-virus-profiles`, `dns-security-profiles`, `external-dynamic-lists`, `url-categories`, `log-forwarding-profiles`, `zone-protection-profiles`, `ike-gateways`, `ipsec-tunnels`, … |
| address | `type`, `value`, `tag` (text) | `name`, `description`, `tag` (string[]), one of `ip_netmask` / `ip_range` / `ip_wildcard` / `fqdn` |
| security rule | `sourcenegated: "false"`, `securityprofilegroup: "null"`, `logsetting: {"end":"true"}` | `from`, `to`, `source`, `negate_source`, `destination`, `negate_destination`, `source_user`, `source_hip`, `destination_hip`, `application`, `service`, `category`, `action`, `disabled`, `profile_setting`, `log_start`, `log_end`, `log_setting`, `schedule`, `tag` |
| profile group | `securityprofiles: {count, virus, …}` | `spyware`, `vulnerability`, `url_filtering`, `file_blocking`, `dns_security`, `virus_and_wildfire_analysis`, … (string[]) |
| tag | `color`, `comments` | `name`, `color`, `comments` |

Example (address, PAN-OS input):

```json
{ "name": "shared-host1", "description": "", "tag": ["grp.shared-group1"], "ip_netmask": "1.2.2.3/32",
  "device_group": "shared" }
```

Building blocks that exist: `SCMChangeGenerator` writes SCM API requests from an SCM configuration, and the schema file
names the fields per resource. (The translation of a whole Panorama / firewall configuration into SCM is part of the
plug-in scm-migration.)

## Own definitions (where the SCM API has nothing)

| Topic | SCM | PAN-OS / Panorama | Proposal |
|---|---|---|---|
| location | `folder` / `snippet` / `device` | `shared`, device group, vsys, template, template stack | own fields `device_group`, `vsys`, `template`, `template_stack` next to the SCM ones (`"device_group": "shared"` for shared); `scm-panorama-to-change` maps shared → folder `All`, DG → folder, template → snippet – for reading a PAN-OS file the real location is kept |
| antivirus and WildFire | one resource `wildfire-anti-virus-profiles` | two profiles: `virus`, `wildfire-analysis` | own resources `antivirus-profiles`, `wildfire-analysis-profiles` with the PAN-OS XML structure in `snake_case`; `profile-groups` gets own fields `virus`, `wildfire_analysis` |
| anti-spyware and DNS security | two resources: `anti-spyware-profiles` and `dns-security-profiles` | one profile: DNS security is part of the anti-spyware profile (`botnet-domains`: DNS lists, DNS security categories, sinkhole) | Panorama / firewall: stays inside the `anti-spyware-profiles` item as own field `botnet_domains` (PAN-OS XML structure in `snake_case`); `dns-security-profiles` exists only for SCM input. Nothing is split or merged when reading. |
| data filtering, custom objects, … | not in the schema file (49 resources) | exist in PAN-OS | own resource per pan-os-php type, XML structure in `snake_case` |
| fields PAN-OS has and SCM not | – | e.g. rule `uuid`, `rule_type` (`universal` / `intrazone` / `interzone`), `position`, `rulebase` (`pre` / `post`), security profile fields of a newer PAN-OS (`local_deep_learning`) | same name as the PAN-OS XML element in `snake_case`, on the object |
| computed values | – | `ip_count`, references, visibility / best practice with the single checks | not configuration: in one own object `_panosphp` on the item (`{"ip_count": 1, "visibility": true, "best_practice": false, "checks": {…}}`), only when asked (`?computed=1`) |
| types without objects | – | `stats`, `playbook`, … | runs (jobs), not part of the object model |

Every own resource / field is listed in one file (`lib/resources/scm/panosphp-extensions.json`, same format as the
schema file), so it is visible what is own and can be removed when PANW defines it.

## Consequences for what is built

- The REST resource names of the config-viewer change to the SCM names (today one resource per pan-os-php type);
  `display-v0` stays reachable for a while (`?model=display-v0`).
- Filters stay pan-os-php filters (`?filter=`); `location=` stays, plus `folder=` / `snippet=` for SCM input.
- Changes stay actions for now; writing an item in the SCM shape (`POST` / `PUT` like the SCM API) is the next step
  and can reuse `SCMChangeGenerator` in the other direction.

## Decisions on the details (2026-11-20)

1. **Location:** Panorama / firewall objects carry their own location (`device_group` – `"shared"` for shared –,
   `vsys`, `template`, `template_stack`, managed device …); SCM objects carry the SCM fields (`folder`, `snippet`,
   `device`). No mapping of a PAN-OS location to a folder / snippet when reading.
2. **Antivirus / WildFire:** Panorama / firewall separate (own resources `antivirus-profiles`,
   `wildfire-analysis-profiles`), SCM combined (`wildfire-anti-virus-profiles`).
   The same rule for **anti-spyware / DNS security**: SCM separate (`anti-spyware-profiles`, `dns-security-profiles`),
   Panorama / firewall together in the anti-spyware profile (`botnet_domains`).
3. **Computed values** (proposal, used unless decided otherwise): one own object `_panosphp` on the item, only when
   asked with `?computed=1` – `{"ip_count": …, "references": …, "visibility": true|false|null, "best_practice": …,
   "checks": {…}}`. One request gives object and checks together (what the SPR report of CDSS needs per profile /
   rule), the SCM shape of the item stays untouched without the parameter, and no second set of routes is needed.
4. **Order:** by dependency – tags, addresses, address-groups, services, service-groups; then schedules,
   url-categories / external-dynamic-lists, log-forwarding-profiles, security profiles, profile-groups, zones (+ zone
   protection profiles), then the rule resources.
5. **Where:** in the library – `lib/misc-classes/ApiObjectModel.php`; `actions=display` with `shadow-json` adds it as
   `model` (`resource`, `item`) to every object, so the CLI and the API give the same.

## Progress

| Date | Step | State |
|---|---|---|
| 2026-11-20 | `ApiObjectModel` (SCM shape via `SCMChangeGenerator::toBody()`, location fields, top-level elements without SCM schema generically in `snake_case`, the rest listed in `_panosphp.not_converted`); resources `tags`, `addresses`, `address-groups`, `services`, `service-groups`; config-viewer serves them as `model: scm-v1` (default for these resources, `?model=display-v0` for the display fields) | done; tests `tests/test_api_object_model.php` (13), `tests/test_config_viewer.php` |
| 2026-11-20 | one hook for all types: `CallContext::executeAction()` adds `model` for `display` with `shadow-json`; a PAN-OS element the SCM schema does not know stays **at its place** in the item (also nested, e.g. `match_list[].send_to_panorama`, AS rule action `default`) | done |
| 2026-11-20 | `schedules`, `url-categories`, `external-dynamic-lists`, `log-forwarding-profiles` | done, tests |
| 2026-11-20 | security profiles: `anti-spyware-profiles`, `vulnerability-protection-profiles`, `url-access-profiles`, `file-blocking-profiles`, `dns-security-profiles`, `wildfire-anti-virus-profiles` (SCM); own resources `antivirus-profiles`, `wildfire-analysis-profiles` (Panorama / firewall); `profile-groups` (own fields `virus`, `wildfire_analysis`); `zones` (location `template` / `template_stack` + `vsys`), `zone-protection-profiles` | done, tests; open: predefined profiles are not marked as predefined; the profile XML is the loaded one (with the PAN-OS defaults the loader makes visible); `dns-security-profiles`, `wildfire-anti-virus-profiles`, `zone-protection-profiles` verified only without objects (viewer) |
| 2026-11-20 | rule resources: `security-rules`, `nat-rules`, `decryption-rules`, `app-override-rules`, `authentication-rules`, `pbf-rules`, `qos-policy-rules` (SCM); own resources `dos-rules`, `tunnel-inspection-rules`, `captive-portal-rules`, `default-security-rules`, `sdwan-rules`, `network-packet-broker-rules`; own fields `uuid`, `rulebase` (`pre` / `post` / `local`), `position` (in its rulebase), PAN-OS elements such as `rule_type`, `target` | done, tests; verified with rules in the tests: security, NAT, decryption, authentication, default security – the other rule types only without rules |
| 2026-11-20 | `?computed=1` → `_panosphp` (`ApiObjectModel::computed()`, off by default): `references`; address `ip_count`; security profiles and profile groups `visibility`, `best_practice` (true / false / null = N/A) and `checks` per profile class (`rules`, `inline`, `dns_lists`, `dns_security`, `advanced_dns_security`, `actions`, `site_access`, `credential`); security / default security rules `profiles_visibility`, `profiles_best_practice` | done, tests; the verdicts use the default BP JSON or, with `?bp=<file id>`, a BP JSON file of the project (also for changes: body `bp`) |
| | file `lib/resources/scm/panosphp-extensions.json` with the own definitions, SCM input (folder / snippet) verified, old resource names of the other types (`rules`, `security-profiles`, …) removed, predefined objects marked | open |
