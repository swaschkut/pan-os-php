# Stable JSON object model for the API (`model: v1`)

**Status:** proposal, to decide (2026-11-20)
**Code reference:** `alpha` – REST resources of the config-viewer (`ViewerApp::resourceList()`, today `model: display-v0`
= the fields of `actions=display` in `shadow-json`)
**Related:** [config-viewer-api.md](config-viewer-api.md) (decision 4), [ui-config-in-browser.md](ui-config-in-browser.md)
(open decision 3), [api-rest.md](api-rest.md)

## Why

`display-v0` is what `actions=display` prints. It was made for reading, not for programs:

| Problem today | Example |
|---|---|
| text instead of structure | address `tag`: `"tag: 'grp.shared-group1'"` |
| booleans / null as text | rule `disabled`: `"false"`, `securityprofilegroup`: `"null"` |
| field names from the display code | service `count values`, `string legth`; securityprofile `ALLOW`, `ALERT`, `BLOCK` |
| computed and configured values mixed | address `ipcount`, rule `srv_count_tcp` next to `value`, `service` |
| shape depends on the object | address group: `members` + `memberscount`; address: `value` |

## Proposal

### Common to every item

| Field | Type | Content |
|---|---|---|
| `name` | string | object name |
| `location` | string | `shared`, device group, vsys, template, SCM folder / snippet |
| `kind` | string | sub type, lower case with dashes (`ip-netmask`, `group-static`, `security`, `url-filtering`, …) |
| `description` | string | empty string when not set |
| `tags` | string[] | tag names |
| `refs` | integer | number of references (optional, `?fields=refs`) |
| `computed` | object | values pan-os-php calculates (never configuration), e.g. `ip_count` |

Rules: lower case `snake_case` names; booleans are booleans; "not set" is `null` (single value) or `[]` (list); names of
other objects as strings (lists of names), not nested objects; `any` stays the string `any` in a list (`["any"]`).

### Per type (the 8 types that can be changed)

| Type | Fields besides the common ones |
|---|---|
| address | `kind` `ip-netmask` / `ip-range` / `fqdn` / `ip-wildcard` / `group-static` / `group-dynamic`; `value` (string, objects); `members` (string[], static group); `filter` (string, dynamic group); `computed.ip_count`, `computed.members_resolved` (dynamic group) |
| service | `kind` `service` / `group`; `protocol` (`tcp` / `udp` / …), `destination_port`, `source_port`, `timeout`, `halfclose_timeout`, `timewait_timeout` (null when not set); `members` (string[], group); `computed.port_count` |
| tag | `color`, `comments` (as `description`) |
| rule | `kind` (rule type: `security`, `nat`, …), `uuid`, `disabled` (bool), `position` (integer in its rulebase), `rulebase` (`pre` / `post` / `local`); security: `action`, `rule_type` (`universal` / `intrazone` / `interzone`), `from`, `to`, `source`, `source_negated`, `destination`, `destination_negated`, `source_user`, `hip`, `application`, `service`, `url_category` (all string[]), `profile_group` (string or null), `profiles` (object: `virus`, `spyware`, … → name or null), `log_start`, `log_end` (bool), `log_setting` (string or null), `schedule`; other rule types: their own fields in the same style |
| zone | `kind` (`layer3`, `layer2`, `virtual-wire`, `tap`, `tunnel`, `external`), `interfaces` (string[]), `zone_protection_profile`, `log_setting`, `user_id` (bool), `template` |
| schedule | `kind` `recurring` / `non-recurring`, `recurring` (object: `daily` / `weekly`), `non_recurring` (string[]) |
| securityprofile | `kind` (`virus`, `spyware`, `vulnerability`, `url-filtering`, `file-blocking`, `wildfire-analysis`, …); content per kind as the XML structure in JSON (`rules`, `decoder`, `inline`, `site_access` → `allow` / `alert` / `block` …, `credential_enforcement`); `computed.visibility`, `computed.best_practice` (true / false / null = N/A) with `computed.checks` (per check) |
| securityprofilegroup | `profiles` (object: `virus`, `spyware`, `vulnerability`, `url-filtering`, `file-blocking`, `wildfire-analysis`, `data-filtering` → name or null); `computed.visibility`, `computed.best_practice` |

Example (address):

```json
{ "name": "shared-host1", "location": "shared", "kind": "ip-netmask", "value": "1.2.2.3/32", "description": "",
  "tags": ["grp.shared-group1"], "computed": { "ip_count": 1 } }
```

## Open decisions

1. **Where the model is built:** (a) in the library – one method per class, e.g. `Address::toArray()`, used by
   `shadow-json` and the API (one source, also for the CLI; more work in the core), or (b) in the viewer – a mapper
   from the `display` output (fast, but parses texts and breaks when `display` changes). Proposal: (a).
2. **`display-v0` next to `v1`:** keep both for a while (`?model=display-v0`), or switch per type as soon as `v1`
   exists? Proposal: both, `v1` default once a type has it.
3. **Security profiles:** JSON as the XML structure (complete, version dependent) or a normalised form per kind
   (stable, more work)? Proposal: XML structure first, plus `computed` for the checks.
4. **Field names:** `snake_case` as proposed, or the PAN-OS XML names (`source-user`, `log-end`)? XML names are known
   to PAN-OS users and match set commands; `snake_case` is easier in code.
5. **Order of types:** address, service, tag, rule (security) first – or what CDSS reads first (securityprofile,
   securityprofilegroup, rule, zone)?
6. **Writing with the model** (`PUT` / `PATCH` of an item) – later, or part of `v1`? Today changes are actions.
