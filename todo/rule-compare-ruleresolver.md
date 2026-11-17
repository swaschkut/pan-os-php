# type=rule-compare – switch to RuleResolver

**Status:** planned, no patch started
**Code reference:** `alpha` `b8381c9`
**Files:** `utils/lib/RULE_COMPARE.php` (`buildFirewallView()`), `utils/common/RuleResolver.php`,
`utils/common/RuleCallContext.php` (`AddressResolveSummaryNEW()`, `ServiceResolveSummary()`)
**Tests:** `tests/test_rule_resolver.php` (RuleResolver), a `tests/test_rule_compare.php` does not exist yet

## Why

`type=panorama-move` compares rules with `RuleResolver` (resolved values, every field, every rule type).
`type=rule-compare resolvemode=firewall` uses the same name resolution (`PH::resolveNameForFirewalls()` /
`PH::expandForFirewalls()`) but compares fewer fields and IPv4 only. One implementation for both keeps
the results consistent and gives rule-compare the missing fields.

## Today: rule-compare `resolvemode=firewall`

`buildFirewallView()` loads the configuration and resolves every **security** rule for the firewalls of every
device group / vsys it reaches. Rules are matched by key `<rule location>/<pre|post>/<rule name>`.

| Field | rule-compare today | RuleResolver |
|---|---|---|
| source / destination | IPv4 ranges (`IP4Map`) – IPv6 objects not compared, `any` only as IPv4 range | IPv4 **and** IPv6 ranges (exact since `0dc8553`), `any` |
| EDL | **skipped** – rules that differ only in an EDL look equal | `edl:<name>` |
| FQDN / region | not part of the IPv4 map | `fqdn:<value>`, `region:<name>` |
| unresolved names | – | `unresolved:<name>` |
| service | port mapping (`ServiceResolveSummary`) | port mapping, `application-default`, source port only when set |
| from / to | zone names | zone names |
| negate-source / negate-destination | **not compared** | part of the match |
| application | **not compared** | names, application groups expanded, filters `filter:<name>` |
| source-user, category, source-hip, destination-hip | **not compared** | values as configured |
| action, profile-setting | **not compared** | action; profile group resolved to its profiles |
| other rule elements (schedule, options, …) | **not compared** | canonical XML (`other`) |
| rule types | security only | any (security, nat, decryption, authentication, pbf, …) |
| rules only in file2 | not reported (only file1 rules are looked up) | `compare()` returns `only_b` |

`resolvemode=rulelocation` (JSON via `display:ResolveAddressSummary|ResolveServiceSummary` + `shadow-json`) is the
older mode: each rule resolved once at its own location.

## RuleResolver (exists, `741cafa`)

* `resolve($ruleNode, $type, $location)` – field → sorted resolved values
* `signature($resolved)` – match hash / action hash
* `firewallRulebase($pan, $location, $types)` – rules reaching the firewalls of a location, in evaluation order
  (shared pre, device group chain pre top-down, post bottom-up, shared post) – the same levels as `buildFirewallView()`
* `resolveView()`, `compare($viewA, $viewB, $keyMap)` – same / changed (with the differing fields) / only in A / only in B
* `diff($a, $b)` – per field: values only in A / only in B

## Plan

1. `buildFirewallView()` → `RuleResolver::firewallRulebase()` + `resolveView()`; map the resolved fields to the existing
   keys (`src_resolved_sum`, `dst_resolved_sum`, `srv_resolved_sum`, `from`, `to`) so that the output stays the same
2. new argument for the compared fields, default = today's five fields (output unchanged); `all` = every RuleResolver
   field (e.g. `fields=basic|all` – name to decide)
3. report rules only in file2 (today silently ignored)
4. optional: rule types beyond security (`types=security,nat,…`)
5. optional: match renamed rules by signature (`compare()` with a key map)
6. `tests/test_rule_compare.php`: two configurations with known differences per field, both resolve modes

## Open decisions

* default of the field argument: today's five fields (stable output) or all fields
* IPv6 in source / destination by default – today IPv6 differences are not reported at all
* EDL: compare by name by default – today an EDL difference is not reported
* output of the new fields in the console / HTML (`generateRuleHtmlFile`)
* `resolvemode=rulelocation`: keep or deprecate

## Effort

Steps 1–3 and the tests: medium (RuleResolver exists and is tested). Steps 4–5: small each.
