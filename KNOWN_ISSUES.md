# Known issues – pan-os-php

**Status:** 2026-11-17, code reference `alpha` `63fa7da`
**Related:** [TODO.md](TODO.md) (planned work), GitHub issues: https://github.com/swaschkut/pan-os-php/issues

Bugs, limitations and open feature requests of pan-os-php itself. Two sources:

1. open GitHub issues (13 open of 61 issues in total, state of 2026-11-17)
2. limitations known from the code / from development that have no GitHub issue

Keep this file in sync: new issue → add a row; issue closed → remove the row (or move it to "Recently closed" for
one release); limitation fixed → remove the row and mention it in the release notes / changelog.

## 1. Open GitHub issues

### Bugs

| Issue | Type | Problem | State / workaround |
|---|---|---|---|
| [#100](https://github.com/swaschkut/pan-os-php/issues/100) | `type=zone` | `actions=name-replaceCharacter` (and other rename actions) changes the zone name in the template, but not the zone references in the rules of the device groups (Panorama, offline) | open. Workaround: `type=rule actions=from-Replace:OLD,NEW 'filter=(from has OLD)'` and the same with `to-Replace` / `to has`. Idea from the issue: use `<reference-templates>` of the device group to find the rules (already read in `DeviceGroup::$referenceTemplateRoot`) |
| [#95](https://github.com/swaschkut/pan-os-php/issues/95) | all types, `actions=create:NAME` | with `location=shared:excludeMaindg` (or several locations) the object is only created in the last device group | by design one object name is created once; **bug:** the combination should be refused with a clear message instead of a silent partial result |
| [#9](https://github.com/swaschkut/pan-os-php/issues/9) | `type=rule` | `(timestamp-last-hit.fast = 0)` does not match disabled rules | PAN-OS API does not return hit data for disabled rules; document as limitation of the filter |
| [#47](https://github.com/swaschkut/pan-os-php/issues/47) | `type=address-merger` | host object `a.b.c.d/32` used on an interface must not be merged into an object `a.b.c.d` without mask (interface needs the netmask) | open – merger has to check interface references |
| [#55](https://github.com/swaschkut/pan-os-php/issues/55) | `type=upload` | Panorama shared → Panorama shared not working | "should be fixed, validation needed" (2025-11-21) – **close candidate** after a test |

### Vendor migration (`type=vendor-migration`)

| Issue | Vendor | Problem | State / workaround |
|---|---|---|---|
| [#76](https://github.com/swaschkut/pan-os-php/issues/76) | `cp-r80` | interface IP addresses missing; they are in the export ("Gateways running this policy package"), but a package can hold several gateways / clusters | needs an argument which gateway is migrated |
| [#75](https://github.com/swaschkut/pan-os-php/issues/75) | all | NAT rules without to-zone; security rules related to DNAT rules (post-NAT zone / pre-NAT destination IP) not adjusted | open |
| [#56](https://github.com/swaschkut/pan-os-php/issues/56) | `fortinet` | FQDN values like `*.xyz.com`, `*xyz.com`, `xyz.com*` not validated; region objects not migrated to PAN-OS regions | open |
| [#45](https://github.com/swaschkut/pan-os-php/issues/45) | Cisco ASA / IOS | migrated `ip-wildcard` objects cannot be used in address groups | workaround exists: `type=address actions=move-wildcard2network` – check if this solves the issue, then let the migration call it automatically or close |

### Feature requests

| Issue | Type | Request | State |
|---|---|---|---|
| [#121](https://github.com/swaschkut/pan-os-php/issues/121) | all with `name-*` actions | `name-truncate:<n>` action (with duplicate check); some objects allow max 31 characters (e.g. IPsec crypto profile, SCM upload error) | open; filter `name.length` exists, no action |
| [#79](https://github.com/swaschkut/pan-os-php/issues/79) | – | local policy finder for all Panorama connected devices | offline done: `type=device-config-bundle` (Panorama device config bundle `.tgz`); online mode open – **close or reduce to online** |
| [#72](https://github.com/swaschkut/pan-os-php/issues/72) | `type=rule` | `exportToExcel`: count of source / destination address objects per rule, split by object type (ip-netmask, fqdn, region, group, EDL, …) | open |
| [#35](https://github.com/swaschkut/pan-os-php/issues/35) | `type=application`, `type=rule` | filter `app included-in` / `includes-full` / `includes-full-or-partial` for app containers / groups / filters | open |

## 2. Known limitations without GitHub issue

| Area | Limitation | Details |
|---|---|---|
| action arguments | `/` inside an argument must be written as `//`; not documented | [TODO.md](TODO.md) → "Action arguments" |
| action arguments | `:` cannot be escaped – an IPv6 address cannot be passed (e.g. `find-zone-from-ip:2001:db8::1`) | [TODO.md](TODO.md) → "Action arguments" |
| IPv6 | zone calculation of rules (from / to) uses only the IPv4 part of the route-to-zone mapping | [TODO.md](TODO.md) → "IPv6" |
| `type=rule-compare` | value comparison only for a subset of fields, no IPv6 / EDL, security rules only | [todo/rule-compare-ruleresolver.md](todo/rule-compare-ruleresolver.md) |
| `type=panorama-move` | limits of the move (e.g. secrets: same master key or re-enter) | [todo/panorama-move-concept.md](todo/panorama-move-concept.md) |
| data in the repo | PAN-OS release notes cache (newest 11.2.5) and platform max values (2021) outdated | [todo/develop-areas.md](todo/develop-areas.md) 1.1, 1.4 |

## Open decisions

1. Close candidates #55, #79, #45 – test and close, or keep open with reduced scope.
2. #95: implement the guard (refuse `create` with more than one location) – small change.
3. Should limitations from section 2 get their own GitHub issues, so that the issue list is the single source?
