# Device best-practice settings – create and validate (firewall, Panorama, template / template stack)

**Status:** concept (2026-11-17)
**Code reference:** `alpha` `5aaf3f1`; today `utils/develop/bp_config_validation/` (standalone, firewall only)
**Related:** [panorama-config-sections.md](panorama-config-sections.md) (`type=config-section`, shared class
`ConfigSection`), best-practice rows of the Done table in [TODO.md](../TODO.md) (iron-skillet / BP security profiles),
[scm-gap-remediation.md](scm-gap-remediation.md), [scm-prisma-access-lifecycle.md](scm-prisma-access-lifecycle.md)
(maturity report)

## Goal

Some device settings are Palo Alto Networks best practice and should be on **every** firewall: login banner, idle
timeout, admin lockout, password complexity, API key lifetime / certificate, commit lock, rule settings
(`rule-require-tag`, …), log settings, … The same two steps as for security profiles:

1. **create** – deliver the settings with the initial configuration, like `type=device actions=sp_spg-create-bp` /
   `sp_spg-create-alert-only-bp` do for security profiles (iron-skillet snippets in the profile classes)
2. **validate** – check an existing configuration against the rules and report / fix the differences

for every kind of configuration:

| target | where the settings live |
|---|---|
| standalone firewall | `/config/devices/entry[@name='localhost.localdomain']/deviceconfig/…`, `/config/mgt-config/…` |
| Panorama itself | the same paths in the Panorama configuration (Panorama's own management settings) |
| template | `…/template/entry[@name=T]/config/devices/entry/deviceconfig/…` (and `config/mgt-config/…` – to verify) |
| **template stack** | effective value = stack-level value (stack `config`) first, then the templates in stack order – first match wins. Typical: a **shared / general template** in every stack carries the best-practice settings |

## Current state (`utils/develop/bp_config_validation/`)

* `validate_xpath.json`: 84 rules (70 active, 14 off: audit tracking, MOTD, SNMP v3), each with `xpath` (relative),
  `value` (expected), `variable-name` (iron-skillet placeholder, e.g. `{{ TIMEZONE }}`, 72 rules), `comment`;
  areas: `deviceconfig/setting` (46), `deviceconfig/system` (26), `mgt-config/password-complexity` (11), one vsys
  rule. `validate_xpath_old.json` is an older copy.
* `bp_config_validation.php`: copy of the script template (`argument1` / `optional_argument2` still there);
  `actions=display` (default) | `compare` | `implement`; own HTML table output
* **firewall only** – the Panorama branch is empty (`$mainXpath` is never set), no template / template stack
* `implement` only sets **missing** values; differing values are not changed (empty branch); API mode with
  `sendSetRequest` per value
* comparison: text after whitespace normalisation – no "at least" / "at most" (e.g. minimum password length ≥ 12),
  no member lists, no "exists"
* placeholders (`{{ … }}`) are documentation only – no variables file per customer
* day-1 reference configurations: `day1config-firewall.xml`, `day1config-firewall2.xml`, `day1_firewall_final.xml`,
  `day1config-Panorama.xml`

## Proposal

### Rule set

Move the rules next to the other best-practice data (e.g. `utils/api/v1/bp/bp_device_settings_panw.json`, like
`bp_sp_panw.json`) and extend each rule:

| field | |
|---|---|
| `id`, `title`, `comment`, `source` | stable id for reports / exceptions; source: iron-skillet, PANW BP doc, own |
| `xpath` | relative to the device entry (`deviceconfig/…`) or to the config root (`mgt-config/…`) – as today |
| `scope` | `firewall`, `panorama`, `template` (Panorama-only settings vs. firewall settings that come from a template) |
| `check` | `equals` (default) \| `min` \| `max` \| `exists` \| `absent` \| `members-include` \| `one-of` |
| `value` / `variable` | expected value, or a variable (`{{ TIMEZONE }}`) taken from a variables file with a default |
| `severity` | `high` / `medium` / `low` / `info` |
| `create` | yes / no – part of the initial configuration (step 1) or check only |
| `min-version` | PAN-OS version from which the setting exists |
| `enabled` | replaces `"check": "true"` |

Customer variables: `vars=customer.json` (`{"TIMEZONE": "Europe/Berlin", "LOGIN-BANNER-TEXT": "…"}`).

### Where it runs

Own type `type=device-bp` (name open) instead of more actions in `type=device` (already ~5600 lines, see
[panorama-config-sections.md](panorama-config-sections.md)); reuses `ConfigSection` (node paths, create along the
path, set commands, HTML via `ExportToHtmlHelper`).

| argument | |
|---|---|
| `in=` / `out=` | firewall or Panorama, offline or `in=api://` |
| `rules=` / `vars=` | rule set (default: the PANW file) / customer variables |
| `target=` | `device` (firewall / Panorama itself, default) \| `template:<name>` \| `template-stack:<name>` \| `template-stack:any` |
| `actions=` | `validate` (default) \| `create` \| `fix` \| `exportToHtml:FILE` \| `exportToJson:FILE` |
| `fix-into=` | template stack: template that receives fixes / created values (default: the general template, see below) |

Actions:

* `validate` – per rule: ok / differs / missing / not applicable (version, scope); for a template stack also **where
  the effective value comes from** (stack override, template name) and whether a later template is hidden by an
  earlier one
* `create` – step 1: write all rules with `create: yes` (missing **and** differing) into the target – the device-level
  counterpart of `sp_spg-create-bp`; for a new Panorama: into the general template
* `fix` – like `create`, but only the rules that failed `validate` (and only with `overwrite` for values that
  differ, otherwise only missing ones)
* reports: text, JSON (`shadow-json`), HTML (one row per rule: id, title, expected, actual, source of the value,
  result, severity)

### Template stack and the general template

* effective value per rule: stack `config` → template 1 → template 2 → … (first one that has the xpath)
* **general template**: `general-template=<name>` or detected automatically (template that is part of every / of
  the selected stacks); report per rule whether the value comes from the general template, from another template or
  from a stack override – an override of a best-practice value in a site template is a finding
* `fix-into` default: the general template; a rule that is overridden by an earlier template / the stack is reported,
  not silently "fixed" in the general template (the fix would have no effect)
* values set locally on the firewall (not in Panorama) are not visible offline – API on the firewall:
  `type=device-bp in=api://<serial>@<panorama>` validates the merged / running configuration

### Day-1 / initial configuration

* `create` on an empty / new configuration = the device part of a day-1 configuration; together with
  `sp_spg-create-bp`, `logforwardingprofile-create-bp`, `zpp-create-bp`, `cleanuprule-create-bp`,
  `defaultsecurityRule-create-bp` → one playbook "day-1 best practice" (`type=playbook`, JSON in
  `utils/api/v1/playbook/`) for firewall and Panorama (general template + device groups)
* the `day1*.xml` files of the folder become test fixtures (expected result of `create`)

## Steps

1. rule set: convert `validate_xpath.json` to the new format (ids, checks, scope, create, variables); remove
   `validate_xpath_old.json`
2. `validate` for firewall and Panorama (`target=device`) + reports
3. template and template stack (effective value, general template, overrides)
4. `create` / `fix` (offline, API), set commands output
5. playbook "day-1 best practice"; tests with the day-1 fixtures
6. remove `utils/develop/bp_config_validation/` (or keep only the reference XML as fixtures)

## Open decisions

1. Name / place: own type (`type=device-bp`, `type=config-validation`) or part of `type=config-section`
   (mode for single settings, open item 3 there).
2. Rule set ownership: PANW best-practice default + customer file (override / disable rules by id)?
3. General template: argument only, or automatic detection.
4. `fix` on differing values: always, or only with `overwrite`.
5. SCM: same rules for SCM device settings (folders / snippets) later – mapping xpath ↔ SCM API.
