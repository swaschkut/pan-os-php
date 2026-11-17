# utils/develop – areas not connected to `pan-os-php type=`

**Status:** inventory (2026-11-17), no code changed
**Code reference:** `alpha` `63fa7da`

How the list was built: `PH::$supportedUTILTypes` (92 types) and `SCM_SCRIPT_TYPES` in `lib/misc-classes/PH.php`
were compared with the folders and scripts in `utils/develop/`. Only `panorama-move` and the `scm-*` types are dispatched
into `utils/develop/`. Everything else there is a standalone script (`php utils/develop/...`) with its own argument
handling, often interactive prompts or variables edited in the script.

Purpose of each entry is taken from the script header, its API calls or (marked *name only*) its file name.

## 1. Main candidates

### 1.1 PAN-OS release notes – known / addressed issues

| | |
|---|---|
| Script | `utils/develop/panos-release-notes/panos_release_notes.php` (`version=`, `description=`) |
| Library | `lib/resources/panos_release_notes/classes/` (`panos_release_notes`, `panos_known_issue`, `panos_addressed_issue`, `panos_version`, `panos_release_misc::request_html()`) |
| Data | cached HTML + JSON in `lib/resources/panos_release_notes/{known_issues,addressed_issues}/` – PAN-OS 10.1, 10.2, 11.1, 11.2 only; **outdated**: newest known issues 10.1.14, 10.2.13, 11.1.8, 11.2.5, newest addressed issues 11.2.5-h2; no 11.0, no 12.x |
| Connected | no |

Open:
- new `type=` (e.g. `type=release-notes`): `version=` from argument **or** from the device (`in=api://`, `show system info`),
  output known issues of the running version and the issues addressed in a target version (`target-version=`)
- **first step: update the cache** (known issues are very old) – then cache update as an action (`actions=update-cache`), today the JSON is committed by hand; 11.0, 12.x and newer
  maintenance releases are missing
- `exportToExcel` / JSON output like the other types
- link with `type=software-preparation` / `software-download`: "known issues in target version" before an upgrade

### 1.2 CVE / security advisory search – **does not exist yet**

Nothing in the repo queries PAN-OS security advisories.

Source: security.paloaltonetworks.com offers a JSON rendering of the advisories (`/json`, documented as the more
stable variant) and a BETA API (`/api`) with filters by product and version. Advisories also exist as CVE JSON 5.0
records with affected / fixed version ranges.

Idea:
- `type=security-advisory` (name open): input `version=` or `in=api://` (running version, also for all devices of a
  Panorama via `show devices all`), output: CVEs affecting the version, severity, fixed version, link
- optional: check "required configuration for exposure" where possible from the config (e.g. GlobalProtect portal /
  gateway configured, management interface profile allows untrusted zones) – only a hint, no verdict
- combine with 1.1: release notes for the fixed version
- offline: cache like the release notes

Open decisions: own type or action of `type=device`; `/json` (stable) vs. `/api` (BETA); offline cache yes / no.

### 1.3 LDAP – read users and groups

| Script | Purpose |
|---|---|
| `ldap/ldap_groups.php` | direct groups of a user (`memberOf`) |
| `ldap/ldap_groups_per_users_sort.php` | groups of a user incl. nested groups (recursive) |
| `ldap/ldap_user_per_group.php` | members of a group incl. nested (AD matching rule `1.2.840.113556.1.4.1941`), account status from `userAccountControl`, Windows filetime |
| `ldap/ldap_user_per_group_table.php` | same, as table |
| `ldap/ldap_validation.php` | validation |

All: DC discovery via DNS SRV `_ldap._tcp.<domain>`, LDAPS 636, self-signed certificates accepted, interactive prompts,
no `PH` arguments. Connected: no (`type=userid-mgr` handles User-ID mappings on the firewall, not LDAP).

Open:
- arguments instead of prompts (`ldap-server=`, `base-dn=`, `bind-user=`, password from file / env, `user=` / `group=`)
- certificate check as option instead of always off
- use case for pan-os-php: compare the group mapping of the firewall (`show user group list` / `group-mapping` config)
  with AD – groups used in rules (`source-user`) but empty or unknown in AD, disabled accounts in rules
- own type (e.g. `type=ldap`) or part of `type=userid-mgr`

### 1.4 Firewall hardware compare / platform limits

Two develop folders cover the same topic and use the same data source (product comparison page on
paloaltonetworks.com, feature keys like `58-0-59-1_dfi`):

| | |
|---|---|
| Connected | no – nothing in `lib/` or `utils/lib/` reads `pan_max_values.json` |

State:
- plain download does not contain the values, the page loads them by JavaScript (that is why `html_manual/` exists)
- data is from 2021: `pan_max_values.json` has no PA-1400, PA-5440 / 5445, PA-7500, PA-400R / 450R-5G – they are already
  in the model list of `hw_request.php` but were never extracted
- `getCounters_20111119.php` / `pan_max_values_20211119.json` are old copies

Use cases for pan-os-php:
1. **platform check of a config**: count objects / rules of a config (`type=stats`, `type=config-size`) and compare with
   the limits of the model (from `show system info` with `in=api://`, or `model=`), e.g. "address objects 3812 of
   5000 (76 %)"; warning above a threshold
2. **hardware refresh / migration target**: same comparison against a target model (`target-model=`), e.g. PA-3220 →
   PA-3410, or consolidation of several firewalls / vsys into one
3. **compare models** side by side (`model=pa-3220,pa-3410`) – what the product page does, but offline and as
   `exportToExcel`
4. with EoL data (URLs below): mark models and PAN-OS versions that are end of life; together with 1.1 / 1.2 and the
   software inventory (`inventory_sw_export.php`) a "device health" view: model, version, EoL, known issues, CVEs

Open:
- data refresh: page needs JavaScript – manual save, a headless browser, or the PDF / JSON export (`createpdf?...&wt=json`)
- where the data lives: move `pan_max_values.json` to `lib/resources/` (like the release notes)
- own type (e.g. `type=platform-check`) or option of `type=stats`
- value names differ between models / page versions – needs a mapping to pan-os-php counters

Sources (former `utils/develop/panos-hw-compare/todo.txt`):
- comparison pages: https://www.paloaltonetworks.com/products/product-comparison?chosen=pa-3410 ,
  `?chosen=pa-1410,pa-1420`, `?chosen=pa-3410,pa-3420,pa-3430,pa-3440`,
  `?chosen=pa-5410,pa-5420,pa-5430,pa-5440,pa-5445,pa-5450`
- PDF: https://www.paloaltonetworks.com/apps/productcompare/createpdf?language=en_US&corename=productcompare&q=product_id:%22pa-5410%22&rows=3&json.nl=map&sort=position+asc&wt=json&chosen=pa-5410
- HW EoL: https://www.paloaltonetworks.com/services/support/end-of-life-announcements/hardware-end-of-life-dates
- SW EoL: https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-life-summary#pan-os-panorama

## 2. Further folders

| Folder | Purpose | Overlap / state | Proposal |
|---|---|---|---|
| `migration/` | vendor converters bluecoat, f5_bigip, mikrotik, pulse, sonicwall, sophos_xg, tmg, vmware_vrni, watchguard; each with "//Todo: possible to bring this in via argument" and variables in the script | sonicwall and sophos_xg also exist in `migration/parser/` (`SONICWALL`, `SOPHOSXG`); `migration/docs/vendors/watchguard.md` exists but there is no parser | per vendor: move to `migration/parser/` (`type=vendor-migration`) or drop; first compare the duplicates |
| `create/` | create custom URL, DHCP reservation, interface, interface IPs, service in policy, tag, template mgmt permitted IPs, vwire | partly covered: `dhcp-server-reservation-create` (`type=dhcp`), `create` (`type=tag`), `custom-url-category-*`; no create actions for interface, vwire, permitted IP | add missing actions to existing types, remove covered scripts |
| `cleanup_customer/` | NGFW vsys → Panorama DG, all security rules into one DG, Panorama cleanup | customer specific | generalise or archive |
| `cisco_aci/get_epg.php` | Cisco ACI EPG info, installs the cisco plugin | – | keep in develop until needed |
| `mapper/get_map_info.php` | FIB + interfaces via op commands | similar data in `type=routing` / `interface` | check if still needed |
| `playbook/process_commands.php` | process command lists to playbook JSON | `type=playbook` exists | merge or remove |
| `ironskillet/url_categories_check.php` | read-only check of URL categories | iron-skillet now in profile classes (Done table) | check if still needed |
| `appid/valdiation.php` | App-ID validation (*name only*, file name typo) | `type=appid-toolbox` | merge or remove |
| `bp_config_validation/` | validate device settings against `validate_xpath.json` (84 rules, day-1 configs) – firewall only | BP security profiles in `type=device` (`sp_spg-create-bp`) | own topic: [bp-config-validation.md](bp-config-validation.md) (create + validate for firewall, Panorama, template / template stack with general template) |
| `certificate/importCert.php` | import certificate via API (template / vsys) | `type=certificate` has no import action | add import action |
| `ui/` | web UI (root `index.php` redirects here) | in use | not a type; documentation only |
| `sase/`, `scm/` | SCM | see SCM topics | – |
| `ldap/`, `panos-release-notes/`, `panos-hw-compare/`, `info_json/` | see 1.3 / 1.1 / 1.4 | | |
| `power/` | energy dashboard / prices | **not related to pan-os-php** | move out of the repo |

## 3. Loose scripts in `utils/develop/`

The 26 scripts directly in `utils/develop/` are listed in the main folder: [TODO-develop-scripts.md](../TODO-develop-scripts.md).

`buckbeak_baseconfig.xml` / `fawkes_baseconfig.xml` are used by `utils/lib` and the install scripts stay – not TODO
items.

## Open decisions

1. Order: release notes (1.1) and CVE search (1.2) together first? Both answer "what does this version mean for this
   device". Hardware compare (1.4) answers the same for the model – possible common "device health" output.
2. CVE search: own type or `type=device` action; data source `/json` vs. `/api`.
3. LDAP: own type or part of `type=userid-mgr`.
4. Superseded scripts (see [TODO-develop-scripts.md](../TODO-develop-scripts.md), `playbook/`) – remove now or after a check.
5. `power/` – move out of the repo.
6. `migration/` vendor scripts – which ones are worth moving to `migration/parser/`.
7. Hardware compare: own type or option of `type=stats`; how to refresh the data.
