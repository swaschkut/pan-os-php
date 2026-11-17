# TODO – loose scripts in `utils/develop/`

**Status:** inventory (2026-11-17), no code changed
**Code reference:** `alpha` `63fa7da`
**Related:** [TODO.md](TODO.md), folders in `utils/develop/`: [todo/develop-areas.md](todo/develop-areas.md)

The 26 PHP scripts directly in `utils/develop/` (not in a sub folder). None of them is reachable via
`pan-os-php type=`; they are started with `php utils/develop/<script>.php`. Purpose is taken from the script code
(arguments, API calls, comments).

Recommendation:
- **remove** – covered by an existing `type=` / action, check once and delete
- **action** – logic is useful, move into an existing type as action / filter
- **type** – worth an own `type=`
- **keep** – stays as develop / helper script
- **check** – customer specific or unclear, owner decides

## Overview

| Script | Purpose | Input / arguments | Covered by | Recommendation |
|---|---|---|---|---|
| `object-merger.php` | object merger, template script (`argument1`, `optional_argument2`) | `in=` | `type=object-merger` | remove |
| `rule_compare.php` | compare rules of two files | `file1=`, `file2=` | `type=rule-compare` | remove |
| `address_object_move.php` | move shared address / address-group objects with a given tag into a vsys / DG, raw XML | DG / vsys name and tag **hard coded** (`vsys1`, `SVEN`) | `type=address 'filter=(tag has X)' actions=move:vsys1` | remove |
| `tsf_request.php` | request tech support file (`<request><tech-support><dump/>`), also for all firewalls of a Panorama | `in=api://` | `type=tsf` (`utils/lib/TSF__.php`) – check if request + Panorama cycle is covered | remove after check |
| `tsf_handler.php` | parse a TSF: system info, license info | file in script | `type=tsf` | remove after check |
| `migration_playbook.php` | migration playbook: parser → address / service / tag / zone / rule edits → mergers | variables in script | `type=playbook` | remove after check |
| `panorama_combine_multiple_shared.php` | several Panorama files: each `/config/shared` into its own DG `DGx` | file names in script; template arguments | – (related: `type=panorama-move`) | check: as option of `panorama-move`? |
| `panorama-PA_cleanup.php` | Prisma Access Panorama: remove all DG / template stacks except Prisma Access (+ parent DGs), rename stacks to `Service_Conn_…`, `Mobile_User_…`, `Remote_Network_…`, `Explicit_Proxy_Template_Stack` | `in=` | – | check (SCM migration context) |
| `panorama-PA_multi2singleTenant.php` | Prisma Access multi tenant → single tenant: keep one tenant, remove the others | `tenant=`; own Todo: list tenants, remove DG / templates of removed tenants | – | check (SCM migration context) |
| `checkpoint-exclude.php` | resolve Check Point "group with exclusion" (include group − exclude group) into address objects; full / partial match by IP ranges | `type=panos\|panorama in= out= location=`, group list or file; **old argument parsing** | migration CP parser handles exclusion groups during conversion | action: `type=addressgroup` action for already migrated configs? otherwise remove |
| `grp-static-to-dynamic.php` | static address group → dynamic group (tag based) | **own legacy API class `PanAPIConnectorOLD`** (own curl, keystore) | – | action on `type=addressgroup`; legacy connector must go |
| `csv-import.php` | import from CSV, only security rules; own Todo: DG location as argument | `csv=`, `location=`, `actions=display\|import` | – | type / action: generic CSV import (rules first) |
| `config_validation.php` | check that given zones exist on every firewall of a Panorama (merged config); own Todo: multi-vsys | `zonelist=`, `cycleconnectedfirewalls` | – | check: part of `type=zone` with Panorama cycle? |
| `interface_getIP.php` | interface IPs of a zone on every firewall of a Panorama (merged config), CSV output | `zone=`, `cycleconnectedfirewalls` | `type=interface` (single device) | action: Panorama cycle for `type=interface` / `zone` |
| `cyclePanorama_ssh.php` | run a CLI command via ssh on every firewall of a Panorama | `command=`, `cycleconnectedfirewalls`, `user=`, `password=` | `type=ssh-connector` (single device) | action: Panorama cycle for `ssh-connector` |
| `inventory_sw_export.php` | `show devices all` – software / content versions of managed firewalls; own `//TODO`; **old argument parsing** | `in=api://` | `type=device` / `software-preparation` partly | action / type: device inventory export (also input for release notes / CVE, see develop-areas 1.1, 1.2) |
| `ike.php` | display IKE / IPsec crypto profiles of a vsys / template; own Todo: only for the selected vsys; **old argument parsing** | `in= location= template=` | `type=ike-profile`, `ike-gateway`, `ipsec-profile`, `ipsec-tunnel` | remove after check |
| `pan_get_user_info.php` | admin users from `/config/mgt-config/users` (role based); API only, own Todo: offline mode | `in=api:// file= out=` | – | type / action: admin user report (no type for admins today) |
| `app-id-change_report.php` | from the threat log App-ID change report: per rule show which App-ID must be added (vsys1 hard coded) | `in=api://` | `type=appid-toolbox` partly | action of `appid-toolbox` |
| `rule_create_dag_fullmesh.php` | create DAGs and full mesh security rules between them; own Todo: ACI tags → DAG | values in script | – | keep (with `cisco_aci/`) |
| `shared_gateway.php` | move a vsys config into a shared gateway; template script (`argument1`); own Todo: vsys ID limits per platform | `in=api://` | – | check |
| `panos_filetype.php` | file type list from threat / predefined XML ("226 filetype" 2025-02-11), device name filter hard coded | values in script | – | keep / check |
| `pppoe_session_clean.php` | show and clear sessions DMZ → untrust (zones **hard coded**) | `in=api://` | `type=session-browser` | action on `session-browser` (`clear` with filter) |
| `reset-config.php` | reset config part by xpath (shared / vsys / template / template-stack); `#TODO: 20170918` | `template=`, `template-stack=`, `xpath=` | `type=xpath` | check: action of `type=xpath`? |
| `wildcard_calculator.php` | Cisco wildcard mask → IP list / networks | `ip=`, `wildcardmask=`, `vendor=`, `actions=display\|displayip` | `type=address actions=move-wildcard2network`; migration CISCO parser | keep as helper |
| `wildfire_api.php` | WildFire public API: report by hash, file upload (local file) | `hash=`, `file=` | – | type: `type=wildfire` (verdict / report), API key handling like other cloud APIs |

## Patterns seen in several scripts

- **"cycle connected firewalls"** (`config_validation`, `interface_getIP`, `cyclePanorama_ssh`, `tsf_request`): the
  same loop over `show devices` + `in=api://<serial>@<panorama>/merged-config`. A shared helper / generic
  `cycleconnectedfirewalls` argument in `UTIL` would make these thin actions.
- **old argument parsing** (`checkpoint-exclude`, `ike`, `inventory_sw_export`): own `display_usage_and_exit()` /
  `PH::$args` loop instead of `new UTIL(...)`.
- **values in the script** (`address_object_move`, `pppoe_session_clean`, `panos_filetype`, `migration_playbook`,
  `rule_create_dag_fullmesh`): need arguments before they can be used by anyone else.
- **template copies** (`object-merger.php`, `panorama_combine_multiple_shared.php`, `shared_gateway.php`): still contain
  the `argument1` / `optional_argument2` placeholders.

## Open decisions

1. Delete the "remove" scripts now, or first compare the result with the existing type once.
2. Generic `cycleconnectedfirewalls` in `UTIL` – yes / no.
3. New types: CSV import, admin user report, WildFire, device inventory – which are wanted.
4. Prisma Access Panorama scripts (`panorama-PA_*`) – keep for the SCM migration or archive.
