# Device / Panorama settings without object model (`type=config-section`)

**Status:** first version implemented (2026-11-17, `alpha` `d5c0b9a` + patch): `type=config-section`, registry with 3
sections, use in `type=panorama-move` (concept 11.3)
**Code:** `utils/lib/CONFIG_SECTION__.php`, `utils/common/ConfigSection.php`, `utils/common/config_sections.json`;
docs [utils/README_config-section.md](../utils/README_config-section.md); tests `tests/test_config_section.php`,
`tests/test_panorama_move.php` (`panorama-settings`)

## Why not `type=device`

`type=device` works on objects (device group, template, stack, vsys, managed device) and is already large
(`utils/common/actions-device.php` ~5600 lines, `exportToExcel` ~350 lines). Settings like schedules are no objects;
each would need its own actions there. `type=xpath` can read / change any node, but knows nothing about entries,
fields or references.

## Approach

* **registry** (`config_sections.json`): section name → path below the device entry, scope (Panorama / firewall /
  template), references yes / no. A new section is one JSON entry, no code.
* **generic actions** for all sections: `display`, `references`, `get:xml|set|json`, `exportToHtml:FILE`
  (`ExportToHtmlHelper`, no Excel overhead), `set`, `add-member`, `remove-member`, `remove-field`, `delete`;
  offline (`out=`) and API (`edit` / `delete` on the candidate configuration)
* **fields generic**: entries are flattened (path → value), the type needs no knowledge of the elements inside
* **references**: text values / entry names that are device group / template / stack names or managed firewall serials
  → used by `type=panorama-move` (report, follow-up, cleanup of file1)

## Sections

| section | path | state |
|---|---|---|
| `deployment-update-schedule` | `deviceconfig/system/deployment-update-schedule` | done (registry, panorama-move) |
| `config-bundle-export-schedule` | `deviceconfig/system/config-bundle-export-schedule` | done (registry) |
| `permitted-ip` | `deviceconfig/system/permitted-ip` (Panorama, firewall, template) | done (registry) |

## Open

1. **verify with a real configuration**: element names inside `deployment-update-schedule` /
   `config-bundle-export-schedule` (tests use example structures); confirm which GUI function
   `deployment-update-schedule` is (Panorama > Scheduled Config Push or Device Deployment > Dynamic Updates >
   Schedules) – the type works either way, the README / report wording may change
2. more sections: access domains (`mgt-config/access-domain`), log collector groups, admin roles, other
   `deviceconfig/system` settings with entries; then panorama-move could read access domains / log collector groups from
   the registry instead of its own code
3. sections without named entries (single settings blocks, e.g. `deviceconfig/system/update-server`): `display` /
   `set` would need a mode without `entry`
4. RQuery filter (`filter=`) for entries – today only `entry=` by name
5. `type=diff`-like compare of a section between two files (Panorama A ↔ B)
6. `in=api://`: load only the section (`show` / `get` on the xpath) instead of the whole configuration
