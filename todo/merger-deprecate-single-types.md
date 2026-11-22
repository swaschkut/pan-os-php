# Merger – set the single `xyz-merger` types to deprecated

**Status:** planned (2026-11-17)
**Code reference:** `alpha` `b109255`
**Related:** [todo/done/merger-missing-object-types.md](done/merger-missing-object-types.md) (`type=object-merger`)

`type=object-merger objecttype=<type>[,<type>…]|any` covers all object mergers (same class `MERGER`). The single
types stay callable for now, but are marked deprecated and point to the new call.

## Types and replacement

| Deprecated | Replacement |
|---|---|
| `type=address-merger` | `type=object-merger objecttype=address` |
| `type=addressgroup-merger` | `type=object-merger objecttype=addressgroup` |
| `type=service-merger` | `type=object-merger objecttype=service` |
| `type=servicegroup-merger` | `type=object-merger objecttype=servicegroup` |
| `type=tag-merger` | `type=object-merger objecttype=tag` |
| `type=custom-url-category-merger` | `type=object-merger objecttype=custom-url-category` |
| `type=securityprofile-merger profiletype=…` | `type=object-merger objecttype=securityprofile profiletype=…` |
| `type=securityprofilegroup-merger` | `type=object-merger objecttype=securityprofilegroup` |

**Not** deprecated (different function): `rule-merger`, `html-merger`, `merger-possible-report`.

## Important: the names are also used internally

`object-merger` runs each object type by switching `utilType` to the old name (`MERGER::$objectMergerTypes`), and
other code branches on these names:

- `utils/lib/MERGER.php` (`utilType` per objecttype)
- `utils/lib/UTIL.php` (~line 361, store selection per merger type)
- `lib/misc-classes/PanSCMAPIConnector.php`, `PanSaseAPIConnector.php` (SCM / SASE API per merger type)
- `lib/object-classes/AddressStore.php`, `ServiceStore.php`, `utils/common/actions-application.php`

→ deprecation only at the **CLI entry** (`PH::callPANOSPHP()`, dispatch ~line 2420 in `lib/misc-classes/PH.php`),
not by renaming or removing the internal names.

## Plan

1. `PH.php`: when `type=` is one of the deprecated types (direct call, not the internal switch from `object-merger`):
   `mwarning()` "type=address-merger is deprecated, please use: type=object-merger objecttype=address" + print the
   rewritten command line (like `PH::UTILdeprecated()` does for old scripts), then continue as today.
   Optional: argument to silence the warning for existing automation.
2. help / type listing: mark the types as deprecated (or hide them) in the `supportedUTILTypes` output.
3. update references to the new call (counts of `xyz-merger` occurrences):
   - `utils/api/PAN-OS-PHP.postman_collection.json` (27), `utils/lib/util_action_filter.json` (16)
   - `utils/api/v1/playbook/panorama-cleanup.json` (5), `missconfiguration.json` (4), `misconfiguration_analysis.json` (4)
   - `READMEutil.md`, `READMEdocker.md`, `utils/README.md` (5 each)
   - `utils/develop/migration_playbook.php` (13), `utils/develop/sase/scm/scm_pa_xml_to_change.php` + README (1)
4. tests: `tests/test_mergers.php`, `tests/api_test_mergers.php`, `tests/test_utilscripts.php` – run the same cases
   via `object-merger`, keep one test that the old type still works and warns
5. CHANGELOG: deprecated now, removal planned in a later version

## Open decisions

1. Removal date / version for the old types, or keep them as deprecated aliases forever.
2. Warning only, or also a pause (like the commented `sleep(600)` in `UTILdeprecated()`).
3. Playbooks / API JSON: switch now, or keep the old names until removal.
