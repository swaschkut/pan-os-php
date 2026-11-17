# panorama-move – move device groups from one Panorama to another

Offline on two Panorama XML files: the selected device groups with their parent device groups, firewalls, template
stacks, templates and the shared objects they use go from Panorama A (file1) to Panorama B (file2); file1 is cleaned
up. Concept: CONCEPT_panorama_to_panorama_move.md.

```
pan-os-php type=panorama-move file1=A.xml file2=B.xml dg-list=dgs.txt                                  # check run
pan-os-php type=panorama-move file1=A.xml file2=B.xml dg-list=dgs.txt mode=execute out1=A_new.xml out2=B_new.xml
```

| argument | |
|---|---|
| `file1=` / `file2=` | Panorama A (source) / Panorama B (target) |
| `dg-list=` | text file, one device group of file1 per line, `#` comments |
| `mode=check` | default – report only (`REPORT.md`, `plan.json` in `report=`, default `panorama-move-report`) |
| `mode=execute` | writes `out1` / `out2` (default `<file1>_moved-out.xml`, `<file2>_moved-in.xml`); refused while there are blocking findings |
| `target-parent-dg=` | device group of file2 that becomes the parent of the top moved device group (default shared) |
| `shared-rules=skip\|to-top-dg` | shared pre / post rules of file1 that apply to moved firewalls and have no equivalent in file2: `skip` (default, lost – listed) or copied into the top moved device group(s) (pre rules at the top, post rules at the end) |
| `shared-settings=report\|copy-missing` | shared setting blocks without named objects (`ssl-decrypt`, `response-page`, `botnet`, …): `report` (default) or copy the blocks missing in file2 – incl. the objects they reference (e.g. certificates); blocks that differ are never overwritten (they apply to all device groups of file2) |
| `accept-blocking` | execute despite blocking findings – conflicting shared objects are not copied |

Exit code: 0 ok, 2 blocking findings.

## What is calculated

* **device groups**: selected + their child device groups (moved together, warning) + parents up to shared – a parent
  is moved when all its child device groups are moved and it has no own firewalls, otherwise copied (stays in file1)
* **firewalls**: devices of the moved device groups; a firewall with vsys in a kept device group blocks
* **template stacks / templates**: of the moved firewalls, members of these stacks, `reference-templates` of the
  device groups; moved when nothing in file1 uses them any more, otherwise copied; device lists in file2 contain only
  the moved firewalls
* **shared objects**: every shared object whose name is referenced (text values) by the relevant device groups,
  templates, stacks (and copied shared rules), resolved recursively; per object: copy / reuse (same value in file2) /
  conflict

## Check run (report)

* findings (blocking / warning / info): version, names of device groups / templates / stacks (one name space), serials
  already in file2, shared objects with the same name and another value or in the same name space (address / group /
  region / EDL, service / group, application / group / filter), case / blank look-alikes, predefined names
  (service-http / -https, URL categories, applications), device group objects overriding shared objects of file2
  (`ancestor-objects-take-precedence`), rule names (moved rules vs. shared rules / target parent chain of file2,
  copied shared rules), master-device, Panorama server settings in moved templates, access domains, log collector
  groups, plugins, objects referenced but not defined
* **shared settings**: every block of shared without named entries is compared (same / missing in file2 / differs /
  only in file2)
* **shared rule impact per moved firewall**: shared rules of file1 that apply (target / negate evaluated per serial,
  device tags counted as applying), shared rules of file2 that will apply, comparison by match (zones, addresses,
  users, applications, services, URL categories – by name) and action / profiles: covered, differs, lost, added; rules
  before / after; default security rules of both files

## What is copied

Device groups, templates, template stacks and managed devices are copied as complete XML entries – also the parts
pan-os-php does not model (new rule types, template network / device settings, variables, new features). pan-os-php
only creates the empty container (readonly id, parent-dg); the device lists keep the moved firewalls. Shared objects
are found generically (every `entry[@name]` below shared), whatever the type. Not transferred (reported): access
domains / admins, log collector groups, plugins, WildFire appliances, Panorama's own device configuration.

## Execute

file2: shared objects → shared setting blocks (copy-missing) → managed devices → device groups top-down (`createDeviceGroup`, readonly id / parent-dg) →
templates → template stacks (each created through pan-os-php, then filled with the original XML) → copied shared
rules. file1: moved device groups bottom-up, firewalls (managed devices, device / stack / template device lists, log
collector groups), moved stacks / templates, access domain members, shared objects of the relevant set that are no
longer referenced (objects that were unused before stay). Both outputs are reloaded with pan-os-php; unresolved
references are counted in the report.

Compare: `pan-os-php type=diff file1=B.xml file2=B_new.xml outputformatset=set_B.txt` (set commands for Panorama B),
the same for A.

## Limits (first version)

* shared object relevance by name references: a text value that equals a shared object name (e.g. a zone named like
  an address) also selects the object – it is copied, nothing breaks; listed in plan.json
* rule equivalence by object names, not by resolved values
* HA pairs are not visible in the Panorama configuration – check both peers are moved
* name conflicts are reported, not renamed (D4 / D5 of the concept)
