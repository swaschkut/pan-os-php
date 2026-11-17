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
| `master-key=same\|different` | master key of file2 compared to file1 (stated by you – the master key is not in the configuration and cannot be checked offline). `same` (default): encrypted values (`-AQ==…`: pre-shared keys, bind / server profile passwords, private keys, SNMP, …) are copied unchanged. `different`: the fields are removed on transfer and listed in `SECRETS_CHECKLIST.md` to be set again in file2 |
| `conflict=stop\|rename:<suffix>` | name conflicts with file2 (device group / template / template stack, shared object, rule): `stop` (default, blocking) or rename the copy in file2 to `<name><suffix>` and rewrite its references – file1 keeps its names, see below. Suffix: letters, digits, blank, `.`, `_`, `-` |
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

## Name conflicts (`conflict=rename:<suffix>`, D4 / D5)

```
pan-os-php type=panorama-move file1=A.xml file2=B.xml dg-list=dgs.txt conflict=rename:_A                 # check run: preview
pan-os-php type=panorama-move file1=A.xml file2=B.xml dg-list=dgs.txt conflict=rename:_A mode=execute
```

Only the copies in file2 are renamed, file1 is not changed (moved entries are removed from file1 as before).

| conflict | renamed in file2 | references updated |
|---|---|---|
| device group name exists in file2 (D4) | `<dg><suffix>` | parent of moved child device groups, `readonly` parent-dg |
| template / template stack name exists (D4) | `<name><suffix>` | template stack `templates`, device group `reference-templates` |
| rule name of a moved device group exists in file2 shared / target parent chain | `<rule><suffix>` | – |
| shared rule copied with `shared-rules=to-top-dg` | `<rule><suffix>` | – |
| shared object: same name and other value, or same name space (D5) | `<object><suffix>` | every reference in the transferred configuration |

Shared objects: references are text values without a type, so all relevant shared objects with the conflicting name
are renamed together; a shared object that would be reused from file2 but references a renamed object is renamed too
(its file2 value would differ). References in a device group whose own (or parent's) local object of the same type
shadows the shared object are not rewritten (info). Still blocking: the new name exists already (choose another
suffix), the name is also a local object of another type in a moved device group chain (references ambiguous – rename
manually), firewall serials already in file2.

The report lists every rename (section *Renames in file2*) and every rewritten reference with its path; the check run
shows the same list as preview. Values of zones (`from` / `to`) and users are never rewritten; any other text value
that equals a renamed object name would be – check the list.

## Encrypted values (master key)

Values encrypted with the master key are valid only on a Panorama with the same master key. The check run lists every
encrypted field of the transferred configuration (location and path, never the value) in the report and in
`SECRETS_CHECKLIST.md`. The tool does not decrypt or re-encrypt: with another master key the values are set again in
Panorama B after the import (a commit reports the missing ones). Shared objects are compared without their encrypted
values (masked); a reused object with encrypted values is listed as info.

## Limits (first version)

* shared object relevance by name references: a text value that equals a shared object name (e.g. a zone named like
  an address) also selects the object – it is copied, nothing breaks; listed in plan.json
* rule equivalence by object names, not by resolved values
* HA pairs are not visible in the Panorama configuration – check both peers are moved
* name conflicts are renamed only with `conflict=rename:<suffix>`; references are found by text value (see above)
