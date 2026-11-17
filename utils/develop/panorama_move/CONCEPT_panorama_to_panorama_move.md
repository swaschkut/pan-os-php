# Concept: move device groups from one Panorama to another (panorama-move)

Status: first version implemented (2026-11-17, branch `alpha`) – README_panorama_move.md; steps 1 – 5 of section 10 done,
decisions D4 / D5 (rename) open.
Script (planned): `utils/develop/panorama_move/panorama_to_panorama_move.php`, `pan-os-php type=panorama-move`.

## 1. Goal

Move a selection of device groups (DG) – with everything they need – from Panorama A (file1) to Panorama B (file2),
offline on two XML files.

Input

| argument | content |
|---|---|
| `file1=` | Panorama A configuration (source) |
| `file2=` | Panorama B configuration (target) |
| `dg-list=` | text file, one DG name of file1 per line (`#` comments, empty lines ignored) |
| `out1=` / `out2=` | output files (default `<file1>_moved-out.xml`, `<file2>_moved-in.xml`) |
| `report=` | report folder (plan, conflicts, mapping) |
| `mode=` | `check` (default: check run 4a, report only) \| `execute` (writes out1 / out2) |
| optional | `target-parent-dg=<DG of file2>` (default: shared), `shared-rules=`, `conflict=`, see 8 |

Output

1. **file2 new**: Panorama B with the transferred configuration (shared objects, DGs, templates, template stacks,
   managed devices, assignments).
2. **file1 new**: Panorama A without the moved DGs and without the template stacks, templates, managed devices and
   shared objects that are no longer used by the remaining configuration.
3. **Report** (also the only output of the check run 4a): plan (what is moved / copied / skipped and why), shared
   rule impact per moved firewall, name problems, conflicts, warnings; `plan.json` machine readable.
4. Check with existing tools: `pan-os-php type=diff file1=<file2> file2=<out2> outputformatset=set.txt` gives the set
   commands for Panorama B (same for A); `type=diff` with `outputformatset` exists in alpha (`DIFF.php`).

## 2. Terms

| term | meaning |
|---|---|
| **move** | transferred to file2 **and** removed from file1 |
| **copy** | transferred to file2, **stays** in file1 (still used by the remaining configuration of file1) |
| **relevant** | needed in file2 by the selected DGs (move + copy) |
| **selected DG** | listed in `dg-list` |

## 3. Calculation of the relevant configuration (order of the calculation)

### 3.1 Device groups

1. Selected DGs (unknown names → error).
2. **Child DGs of a selected DG**: a child cannot stay without its parent → open decision D1 (default: child DGs are
   moved too and listed in the report).
3. **Parent DGs** (full hierarchy up to shared) of every selected DG:
   * parent used only by DGs that are moved (all its children are selected / moved) → **move**
   * parent with at least one child DG that stays in file1 → **copy** (needed in file2 for the hierarchy, must stay in
     file1)
   * the content of a copied parent DG (objects, rules) goes to file2 as well – it is inherited by the moved DGs.
4. Result: list of DGs with action move / copy and their parent in file2 (top DG under `target-parent-dg` or shared).

### 3.2 Managed devices

* All devices (serial + vsys) of the moved DGs (`DeviceGroup::getDevicesInGroup()`); copied parent DGs bring no
  devices.
* **Multi-vsys firewall**: vsys of one serial in a moved and in a kept DG → conflict (a device can only be managed by
  one Panorama) – stop or list (D2).
* **HA pairs**: both peers must move; peer not in the selection → conflict.
* Device entries: `mgt-config/devices/entry[@name=serial]` (incl. vsys), DG `devices`, template stack `devices`
  (incl. per-device variable overrides).

### 3.3 Template stacks and templates

* Template stacks of the moved devices; templates assigned directly to a device (no stack).
* Templates of these stacks (order of the stack is kept).
* DG `reference-templates` of the relevant DGs (zone lookup) → these templates / stacks are relevant too.
* move / copy per stack and per template: **move** only when no device / stack / DG reference of the remaining file1
  configuration uses it, otherwise **copy**.
* Template / stack **variables** (`$var`): definitions in templates and stacks, values per device in the stack →
  transferred with the stack / template.
* `master-device` (User-ID) of DGs / stacks: serial must be one of the moved devices, otherwise warning.

### 3.4 Shared objects

Everything in file1 `shared` that the relevant DGs, templates and stacks reference – directly or indirectly:

* addresses, address groups (static members, dynamic groups: tags), regions, services, service groups, tags,
  applications (custom), application groups / filters, custom URL categories, EDL, schedules, HIP objects / profiles,
  custom threat signatures, data patterns
* security profiles and profile groups (and the profiles inside the groups), log forwarding profiles and the shared
  server profiles they use (syslog, HTTP, e-mail, SNMP), decryption profiles and the certificates / certificate
  profiles they use, authentication profiles
* recursive resolution (group → members → …) until nothing new is found
* method: pan-os-php object model (`countReferences()` / `getReferences()`, owner = shared) **plus** an XML name scan of
  the relevant XML (every `member` / text value against the names in file1 shared) as safety net for types pan-os-php
  does not model; differences between the two methods are listed in the report.

### 3.5 Shared rules (missing in the requirement)

The shared pre- / post-rules of Panorama A apply to the moved DGs, the shared rules of Panorama B will apply after
the move. Decision D3: `shared-rules=skip` (default, report lists them) | `to-top-dg` (copy them as pre rules at the
top / post rules at the end of the top moved DG).

## 4. Conflict checks in file2 (before anything is written)

| check | default |
|---|---|
| DG / template / template stack name exists in file2 | stop (D4: `conflict=rename:<suffix>` later) |
| managed device serial exists in file2 | stop |
| shared object name exists in file2 with **the same value** | reuse, nothing copied |
| shared object name exists in file2 with **another value** | stop (D5: rename with suffix + replace references, or copy into the top moved DG) |
| object name of a moved DG equals a shared object of file2 (override) | warning – the effect depends on `ancestor-objects-take-precedence` of file2 (compare the setting of A and B) |
| address vs. address group / service vs. service group same name (common namespace) | stop |
| rule names: moved rules vs. shared rules of file2 | stop (rule names must be unique in the hierarchy) |
| Panorama version of file2 older than file1 | stop; newer: warning |
| applications / threats unknown in file2 (content version) | warning (would become tmp objects) |
| template variables with the same name and another value | stop |

## 4a. Check run (`mode=check`, default)

Runs calculation 3 and the checks 4 and writes **only the report** – no output XML. `mode=execute` writes out1 /
out2 and is refused while the check run has blocking findings (unless they are accepted by an option, see D3 – D5).
The check run is the basis for the decisions D1 – D9.

### Shared rules (impact on the moved firewalls)

| report part | content |
|---|---|
| A shared rules that apply to moved firewalls | per rule: pre / post, position, name, action, target (rules with `target` only for the serials they include, negate honoured), disabled; count per moved DG |
| A shared rules that no longer apply after the move | the same list – these rules are **lost** for the moved firewalls with `shared-rules=skip` |
| B shared rules that will newly apply | all B shared pre / post rules with target `any` or a target that includes moved serials (normally none) – count, names, action |
| equivalent rules | A shared rule ↔ B shared rule with the same match and action (source / destination / application / service / user / zones / profiles after object resolution) → "covered"; similar rules (same match, other action / profile) → "differs" |
| effective rulebase per moved firewall | before: rulebase of the firewall in A (shared pre + DG hierarchy pre + DG hierarchy post + shared post); after: in B (with the D3 option) – resolved per firewall like `type=rule-compare resolvemode=firewall` (alpha, `RULE_COMPARE.php buildFirewallView()`), the difference listed per firewall |
| default rules | `default-security-rules` (intrazone / interzone) of A shared vs. B shared vs. the moved DGs |

Result per moved firewall: number of rules before / after, rules lost, rules added, rules with a different result.

### Name problems (all kinds)

| check | scope |
|---|---|
| DG, template, template stack, template variable names | relevant set of A vs. B |
| managed device serials | moved devices vs. B (incl. devices already in B, HA peer) |
| shared objects | per type: name in B with the same value (reuse) / another value (conflict) / free |
| common namespaces | address ↔ address group ↔ region / EDL (address); service ↔ service group; application ↔ application group ↔ application filter ↔ custom application; tag; security profile ↔ profile group per type |
| DG objects overriding B shared objects | names of the moved DG objects that exist in B shared → effect with `ancestor-objects-take-precedence` of B (yes: B shared wins, no: DG object wins) compared to A |
| rule names | moved DG rules vs. B shared rules and vs. each other in the new hierarchy (pre / post / all rule types); A shared rules copied by `shared-rules=to-top-dg` vs. the rules of the top DG |
| objects referenced but defined nowhere | names in the relevant XML that resolve neither in A nor in B (tmp objects) |
| predefined names | moved objects with the name of a predefined object of B (application, service-http / service-https, URL category, predefined profile) |
| case / blanks | names that differ only in upper / lower case or leading / trailing blanks (PAN-OS treats them as different, users often not) |
| invalid characters / length | names B does not accept (version of B: length limits, characters) |

Each finding: severity (blocking / warning / info), object type, name, location in A, location in B, proposal.

## 5. Transfer order into file2

1. shared objects (dependency order: tags → addresses / regions → address groups → services → service groups →
   applications / filters / groups → URL categories, EDL, schedules, HIP → server profiles, certificates →
   security profiles → profile groups → log forwarding / decryption / authentication profiles); same-value objects
   are skipped
2. managed devices (`mgt-config/devices`)
3. device groups top-down along the hierarchy (parent before child; empty DG first:
   `PanoramaConf::createDeviceGroup($name, $parent)` → also `readonly` id + `parent-dg`)
4. templates (`createTemplate()` → `readonly` id)
5. template stacks (`createTemplateStack()`), template list in the original order
6. assignments: DG `devices`, stack `devices` (+ variable overrides), `reference-templates`, `master-device`
7. DG content (objects, pre / post rules, default rules, other DG settings)
8. template content (network, vsys, device settings, variables)
9. template stack content (stack-level overrides, variables)
10. optional shared rules (D3)
11. reload file2 with pan-os-php: no unresolved references (tmp objects), hierarchy ok, devices assigned

Content is copied as XML (`importNode` of the original entries) – keeps every setting, also those pan-os-php does not
model. Steps 3–5 create the containers through the pan-os-php API so that the `readonly` section (ids,
`max-internal-id`, `parent-dg`) is consistent.

## 6. Cleanup of file1

Order: rules / content are not touched in kept DGs.

1. remove moved DGs bottom-up (children first) – XML + `readonly` entry
2. remove the moved devices from `mgt-config/devices`, from DG / stack `devices`, log collector groups, access domains
3. remove template stacks / templates with action move (+ `readonly` entries)
4. shared objects: **only the objects of the relevant set** (3.4) that have no reference any more, repeated until
   stable (group members become unused after the group). Objects that were already unused before the move stay
   (D6).
5. reload file1 with pan-os-php: no broken references

## 7. Other places that reference DGs / templates / devices (to check)

| place | file2 | file1 |
|---|---|---|
| access domains (`mgt-config/access-domain`) and admins | report only (D7) | remove moved DG / template names |
| log collector groups (`log-collector-group/…/logfwd-setting/devices`) | report (log collection of B to configure) | remove moved serials |
| plugins (SD-WAN, cloud services, ZTP …) referencing DGs / stacks / devices | report | report |
| Panorama settings in templates (`deviceconfig/system/panorama` server IPs) | report: devices still point to Panorama A (D8: replace by new IPs) | – |
| rule `target` with serials | kept (serials move with the DG) | – |
| scheduled config push, WildFire appliances, device certificates, collector-group | report | report |
| logs already stored for the moved devices | stay on Panorama A / collectors | – |

## 8. Decisions to take (D)

| | question | proposal |
|---|---|---|
| D1 | child DGs of a selected DG: move automatically or stop? | move automatically, report |
| D2 | multi-vsys device split over DGs | stop |
| D3 | shared rules of A | decided after the check run (4a): `skip` (rules lost, listed) or `to-top-dg`; the check run shows per moved firewall which A shared rules are lost and which B shared rules start to apply |
| D4 | name conflicts DG / template / stack | stop; later `rename:<suffix>` |
| D5 | shared object with same name, other value | stop; later rename / copy into top DG |
| D6 | shared objects unused before the move | keep |
| D7 | access domains in B | report only |
| D8 | Panorama server IPs in moved templates | report; option `panorama-ip=` |
| D9 | parent of the top moved DG in file2 | `target-parent-dg=`, default shared |

## 9. pan-os-php building blocks in alpha (checked)

| need | available | gap |
|---|---|---|
| load both files | `PanoramaConf::load_from_file()`; two configs in one run is used by `type=diff` / rule compare | – |
| DG hierarchy | `childDeviceGroups($nested)`, `parentDeviceGroups()`, `getDevicesInGroup(TRUE)` | – |
| create DG / template / stack incl. `readonly` | `createDeviceGroup($name,$parent)`, `createTemplate()`, `createTemplateStack()`, `setParentDG()` | – |
| remove DG | `removeDeviceGroup()` (stops on child DGs) | `unset($this->deviceGroups[$name])` while the array is numeric → object stays in memory; parent's `_childDeviceGroups` not updated |
| remove template / stack | `removeTemplate()`, `removeTemplateStack()` | same array problem; `removeTemplate()` leaves the `readonly` entry; no check that a stack still uses the template |
| devices | `ManagedDeviceStore` (`findOrCreate`, `removeManagedDevice`), `DeviceGroup::addDevice/removeDevice`, `TemplateStack::addDevice/removeDevice`, `managedDevices()` | multi-vsys / HA check new |
| references / unused | `getReferences()`, `countReferences()`, filters `is.unused`, `is.unused.recursive` | coverage of all shared types to check (server profiles, certificates, auth profiles) |
| same value of objects | merger engine / `sameValue()` per type (`MERGERENGINE.php`) | – |
| XML copy | `DH`, `importNode`; `type=upload fromXpath/toXpath` as reference | – |
| diff / set commands | `type=diff outputformatset` | – |
| existing similar scripts | `utils/develop/panorama-PA_multi2singleTenant.php` (keeps one tenant, removes DGs / stacks of the others), `panorama-PA_cleanup.php` | – |

The DG / template removal gaps are fixed first (own patch) – the cleanup of file1 depends on them.

## 10. Implementation steps

1. fixes of 9 (remove DG / template / stack)
2. check run (4a): calculation 3, conflicts 4, shared rule impact and name problems → report, nothing written
   (`mode=check`)
3. transfer into file2 (5) + validation by reload
4. cleanup of file1 (6) + validation
5. report / `plan.json`, `type=panorama-move` registration, README
6. tests: `tests/input/panorama-10.0-merger.xml` / `panorama-11.0-merger.xml` as file1, a reduced Panorama as file2;
   cases: leaf DG, DG with shared parent, parent used by others, shared stack / template, name conflict, same-value
   shared object, multi-vsys device
