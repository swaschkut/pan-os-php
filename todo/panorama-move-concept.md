# Concept: move device groups from one Panorama to another (panorama-move)

Status: first version implemented (2026-11-17, branch `alpha`) – README_panorama_move.md; steps 1 – 5 of section 10 done;
D4 / D5 implemented as option `conflict=rename:<suffix>` (2026-11-17), default stays `stop`; step 6 done
(`tests/test_panorama_move.php`, fixtures `tests/input/panorama-move/`); D8 (`panorama-ip=`) and the follow-up checklist
`MIGRATION_FOLLOWUP.md` (report-only places of section 7) done; rule comparison by resolved values + effective rule
base check (section 4a) done with `utils/common/RuleResolver.php` – shared class, to be used by `type=rule-compare`.
Script: `utils/develop/panorama_move/panorama_to_panorama_move.php` + `lib/PanoramaMove.php`, `pan-os-php type=panorama-move`.
Code compared with the concept on 2026-11-17 (`alpha` `3a10f30`): open items in section 11.

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
* **HA pairs**: both peers are managed in the same device group and move with it – no own check (HA is not part
  of the Panorama configuration).
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
* method (implemented): XML name scan of the relevant XML (every `member` / text value against the names in file1
  shared, `PanoramaMove::tokens()` / `objectIndex()`) – covers all types, also those pan-os-php does not model. The
  planned second method (pan-os-php object model `getReferences()`) with a difference list was not implemented;
  pan-os-php is used to validate the outputs (unresolved references after reload).

### 3.5 Shared rules (missing in the requirement)

The shared pre- / post-rules of Panorama A apply to the moved DGs, the shared rules of Panorama B will apply after
the move. Decision D3: `shared-rules=skip` (default, report lists them) | `to-top-dg` (copy them as pre rules at the
top / post rules at the end of the top moved DG).

## 4. Conflict checks in file2 (before anything is written)

| check | default |
|---|---|
| DG / template / template stack name exists in file2 | stop (D4: or `conflict=rename:<suffix>`) |
| managed device serial exists in file2 | stop |
| shared object name exists in file2 with **the same value** | reuse, nothing copied |
| shared object name exists in file2 with **another value** | stop (D5: or `conflict=rename:<suffix>` – rename + replace references) |
| object name of a moved DG equals a shared object of file2 (override) | warning – the effect depends on `ancestor-objects-take-precedence` of file2 (compare the setting of A and B) |
| address vs. address group / service vs. service group same name (common namespace) | stop |
| rule names: moved rules vs. shared rules of file2 | stop (rule names must be unique in the hierarchy) |
| Panorama version of file2 older than file1 | stop; newer: warning |
| applications / threats unknown in file2 (content version) | done (11.1): the content version of file2 is not in the configuration – applications (also in application groups) and threat IDs (threat exceptions) used are listed (`plan.json` `content`, info + follow-up: same or newer content on Panorama B); names unknown to pan-os-php's predefined content → warning `content` |
| template variables with the same name and another value | info – variables are defined per template / stack, no conflict (changed during implementation) |

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
| equivalent rules | done (resolved values, `utils/common/RuleResolver.php`): A shared rule ↔ B shared rule with the same match and action (source / destination as IPv4 / IPv6 ranges, services as ports, applications with groups expanded, users, zones, profiles resolved) → "covered"; same match, other action / profile → "differs" |
| effective rulebase per moved firewall | done: before = rule base of the firewall in A (shared pre + DG hierarchy pre + DG hierarchy post + shared post), after = in the simulated B (the transfer of execute on a copy of file2, with the D3 option and renames) – resolved per firewall with RuleResolver (same name resolution as `type=rule-compare resolvemode=firewall`); transferred rules that resolve differently → warning, order per rule type checked |
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
| objects referenced but defined nowhere | done (11.2): address / service (tmp objects) + tags, schedules, log forwarding profiles, security profiles, profile groups (and their profiles), URL categories of the rules of the relevant DGs, resolved on the XML as stored along the DG chain to shared and against the predefined names; also counted in the validation of out1 / out2 |
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
| access domains (`mgt-config/access-domain`) and admins | report + MIGRATION_FOLLOWUP.md (D7) | remove moved DG / template / stack names and firewalls |
| log collector groups (`log-collector-group/…/logfwd-setting/devices`) | report + MIGRATION_FOLLOWUP.md | remove moved serials |
| plugins (SD-WAN, cloud services, ZTP …) referencing DGs / stacks / devices | report + MIGRATION_FOLLOWUP.md | report + MIGRATION_FOLLOWUP.md |
| Panorama server in templates / stacks (`deviceconfig/system/panorama/local-panorama/panorama-server(-2)`, older `deviceconfig/system/panorama-server(-2)`) | done: report; `panorama-ip=` replaces it in the file2 copies (D8) | unchanged |
| rule `target` with serials | kept (serials move with the DG) | – |
| scheduled config push, WildFire appliances, device certificates, collector-group | report | report (WildFire, log collectors, device certificates in `MIGRATION_FOLLOWUP.md`; scheduled config push **open**, see 11) |
| logs already stored for the moved devices | stay on Panorama A / collectors | – |

## 7a. Encrypted values (master key)

The master key is not part of the configuration and cannot be compared offline. Encrypted values (`-AQ==`) of the
transferred configuration are listed (location / path, never the value). `master-key=same` (default, to be confirmed on
both Panoramas): copied unchanged. `master-key=different`: the fields are removed on transfer and listed in
`SECRETS_CHECKLIST.md` to be set again in Panorama B. The tool never decrypts or re-encrypts values. Value comparison
of shared objects masks encrypted values.

## 8. Decisions to take (D)

| | question | proposal |
|---|---|---|
| D1 | child DGs of a selected DG: move automatically or stop? | move automatically, report |
| D2 | multi-vsys device split over DGs | stop |
| D3 | shared rules of A | decided after the check run (4a): `skip` (rules lost, listed) or `to-top-dg`; the check run shows per moved firewall which A shared rules are lost and which B shared rules start to apply |
| D4 | name conflicts DG / template / stack (and rule names) | done: `conflict=stop` (default) \| `conflict=rename:<suffix>` – copy in file2 renamed, references (parent DG, stack templates, reference-templates) updated |
| D5 | shared object with same name, other value / same name space | done: with `conflict=rename:<suffix>` renamed in file2 + references rewritten; all relevant objects of that name renamed together, reused objects referencing a renamed object renamed too; blocking when the new name exists or the name is a local object of another type in a moved DG chain (README) |
| D6 | shared objects unused before the move | keep |
| D7 | access domains in B | report only |
| D8 | Panorama server IPs in moved templates | done: report; option `panorama-ip=<server>[,<server-2>]` (templates and stacks, both formats; server-2 removed without a second address; variables unchanged) |
| D9 | parent of the top moved DG in file2 | `target-parent-dg=`, default shared |

## 9. pan-os-php building blocks in alpha (checked)

State of the gap column re-checked on 2026-11-17 (`alpha` `3a10f30`).

| need | available | gap |
|---|---|---|
| load both files | `PanoramaConf::load_from_file()`; two configs in one run is used by `type=diff` / rule compare | – |
| DG hierarchy | `childDeviceGroups($nested)`, `parentDeviceGroups()`, `getDevicesInGroup(TRUE)` | – |
| create DG / template / stack incl. `readonly` | `createDeviceGroup($name,$parent)`, `createTemplate()`, `createTemplateStack()`, `setParentDG()` | – |
| remove DG | `removeDeviceGroup()` (stops on child DGs) | done: removal from the numeric array by object, parent's `_childDeviceGroups` updated, `readonly` entry removed |
| remove template / stack | `removeTemplate()`, `removeTemplateStack()` | done: array problem fixed, `readonly` entry removed (`removeReadonlyEntry()`). **Open (library):** `PanoramaConf::removeTemplate()` does not check that a stack still uses the template – only the action `template-delete` checks `countReferences()`; stale commented-out DG block and `//Todo: cleanup memory` in both functions. Not relevant for panorama-move (only templates with action move are removed) |
| devices | `ManagedDeviceStore` (`findOrCreate`, `removeManagedDevice`), `DeviceGroup::addDevice/removeDevice`, `TemplateStack::addDevice/removeDevice`, `managedDevices()` | done: multi-vsys split → blocking; HA peers move with their device group (no check needed) |
| references / unused | `getReferences()`, `countReferences()`, filters `is.unused`, `is.unused.recursive` | bypassed: panorama-move uses the XML name scan (3.4) for all types; the coverage of the object model (server profiles, certificates, auth profiles) is still not complete, but not needed here |
| same value of objects | merger engine / `sameValue()` per type (`MERGERENGINE.php`) | – (panorama-move compares canonical XML, `PanoramaMove::canon()`) |
| XML copy | `DH`, `importNode`; `type=upload fromXpath/toXpath` as reference | – |
| diff / set commands | `type=diff outputformatset` | – |
| existing similar scripts | `utils/develop/panorama-PA_multi2singleTenant.php` (keeps one tenant, removes DGs / stacks of the others), `panorama-PA_cleanup.php` | – |

## 10. Implementation steps

1. fixes of 9 (remove DG / template / stack)
2. check run (4a): calculation 3, conflicts 4, shared rule impact and name problems → report, nothing written
   (`mode=check`)
3. transfer into file2 (5) + validation by reload
4. cleanup of file1 (6) + validation
5. report / `plan.json`, `type=panorama-move` registration, README
6. tests (done): `tests/test_panorama_move.php`; fixtures derived from `panorama-11.0-merger.xml` by
   `tests/input/panorama-move/build_fixtures.php`; cases: leaf DG, DG with shared parent, parent used by others,
   shared stack / template, name conflict (stop / rename), same-value shared object, multi-vsys device, encrypted
   values (master-key same / different), rename target taken, ambiguous local object, arguments

## 11. Open items (code compared with the concept, 2026-11-17)

| # | item | where | state |
|---|---|---|---|
| 1 | applications / threats used by the moved configuration but unknown in file2 (older content version of Panorama B, section 4) | `PanoramaMove::checkUnresolved()`, `predefined()` | done (2026-11-17): content version of file2 is not in the configuration → predefined applications / threat IDs used are listed (`plan.json` `content`, info finding, follow-up item); unknown to pan-os-php → warning `content`; test `unresolved-and-content` |
| 2 | unresolved references beyond address / service | `PanoramaMove::unresolvedRefs()`, `checkUnresolved()`, `validate()` | done (2026-11-17): tags, schedules, log forwarding profiles, security profiles, profile groups (+ profiles inside), URL categories, applications / application groups, threat exceptions; XML as stored (pan-os-php creates missing tags on load); test `unresolved-and-content` |
| 3 | scheduled config push (Panorama A / B) that contains moved device groups / stacks | report + `MIGRATION_FOLLOWUP.md` | open |
| 4 | `PanoramaConf::removeTemplate()`: guard when the template is still used by a stack (like `removeDeviceGroup()` with child DGs); remove the stale commented-out block / memory Todo | `lib/device-and-system-classes/PanoramaConf.php` | open (library, not needed by panorama-move) |
| 5 | D3 shared rules: `skip` / `to-top-dg` | per migration after the check run | decision per project (both options implemented) |

Next: 3 as text in the report / follow-up, 4 with the next library change in `PanoramaConf`.

Not covered by 2: references outside the rule bases (e.g. tags of address objects, log forwarding inside zone
protection or template settings) – the shared-object relevance (3.4) copies them when they exist; when they exist
nowhere, PAN-OS reports them on commit.
