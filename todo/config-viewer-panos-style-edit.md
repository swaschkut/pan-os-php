# config-viewer: PAN-OS-like viewer, object window, single edit → filter + action → multi-edit

Status: **in progress** (Sven, 2026-11-21).

* **Built (2026-11-21)**: steps 1 and 2 - menu on the left (Objects, Policies, Network, Device, Other; no type select),
  location on top; object window (overlay) for addresses, address groups, services, service groups, tags - each field
  applied on leaving it after a change, as one action on this object; change list as data (`time`, `user`, `type`,
  `location`, `filter`, `actions`, `field` - later the trailers of a git commit). `…/configs/<cid>/object` for one
  object. Address `name-rename` is offered although its class is "network" (only `$$reverse-dns$$` reaches the
  network - that argument is refused: `ACTION_GUARDED`). Not yet: security rules in the window (next), multi-edit with
  filter suggestions, Network / Device windows, git.

## Goal

The pan-os-php config viewer should look and work like the web UI of Panorama / a firewall (see also
fahadysf/pan-config-viewer: menu on the left, tables per object type), not like a form for pan-os-php arguments:

1. **Menu on the left** as in PAN-OS - *Objects*, *Policies* (later *Network*, *Device*); the select "type"
   (store type) goes away - the menu entry decides what is shown.
2. **Location on top** as the "Device Group" / "Virtual System" select of PAN-OS (exists since the location select:
   Panorama - device groups incl. shared; firewall - vsys incl. shared; SCM - folders and snippets).
3. **Every object opens in a window** (as the edit dialog of PAN-OS) - every field of it can be changed on its own.
4. **Every single change is tracked as filter + action** (pan-os-php), so that
5. a single change on one object (e.g. an address) can be turned into a **multi-edit** - the same action with a
   wider filter on all objects that match.

## Main idea: a change is a pan-os-php action

The viewer gets no edit logic of its own. A change of one field in the object window is executed as exactly **one
pan-os-php action on exactly this object**:

```
type=address  location=shared  filter=(name eq web01)  actions=tag-add:grp.web
```

So every change is, by construction, already "filter + action" - it can be shown, undone (discard), repeated with
another filter, and exported. Execution: the existing way - `POST …/configs/<cid>/<resource>/actions` (`location`,
`filter`, `actions`) on the loaded version (the worker), only actions that `action-classes.json` marks as reviewed
"change"; at the end "Save as new version" as today.

Rules for the mapping:

* **List fields are changed as add / remove**, never as "set the list": `tag-add:X` fits every object, "tags =
  [A, B]" does not. In the window a list field shows its members with ✕ (→ `…-remove`) and an add field
  (→ `…-add`, with suggestions from the objects of the location).
* **Single values** → the `…-set` action of the field.
* A field **without an action** is shown read-only (with a note "no pan-os-php action yet") until the action exists
  in pan-os-php - no hidden XML editing in the viewer.
* The window shows next to each changed field the action it became (as a small line), so the user learns the
  pan-os-php syntax on the way.

## Field → action (pan-os-php today, from utils/lib/util_action_filter.json)

### Address

| Field | Action (arguments) | Note |
|---|---|---|
| name | `name-rename` (stringFormula) | single edit: the new name; multi-edit only with a formula (`$$current.name$$-old`) |
| value | `value-replace` (search, replace) | check how it behaves for the types; **open: `value-set`** (a new value, type kept) |
| type | - | **open: change of type** (ip-netmask / ip-range / fqdn / ip-wildcard) - maybe together with `value-set` |
| description | `description-append` (stringFormula), `description-delete` | **open: `description-set`** |
| tags | `tag-add` (tagName), `tag-remove` (tagName) | |
| location | `move` (location, mode, recursive) | |
| (helpers) | `value-host-object-add-netmask-m32`, `value-set-reverse-dns`, `value-set-ip-for-fqdn` | as buttons in the window |

### Address group

| Field | Action | Note |
|---|---|---|
| members (static) | `add-member` | **open: `remove-member`** (check `removewhereused` - other meaning) |
| dynamic filter | - | **open** |
| name / description / tags / location | as address | check which exist for groups |

### Service

| Field | Action | Note |
|---|---|---|
| name | `name-rename` | |
| protocol, destination port | - | **open: `protocol-set`, `dstport-set`** |
| source port | `sourceport-set`, `sourceport-delete` | |
| timeouts | `timeout-set`, `timeout-halfclose-set`, `timeout-timewait-set`, `timeout-inherit` | |
| description | `description-append`, `description-delete` | **open: `description-set`** |
| tags | `tag-add`, `tag-remove` | |
| location | `move` | |

### Service group

| Field | Action | Note |
|---|---|---|
| members | - | **open: `add-member` / `remove-member`** (none for service groups today) |

### Tag

| Field | Action | Note |
|---|---|---|
| name | - | **open: `name-rename`** (only add/remove prefix / suffix, case today) |
| color | `color-set` (color) | |
| comments | `comments-add`, `comments-delete` | |
| location | `move` | |

### Security rule (almost complete)

| Field | Action | Note |
|---|---|---|
| name | `name-rename` | |
| description | `description-append`, `description-prepend` | **open: `description-set`** |
| enabled / disabled | `disabled-set`, `enabled-set` (trueOrFalse) | |
| action | `action-set` | |
| from / to (zones) | `from-add` / `from-remove`, `to-add` / `to-remove`, `from-set-any` | |
| source / destination | `src-add` / `src-remove`, `dst-add` / `dst-remove`, `src-set-any`, `dst-set-any` | |
| negate source / destination | `src-negate-set`, `dst-negate-set` (YESorNO) | |
| source user | `user-add` / `user-remove`, `user-set-any` | |
| application | `app-add` / `app-remove`, `app-set-any` | |
| service | `service-add` / `service-remove`, `service-set-any`, `service-set-appdefault` | |
| URL category | - | **open: `category-add` / `category-remove`** (no rule action for it today) |
| tags | `tag-add`, `tag-remove` | |
| profile setting | `securityprofile-group-set`, `securityprofile-profile-set` (type, profName), `securityprofile-remove` | |
| log forwarding / log at start / end | `logsetting-set`, `logstart-enable` / `-disable`, `logend-enable` / `-disable` | |
| schedule | `schedule-set`, `schedule-remove` | |
| QoS, DSRI, HIP | `qosmarking-set`, `dsri-set`, `hip-set` | |
| target (Panorama) | `target-add-device` / `target-remove-device`, `target-set-any`, `target-negate-set` | |
| position | `position-move-to-top` / `-to-bottom`, `position-move-before` / `-after` | |

NAT and the other rule types: the same mapping to be checked per field (`dnat-set`, `snat-set-interface`, …).

The complete table per type is built from `util_action_filter.json` (actions + arguments) and kept in the viewer as
a mapping file (field → action, argument from the field value) - checked by a test against
`util_action_filter.json`, so that a renamed action is noticed.

## Change list and multi-edit

* Every change is a line in the **change list** of the loaded version: time, type, location, filter, action, result
  (`1 object changed`). "Discard changes" works as today.
* **Multi-edit** next to each line: the viewer suggests filters from the properties of the changed object - e.g.
  `(value eq 10.1.1.0/24)`, `(tag has grp.dmz)`, `(name regex /^web/)`, `(object is.unused)`, location `any` - to
  pick and combine (the filter field with suggestions exists). The **number of matches is shown live** (the object
  query with a filter exists), with the list to check before.
* **Apply** runs the same action with the wider filter on all matches - one more line in the change list.
* Not every action generalizes: a rename with a literal name, `value-replace` with a value of one object - the
  multi-edit offers it only with a formula / makes the user change the argument.

## Playbook export

The change list **is** a pan-os-php playbook: every line is a step (type, location, filter, actions). Export as
playbook JSON (project file), to run with `type=playbook` on another version or another customer configuration, and
to change it in the playbook editor (exists in the project files). This turns "clicked once in the viewer" into a
repeatable, documented change.

## Steps (proposal)

1. Menu on the left (Objects / Policies, per kind of configuration: Panorama, firewall, SCM), location on top; the
   type select goes away.
2. Object window (overlay) for addresses, services, tags - each field applied after focus + change; fields without
   an action read-only; change list.
3. Multi-edit: filter suggestions from the object, number of matches, apply.
4. Security rules in the window (the actions are almost complete), then NAT.
5. Missing actions in pan-os-php (marked **open** above): `description-set` (address, service, rule), `value-set` /
   type change (address), `protocol-set` / `dstport-set` (service), `remove-member` (groups), `name-rename` (tag),
   URL category (rule) - useful on the command line too.
6. Playbook export of the change list.

## Decisions (Sven, 2026-11-21)

* **Window: overlay** as the edit dialog of PAN-OS (modal over the table).
* **Each field on its own**: a field is applied when it loses the focus after a change (blur / Enter) - one action
  per field, at once; no common "OK". A field that did not change sends nothing. A failed action shows its error at
  the field and leaves the old value.
* **Location of an object: from the PHP object** - every object belongs to its store, the store to its location
  (DeviceGroup / VirtualSystem / shared, SCM: Container / DeviceCloud / DeviceOnPrem / Snippet);
  `PH::getLocationString( $obj )` gives it (the worker uses it already for references). The window and the table show
  it; the action of a change runs with exactly this location (`location=<location of the object>`), so an object with
  the same name in another location is not touched. An object that overrides a shared one: the window says so and
  shows the other one as a reference (the "Open" link exists).
* **SCM**: folders (Container, DeviceCloud, DeviceOnPrem) have parents - `parentContainer` / `parentContainers()`,
  `childContainers()` (lib/device-and-system-classes/Container.php, BuckbeakConf.php: parent "All" when none);
  objects of a parent are seen below. **Snippets are not inherited** - a snippet is attached to containers
  (`attachedSnippets`, `getAttachedSnippets()`). Menu / location select: the folder tree with its parents, the
  snippets as their own locations; the window of a folder object shows the snippets attached to its folder only as
  information.
* **Rights**: as today - a member limited to object types / locations sees and changes only these; no access to the
  type or the location = no access (not in the menu, not in the location select, the API refuses). Nothing more
  fine-grained (no per field rights).

* **Menu: Objects, Policies, Network, Device - for Panorama and for a firewall** (Sven, 2026-11-21). Panorama: Objects
  / Policies with a device group (or shared) as location, Network / Device with a template / template stack; firewall:
  Objects / Policies per vsys (or shared), Network / Device of the firewall. SCM: the same with folders / snippets.
  Steps 1-4 build Objects / Policies; Network / Device follow (the field → action table for them is still to make).

## Changes with git, on object level (Sven, 2026-11-21)

Idea (from about 2021; only rudimentary in the project today: `git-php/` and `git=` in UTIL.php, which commits the
whole file - not reused): source XML → changes → everything documented in git → changes can be taken back. The
problem with git on the whole XML file: two changes to different objects that stand close together conflict, a small
difference in formatting gives huge diffs, and the revert of one change fails as soon as something near it changed
later. **Solution: git on objects instead of the file.**

### Objects as entries of the repository

* Every pan-os-php object has its own XML node (`$obj->xmlroot`, kept up to date by the setters) - so one object = one
  entry: path = location (`PH::getLocationString`, from the owner of its store) + type + name, rules by their UUID:

  ```
  shared/address/web01.xml
  device-group/DG-Berlin/address/web01.xml          (same name, other location = other entry)
  device-group/DG-Berlin/pre-rulebase/security/rules/<uuid>.xml
  device-group/DG-Berlin/pre-rulebase/security/order   (only the order of the rule UUIDs)
  template/T1/...                                       (Network / Device, later)
  _rest.xml                                             (everything not split yet)
  ```
* **Canonical XML per object**: one field per line, fixed order and indentation; lists whose order does not matter
  (group members, tags, source / destination of a rule) sorted - two people adding different tags change different
  lines. The rule order is its own entry (`order`), so changing a rule and moving rules do not conflict.
* A rename is a move of the entry plus the changed references (groups, rules) in the same commit - the pan-os-php
  action changes them anyway.

### No files: a bare repository fed from the DOM

git needs no working tree - it is an object database (blobs, trees, commits). One **bare repository per project** in
the volume (git is in the image), written with the plumbing commands:

| Step | git (plumbing) |
|---|---|
| store the XML of an object | `git hash-object -w --stdin` → blob id |
| tree with the changed paths | `git update-index --index-info` with a temporary index (`GIT_INDEX_FILE`), `git write-tree` |
| commit with filter / action | `git commit-tree <tree> -p <before>`, `git update-ref` |
| read an object of a state | `git cat-file -p <commit>:<path>` |
| merge / revert in memory | `git merge-tree --write-tree` (revert: `--merge-base <commit>`) → new tree or the conflicts |

* The worker of the viewer holds the loaded configuration as DOM already: it runs the action as today, serializes
  **only the objects that changed**, writes them as blobs and makes a commit - no whole XML, no file, no working tree
  per change.
* Taking a state back (revert, merge): replace only the nodes of the objects concerned (`importNode` +
  `replaceChild`) and load these objects again. The whole XML is only written when needed (download, a run, "save as
  version").
* The first commit of a project version: the split of the uploaded / imported XML.

### What it gives

* **Change list = `git log`**: each change in the viewer is one commit; its message carries the change as trailers -
  `Type:`, `Location:`, `Filter:`, `Action:`, `User:` - the playbook export is built from them. A multi-edit is one
  commit over many object entries.
* **Undo of one change = `git revert <commit>`**: touches only the entries of that commit; a conflict only when a
  later commit changed the same object - a real, small conflict (offer: revert the later one too, or choose per field).
* **Versions** = commits / tags; the diff of two versions = the list of changed objects (`type=diff` stays for the
  set commands).
* **Import from a device** on its own branch, merged with the local changes - shows what changed on the device since
  (drift) and keeps the own changes.
* **Several people**: a branch per user, merged when saved as a version - conflicts only per object, and per field.

### Merge per field

* An own merge driver for object entries (`.gitattributes`: `*.xml merge=panos`): pan-os-php merges base / mine /
  theirs field by field; set fields: additions of both sides united, removals taken out. A conflict is left only when
  both set **the same field** differently - the viewer shows "mine or theirs" for this field.

### Limits and checks

* Split / join is real work: start with shared and device group objects, then security / NAT rules; templates
  (Network / Device) stay in `_rest.xml` as one entry until split.
* A revert / merge can be logically wrong without a git conflict (an object is back, a rule that referred to it is
  deleted meanwhile): after each revert / merge pan-os-php loads and checks (references, dangling members).
* Test: split + join of a configuration = the canonical XML of the original (round trip), for Panorama, firewall, SCM.

### To check first

1. **Which objects did an action change?** Not only the matches of the filter (a rename changes the groups and rules
   that refer to it). Safest: a hash per object before / after the action; better in the long run: a "dirty" mark in
   the setters of pan-os-php. Measure with large configurations.
2. **Merge driver without a working tree**: does `git merge-tree` in a bare repository use a merge driver of
   `.gitattributes` (newer git: `--attr-source`)? If not: the viewer merges per field itself and uses git for storage,
   history and diff only.

## Open questions

* (none open at the moment - undo: see "Changes with git"; the menu: see the decisions)
