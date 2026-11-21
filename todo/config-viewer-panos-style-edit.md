# config-viewer: PAN-OS-like viewer, object window, single edit → filter + action → multi-edit

Status: **in progress** (Sven, 2026-11-21).

* **Built (2026-11-21)**: steps 1 and 2 - menu on the left (Objects, Policies, Network, Device, Other; no type select),
  location on top; object window (overlay) for addresses, address groups, services, service groups, tags - each field
  applied on leaving it after a change, as one action on this object; change list as data (`time`, `user`, `type`,
  `location`, `filter`, `actions`, `field` - later the trailers of a git commit). `…/configs/<cid>/object` for one
  object. Address `name-rename` is offered although its class is "network" (only `$$reverse-dns$$` reaches the
  network - that argument is refused: `ACTION_GUARDED`). Step 4 (2026-11-21): the rule window for every rule
  type (Policies menu) - list fields add / remove / set any, -set fields, move; the description of a rule with the
  aliases of pan-os-php (`$$comma$$`, `$$colon$$`, `$$forwardslash$$`, `$$pipe$$`) - set as
  `description-replace-character:<old>,<new>`. Shown only: URL category. NAT translations (2026-11-21): source
  and destination translation in the rule window - new pan-os-php actions `snat-set:<type>,<addr|addr>,<interface>,
  <bidirectional>`, `snat-remove`, `dnat-remove`, `dnat-set` with the port; not yet: persistent dynamic IP, DNAT
  distribution, the interface IP as an object (written as value). DNS Rules under *Other* next to Threat Rules. Aliases and tag rename (2026-11-21): `PH::textAliases()`
  (`$$comma$$`, `$$forwardslash$$`, `$$colon$$`, `$$pipe$$`, `$$newline$$`, `$$space$$`) in `description-append` of
  addresses and services and in `comments-add` of tags; new tag action `name-rename` (`$$current.name$$`,
  `$$location$$`, the references follow); in the window: tag name editable, descriptions / comments with `,` `:` `/`. Step 3 (2026-11-21): multi-edit - "Multi-edit …" at a change of one object: filter
  suggestions from the object (filter fields of the meta only), location, own filter, the number of matches and their
  names live, apply = one change with the wider filter (field `multi-edit`); the object itself left out by default; a
  rename needs a `$$` formula. Playbook export (2026-11-21): "Export as playbook …" (unsaved changes) and
  "Playbook" at a version saved from changes (column `configs.changes`: the change list as JSON); one step per change
  with a comment; checked like an uploaded playbook; save as a project file or download. Tested: the playbook of the
  changes, run on the original version, gives the same changes. Network / Device (2026-11-21): every menu entry opens its objects in a window - zones
  with their fields (name, zone protection profile, log setting, user identification, packet buffer protection; the
  only reviewed network type), every other type in a generic window (all fields, read only, nested values as one
  line). Panorama: objects of a template carry it (`template` column; `…/object?template=`, changes with
  `location=any` + `template=` - only when the name is unique in the template; in the change list and the playbook).

### Still open (list of Sven, 2026-11-21)

* git on object level (see below): steps 1-3 and step 4a (merge per field, XML and history per object in the window) built 2026-11-21; open: step 4b (branches: import from a device = drift, a branch per user, merge when saved)
* **run.log in a window** - shown in the page (as the LDAP results), not only as a download
* ~~**the XML snippet of each object**~~ - built 2026-11-21 (git step 4a): XML and history in the object window
* **search text in the whole XML** (as `type=xpath`): a name / text anywhere in the configuration, with options -
  exact / contains / regex, element names or values, attributes (`name=`), limited to a location / template; the hits
  with their XPath and a link to the object (window) where there is one
* more network / device types editable as soon as their actions are reviewed (action-classes.json `reviewed`)
* **object-merger in the viewer** (Sven, 2026-11-21) - see "Object merger in the viewer" below
* **what can not be changed in the windows yet** - see "Not editable in the windows" below (missing pan-os-php
  actions vs. windows not built)

### Object merger in the viewer (open, 2026-11-21)

* Today the viewer offers no merger: playbook steps `*-merger` are refused (`playbookCheck`), there is no run type for
  `type=object-merger`, and the change window has no merge.
* Wanted: `type=object-merger objecttype=<type>[,…]|any` (all object mergers, class `MERGER`) on the loaded version -
  first a **preview** (which objects would be merged into which, with the merger's own report / `merger-possible-report`),
  then **apply** on the memory as one change; with the git history the merge is **one commit** (all merged and
  removed objects and every reference) and can be **undone** as a whole (step 3).
* Arguments of the merger (`objecttype`, `location`, `pickfilter`, `excludefilter`, `allowmergingwithupperlevel`,
  `mergecountlimit`, `DupAlgorithm`, …) as fields of the window with the values of the merger only (checked like the
  playbook steps); a member limited to locations: only merges inside them (no upper level).
* In the change list: one entry `object-merger …` (multi-edit / playbook: a step `type=object-merger`, allowed once
  reviewed).
* pan-os-php itself: set the single `xyz-merger` types to deprecated in favour of `type=object-merger`
  ([merger-deprecate-single-types.md](merger-deprecate-single-types.md), planned, not built).

### Not editable in the windows (state 2026-11-21)

Fields of the own windows that are read only - **missing pan-os-php action** (the window shows why):

| Type / field | Missing in pan-os-php |
|---|---|
| address: type, value of ip-range / fqdn / ip-wildcard | `value-set` / change of type (only `value-replace` for ip-netmask) |
| address, service, rule: description | `description-set` (works as `description-delete` + `description-append`: two actions) |
| address group: remove a member, dynamic filter | `remove-member`, an action for the filter |
| service: protocol / port | `protocol-set`, `dstport-set` |
| service group: members | `add-member` / `remove-member` (none for service groups) |
| rule: URL category | `category-add` / `category-remove` |
| NAT: persistent dynamic IP, DNAT distribution, interface IP as an object | in `snat-set` / `dnat-set` (built 2026-11-21) not yet |
| zone: remove the zone protection profile | an action for it; yes / no fields show no current value |
| every field outside descriptions / tag comments | `,` and `:` not possible (no aliases there) |

Types with the **generic window only** (all fields, read only):

| pan-os-php has change actions - only the window is missing | pan-os-php has no change action |
|---|---|
| EDL, schedule (name actions), security profiles (61, e.g. `alert-only-set`, `best-practice-set`), security profile groups (`securityprofile-set` / `-remove`), log forwarding, application (create / delete / move), interfaces (`name-rename`, AE group), zone protection profiles (`alert-only-set`), device (38), static routes / IKE / IPSec crypto (delete only), DHCP (reservation) | threats, threat rules, DNS rules, virtual wires, routing, IKE gateways, IPSec / GRE tunnels, GlobalProtect portals / gateways / tunnels, interface management profiles, certificates, certificate profiles, SSL/TLS service profiles |

(counted from `utils/develop/config-viewer/action-classes.json`, class `change`)

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

NAT and the other rule types: the same mapping per field; NAT translations built 2026-11-21 (`snat-set`, `snat-remove`, `dnat-set`, `dnat-remove`).

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
   type change (address), `protocol-set` / `dstport-set` (service), `remove-member` (groups), ~~`name-rename` (tag)~~ (built 2026-11-21),
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

### Step 1 built (2026-11-21): split and join

* `lib/misc-classes/ConfigObjectSplit.php`: `split( DOMDocument )` → `array( path => text )`, `join( array )` →
  `DOMDocument`, `canonical( node )`. CLI: `pan-os-php type=config-split in=<config.xml> out=<folder>`,
  `mode=join in=<folder> out=<config.xml>`, `mode=check in=<config.xml>`.
* Path = the XML path from `<config>` (element names and the names of the entries), e.g.
  `devices/localhost.localdomain/device-group/DG-Berlin/address/web01.xml`, `shared/address/web01.xml`; rules by their
  UUID (without one: by name). Locations: `/config/shared` and every entry of a device group, vsys, SCM snippet,
  container (folder), device. Stores: address, address-group, service, service-group, tag, schedule, external-list,
  region, application, application-group, application-filter, dynamic-user-group, profile-group, profiles/*,
  threats/*, log-settings/profiles, (pre-|post-)rulebase/*/rules. Templates, network, device: in `_rest.xml`.
* **Different from the plan above**: every store has an `_order` (one key per line) - also the objects, so the
  configuration comes back in its own order (no sorting); the member lists in an object are not sorted either (the
  field-wise merge driver unites them, see below). `_order` of objects: merge = union later.
* A store with anything else than named `<entry>` elements (a comment, an unnamed child) stays whole in `_rest.xml`.
  Names in paths: `%` `/` control characters and a leading `.` as `%XX`; the same name twice in a store: `~2`.
* Tested (`tests/test_config_split.php`): round trip (split + join = the same configuration up to the whitespace
  between elements) for the Panorama / SCM configurations of `tests/input` and a synthetic firewall; join with a
  changed, deleted, added entry, moved rules, a store added after the split; refused: a location that is not there,
  an entry that is no XML. Large synthetic Panorama (60 001 objects, 20 device groups): split 1.1 s, join 1.4 s,
  96 MB. A git repository accepts all paths (spaces, `%XX`).

### Step 2 built (2026-11-21): a commit per change

* `utils/develop/config-viewer/lib/ViewerGit.php`: bare repository `<project>/history.git` (created on the first
  load; no hooks, `gc.auto 0`), written with `git fast-import` only (one process per commit, no index, no files).
  Refs: `refs/viewer/versions/<version file>` (the first commit: `ConfigObjectSplit::files()` of the DOM after the
  load of pan-os-php), `refs/viewer/work/<version file>` (the unsaved changes, one commit each).
* Worker (`bin/worker.php`): after the real run of a change `ConfigObjectSplit::state()` of the DOM, `changes()`
  against the state before → `put` / `delete` → one commit; message = one line + trailers (`Type:`, `Location:`,
  `Template:`, `Ruletype:`, `Filter:`, `Action:`, `Field:`, `User:`), committer = the user, time = the change.
  Save: `versions/<new>` = the last commit, the work ref moves; discard: the work ref is deleted. Status of the worker:
  `history` (on, head, commits, error). A git error stops the history of this worker only (logged), never a change.
* **Which objects did an action change** (to check 1): a hash of every entry as it is in the DOM (`saveXML` + md5,
  the split stores emptied for the rest) before / after - no change in pan-os-php needed. Measured with 60 001
  objects: state 0.27 s; first commit 2.2 s; one change 0.35 s (1 entry); a multi-edit of 2 500 objects 0.5 s;
  repository 6.9 MB.
* Tested (`tests/test_config_viewer.php` 9b): a commit per change on the first commit of the version; trailers and
  user; a description change = exactly `shared/address/shared-host1.xml`; a tag rename = tag D + A, `tag/_order`, the
  address that refers to it; **the tree of the saved version = the split of the saved file, every object**.
* Not yet: a version recovered from the autosave file (worker stopped) starts a new history (its first commit is the
  recovered state, without the commits before); a version made by a run (playbook, plug-in) the same. The page shows
  nothing of the history yet.

### Step 3 built (2026-11-21): undo of one change

* Each change of the list carries its commit (`commit`). `POST …/configs/<cid>/undo {index}` → worker `viewerUndo()`:
  `git merge-tree --write-tree --merge-base=<commit> <head> <commit>^` (revert in memory, no working tree) → the tree
  or the conflicting paths (refused: "take the later change back first"); the entries that differ between head and
  that tree replace those of the memory (`ConfigObjectSplit::files()` of the state + `join()`), and **pan-os-php
  loads the whole configuration again** - the plan "replace only the nodes and load these objects again" does not
  work: the PHP objects of pan-os-php (values, members, references) are parsed from the XML once; changed nodes under
  them would not be seen. Load of the result fails → the memory before stays.
* Then one commit `undo: …` with `Reverts: <commit>`; the change is marked `undone`, an entry `type undo` follows in
  the list; both are left out of the playbook. Checks after the load: objects used but not there (pan-os-php tmp
  objects, new against before the undo) are named; when the tree in memory differs from the tree git computed
  (pan-os-php creates a tag that is used but missing when it loads), the entries are named as a warning.
* Permissions: write; a member limited to types / locations only for a change in them (`queryArgs` of the change).
* Tested (`tests/test_config_viewer.php` 9c, 13 checks): conflict refused and nothing changed; one change undone, the
  others stay; twice / an undo / a bad index refused; later change undone first, then the earlier one; all undone =
  the tree of the version; playbook; a rename undone while a later change uses the new name (address: named as not
  there; tag: pan-os-php creates it - said); read only and other locations refused. Browser: Undo in the change list.
* Limits: the line merge of git - two changes of different fields in neighbouring lines of one object conflict
  (merge driver per field: step 4). A large configuration is loaded again for an undo (the time of opening it).
  Only unsaved changes (the list of the loaded version).

### Step 4a built (2026-11-21): merge per field, XML and history per object

* `lib/misc-classes/ConfigObjectMerge.php` (standalone): three-way merge of one entry - elements matched by key
  (`<member>` by text = a set, `<entry>` by name, other elements by name + place), attributes per name; one side
  changed = taken, both the same = taken, both different = conflict, removed on one side + changed on the other =
  conflict. `_order`: removals out, additions after their predecessor, a move of one side kept. `_rest.xml` the same
  (whole document).
* Merge driver `utils/develop/config-viewer/bin/git-merge-entry.php %O %A %B %P`, set by `ViewerGit::ready()`:
  `merge.panos.driver` in the repository config and `info/attributes` (`*.xml merge=panos`, `_order merge=panos`) -
  git reads `info/attributes` also in a bare repository (tested with `git merge-tree`, git 2.43). Used by the undo.
* Object window: `…/object` gives `xml` (canonical XML of `xmlroot`, worker read flag `x-xml`) and `history` (path of
  the entry `ConfigObjectSplit::entryPath()`, `git log -- <path>` of the work ref, the entry after each commit);
  `history` null for objects in `_rest.xml` (templates).
* Tested: `tests/test_config_merge.php` (16 checks: fields, members, removal / change, attributes, `_order`,
  `_rest.xml`, git undo with the driver vs. conflict); `tests/test_config_viewer.php` (undo merged per field; XML and
  history of an object; a template object without history). Browser: XML and history in the window.

### Step 4b open: branches

* Import from a device (read only, todo/config-viewer-device-access.md) on its own branch
  `refs/viewer/import/<project>/<time>`: diff against the version = what changed on the device (drift); merge into
  the work with the merge driver - conflicts per field shown "mine or the device's".
* A branch per user (several people on one version): today all members change the same memory of one worker (one
  change list) - a branch per user needs a worker per user or a merge of their change lists when saving; decide first
  whether it is wanted.
* Objects of templates (Network / Device) split into entries (today `_rest.xml`): history and merge per object there.

### To check first

1. ~~**Which objects did an action change?**~~ - solved in step 2 (hash per entry before / after, see above). Not only the matches of the filter (a rename changes the groups and rules
   that refer to it). Safest: a hash per object before / after the action; better in the long run: a "dirty" mark in
   the setters of pan-os-php. Measure with large configurations.
2. ~~**Merge driver without a working tree**~~ - **yes** (tested 2026-11-21, git 2.43 as in the image):
   `git --attr-source=<commit> merge-tree --write-tree <a> <b>` in a bare repository calls the merge driver of
   `.gitattributes` (`*.xml merge=panos`, `merge.panos.driver` in the repository config). Without it two changes of
   different fields in neighbouring lines of one object conflict (line merge). Original question: does `git merge-tree` in a bare repository use a merge driver of
   `.gitattributes` (newer git: `--attr-source`)? If not: the viewer merges per field itself and uses git for storage,
   history and diff only.

## Open questions

* (none open at the moment - undo: see "Changes with git"; the menu: see the decisions)
