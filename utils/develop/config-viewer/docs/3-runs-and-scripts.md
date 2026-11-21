# Runs and scripts

## Looking at a version

Open a version: as in the web interface of Panorama / a firewall, the **menu on the left** has *Objects* (Addresses,
Address Groups, Services, Service Groups, Tags, Applications, …), *Policies* (Security, NAT, … - one entry per rule
type), *Network* (Zones, Interfaces, …) and *Device* (Certificates, …); types without an entry of their own are under
*Other*. An entry shows its objects at once.

- **Location**: *any* or one location of this configuration - Panorama: *shared* and every device group; firewall:
  *shared* and every vsys; SCM: every folder (container) and snippet. A member limited to locations sees only those.
- **pan-os-php filter**: type and the page suggests - first the fields of the type (`name`, `object`, `value`, …),
  then their operators (`eq`, `regex`, `contains`, `is.unused`, …) with an example and whether a value is needed;
  after a term `and (` / `or (`. Arrow keys + Enter (or Tab) take a suggestion.
- **Object window**: click an address, address group, service, service group or tag - it opens over the list (as the
  edit dialog of PAN-OS) with its fields. A field is applied **when you leave it after a change** (or press Enter) -
  as **one pan-os-php action on exactly this object** (its location, filter `(name eq …)`): e.g. the description →
  `description-delete/description-append:…`, a tag → `tag-add:…` / ✕ `tag-remove:…`, the value of an ip-netmask →
  `value-replace:…`, the name → `name-rename:…` (tags too), a member → `add-member:…`, the color of a tag →
  `color-set:…`, its comments → `comments-delete/comments-add:…`. Under the field the action is shown (✓). A field
  without a pan-os-php action for it is read only (and says why). Descriptions and tag comments may contain `,` `:`
  `/` `|` (written as the pan-os-php aliases `$$comma$$`, `$$colon$$`, `$$forwardslash$$`, `$$pipe$$`); in every other
  value `,` and `:` can not be used (they separate the arguments of an action).
- **Rule window** (every entry under *Policies*: Security, NAT, QoS, PBF, Decryption, …): the fields the rule has -
  name, description (`,` `:` `/` allowed: pan-os-php aliases), tags, disabled, move (to the top / bottom, before /
  after a rule), source / destination zone, address, negate, user, application, service (each: add, ✕ remove, *set to
  any*; service also *application-default*), action, profile group, log forwarding, log at start / end, schedule.
  NAT rules also: **source translation** (none, dynamic IP and port with addresses or with the interface address
  - interface, optional IP -, dynamic IP, static IP with bi-directional; `snat-set` / `snat-remove`) and
  **destination translation** (none, static IP or dynamic IP with address and optional port; `dnat-set` /
  `dnat-remove`). The parts of a translation are applied together, once they are complete (until then the window says
  what is missing). Shown only: URL category, UUID (no pan-os-php action for them yet). The default security rules
  can not be renamed or moved.
- *Other*: Threat Rules and DNS Rules (comparable, no policies), and every type without an own entry.
- **Network / Device and every other entry**: a click opens the object too. Zones can be changed (name, zone
  protection profile, log setting, user identification, packet buffer protection); every other type shows all its
  fields, read only (its actions are not reviewed for the viewer yet). Panorama: zones, interfaces, … of a template
  show the template (column and window); a change names it.
- **Unsaved changes**: every change as one line - when, who, type, location, filter → action (and the field of the
  window). Nothing is written until **Save as new version**; **Discard changes** drops them all.
- **History on object level** (git, being built - 2026-11-21 step 2): every project has a git repository
  (`history.git` in its folder, no working tree) with one entry per object (`shared/address/web01.xml`, rules by their
  UUID, the rest of the configuration as `_rest.xml`). The first load of a version is its first commit; every change
  is one commit with exactly the objects it changed (a rename: the object, its order and every object that refers to
  it) and the change as its message (`Type:`, `Location:`, `Filter:`, `Action:`, `User:`). Save as new version: the
  new version is the state of the last commit; discard: the commits are dropped. `PANOSPHP_VIEWER_GIT=0` switches it
  off (then there is no undo).
- **XML and history in the object window**: *XML* - the object as it is in memory; *History* - every commit that
  changed its entry (unsaved changes and the versions before), newest first, with the object after each commit
  (button *XML*). A rename starts a new entry; objects of a template are part of the rest (no history of their own
  yet).
- **Undo** (at every unsaved change): takes back exactly this change - the later changes stay. git takes the commit of
  the change back on the current state, pan-os-php loads the result again (nothing of the old memory is kept), and
  the undo is one more commit. git merges **per field** (a merge driver of pan-os-php): a later change of another field
  of the same object stays (e.g. the description taken back, a tag added later kept; members are a set). Refused only
  when a later change set the same field (*take the later change back first*). After the undo the viewer says which objects are used but not there any more (e.g. a rename
  undone while a later change uses the new name) and what pan-os-php changed when it loaded the result (it creates a
  missing tag, for example). The undone change is struck through; undone changes and undos are no playbook steps.
  A member limited to types / locations can undo only a change he could have made. API: `POST …/configs/<cid>/undo`
  with `{"index": n}` (the place in the change list, from 0). The repository holds the
  configuration like its version files (same protection, deleted with the project).
- **Multi-edit …** (at a change of one object in the list of unsaved changes): the same action on more objects. The
  window suggests what they could have in common - taken from the changed object: name begins with …, same value,
  same type, a tag, no groups / groups only, unused; for rules: zone / address / application / service has … or is
  any, the action, pre / post rules, enabled / disabled. Tick them (they are joined with *and*), choose the location
  (any or one), add a pan-os-php filter if needed - the **number of matches and their names** are shown at once. The
  changed object itself is left out (it can be ticked back). **Apply** runs the action on all matches - one more line
  of the change list (*multi-edit*). The action can be changed before; a rename of many objects needs a formula
  (`$$current.name$$-old`).
- **Export as playbook …** (below the unsaved changes): the change list as a pan-os-php playbook - one step per
  change (type, location, rule type, filter, actions, a comment with time, user, field / multi-edit). Save it as a
  playbook file of the project (then it can be run on another version under *Runs*, or changed in the playbook editor)
  or download it (`pan-os-php type=playbook in=… out=… json=<file>`). A version saved from changes of the viewer keeps
  them: **Playbook** next to it in *Configuration versions*.
- **Run a pan-os-php action on all objects of the list** (below): one action on all objects of the list (menu entry +
  location + filter) - type part of the name; the suggestions show the arguments of each action.
- **refcount** (address, service, tag, zone, schedule, security profile (group), …): how many objects use this one.
  Click the number to see them right below the object (0: not used, nothing to click): the rules (with rule type, pre / post and the field, e.g. `source`), groups and
  profile groups, with their location. **Open ↗** shows the user in a new window - same version, its type, location
  and `(name eq …)` already set. A member limited to types / locations sees only the users inside them.


## Runs

A run works on a copy of one version in its own folder and container (no network). The project page has the tabs
**Configuration versions**, **Runs and project files**, **Merger** (see below), **LDAP**, **Members, API tokens, audit log**. Under **Runs**:

| Run | What it does |
|---|---|
| stats | best practice figures of the configuration |
| playbook | the steps of a playbook - exports, set commands, changed configuration |
| diff | compares two versions (file1 = the original, file2 = the newer one): differences in `run.log`, set commands file1 → file2 in `set-commands.txt`; optional only a part (XPath) |
| migration (licence) | a configuration of another vendor (project file) to PAN-OS |

**Playbooks** come from two places, like the BP JSON:

- **predefined** - shipped with pan-os-php (`visibility.json`, `best-practice-set.json`, …). Offered are only the ones an
  administrator turned on under **Account → Predefined playbooks**; by default `visibility.json`. Some shipped
  playbooks can not run in the viewer (e.g. mergers) - the list says why.
- **own** - a playbook JSON uploaded under **Project files**; it is checked when it is uploaded and before every run.

**Editors.** Under **Project files**: **Edit** opens a copy of a playbook / BP JSON in the editor of pan-os-php;
**New playbook (editor)** / **New BP JSON (editor)** start a new one (a new BP JSON starts with the one shipped with
pan-os-php). **SAVE** / **Export JSON** stores the result as a **new** project file (a playbook is checked like an
upload). The editors run apart from the viewer - they can not reach the viewer, the project or the network.

**Large configurations** need a lot of memory. Under **Options for large configurations** (playbook runs):

- **Every step its own process** (`subprocess`) - needs the least memory, slower.
- **Own process above … MB** (`memorythreshold`) - only when the run already uses more than this.
- **Memory use in run.log** (`debugmemory`) - to see what each step needs.
- **Remove stage files** (`removestagefiles`) - less disk and memory.

A run stopped for memory is shown as **out of memory**, with the limit per run. The limit is set on the computer the
viewer runs on: `VIEWER_RUN_MEMORY=4g` in `.env` next to `panosphp-viewer` (default `2g`), then
`./panosphp-viewer restart`. With Docker Desktop, give the VM more memory than that (Settings → Resources).

When a run is done: **Result files** to download (e.g. `out.xml`, `set-commands.txt`, `run.log`), and
**Result as new version** - in this project or in another one.

## Merger

Tab **Merger** of a project (members without a limit to types / locations):

* **object-merger** (`type=object-merger`): object types (none = any), location, DupAlgorithm, pickFilter,
  excludeFilter, mergeCountLimit, allowMergingWithUpperLevel - write permission
* **rule-merger** (`type=rule-merger`): location, method, pre / post rules (Panorama), mergeDenyRules,
  stopMergingIfDenySeen, mergeAdjacentOnly, filter, additionalMatch - write permission
* **merger-possible-report** (`type=merger-possible-report`): object types, mergecheck - only a report, read permission

A merger run works on a copy of the version like every run; the version stays. **Show report** draws the report as
tables with a text filter: the summary, **Merged** (kept ← removed, with location and value / key; for rules: the
kept rule, the rules merged into it, its main fields after the merge) and **Not merged** with the **reason** (and the
deny rule that stopped a rule merge). **Result as new version** takes the merged configuration. Downloads: the HTML of
pan-os-php (`exportCSV`: merged / skipped), the JSON, run.log.

The tables come from `exportJSON=merger.json` of pan-os-php - the same data the HTML of `exportCSV=` is made of (one
code path, `utils/lib/MergerReport.php`); on the command line: `pan-os-php type=object-merger … exportjson=report.json`,
or `shadow-json` (key `merger-report`). Applying a merge to the loaded version (one change, one commit, undo): later.

API: `POST …/configs/<cid>/object-merger/runs` (body: `objecttype`, `location`, `dupalgorithm`, `pickfilter`,
`excludefilter`, `mergecountlimit`, `allowmergingwithupperlevel`), `…/rule-merger/runs` (`location`, `method`,
`rulebase` pre / post, `mergedenyrules`, `stopmergingifdenyseen`, `mergeadjacentonly`, `filter`, `additionalmatch`),
`…/merger-possible-report/runs` (`objecttype`, `mergecheck`); the report: `GET …/runs/<jid>/files/merger.json`.

## Scripts (API)

Everything of the page is also reachable as REST API under `api.php/…`.

- With user and password: log in, then the session cookie and the CSRF token (example script
  `examples/viewer-playbook-run.sh`: project, upload, playbook run, download).
- With an **API token** (no password in the script): one project, read or write, valid for some days.
  In the page: project → **API tokens** (not on the command line). Scripts send `Authorization: Bearer <token>`.

A token is shown only once. It never has administrator rights and works only for its project - to create a project
from a script, log in with user and password.
