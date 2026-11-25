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
- **Extra columns** (types whose pan-os-php `exportToExcel` has additional fields): tick e.g. *NestedMembers*,
  *ResolveIP* (addresses, groups, zones, interfaces, …), *ResolveSRV* (services), the summaries / *BestPractice* /
  *Visibility* / *Adoption* (rules), *TotalUse* / *URLmembers* (profiles) - they are computed on the server for the
  objects of the list and shown as columns of the list (only the columns the field adds). The same code as
  `actions=exportToExcel:file.html,<fields>` on the command line: pan-os-php gives the export table also as data
  (`shadow-json`: `export-table`). Not offered: *WhereUsed* / *UsedInLocation* (the list has its References), what needs
  a live device (*HitCount*, *ApplicationSeen*) and secrets (*PSKcleartext*). API: `…/objects?…&columns=A|B`.
- **Object window**: click an address, address group, service, service group or tag - it opens over the list (as the
  edit dialog of PAN-OS) with its fields. A field is applied **when you leave it after a change** (or press Enter) -
  as **one pan-os-php action on exactly this object** (its location, filter `(name eq …)`): e.g. the description →
  `description-set:…`, a tag → `tag-add:…` / ✕ `tag-remove:…`, type and value of an address →
  `value-set:…` (also IPv6), protocol / destination port of a service → `protocol-set:…` / `dstport-set:…`, the name → `name-rename:…` (tags too), a member of an address / service group → `add-member:…` / ✕ `remove-member:…`, the color of a tag →
  `color-set:…`, its comments → `comments-delete/comments-add:…`. Under the field the action is shown (✓). A field
  without a pan-os-php action for it is read only (and says why). A **read-only object** - a value used directly in a rule
  (temporary), a predefined object (e.g. service-http / service-https, listed at *shared*), a GlobalProtect gateway
  tunnel, a threat, a threat rule / DNS rule - is shown read only with the reason. The location **predefined** lists the
  predefined objects (services, applications, log forwarding profiles, threats, security profiles); a predefined object
  is listed with this location, its XML comes from predefined.xml; *predefined* is never a target; pan-os-php does not change it (an action for its users, e.g.
  `replacewithobject`, still works). A field that names other objects (members, tags,
  zones, addresses, services, applications, URL categories, interfaces, profiles, …) offers them as a drop down: the
  objects of its own location and of the locations above it (vsys → shared; device group → parent device groups →
  shared; SCM folder → its snippets → parent folders → All; template), grouped by location, without the ones it has
  already and without the ones the action would refuse (the group itself, an interface of another zone, …); a rule of
  a Panorama device group gets the zones of the templates. A name can still be typed.
- **Network types** (zones, interfaces, routers, static routes, virtual wires, DHCP, IKE / IPsec, profiles, …): the
  objects live on the firewall itself (location *shared*, all of them) - a vsys imports interfaces, virtual / logical
  routers and virtual wires and lists what it imports (routers with their static routes, DHCP of its interfaces); the
  column / field *vsys* names the vsys that import an object. Panorama: a
  **Template** choice (any, templates, template stacks; pan-os-php `template=`) instead of the device groups; location
  *shared* is the template itself, a vsys of the template lists what it imports. SCM: containers and snippets as before.
- **NAT rule window - Security rules** (closed until opened): the allow security rules the traffic of the NAT rule
  really reaches, in their order (pan-os-php `actions=display-nat-security`): pre-NAT addresses and service, post-NAT
  zones - for destination NAT the zone of the translated address by the route lookup in the virtual / logical router of
  the ingress interface (connected networks, static routes; a zone found only by the default route is marked
  *uncertain*, dynamic routes are not in the configuration). Per rule: zones, source, destination, service *full* /
  *partial*, until the first rule that covers the traffic fully; a deny / drop / reset rule that blocks the traffic
  before is named. Panorama: one block per device group / template stack / vsys of the firewalls of the device group
  (the template stack merged, variables with the values of the firewall; rule targets); without firewalls the template
  stacks. Bi-directional static NAT: also the reverse direction.
  **Allow rules to adapt** (destination NAT): rules written the way of other vendors - the security rule after the NAT,
  with the translated (post-NAT) address, the pre-NAT zone or the translated port. The corrected rule is shown;
  *Adapt* changes an exact one in place (it carries only this NAT traffic) or clones it before the rule (the rule stays
  for its other traffic), *Clone only* always clones - never more traffic than the rule names. A *partial* one (a part
  of a translated pool, more ports, other post-NAT zones on other firewalls) would allow more: only after the review
  checkbox. Rules whose traffic is allowed already are shown greyed, not changed. pan-os-php:
  `actions=nat-security-fix:fix|clone|report,approvePartial,suffix`. Filters: `(nat.security is.full|is.partial|
  is.missing|is.blocked|is.unknown)`, `(nat.security has <rule>)`, `(nat.security.mismatch is.set|is.full|is.partial)`,
  `(nat.security.mismatch has <rule>)`.
- **Rule window** (security rules): the security profiles one by one (each with the profiles of its type; a profile
  replaces a profile group and the other way round), rule type, source HIP profile, QoS marking, disable server response
  inspection; Panorama: target firewalls (serial or serial and vsys), target negate, all firewalls. An action that refuses the change (pan-os-php
  SKIPPED, e.g. the last member of a group) leaves the version as it was and shows its reason at the field. Descriptions, tag comments and address values may contain `,` `:`
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
  protection profile, log setting, user identification, packet buffer protection). **IKE gateways**: IKE version,
  IKE crypto profile of IKEv2 / IKEv1, peer address (IP, FQDN, dynamic), local interface / IP, local / peer
  identification, NAT traversal, fragmentation, passive mode, dead peer detection, exchange mode, disabled - the
  pre-shared key is shown (encrypted, as the configuration has it), not changed. **IKE crypto profiles**: encryption,
  hash, DH groups, key lifetime, authentication multiple. **IPsec crypto profiles**: ESP encryption / authentication,
  DH group, lifetime, lifesize. **IPsec tunnels**: IKE gateway, IPsec crypto profile, tunnel interface, proxy IDs (add:
  `name local remote`, ✕ remove), anti replay, copy TOS, tunnel monitor, disabled. A profile / gateway must exist in
  the location or above it (template stack, SCM parent folder / snippet / All), else the change is refused.
  **Interfaces** (layer3 ethernet / aggregate, sub-interface, loopback, tunnel, VLAN): comment, IPv4 addresses, MTU,
  interface management profile, adjust TCP MSS, link state, VLAN tag - another mode is shown read only. **Interface
  management profiles**: services, permitted IPs. **Zone protection profiles**: description, flood protection,
  reconnaissance scans, packet based options. **Virtual / logical routers** (logical: vrf default): interfaces, ECMP,
  administrative distance, add a static route. **Static routes**: destination, next hop, interface, metric,
  administrative distance, route table. **GRE tunnels**: local interface / IP, peer, tunnel interface, TTL, copy TOS,
  keep alive, disabled. **DHCP**: server (mode, IP pools, gateway, subnet mask, DNS, lease, reserved addresses) or
  relay (on / off, servers). **Virtual wires**: interfaces, allowed tags, multicast firewalling, link state pass
  through. **GlobalProtect portals / gateways**: local interface / IPv4, SSL/TLS service profile; gateway also tunnel
  interface and the IP pool / access route lists of each client setting. **GlobalProtect gateway tunnels**: read only
  (a helper object of the GlobalProtect gateway). The **name** of these network objects (not of an interface / DHCP) can be
  changed: `name-rename` changes it also in every object that uses it. IPv6 values can not be entered (":" separates the arguments of an
  action); a change works on the version (offline), not through an API connection. Every other value of these
  objects - and every other network / device type - is shown read only (all values of the object). Panorama: zones, interfaces, … of a template
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
- **Run results in the history**: *Result as new version* of a run (object-merger, rule-merger, playbook, …) writes
  the result configuration as one commit on the history of the version the run ran on (that version gets its first
  commit then if it was never opened). Subject: `<type> run <id>: <settings>`; trailers `Type:`, `Run:`, `Settings:`.
  For a merger the message also lists per object what happened - `Merged: DG-P:web -> DG-P:web2`,
  `Not-merged: DG-P:x (kept DG-P:y): <reason>` (from `merger.json`). In the object window of the new version the
  *History* shows the run at every object the run changed (e.g. a group whose member was replaced) and also at the kept
  object of a merge with its `Merged:` lines, although its own entry did not change. Removed objects are not in the new
  version any more - they are in the report of the run.
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
  profile groups, with their location. **Open ↗** shows the user in a new window - same version, the entry of its
  class (an address group under *Address Groups*, a service group under *Service Groups*), location and `(name eq …)`
  already set. A member limited to types / locations sees only the users inside them.


## Runs

A run works on a copy of one version in its own folder and container (no network). The project page has the tabs
**Configuration versions**, **Runs and project files**, **Merger** (see below), **LDAP**, **Members, API tokens, audit log**. Under **Runs**:

| Run | What it does |
|---|---|
| stats | best practice figures of the configuration |
| playbook | the steps of a playbook - exports, set commands, changed configuration |
| diff | compares two versions (file1 = the original, file2 = the newer one): differences in `run.log`, set commands file1 → file2 in `set-commands.txt`; optional only a part (XPath) |
| IKE gateways / PSK list | the IKE gateways of the version and their pre-shared keys; optional with one of your SCM keys also the firewalls managed by that SCM tenant (newest configuration SCM keeps of each firewall, read only, network) - then both compared |
| migration (licence) | a configuration of another vendor (project file) to PAN-OS |

**IKE gateways / PSK list** (`type=scm-ngfw-psk-list`, write permission): a version, an SCM key, or both.

- `run.log`: per gateway its place, peer and whether the pre-shared key can be decrypted (PAN-OS default master
  key) - never a secret.
- **Sensitive - download once**: `psk-list-version.csv` / `psk-list-firewalls.csv` - one row per gateway with the clear
  text of the keys that could be decrypted (`psk_current`) and the whole encrypted value as the configuration has it
  (`psk_encrypted`, e.g. `-AQ==…`; `psk_sha1` is only the SHA-1 kept in that value, not the key). Only members with write permission see them; the download removes the file
  on the server (a second download is not possible - start the run again); not downloaded: removed after 7 days
  (`PANOSPHP_VIEWER_SENSITIVE_DAYS`). The download is in the audit log, its content never.
- Result files without clear text: `psk-sha1-version.csv` / `psk-sha1-firewalls.csv` (the SHA-1 of each key, as PAN-OS
  keeps it in the encrypted value) and, with both, `psk-compare.csv` - per gateway name: `same`, `different`,
  `only-a` (only in the version), `only-b` (only on the firewalls), `unknown` (no pre-shared key / other format).
  The comparison works without decrypting: also for keys of another master key.

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
pan-os-php (`exportCSV`: merged / skipped), the JSON, run.log. In **Not merged** and in the copies of a finding the values are
shown with what differs **marked** (e.g. `23.99.160.140/`**27** against `23.99.160.140/`**31**; a part that is missing
in one copy is marked ∅). Copies with the same name and value in locations that do not see each other (sibling device
groups) are listed with the reason when the merger does not merge them (it would create the object in their common
parent - needs allowMergingWithUpperLevel and a DupAlgorithm that creates, not Identical); the merger-possible-report
shows them as **merge-into-parent** with the common parent.

**Explain**: a row that pan-os-php did not merge because the firewalls would receive something else ("effective policy
would change for firewalls of … before […] after […]") has a button **Explain**. The window shows for the firewalls of
that location what the name gives before and after the merge (differences marked), how the name resolves level by level
(device group, its parents, shared - the level that wins is highlighted, with "ancestor objects take precedence" or
"the nearest level wins"), the members of a group as the firewall resolves them, the simulated changes of the merge step
and the cause in words, e.g. a copy of the name in a lower device group that shadows the copy that would be removed, or
a group that would contain itself (`after []`: group G-B = [G-A] merged with G-A). Links open the objects in the version
the run ran on. The data is in `merger.json` (`skipped[].safety`, merger-possible-report `blocked[].detail`).

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
