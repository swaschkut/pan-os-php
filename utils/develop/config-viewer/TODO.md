# config-viewer: open points

State 2026-11-21 (GitHub `alpha` up to `ddcbf3a7`). One list of everything still open for the config viewer; the
details stay in the todo files that are linked. Done points are struck out here only when they were listed before.

---

## 1. Viewer like PAN-OS

Todo: [todo/config-viewer-panos-style-edit.md](../../../todo/config-viewer-panos-style-edit.md)

### 1.1 Fields that can not be changed - a pan-os-php action is missing

| Type / field | Missing in pan-os-php |
|---|---|
| address: type, value of ip-range / fqdn / ip-wildcard | `value-set` / change of type (only `value-replace` for ip-netmask) |
| address, service, rule: description | `description-set` (today `description-delete` + `description-append`: two actions) |
| address group: remove a member, dynamic filter | `remove-member`, an action for the filter |
| service: protocol / port | `protocol-set`, `dstport-set` |
| service group: members | `add-member` / `remove-member` (none for service groups) |
| rule: URL category | `category-add` / `category-remove` |
| NAT: persistent dynamic IP, DNAT distribution, interface IP as an object | not in `snat-set` / `dnat-set` yet |
| zone: remove the zone protection profile | an action for it; yes / no fields show no current value |
| every field except descriptions and tag comments | `,` and `:` not possible (no aliases there) |

### 1.2 Types with the generic window only (read only)

| pan-os-php has change actions - only the window is missing | pan-os-php has no change action |
|---|---|
| EDL, schedule (name actions) | threats, threat rules, DNS rules |
| security profiles (61 actions, e.g. `alert-only-set`, `best-practice-set`) | virtual wires, routing |
| security profile groups (`securityprofile-set` / `-remove`) | IKE gateways, IPSec / GRE tunnels |
| log forwarding, application (create / delete / move) | GlobalProtect portals / gateways / tunnels |
| interfaces (`name-rename`, AE group) | interface management profiles |
| zone protection profiles (`alert-only-set`) | certificates, certificate profiles |
| device (38 actions) | SSL/TLS service profiles |
| static routes, IKE / IPSec crypto (delete only), DHCP (reservation) | |

Counted from [action-classes.json](action-classes.json), class `change`.

### 1.3 More

* **run.log in a window** - shown in the page (as the LDAP results), not only as a download
* **search text in the whole XML** (as `type=xpath`): exact / contains / regex; element names, values or attributes
  (`name=`); limited to a location / template; the hits with their XPath and a link to the object window
* more network / device types editable as soon as their actions are reviewed (`action-classes.json` `reviewed`)

### 1.4 object-merger / rule-merger in the viewer

* ~~step 1~~ built 2026-11-21: tab **Merger** - object-merger, rule-merger, merger-possible-report as runs on a copy;
  the report as tables (merged, not merged with the reason) from `exportJSON` (pan-os-php `MergerReport`, the same
  data as the HTML of `exportCSV`); result as new version
* open: **apply to the loaded version** - the merger in the worker on the memory as one change: one commit with every
  merged / removed object and every reference, undone as a whole (git step 3)
* open: members limited to locations (today the tab needs the whole configuration, like every run)
* open: playbook steps `*-merger` (refused today)
* pan-os-php: the single `xyz-merger` types deprecated in favour of `type=object-merger`
  ([todo/merger-deprecate-single-types.md](../../../todo/merger-deprecate-single-types.md), planned)

---

## 2. git on object level

Todo: [todo/config-viewer-panos-style-edit.md](../../../todo/config-viewer-panos-style-edit.md), "Changes with git,
on object level". Built: steps 1-3 and 4a.

* **step 4b - branches:**
  * import from a device on its own branch: the diff to the version = what changed on the device (drift); merged into
    the work with the merge driver, conflicts per field as "mine or the device's"
  * a branch per user: today all members change the same memory (one change list) - decide first whether it is
    wanted (a worker per user, or a merge of the change lists when saving)
  * objects of templates (Network / Device) as entries of their own (today in `_rest.xml`: no history / merge of
    their own)
* a version recovered from the autosave file, or made by a run (playbook, plug-in), starts a new history without the
  commits before
* undo only for unsaved changes of the loaded version
* an undo of a large configuration takes as long as opening the version (pan-os-php loads again)
* `history.git` holds the configuration like the version files - part of the encryption topic (5.)

---

## 3. APIs documented on pan.dev, with the user's service account

Todo: [todo/config-viewer-pandev-api.md](../../../todo/config-viewer-pandev-api.md) - idea, nothing built.

* catalogue from the OpenAPI specs of pan.dev (GitHub `PaloAltoNetworks/pan.dev`, folder `openapi-specs`), download
  or upload (air gap) - which APIs exist is given by pan.dev, not by pan-os-php
* with the SCM service account (personal key store entry `scm`): SCM (tenancy, IAM, subscription, configuration
  SASE / NGFW / Cloud NGFW, insights, monitoring, incidents, posture, ADEM, …) and Prisma SASE
* other products with their own authentication (Threat Vault, Prisma Cloud, IoT, DNS Security, …): listed, greyed out
  until there is a key kind for them
* read only: `GET` and reviewed `POST` queries; as a run with network to the server of the spec only
* coverage report: which SCM configuration paths the SCM import reads already, which not
* open decisions: source / version of the specs, allow list of `POST` queries, which other key kinds first, 403 shown
  as "no right of the role", results only in the run or also in the project

---

## 4. Access to devices

Todo: [todo/config-viewer-device-access.md](../../../todo/config-viewer-device-access.md)

| # | Open |
|---|---|
| A | writing to a device (`out=api://`, `type=upload`, `config-commit`): own administrator switch "write to devices" (off), per project, maybe per user; review step (diff / set commands first), audit; never by a playbook |
| B | set commands per SSH (`type=ssh-connector`): personal SSH credentials as a new key kind; the same switches as A |
| C | firewall through Panorama (`api://<serial>@<panorama>`) |
| D | API key from user + password (`type=key-manager`); needs network from the web part |
| E | network limited to the targets for real: today the viewer checks the allow list; a docker network with egress rules would be stronger |
| F | encryption of the key store (the key of the installation lies in the volume today) |
| G | more named entries for runs, e.g. `bpa-apikey` for bpa-generator |
| H | DNS servers per project and per user: FQDN address objects, LDAP (finding the domain controllers), device names of an import; order user / project / installation to decide; a run that only resolves gets network for DNS only (port 53); run.log names the DNS servers used. Today: installation-wide `VIEWER_RUN_DNS` only |

---

## 5. Data at rest

Todo: [todo/config-viewer-encryption.md](../../../todo/config-viewer-encryption.md) - analysis done, no decision,
nothing built.

* today everything in the volume is plain text (database, projects, working copies, now also `history.git`); a
  Docker administrator can read it all
* to decide: encryption in the viewer bound to administrators or per project; emergency data key (offline); backup
  command `./panosphp-viewer backup` (encrypted file)

---

## 6. Limits per run

Todo: [todo/config-viewer-run-limits.md](../../../todo/config-viewer-run-limits.md) - idea, not built.

* memory, CPUs, time per run set by an administrator in the browser instead of `.env`; stored in the viewer, read
  before every run (no restart)
* upper bound from `docker info` / `VIEWER_RUN_MEMORY_MAX`; `.env` stays the default

---

## 7. Licences and migration

* **licences** ([todo/config-viewer-license.md](../../../todo/config-viewer-license.md)): ~~`keygen`~~ done (public
  key `sven-2026` in `lib/resources/license/keys.json`); open: packages into the air-gap bundle, the licence of the
  first customer; decision 6 (encrypted plug-ins)
* **migration** ([todo/config-viewer-migration.md](../../../todo/config-viewer-migration.md)): requirements and design
  only, several decisions open; first vendor Cisco switch / ISR; online inputs need secrets at rest and network

---

## 8. API of the viewer

Todo: [todo/config-viewer-api.md](../../../todo/config-viewer-api.md)

* types without objects (mergers, `diff`, SCM types, …) only through jobs
* container per worker (decision 2, second part)
* Podman
* secrets at rest
* `tool.php` behind the login
* errors as HTTP status

---

## 9. Other

* **IronSkillet 12.2** ([todo/ironskillet-url-http-header-logging-12.2.md](../../../todo/ironskillet-url-http-header-logging-12.2.md)):
  URL HTTP header logging - the XML element names are not known yet
* **LDAP:** the query failed at the TLS handshake with a domain controller that was not available at that time - hence
  the automatic choice of the server from DNS; to check on the real installation that another DC answers now
