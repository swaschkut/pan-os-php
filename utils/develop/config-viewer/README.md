# config-viewer (prototype)

Web UI on top of pan-os-php: upload a PAN-OS / Panorama XML configuration, look at its objects in the browser,
change them with pan-os-php actions and save the result as a new version – with users, projects and project members.

**Prototype.** It is a separate area next to `utils/api/v1/tool.php` (which is unchanged and has no authentication).
Background and open points: [todo/ui-config-in-browser.md](../../../todo/ui-config-in-browser.md).

## How it works

| Part | File | Function |
|---|---|---|
| browser | `index.html`, `app.js`, `style.css` | login, projects, members, versions, object table, change box. Every loaded list is kept in the browser (cache per query); sort, paging and the quick filter run there |
| API | `api.php` → `lib/ViewerApp.php` | JSON API; users / projects / members / versions in SQLite; every request is checked against the project permission |
| service | `bin/service.php` | the one long running process; starts a worker when a version is opened |
| worker | `bin/worker.php` | one per opened version: loads the configuration **once** and keeps it in memory (`UTIL::$sharedConfig`); reads and changes run on that memory |
| jobs | `bin/jobs.php` | second long running process: executes the queued runs (`stats`), result files in the folder of the run |
| users | `bin/user.php` | create users on the command line |

**Load once:** the first request for a version loads it (seconds to minutes for a large Panorama configuration), every
further read or change works on the loaded configuration (milliseconds for the test file).

**Change and save:** an action changes the configuration in memory only. **Save** writes the memory into a **new
version** file – an existing version is never overwritten. The version list shows the parent version, who saved and
which actions were run. **Discard** drops the unsaved changes.

**Auto save:** two things –
* the worker writes unsaved changes to a recovery file every `PANOSPHP_VIEWER_AUTOSAVE_MIN` minutes (default 5) and
  when it stops; the next request turns it into a version `autosave (recovered …)`
* in the browser "Auto save as version" (off / 5 / 10 min) saves a new version by itself while there are unsaved
  changes

All members of a project work on the same loaded configuration of a version (one worker per version).

## Security

* **Login required** for everything except `login`. Passwords: `password_hash()`; at least 10 characters; 5 failed
  logins block the user name for 15 minutes; same answer for an unknown user and a wrong password.
* **Session:** cookie `HttpOnly`, `SameSite=Strict`, `Secure` with HTTPS, new session id at login, idle timeout
  (default 120 min). **HTTPS is required**; plain HTTP only for a client on the same machine (loopback address) or
  with `PANOSPHP_VIEWER_ALLOW_HTTP=1` (lab).
* **CSRF:** every request that is not `GET` needs the header `X-CSRF-Token` of the session.
* **Separation:** a project is visible to its owner and its members only. Without access every route of the project
  answers `404` like a project that does not exist. Project and version ids are random (128 bit).
* **Permissions per project:** `read` (view, download), `write` (upload, change, save, discard, delete versions),
  `owner` (members, delete project). Only the owner adds members, by exact user name.
* **Grants per member** (owner sets them): besides `read` / `write` a member can be limited to some **types**
  (`types`: list of offered types) and to some **locations** (`scope`: device groups, vsys, `shared`, SCM folders /
  snippets). Enforced on the server for every read and change: a limited member must name exactly one location of its
  scope (no `any`, no list), can not use another type, can not download / upload / delete whole versions and can not
  run actions that move or copy objects to another location. Not covered yet: type `zone` with a scope (templates) –
  refused; objects of `shared` / parent device groups referenced from the scope are not shown.
* **API tokens** (scripts, e.g. CDSS): `Authorization: Bearer pvt_…` instead of cookie + CSRF token. A token belongs
  to one user and **one project**, has a role (`read` / `write`, never more than the user) and an expiry (1–365 days);
  only the SHA-256 of the secret is stored, the value is shown once. A token follows the grants of its user, can not
  manage members, tokens, projects or users (also not for an admin) and stops working when the user leaves the project.
* **Audit log:** one line for every login (also a failed one), every request that is not a plain read (changes, save,
  uploads, members, tokens, runs, deletes – also refused ones, with their HTTP status) and every download: time, user,
  token id, client address, project, method, route, status and the request fields that describe it (`actions`,
  `filter`, `user`, `role`, …) – never passwords, token secrets or file content. The owner reads the log of a
  project (`projects/<pid>/audit`), an admin everything (`audit`); not with an API token. Lines are kept
  `PANOSPHP_VIEWER_AUDIT_DAYS` days (default 365).
* **Users:** created by an admin (UI) or with `bin/user.php`; there is no self registration and no default user.
* **Files:** stored under random names in the data directory, which must be **outside the web root** (the API refuses
  to work otherwise). The uploaded file name is only a label. An upload must be XML with the root element `<config>`.
* **pan-os-php calls:** no shell, no file name or path from a request. Whitelist of types (`address`, `service`,
  `tag`, `rule`, `zone`, `schedule`, `securityprofile`, `securityprofilegroup`); `in=` is always the file of the
  version; no `out=`, no `in=api://`. Filters that read a file (`is.in.file` …) and actions that read / write files or
  reach other systems (`export…`, `upload-…`, `…-fastapi`, `…from-file`, …) are rejected.
* **Processes:** the web server process starts no process. The service only accepts paths inside the data directory.
  A failing action is tried in a forked copy first, so it can not stop or half-change the loaded configuration.
* **Browser:** no external scripts, Content-Security-Policy `default-src 'self'`, all text is inserted as text.
* Errors do not contain server paths.

Known limits of the prototype: no OS level isolation between projects (all workers run as the web server user); the
action deny list is a pattern list, not a reviewed allow list per action; an owner can find out whether a user name
exists (adding a member); sessions are PHP file sessions.

## Run it (lab)

Needs PHP ≥ 7.4 with `pdo_sqlite`; the PHP **CLI** also needs `pcntl` and `posix` (service / worker). Check:

```bash
php -m | grep -E "pcntl|posix|pdo_sqlite"      # all three must be listed (Homebrew PHP on macOS has them)
```

Two terminals; `PANOSPHP_VIEWER_DATA` must be **the same** in both.

Terminal 1 – data directory, first user, service:

```bash
cd utils/develop/config-viewer
export PANOSPHP_VIEWER_DATA=$HOME/pan-os-php-viewer-data    # outside the web root; path ≤ 60 characters
php bin/user.php add alice admin                            # once; asks for the password (10+ characters)
php bin/service.php                                         # stays in the foreground, prints "running"
php bin/jobs.php                                            # third terminal (or background): runs (stats)
```

Terminal 2 – web server (lab only):

```bash
cd utils/develop/config-viewer
export PANOSPHP_VIEWER_DATA=$HOME/pan-os-php-viewer-data
php -S 127.0.0.1:8080 -t .
```

Browser: `http://127.0.0.1:8080/` → log in → create a project → upload an XML configuration → click the file name.
Stop: `Ctrl-C` in both terminals. Stopping the service stops its workers; a worker with unsaved changes writes its
recovery copy first.

Do not rely on the default data directory (`<parent of the repository>/pan-os-php-viewer-data`): the path must not
be longer than 60 characters (limit of unix socket paths), and it must be outside the web root.

More users: as admin in the UI (Account → Users), or `php bin/user.php add <name>`; also `password <name>`,
`delete <name>` (deletes the projects the user owns), `list`.

Behind Apache / nginx: publish only this folder (or the repository) over HTTPS, set `PANOSPHP_VIEWER_DATA` for the web
server **and** the service, run the service as the web server user. With TLS at a reverse proxy set
`PANOSPHP_VIEWER_TLS_PROXY=1`.

### Using it

1. **Projects** – "Create" makes a project that only you see. Open it by its name.
2. **Members** (owner only) – user name + `read` or `write` → "Add / change"; "Remove" takes the access away at once.
3. **Configuration versions** – upload an XML file (`write`); "Download" any version (`read`); "Delete" (`write`).
   The column "How it was created" shows `upload`, the actions of a save, or `autosave (recovered …)`.
4. **Viewer** (click a version) – choose type (and rule type / profile type), location, optionally a pan-os-php
   filter, "Show". The first "Show" of a version loads it; after that lists come back in milliseconds, and a list
   that was shown before comes from the browser cache ("Reload" asks the server again). Click a column to sort; the
   quick filter searches the shown list in the browser.
5. **Change** (`write`) – choose an action and its arguments, "Run on loaded configuration". The action runs on **all**
   objects of the current type + location + pan-os-php filter (not the quick filter). The badge shows the number of
   unsaved changes, the list below shows them, the log shows the pan-os-php output.
6. **Save as new version** writes the loaded configuration to a new version and continues on it. **Discard changes**
   drops them. "Auto save as version" (off / 5 / 10 min) saves by itself while there are unsaved changes.

### Troubleshooting

| Message | Cause |
|---|---|
| `the config-viewer service is not running` | `bin/service.php` is not started, or `PANOSPHP_VIEWER_DATA` differs between service and web server |
| `config-viewer service: PHP CLI extensions pcntl and posix are needed` | PHP CLI without `pcntl` / `posix` |
| `the path of the data directory is too long` | `PANOSPHP_VIEWER_DATA` longer than 60 characters |
| `data directory is inside the web root` | choose a data directory outside the folder the web server publishes |
| `HTTPS required` | plain HTTP from another machine; use HTTPS, or `PANOSPHP_VIEWER_ALLOW_HTTP=1` in a lab |
| `the configuration could not be loaded` | pan-os-php could not load the file; the text after the colon is the end of the worker log (`<data>/projects/<id>/work/*.log`) |
| `the loaded configuration is not reachable - open the version again` | the worker of the version stopped (idle timeout, restart); the next request starts a new one |
| `too many failed logins` | 5 failed logins for this user name within 15 minutes |
| `not found` on a project you expect to see | you are not a member (any more) – this is the answer for "no access" |
| upload fails for a large file | `upload_max_filesize` / `post_max_size` of PHP, `PANOSPHP_VIEWER_MAX_UPLOAD_MB` |

### Settings

| Environment variable | Default | |
|---|---|---|
| `PANOSPHP_VIEWER_DATA` | `<parent of the repository>/pan-os-php-viewer-data` | data directory (SQLite DB, projects, sockets); path ≤ 60 characters |
| `PANOSPHP_VIEWER_AUTOSAVE_MIN` | 5 | recovery copy of unsaved changes (service) |
| `PANOSPHP_VIEWER_IDLE_MIN` | 60 | a worker without requests stops (service) |
| `PANOSPHP_VIEWER_SESSION_IDLE_MIN` | 120 | login session idle timeout |
| `PANOSPHP_VIEWER_MAX_UPLOAD_MB` | 200 | upload limit (also `upload_max_filesize` / `post_max_size` of PHP) |
| `PANOSPHP_VIEWER_LOAD_TIMEOUT` | 600 | seconds to wait for the first load of a version |
| `PANOSPHP_VIEWER_AUDIT_DAYS` | 365 | days the audit log keeps a line |
| `PANOSPHP_VIEWER_ALLOW_HTTP` | – | `1` allows HTTP from other hosts (lab only) |
| `PANOSPHP_VIEWER_TLS_PROXY` | – | `1` when TLS ends at a reverse proxy in front of PHP (cookie gets `Secure`); the proxy must be the only way in |

## Reference

### Data directory

```
<data>/viewer.sqlite                      users, projects, members, versions, sessions of loaded versions (mode 0600)
<data>/service.sock                       socket of bin/service.php
<data>/run/<id>.sock                      socket of one worker
<data>/projects/<project id>/<id>.xml     one file per version (random name; label and history are in the DB)
<data>/projects/<project id>/work/        per worker: <id>.pid, <id>.log, <id>.autosave.xml (recovery copy)
```

Backup = the whole data directory (stop the service first, or save / discard open changes). Deleting a project or a
user in the UI / CLI removes the files.

### API (`api.php/<route>`, JSON)

Every route except `login` needs the session cookie or `Authorization: Bearer <API token>`; with the cookie every
route that is not `GET` needs the header `X-CSRF-Token` (value from `login` / `me`). Errors: `{"error": "…"}` with HTTP status 400 (input / pan-os-php error), 401 (login
required), 403 (permission, CSRF, HTTPS), 404 (unknown or no access), 409, 413, 429, 5xx.

| Route | Method | Permission | Function |
|---|---|---|---|
| `login` | POST | – | body `user`, `password` → `user`, `admin`, `csrf` |
| `logout` | POST | login | ends the session |
| `me` | GET | login | `user`, `admin`, `csrf` |
| `password` | POST | login | body `old`, `new` |
| `meta` | GET | login | offered types with their actions (arguments, help) and filters, rule types, profile types |
| `users` | GET / POST | admin | list / create (`user`, `password`, `admin`) |
| `users/<name>` | DELETE | admin | delete a user and the projects the user owns |
| `audit` | GET | admin | audit log, newest first; query `user`, `before` (id), `limit` (1–1000) |
| `projects/<pid>/audit` | GET | owner | audit log of the project |
| `projects` | GET / POST | login | own and shared projects / create (`name`) |
| `projects/<pid>` | GET / DELETE | read / owner | project with own permission / delete |
| `projects/<pid>/members` | GET / PUT | read / owner | list / add or change (`user`, `role` = `read` or `write`, optional `types`, `scope`) |
| `projects/<pid>/tokens` | GET / POST | read | own tokens (owner: all) / create (`label`, `role`, `days`) → `token` (shown once) |
| `projects/<pid>/tokens/<tid>` | DELETE | own token or owner | delete |
| `projects/<pid>/members/<name>` | DELETE | owner (or the member itself) | remove / leave |
| `projects/<pid>/configs` | GET / POST | read / write | versions / upload (multipart field `config`) |
| `projects/<pid>/configs/<cid>` | DELETE | write | delete a version |
| `…/<cid>/download` | GET | read | the XML file |
| `…/<cid>/<resource>` | GET | read | REST per type, e.g. `addresses`, `rules`, `security-profiles` (names: `meta` → `resource`). Query `location`, `filter`, `ruletype`, `securityprofiletype`, `limit` (1–5000, default 1000), `offset` → `type`, `model`, `total`, `offset`, `limit`, `items` |
| `…/<cid>/<resource>/<name>` | GET | read | the object(s) with this name (all locations, or `?location=`); `404` when there is none |
| `…/<cid>/<resource>/actions` | POST | write | body `location`, `filter`, `actions` → like `change`; the type comes from the resource |
| `projects/<pid>/files?kind=playbook\|bp` | GET / POST | read / write | project files: list / upload (multipart field `file`) of a playbook JSON (checked, see below) or a BP JSON |
| `projects/<pid>/files/<fid>[/download]` | DELETE / GET | write / read | delete / download a project file |
| `…/<cid>/stats/runs` | POST | read, whole configuration | queues a run (`type=stats actions=display-bpa json-to-folder`), body `location` (default `any`), optional `bp` (BP JSON of the project) → `202` with `jid`, `state` |
| `…/<cid>/playbook/runs` | POST | read, whole configuration | queues `type=playbook` on this version: body `playbook` (file id), optional `bp` (file id, becomes `shadow-bpjsonfile=`) |
| `projects/<pid>/runs/<jid>/save` | POST | write | the result configuration (`out.xml`) of a finished playbook run becomes a new version |
| `projects/<pid>/runs` | GET | read, whole configuration | the last 200 runs |
| `projects/<pid>/runs/<jid>` | GET / DELETE | read / who started it or write | `state` (`queued`, `running`, `done`, `failed`, `cancelled`), `files` / cancel an open run, delete a finished one with its files |
| `projects/<pid>/runs/<jid>/files/<name>` | GET | read, whole configuration | one result file (e.g. `json/debugAPI_string.json`, `run.log`) |
| `…/<cid>/objects` | GET | read | query `type`, `location`, `filter`, `ruletype`, `securityprofiletype` → `total`, `columns`, `rows`, `status`; starts the worker if needed |
| `…/<cid>/status` | GET | read | `loaded`, `dirty`, `changes`, `saved`, `autosaved` (does not start a worker) |
| `…/<cid>/change` | POST | write | body like `objects` plus `actions` → `processed`, `log`, `status` |
| `…/<cid>/save` | POST | write | → `saved`, `cid` of the new version, `status` |
| `…/<cid>/discard` | POST | write | drops unsaved changes (stops the worker) |

**Object model.** `tags`, `addresses`, `address-groups`, `services`, `service-groups`, `schedules`, `url-categories`,
`external-dynamic-lists`, `log-forwarding-profiles`, the security profile resources (`anti-spyware-profiles`,
`vulnerability-protection-profiles`, `url-access-profiles`, `file-blocking-profiles`, `dns-security-profiles`,
`wildfire-anti-virus-profiles`; Panorama / firewall: own `antivirus-profiles`, `wildfire-analysis-profiles`, and DNS
security inside the anti-spyware profile as `botnet_domains` – SCM has it apart in `dns-security-profiles`),
`profile-groups`, `zones`, `zone-protection-profiles` and the rule resources (`security-rules`, `nat-rules`,
`decryption-rules`, `app-override-rules`, `authentication-rules`, `pbf-rules`, `qos-policy-rules`; own: `dos-rules`,
`tunnel-inspection-rules`, `captive-portal-rules`, `default-security-rules`, `sdwan-rules`,
`network-packet-broker-rules`; rules carry the own fields `uuid`, `rulebase`, `position`) answer in the shape of the
SCM API (`model: scm-v1`, `lib/misc-classes/ApiObjectModel.php`): SCM field names and structure, plus the location of
the object (`device_group` – `"shared"` for shared –, `vsys`, `template` / `template_stack`; SCM input: `folder`, `snippet`, `device`). Example:
`{"name": "shared-host1", "ip_netmask": "1.2.2.3/32", "tag": ["grp.shared-group1"], "device_group": "shared"}`.
`?computed=1` adds what pan-os-php calculates as `_panosphp` (never configuration): `references`, `ip_count`
(address), `visibility` / `best_practice` with the single `checks` (security profiles, profile groups; `null` = N/A),
`profiles_visibility` / `profiles_best_practice` (security rules). The verdicts use the BP JSON shipped with pan-os-php,
or a BP JSON file of the project with `?bp=<file id>` (also for `objects`, and as `bp` in the body of a change, where
`alert-only-set` / `best-practice-set` then set what that file lists). It applies to this one request only.
`?model=display-v0` gives the display fields of the pan-os-php type instead. The other resources follow in the order of
their dependencies ([todo/json-object-model.md](../../../todo/json-object-model.md)).

**Types.** Every pan-os-php type with objects (action `display`, 34 today) has a REST resource. The 8 types of
`ViewerApp::TYPES` can be changed; all others are **read only** until their actions are in a reviewed allow list.
`model` = `display-v0`: an item has the fields of `actions=display`; this is not a stable object model yet. Verified
with objects in the test configuration: address, application, device, dns-rule, interface, log-profile, rule,
securityprofile, securityprofilegroup, service, tag, threat, threat-rule, zone; the other types answer, verified only
with an empty result. Types without objects (`playbook`, `stats`, mergers, …) are not offered yet (jobs).

**Runs (jobs).** A run is queued by the API and executed by `bin/jobs.php` (start it like the service; `PANOSPHP_VIEWER_JOBS`
parallel runs, default 2; `PANOSPHP_VIEWER_JOB_TIMEOUT` seconds, default 3600). The pan-os-php arguments are built on the
server from checked values (`ViewerApp::jobCreate()`); nothing of the request becomes an argument, a file name or a path.
`in=` is the version file, the working directory is `<data>/projects/<pid>/jobs/<jid>/`, where the result files and
`run.log` stay; server paths are replaced when a file is downloaded. At most 20 open runs per project. Run types:
`stats` and `playbook`; not yet: mergers, `diff`, one container per run.

**Playbook runs.** The playbook JSON and the BP JSON are files of the project (`projects/<pid>/files`). A playbook is
checked when it is uploaded and again before every run (`ViewerApp::playbookCheck()`):
* no keys `in`, `out`, `projectfolder`, `json` – input, output and folders are set by the run;
* every step: `type` out of `ViewerApp::PLAYBOOK_TYPES` (types that work on the configuration file only), every
  argument out of `PLAYBOOK_ARGS` (`actions`, `filter`, `location`, `template`, `ruletype`, `securityprofiletype`,
  `devicetype`, `outputformatset`, `exportCSV`, …) – `in=`, `out=`, `shadow-bpjsonfile=` and anything else is refused;
* file names (`outputformatset=`, `exportCSV=`, first argument of `export…` actions) are plain names without a path;
  filters that read a file and actions that reach other systems are refused; the `scm` variant of a step is checked
  the same way.

The run calls `type=playbook in=<version> json=<playbook> out=out.xml stagename=stage/step- outputformatset=set-commands.txt`
(+ `shadow-bpjsonfile=<BP JSON>`) in the folder of the run; exports, set commands, stage files and `out.xml` are its
result files. `POST …/runs/<jid>/save` takes `out.xml` as a new version.


### Processes

```
browser ──HTTPS──> api.php (ViewerApp) ──unix socket──> worker of the version   (configuration in memory)
                         │                                   ▲
                         └──unix socket──> bin/service.php ──┘ fork (only when a version is opened)
```

* `bin/service.php` accepts one request: start a worker for a version file. Every path of the request must be inside
  one project folder of the data directory.
* A worker answers `read`, `change`, `save`, `status`, `close` (one JSON line per connection). `read` runs in a forked
  copy; `change` is tried in a forked copy and, when that worked, run on the real memory; `save` only writes a new
  `<id>.xml` into the folder of its own project.
* A worker stops after `PANOSPHP_VIEWER_IDLE_MIN` minutes without a request, on `discard`, when its version or
  project is deleted, or when the service stops. Unsaved changes are then in `<id>.autosave.xml` and become a version
  on the next request for that version.

### Change in the pan-os-php library

`UTIL::$sharedConfig` (`utils/lib/UTIL.php`): `null` by default = unchanged behaviour. A long running process sets it
to `array( 'xmlDoc' => DOMDocument, 'pan' => null )`; the first `UTIL` run loads the configuration into `'pan'`, every
later run in the same process reuses it instead of reading `in=` again, and `UTIL::__destruct()` leaves it alone.
Used by `bin/worker.php` only.

### Allow list per action

`action-classes.json` (built by `php bin/action-classes.php`; `… check` tells whether it is up to date) holds the risk
class of every pan-os-php action, from its arguments and its source:

| Class | Meaning | Interactive change | Playbook run |
|---|---|---|---|
| `read` | shows objects | offered | offered |
| `change` | changes the configuration in memory | offered | offered |
| `writes-file` | writes a file (`export…`, `display-shadowrule`, …); `file_arg` = position of the file name | not offered | offered, plain file name, folder of the run |
| `reads-file` | reads a file of the server (`…-from-file`, …) | never | never |
| `network` | reaches another system or handles keys (DNS lookup, LDAP, `…-fastapi`, `upload-…`, `authkey-…`, `system-…`) | never | never |

An action that is not in the file is never offered. A type can be **changed** only when it is in `"reviewed"` – the 8
types of the prototype today; add a type there after reading its classes (and correct single actions in `"override"`,
which survives a rebuild). All other types stay read only. The classes are generated, not proven: an action can do
more than its name, arguments and the scanned calls show – that is what the review per type is for.

### Extending

* another type: `ViewerApp::TYPES` (the type must be in `utils/lib/util_action_filter.json` and print its objects
  with `actions=display` in `shadow-json`)
* offered actions: the `read` / `change` actions of `action-classes.json` (except `display`); in addition still the
  name patterns `ViewerApp::ACTION_DENY_NAME` and actions with an argument matching `ViewerApp::ACTION_DENY_ARG`

## Test

```bash
cd tests && php test_config_viewer.php
```

340 checks: login, allow list per action, audit log, project files, playbook runs, SCM object model, REST resources per type, runs (jobs), grants per member (types, locations), API tokens, separation between users (every project route `404` without access), read / write / owner, CSRF,
input checks, load once, change in memory, save as new version, recovery of unsaved changes, discard, delete, service stop.
