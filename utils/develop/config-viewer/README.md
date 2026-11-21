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
| jobs | `bin/jobs.php` | second long running process: executes the queued runs (`stats`, `playbook`), result files in the folder of the run; optional one container per run |
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

## Start it: ./panosphp-viewer

**For customers - one command** (computer with internet and Docker; nothing else to download):

```bash
curl -fsSL https://raw.githubusercontent.com/swaschkut/pan-os-php/alpha/utils/develop/config-viewer/install-viewer.sh | bash
```

`install-viewer.sh` makes the folder `panosphp-viewer`, downloads the start script and the compose files into it and runs `./panosphp-viewer start` (the questions come up in the terminal also through the pipe). Run the same command again to update: files and images are renewed, settings (`.env`), plug-ins and data stay. `PANOSPHP_CHANNEL=beta|dev|main` takes the files of that branch and the matching image (`beta`, `develop`, `latest`); a folder name as argument: `… | bash -s -- /opt/panosphp-viewer`. Without internet: the air-gap bundle.

The script itself - next to the compose files, for Sven and for customers:

```bash
cd utils/develop/config-viewer          # or the unpacked air-gap bundle
./panosphp-viewer start                 # the first time: asks who uses it (this computer / HTTPS) and the port
```

| Command | What it does |
|---|---|
| `start` / `stop` / `restart` | start (questions the first time), stop (data stays), restart |
| `status` | containers, address, licence and plug-ins |
| `logs [web\|service\|jobs\|proxy]` | the last lines of the log |
| `setup` | the questions again (port, HTTPS, name, certificate: own CA / own files / Let's Encrypt) |
| `user add <name> admin` | the first administrator without a browser (password shown once) - only while there is none |
| `user list` / `projects <user>` / `token list <user> <project>` | look only |
| `license <file>` / `license` | install a licence / show it |
| `plugin <file.ppp>` / `plugin` | add a licensed plug-in package to `plugins/` / list them |
| `update` | newer images (`images.tar.gz` next to the script = air gap, else from Docker Hub), restart |

**First administrator:** a new installation has no user. `start` (and `status`) show a one-time code; the login page offers "create the administrator" with it. Without a browser: `./panosphp-viewer user add <name> admin`. Installations without questions: `VIEWER_ADMIN_USER` + `VIEWER_ADMIN_PASSWORD` at the first start. After that, **users, passwords, projects and API tokens are changed in the browser only** (admin: Account → Users, with **New password**; tokens: project → API tokens): `bin/user.php` (`add`, `password`, `delete`) and `bin/token.php` (`project-add`, `create`, `delete`) refuse once there is an administrator, so whoever can run commands on the computer can not reset a password or make himself an administrator. Done and refused command line changes go into the audit log (method `CLI`) and are shown once to every administrator after the next login. Whoever can use Docker on the computer can still read the volume - that is the real border. Keep two administrators: when the only one forgets the password, only a new start without the data is left. The login page also shows the help pages of `docs/*.md` (Markdown, no login needed - nothing secret belongs there).

The answers are kept in `.env` next to the script (readable only for the user; the environment wins, as with docker compose, so `VIEWER_HTTPS=yes VIEWER_DOMAIN=viewer.example.com ./panosphp-viewer setup` needs no questions). Plug-ins are in `plugins/` next to the script. `bin/license.php` is the command line for the licence inside the web container (`install <file|->`, `show`, `remove`).

**Not checked yet:** the script was run against a stand-in `docker` (`tests/test_config_viewer_start.php`: calls, settings, password, licence, plug-in, update), not against a real Docker.

## Run it with one command (Docker)

Needs Docker with `docker compose` and the pan-os-php image (`swaschkut/pan-os-php:alpha`; it holds the viewer, since `docker/Dockerfile` installs SQLite for PHP and the docker client). Only `docker-compose.yml` of this folder is needed, not the repository:

```bash
docker compose -f docker-compose.yml up -d
docker compose -f docker-compose.yml exec -w /tools/pan-os-php/utils/develop/config-viewer web php bin/user.php first-code   # first start: the one-time code
```

Browser: `http://127.0.0.1:8080/` → create the administrator with the one-time code (first start) → create a project → upload a configuration.

* Three containers from the one image: `web`, `service` (workers) and `jobs` (job runner). Runs (`stats`, `playbook`) get their own container each - see "One container per run".
* Data (database, versions, result files) is in the volume `panosphp-viewer-data`. `... down` stops everything and keeps the data, `... down -v` deletes it. New image: `... pull`, then `... up -d`.
* Other image / tag: `VIEWER_IMAGE=swaschkut/pan-os-php:develop`. Own build from the repository root: `docker build -t swaschkut/pan-os-php:alpha -f docker/Dockerfile .`
* Own first user / port: `VIEWER_ADMIN_USER=sven VIEWER_ADMIN_PASSWORD='ten+ characters' VIEWER_PORT=9000 docker compose ... up -d` (the password is used at the first start only).
* The page answers on this computer only (`127.0.0.1`), over HTTP, with the built-in web server of PHP. That fits one person on a notebook; for several people see HTTPS below.
* Only `jobs` gets the Docker socket; `service` and `jobs` have no network. The web part checks workers by their files only (pid file, socket), never by process id - `web` and `service` are separate containers; the service removes the files of a worker that has ended.
* The containers start as root only to hand over the data volume and (jobs) the group of the Docker socket; the PHP processes run as the user `ubuntu` (`docker/start.sh`).

## HTTPS (several users, server)

A reverse proxy (Caddy) in front; the web part is then reachable through it only. `VIEWER_DOMAIN` is the name the users type into the browser:

```bash
VIEWER_DOMAIN=viewer.example.com docker compose -f docker-compose.yml -f docker-compose.https.yml up -d
```

| Certificate | Setting | Fits |
|---|---|---|
| Caddy's own CA (default) | nothing (`VIEWER_TLS=internal`) | air gap, first start. Browsers warn until the CA certificate is trusted: `docker compose -f … -f … exec proxy cat /data/caddy/pki/authorities/local/root.crt` |
| your own certificate | `VIEWER_CERTS=/folder` with `cert.pem` + `key.pem`, `VIEWER_TLS="/certs/cert.pem /certs/key.pem"` | company CA, air gap |
| Let's Encrypt | `VIEWER_TLS=name@example.com` | public DNS name, internet access |

Ports: 443 and 80 (redirect), change with `VIEWER_HTTPS_PORT` / `VIEWER_HTTP_PORT`. Behind the proxy the audit log and the login lock use the client address the proxy reports (last entry of `X-Forwarded-For`).

**Air gap (no internet at the customer):** `airgap/make-bundle.sh [image] [platform]` on a computer with internet writes one file `panosphp-viewer-<tag>-<platform>-<date>.tar.gz` with the images (pan-os-php, proxy), both compose files, the proxy settings, `install.sh` and `README.txt`. At the customer: unpack, `./install.sh` (or `VIEWER_DOMAIN=… ./install.sh` for HTTPS). The same again with a newer bundle is the update. One bundle per platform: `linux/amd64` (Intel / AMD) and `linux/arm64` (Apple silicon); `install.sh` refuses the wrong one. Docker itself must already be installed there.

**Checked (Sven, 2026-11-20, Docker Desktop on macOS, image `swaschkut/pan-os-php:alpha`):** start with the published image, opening a version, runs, and HTTPS through the proxy with its own CA (`VIEWER_DOMAIN=localhost`). **Not checked yet:** own certificate and Let's Encrypt; the air-gap bundle on a real installation (`make-bundle.sh` / `install.sh` ran only with a stand-in `docker`: content of the bundle, order of the calls, wrong platform refused); Linux hosts; Podman.

## Run it without Docker (lab)

Needs PHP ≥ 7.4 with `pdo_sqlite`; the PHP **CLI** also needs `pcntl` and `posix` (service / worker). Check:

```bash
php -m | grep -E "pcntl|posix|pdo_sqlite"      # all three must be listed (Homebrew PHP on macOS has them)
```

Two terminals; `PANOSPHP_VIEWER_DATA` must be **the same** in both.

Terminal 1 – data directory, first user, service:

```bash
cd utils/develop/config-viewer
export PANOSPHP_VIEWER_DATA=$HOME/pan-os-php-viewer-data    # outside the web root; path ≤ 60 characters
php bin/user.php add alice admin                            # once - the first administrator; asks for the password (10+ characters)
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

More users and new passwords: as admin in the UI (Account → Users). `bin/user.php` changes users only while there is
no administrator (`add`, `password`, `delete`); `list` always.

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
| `login` | POST | – | body `user`, `password` → `user`, `admin`, `csrf`, `notices` (admin: command line use since the last login) |
| `logout` | POST | login | ends the session |
| `me` | GET | login | `user`, `admin`, `csrf` |
| `password` | POST | login | body `old`, `new` |
| `bp-default` | GET | login | the BP JSON shipped with pan-os-php (`utils/api/v1/bp/scm_bp_sp_panw.json`): start of a new BP JSON in the editor |
| `meta` | GET | login | offered types with their actions (arguments, help) and filters (field → operator → `arg`, `example`, `help`; from `utils/lib/util_action_filter.json`), rule types, profile types |
| `users` | GET / POST | admin | list / create (`user`, `password`, `admin`) |
| `network` | GET / PUT | admin | network for runs (imports): `enabled`, `allow`, `deny` (lists: host, `*.domain`, IP, network, `tsg:<id>`, `*`; deny wins, empty allow list = nothing) |
| `keys` | GET / POST | login (no token) | own API keys (personal): list (`kid`, `kind`, `target`, `label`, `hint` = last 4 characters, `refused` = why not usable now) / store (`kind` `panos`: `target` host, `key`; `scm`: `target` TSG, `client_id`, `client_secret`) - the secret is never sent back |
| `central` | GET | admin | App-ID database / MaxMind data of the installation (`appid`, `geoip`: version / countries, source, user, time; `image`: App-ID of the image) and their runs (`pid` = the project of the installation, runs under `projects/<pid>/runs`) |
| `central/appid/runs`, `central/geoip/runs` | POST | admin | download with an own key (`kid`: firewall key / `maxmind-licensekey` entry); network rules as for imports, no project switch |
| `central/appid`, `central/geoip` | POST / DELETE | admin | upload (multipart `file`: `predefined.xml` / GeoLite2-Country-CSV zip - converted by a run without network) / back to the image |
| `projects/<pid>/appid` | GET / POST / DELETE | read / write / write | App-ID database the project uses (`from`: project / installation / image) / upload an own one / back to the installation; download: `POST projects/<pid>/appid/runs` (`kid`) |
| `keys/import` | POST | login (no token) | take over an existing `.panconfkeystore` (multipart field `keystore`, or JSON `keystore` = its text): `<host>[%port]`, `tsg_id<TSG>`, `egressip_tsg_id<TSG>`, `ldap_user<user>` (kind `ldap`), `ldap-password`, `bpa-apikey`, `license-apikey`, `maxmind-licensekey`, `gcp-mysql-password`, other names → `imported` (kind, target), `skipped` (line, reason) |
| `keys/<kid>` | PUT / DELETE | login (no token) | change an own key: `label`, `port` (PAN-OS), optionally a new secret (`key` / `client_id` + `client_secret`; empty = the stored one stays) / delete it |
| `ldap` | GET / POST | login (no token) | own saved LDAP queries (personal; `accounts` = my LDAP accounts, key store entries `ldap_user<user>`) / save one: `name`, `domain`, `server` (`ldaps://host[:port]`, empty = automatic: the first domain controller of the domain from DNS that works), `ldaps` (automatic: LDAPS / LDAP), `bind_user`, `base_dn`, `attribute` (default `sAMAccountName`), `mode` (`validation`, `user-groups`, `common-groups`, `group-members`), `users`, `group`, `transitive` |
| `ldap/<qid>` | PUT / DELETE | login (no token) | change / delete an own LDAP query |
| `projects/<pid>/ldap-discover/runs` | POST | write (no token) | help for a first LDAP query: `domain` (AD domain), `ldaps` (default yes) → `type=ldap-query mode=discover` (DNS SRV of the domain controllers, base DN from the RootDSE of the first that answers - no login, no key); the allow list must cover the hosts of the domain (`*.<domain>`) |
| `projects/<pid>/runs/<jid>/ldap-servers` | GET | write | result of such a run: servers with `refused` (network rules now), `rootDse`, `suggestion` (name, server, base DN, my LDAP account of the domain) |
| `projects/<pid>/ldap/runs` | POST | write | run an own LDAP query (`qid`) with `type=ldap-query` → `ldap.json`, `ldap.csv`; network rules as for imports (server on the allow list); see `docs/7-ldap.md` |
| `projects/<pid>/configs/<cid>/ldap-users/runs` | POST | write | users of the security rules of a version against the LDAP of a query (`qid`, `action` `show` / `remove`): `type=rule actions=user-check-ldap`; `remove` → result configuration (`…/save`) |
| `projects/<pid>/runs/<jid>/convert` | POST | write (no token) | a failed SCM import: only the conversion (`scm-export-xml`) again on the export the run has - no network, no key; the run is queued again (old log → `run-<n>.log`), its result becomes a new version |
| `projects/<pid>/network` | PUT | owner | network for the runs of the project (`enabled`); works only while the administrator allows it |
| `projects/<pid>/import/runs` | POST | write | import from a device with an own key: `kid`, `source` (`candidate` / `running`, PAN-OS) → a new version when done; see `docs/6-import-from-devices.md` |
| `users/<name>/password` | POST | admin | a new password for the user, made by the viewer → `password` (shown once) |
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
| `…/<cid>/references` | GET | read | who uses an object (pan-os-php `displayreferences`): query `type` (one with `references` in `meta`), `location`, `name` (+ `ruletype` / `securityprofiletype`) ; the list of the page (`…/<cid>/objects`) has a `refcount` column after `name` for these types (the same users, counted; not in REST items) → `objects` (every object of that name: `location`, `class`, `references`: `type`, `ruletype`, `securityprofiletype`, `location`, `name`, `class`, `rulebase`, `fields`, `open`; `hidden`: users outside the types / locations of a limited member) |
| `…/<cid>/locations` | GET | read | locations of the version (loads it): `config` (`panorama` / `firewall` / `scm`), `any`, `locations` (`name`, `kind`: `shared`, `device-group`, `vsys`, `shared-gateway`, `container`, `snippet`); limited members: only theirs, `any` false |
| `…/<cid>/<resource>` | GET | read | REST per type, e.g. `addresses`, `rules`, `security-profiles` (names: `meta` → `resource`). Query `location`, `filter`, `ruletype`, `securityprofiletype`, `limit` (1–5000, default 1000), `offset` → `type`, `model`, `total`, `offset`, `limit`, `items` |
| `…/<cid>/<resource>/<name>` | GET | read | the object(s) with this name (all locations, or `?location=`); `404` when there is none |
| `…/<cid>/<resource>/actions` | POST | write | body `location`, `filter`, `actions` → like `change`; the type comes from the resource |
| `projects/<pid>/files?kind=playbook\|bp` | GET / POST | read / write | project files: list / upload (multipart field `file`) of a playbook JSON (checked, see below) or a BP JSON |
| `projects/<pid>/files/<fid>[/download]` | DELETE / GET | write / read | delete / download a project file |
| `…/<cid>/stats/runs` | POST | read, whole configuration | queues a run (`type=stats actions=display-bpa json-to-folder`), body `location` (default `any`), optional `bp` (BP JSON of the project) → `202` with `jid`, `state` |
| `…/<cid>/playbook/runs` | POST | read, whole configuration | queues `type=playbook` on this version: body `playbook` (file id) **or** `predefined` (name of an offered predefined playbook, e.g. `visibility.json`), optional `bp` (file id, becomes `shadow-bpjsonfile=`), optional `subprocess`, `memorythreshold`, `debugmemory`, `removestagefiles` |
| `playbooks` | GET | login | the predefined playbooks offered for runs (`name`, `steps`) |
| `playbooks?all=1` / `playbooks` | GET / PUT | admin | all predefined playbooks with `on`, `usable`, `why` / turn them on: body `enabled` (list of names; only usable ones) |
| `…/<cid>/diff/runs` | POST | read, whole configuration | queues `type=diff`: this version = `file1`, body `other` (cid) = `file2`; optional `setcommands` (→ `set-commands.txt`, file1 → file2), `noruleordercheck`, `xpath` (an XPath of the configuration: `/config…`, `/policy…`, `/template…`, `/cloud_services…`; never a file); no `in=` |
| `projects/<pid>/runs/<jid>/save` | POST | write | the result configuration (`out.xml`) of a finished playbook run becomes a new version |
| `projects/<pid>/runs` | GET | read, whole configuration | the last 200 runs |
| `projects/<pid>/runs/<jid>` | GET / DELETE | read / who started it or write | `state` (`queued`, `running`, `done`, `failed`, `cancelled`), `files` / cancel an open run, delete a finished one with its files |
| `projects/<pid>/runs/<jid>/files/<name>` | GET | read, whole configuration | one result file (e.g. `json/debugAPI_string.json`, `run.log`) |
| `…/<cid>/object` | GET | read | one object for the object window: query `type`, `location` (of the object, not `any`), `name` (+ `ruletype` / `securityprofiletype`) → `row` (the fields of the list), `model` (scm-v1 item: values, members, tags as lists) |
| `…/<cid>/objects` | GET | read | query `type`, `location`, `filter`, `ruletype`, `securityprofiletype` → `total`, `columns`, `rows`, `status` (`changes`: the unsaved changes, each `time`, `user`, `type`, `location`, `filter`, `actions`, `field`); starts the worker if needed |
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

**Playbook runs.** The playbook JSON and the BP JSON are files of the project (`projects/<pid>/files`) - or the playbook
is a **predefined** one shipped with pan-os-php (`utils/api/v1/playbook/*.json`), like the BP JSON shipped with
pan-os-php. Predefined playbooks are offered only when an administrator turned them on (Account → Predefined playbooks,
setting `playbooks` in `viewer.sqlite`); by default only `visibility.json`. Shipped playbooks the check below refuses
(today: the `*-merger` ones, `NGFW_migration_to_Panorama.json` with `in=`, `missconfiguration.json` with
`projectfolder`) are listed with the reason and can not be turned on. A run of a predefined playbook calls
`json=$$playbook$$/<name>`, as on the command line. A playbook is checked when it is uploaded and again before every run
(`ViewerApp::playbookCheck()`):
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

**Large configurations.** The run body takes the memory options of `type=playbook` (all optional, checked):
`subprocess` (true: every step its own PHP process), `memorythreshold` (MB, 64 - 1048576: a step runs as its own process
when the container uses more), `debugmemory` (true: memory use per step in `run.log`), `removestagefiles` (true). The
page offers them under "Options for large configurations". What they do: [utils/api/v1/playbook/README.md](../../api/v1/playbook/README.md).
The memory one run may use is the limit of its container - compose: `VIEWER_RUN_MEMORY` in `.env` (default `2g`; also
`VIEWER_RUN_CPUS`, `VIEWER_RUN_TIMEOUT` in seconds; a comment after the value is fine), then `./panosphp-viewer restart`;
`./panosphp-viewer status` and `restart` show the limits the job runner really has (and name a `docker-compose.yml` that is
too old for them). Setting them in the browser: idea, [todo/config-viewer-run-limits.md](../../../todo/config-viewer-run-limits.md). With Docker Desktop the VM needs
more memory than that (Settings → Resources).

**Editors** (`editor.php?e=playbook|bp`): the editors of pan-os-php (`utils/common/html/editor`), with their scripts
inline (the playbook editor gets `utils/lib/util_action_filter.json` instead of its copy `json_array.js`), under a policy of
their own - `sandbox allow-scripts` (an origin of their own: no cookies, no API), `connect-src 'none'`,
`frame-ancestors 'self'`. The page sends the file with `postMessage` (`panosphp-editor-load`), the editor answers
`panosphp-editor-save`; the page stores a new project file. Opened on their own the editors work as before.

**App-ID database and MaxMind data.** pan-os-php reads `PANOSPHP_PREDEFINED_XML` (instead of
`lib/object-classes/predefined.xml`) and `PANOSPHP_GEOIP_DIR` (instead of `lib/resources/geoip`). The viewer keeps its
own in the data directory (`central/predefined.xml`, `central/geoip/`, `projects/<pid>/predefined.xml`) and sets them for
every run (container: `/central` read-only, `/project`) and every worker (the service, from the folders, never from the
request); the image stays as it is. `type=download-predefined predefined-out=<file>` and `type=maxmind-update
maxmind-zip=<zip>` (new) make them.

**Why a run failed** (`reason` of a run): `memory` - the run was killed for memory (exit code 137 / signal 9, a killed
playbook subprocess step, or PHP's `memory_limit` in `run.log`); the page shows **out of memory** with the limit per run;
`timeout` - longer than `PANOSPHP_VIEWER_JOB_TIMEOUT`; `error` - anything else (see `run.log`).


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

* `utils/lib/util_action_filter.json` (in the repository and the image) is written by `pan-os-php type=util_action-filter`
  (`utils/lib/UTIL_GET_ACTION_FILTER.php`): per type the actions with their arguments and the filter fields with their
  operators (`arg`, test string `ci.fString`, `help`). The viewer reads it for `meta` - actions (with the allow list),
  and the filter suggestions of the page; run it again after new actions / filters, then `bin/action-classes.php`.
* another type: `ViewerApp::TYPES` (the type must be in `utils/lib/util_action_filter.json` and print its objects
  with `actions=display` in `shadow-json`)
* offered actions: the `read` / `change` actions of `action-classes.json` (except `display`); in addition still the
  name patterns `ViewerApp::ACTION_DENY_NAME` and actions with an argument matching `ViewerApp::ACTION_DENY_ARG`

## Test

```bash
cd tests && php test_config_viewer.php
```

420 checks: login, allow list per action, audit log, project files, playbook runs (own and predefined), SCM object model, REST resources per type, runs (jobs), grants per member (types, locations), API tokens, separation between users (every project route `404` without access), read / write / owner, CSRF,
input checks, load once, change in memory, save as new version, recovery of unsaved changes, discard, delete, service stop.

## Browser pages for the API parts

The project page shows, next to versions and members: **Runs** (start a `stats` / `playbook` run on a version, optional BP JSON, state refreshes while a run is open, result files, "Result as new version"), **Project files** (playbook JSON / BP JSON upload, download, delete), **Members** with the limits per member (types, locations), **API tokens** (create - the token is shown once -, list, delete) and for the owner the **Audit log** of the project. Admins see the audit log of everything under "Account".
A member limited to types or locations sees no runs card and no upload / download / delete of whole versions; the viewer offers only its types and starts with its first location. The page only hides what the server refuses anyway - the checks are in `ViewerApp`.

## One container per run

Without a setting a run is a process of the job runner. With `PANOSPHP_VIEWER_CONTAINER=docker` (or `podman`) for `bin/jobs.php` every run is one container, built in `lib/ViewerContainer.php`:

```
docker run --rm --name panosphp-run-<jid> --label panosphp-viewer=<installation>
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges
  --pids-limit 256 --memory 2g --cpus 2 --tmpfs /tmp:rw,noexec,nosuid,size=256m
  --mount <data>/projects/<pid>             -> /project  (read-only: version files, playbooks, BP JSON)
  --mount <data>/projects/<pid>/jobs/<jid>  -> /job      (read-write: working directory, result files)
  --workdir /job --user <uid:gid> --entrypoint php <image>
  /tools/pan-os-php/utils/pan-os-php.php type=<type> in=/project/<version>.xml <checked arguments>
```

* From the job come only project id, job id, version file name (each checked) and the pan-os-php arguments. They stand after the image, so they are arguments of pan-os-php and can not become options of the runtime.
* A run sees the versions and files of its own project (read-only), no other project, not the database, no network.
* Cancel, time limit and delete remove the container (`rm --force`); at its start the job runner removes containers left over from this installation.
* A wrong setting or a runtime that does not answer stops the job runner. It does not fall back to runs without a container.

| Setting (for `bin/jobs.php`) | Meaning |
|---|---|
| `PANOSPHP_VIEWER_CONTAINER` | `docker` or `podman`; empty: no container |
| `PANOSPHP_VIEWER_CONTAINER_IMAGE` | image with pan-os-php, same version as the viewer (needed) |
| `PANOSPHP_VIEWER_CONTAINER_DATA` | where the **runtime** finds the data directory: absolute path on its host, or the name of the volume that holds it. Default: `PANOSPHP_VIEWER_DATA` (job runner directly on the host) |
| `PANOSPHP_VIEWER_CONTAINER_TOOL` | `pan-os-php.php` in the image (default `/tools/pan-os-php/utils/pan-os-php.php`) |
| `PANOSPHP_VIEWER_CONTAINER_MEMORY`, `_CPUS` | limits per run (default `2g`, `2`; compose: `VIEWER_RUN_MEMORY`, `VIEWER_RUN_CPUS` in `.env`) |
| `PANOSPHP_VIEWER_CONTAINER_DNS` | DNS servers (IP addresses, `,` separated) of a run step with network - for internal names (AD domain controllers, firewalls); compose: `VIEWER_RUN_DNS` in `.env`; empty: the runtime decides (Docker: the resolver of the host, or public ones when the host has only a local one) |
| `PANOSPHP_VIEWER_CONTAINER_USER` | `uid:gid` in the container (default: the one of the job runner, so that it can read the result files) |

**Viewer itself in containers (Docker).** Three services with the same data volume: web (`api.php`), service (`bin/service.php`), job runner (`bin/jobs.php`). Only the job runner gets the Docker socket (`/var/run/docker.sock`) and the `docker` client; web and service get neither. Who controls the socket controls the host - that is why it stays in the one process that builds the call from fixed parts and takes no request from the network. The run containers are started by the Docker of the host, so `PANOSPHP_VIEWER_CONTAINER_DATA` must be the volume name (as `docker volume ls` shows it, with the compose project prefix) or the host path of the data directory, not the path inside the job runner.

**Checked (Sven, 2026-11-20):** stats and playbook runs in containers with Docker Desktop on macOS, data in the volume (`volume-subpath`), result files readable by the viewer. **Not checked yet:** Docker Engine on Linux (group of the socket, file owner), a host path instead of a volume, Podman. The repository test (`tests/test_config_viewer_container.php`) uses a stand-in `docker` program. The interactive workers (`bin/worker.php`) are not in containers yet.

## Example: a playbook run from a script

`examples/viewer-playbook-run.sh` (needs `curl`, `jq`): log in → new project → upload a Panorama / firewall XML (and the playbook, when it is a file) → run → download `out.xml` (changed configuration), `set-commands.txt` and `run.log`.

```bash
# predefined playbook of pan-os-php (turned on by an administrator; visibility.json is on by default)
VIEWER_PASSWORD='...' utils/develop/config-viewer/examples/viewer-playbook-run.sh panorama.xml visibility.json [bp.json]
VIEWER_PASSWORD='...' utils/develop/config-viewer/examples/viewer-playbook-run.sh panorama.xml '$$playbook$$/visibility.json'
# an own playbook file (uploaded into the project)
VIEWER_PASSWORD='...' utils/develop/config-viewer/examples/viewer-playbook-run.sh panorama.xml ./my-playbook.json [bp.json]
```

Without the third argument the BP JSON shipped with pan-os-php is used (CLI: no `shadow-bpjsonfile=`). The set commands file is always written (CLI: `outputformatset=`); its name is fixed. Settings: `VIEWER_URL`, `VIEWER_USER`, `VIEWER_PROJECT`, `VIEWER_OUT`. It logs in with user and password because an API token belongs to one existing project; for repeated runs in one project use a token (`Authorization: Bearer`, no CSRF header).

## Plug-ins (interface version 1)

A plug-in adds to the viewer without changing its code (`lib/ViewerPlugins.php`):

| What | How it shows |
|---|---|
| run types | `POST …/configs/<cid>/<plugin>-<run>/runs`; in the page: the "Runs" card with the fields the plug-in declares (`text`, `location`, `select`, `multi`, `file:<kind>`) |
| run types without a version (`'input' => 'none'`) | `POST …/projects/<pid>/<plugin>-<run>/runs` - the input is a project file, the result becomes a version (e.g. a migration) |
| file kinds | files of a project for its runs: `…/files?kind=<plugin>-<kind>`, with a check by the plug-in at upload. JSON, or `'format' => 'raw'` for any file (a 3rd party configuration) with its own size limit (`'max'`, up to 200 MB) |
| result into another project | `POST …/runs/<jid>/save` with `{"project": "<pid>"}` (write permission there): the version's note names the run and the project it comes from |
| playbook step types | pan-os-php types a playbook may use in addition |

A plug-in is a folder `<name>/` with `plugin.php` that returns the description as an array - see `examples/plugins/example/plugin.php` (two run types, one file kind). Folders: `plugins/` in this folder, and the folder named by `PANOSPHP_VIEWER_PLUGINS` (set it for web, service and job runner). `GET meta` → `plugins` lists run types, fields and file kinds; admins also see under Account which plug-ins are loaded and why one was refused.

What a plug-in run can do is limited by the viewer, not by the plug-in:

* The plug-in only builds the pan-os-php arguments, from checked values (`ViewerPluginRun`: `text()`, `location()`, `file()`, `json()`, `out()`). It never gets a path of the server.
* `in=` is always the version of the run; `in=`, `type=`, `projectfolder=` and an `out=` outside the folder of the run are refused. Files come from the same project only. The run itself is a normal run (own folder, own container when configured, no network).
* A run type with `'result' => 'out.xml'` can be taken as a new version; a run never changes a version.
* A description that does not fit (interface version, names, fields) is refused as a whole.

A plug-in is PHP code inside the web part and the job runner - install only what you would install as part of the viewer. `'feature' => '<name>'` marks a plug-in as a licensed feature; `ViewerApp::featureOn()` is the one place for that check and says yes to everything until licences are built ([todo/config-viewer-license.md](../../../todo/config-viewer-license.md)).

**Files of a plug-in in its runs:** a run type can set environment variables for pan-os-php (`'env' => array( 'PANOSPHP_MIGRATION_PARSERS' => '%PLUGIN%/parser' )`; names `PANOSPHP_…`, not `PANOSPHP_VIEWER_…`; `%PLUGIN%` is the folder of the plug-in). With one container per run that folder is mounted read-only at `/plugin`.

**Install a plug-in that is not in the image (Docker):** put its folder (e.g. `migration/` with `plugin.php`) into a folder on the host and start with that folder:

```bash
VIEWER_PLUGINS_DIR=/path/to/plugins docker compose -f docker-compose.yml up -d
```

The compose file mounts it read-only into web, service and job runner (`/plugins`) and tells the job runner the host path (`PANOSPHP_VIEWER_CONTAINER_PLUGINS`), so that a run of the plug-in gets its folder. Without Docker: `PANOSPHP_VIEWER_PLUGINS=/path/to/plugins` for web part, service and job runner. Account → Plug-ins shows whether it was loaded.

A raw file is not given to members limited to types / locations. **Not yet:** own PHP code of a plug-in inside the run (today a run is one pan-os-php call), own API routes and own pages, a result page from a JSON of the run (estimate of a migration), a link between projects that offers a newer import, encrypted plug-ins. In Docker a plug-in folder must be mounted into `web`, `service` and `jobs` (not in the compose file yet).

## Licence and licensed plug-ins

Basic is everything without a licence. Licensed plug-ins (e.g. migration) are delivered as encrypted packages `<name>.ppp`: put the file into the plug-in folder (`VIEWER_PLUGINS_DIR` / `PANOSPHP_VIEWER_PLUGINS`) and install the licence under Account → Licence (admin; paste the text or choose the file). Account → Plug-ins shows each package as on or locked, with the reason (no licence, feature missing, licence ended, key of this release missing, clock set back).

* The licence is signed (Ed25519) by the maker; the public keys pan-os-php trusts are in `lib/resources/license/keys.json`, withdrawn licence ids in `lib/resources/license/revoked.json` (ship with every release - the way to withdraw without an online check).
* A package is decrypted only in memory (`ppp://<name>/…`); its key is in the licence, a new key per release - a licence that is not renewed does not open newer releases.
* After the end date: 14 days grace (default), then the packages are locked. Basic and all data stay.
* The licence is stored in the data directory (`license.txt`); `GET license` shows it without keys; the audit log notes the change, not the text.
* What it does not do: stop a customer who changes pan-os-php on his own computer. It does stop everyone without a licence from having the code at all.

Licences and packages are made with the licence tool in the private repository (`license/license.php`).
