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
exists (adding a member); no audit log besides the version history; sessions are PHP file sessions.

## Run it (lab)

Needs PHP ≥ 7.4 with `pdo_sqlite`; the PHP **CLI** also needs `pcntl` and `posix` (service / worker).

```bash
export PANOSPHP_VIEWER_DATA=/var/lib/pan-os-php-viewer     # outside the web root, readable only by the web server user
cd utils/develop/config-viewer
php bin/user.php add alice admin                            # first user (asks for the password)
php bin/service.php &                                       # as the same OS user as the web server
php -S 127.0.0.1:8080 -t .                                  # lab only; then http://127.0.0.1:8080/
```

Behind Apache / nginx: publish only this folder (or the repository) over HTTPS, set `PANOSPHP_VIEWER_DATA` for the web
server **and** the service, run the service as the web server user.

| Environment variable | Default | |
|---|---|---|
| `PANOSPHP_VIEWER_DATA` | `<parent of the repository>/pan-os-php-viewer-data` | data directory (SQLite DB, projects, sockets); path ≤ 60 characters |
| `PANOSPHP_VIEWER_AUTOSAVE_MIN` | 5 | recovery copy of unsaved changes (service) |
| `PANOSPHP_VIEWER_IDLE_MIN` | 60 | a worker without requests stops (service) |
| `PANOSPHP_VIEWER_SESSION_IDLE_MIN` | 120 | login session idle timeout |
| `PANOSPHP_VIEWER_MAX_UPLOAD_MB` | 200 | upload limit (also `upload_max_filesize` / `post_max_size` of PHP) |
| `PANOSPHP_VIEWER_LOAD_TIMEOUT` | 600 | seconds to wait for the first load of a version |
| `PANOSPHP_VIEWER_ALLOW_HTTP` | – | `1` allows HTTP from other hosts (lab only) |
| `PANOSPHP_VIEWER_TLS_PROXY` | – | `1` when TLS ends at a reverse proxy in front of PHP (cookie gets `Secure`); the proxy must be the only way in |

## Test

```bash
cd tests && php test_config_viewer.php
```

96 checks: login, separation between users (every project route `404` without access), read / write / owner, CSRF,
input checks, load once, change in memory, save as new version, recovery of unsaved changes, discard, delete.
