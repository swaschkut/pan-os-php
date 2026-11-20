# pan-os-php API (`utils/api/v1/`)

**Status:** review / hardening needed (2026-11-17); smoke test and Postman collection review added 2026-11-18
**Code reference:** `alpha` `45bc6d8`
**Related:** [config-viewer-api.md](config-viewer-api.md) (secured API via the config-viewer), [ui-config-in-browser.md](ui-config-in-browser.md), [util-class-refactoring.md](util-class-refactoring.md)
(`exit()` in `UTIL`), [shell-autocompletion.md](shell-autocompletion.md) (same data source `util_action_filter.json`)

## Current state

| Part | File | Function |
|---|---|---|
| entry point | `utils/api/v1/tool.php` (372 lines) | `…/tool.php/<type>?in=<file>&filter=…&actions=…[&out=…]` → builds `argv` from the query and calls `PH::callPANOSPHP()`; JSON output (`shadow-json` default); upload via `$_FILES['configInput']`; `help`, `listactions`, `listfilters`; `in=api://` (PAN-OS XML API) allowed |
| upload | `utils/api/v1/file_upload.php` | upload into the project folder of the session |
| project folder | `utils/api/v1/project/` (or `$_SESSION['folder']` per user) | uploaded configs, `in=` / `out=` are relative to it |
| playbooks / BP | `utils/api/v1/playbook/*.json`, `utils/api/v1/bp/` | playbook definitions, best practice JSON |
| examples | `utils/api/PAN-OS-PHP.postman_collection.json` | Postman collection |
| container | `docker/Dockerfile-API` (+ `-API74` … `-API85`, `_amd`, `_arm64v8`) | `php:8.5-apache`, copies `lib`, `utils`, `phpseclib`, `git-php`, …; `chmod 777` project and log folder; upload / memory 500M, 600 s |
| with DB / users | `docker-compose/docker-compose.yml` + `docker-compose/init/` | image `swaschkut/pan-os-php-api:develop` (port 8000), MySQL (port 9906 published), phpMyAdmin (port 8080); login of the web UI `utils/develop/ui/test/` |

Own Todos in `tool.php`: user authentication (OAuth2, access only to own projects), create project per user →
project ID, upload into the project by ID, git module for all changes of one file (2021-06-24); `actions=display`
default (2025-01-03).

## Findings to check (security)

The API runs pan-os-php actions on the server and can write files and reach devices – it must not be reachable
without authentication.

1. **no authentication on `tool.php`**: without session the shared folder `utils/api/v1/project` is used; CORS
   `Access-Control-Allow-Origin: *` on `OPTIONS`
2. **path traversal**: `in=` / `out=` are prefixed with the project folder, but `../` is not blocked (the input check
   only blocks NUL, quotes, `;`, backtick, whitespace) → reading / writing files outside the project folder with the
   rights of the web server – to verify and fix (`realpath()` must stay inside the project folder)
3. `in=api://<host>` from the API: requests to any host with the stored API keys (`.panconfkeystore` of the project)
   – restrict or allow only for authenticated users
4. `filter=` / `actions=` are passed unchecked (the stricter check is commented out) – they are parsed by pan-os-php,
   not by a shell; check actions that write files (`exportToExcel:<file>`, `out=`) for paths
5. web UI login (`utils/develop/ui/test/php/check-login.php`, `create-user.php`): passwords as **MD5**, SQL built by
   string concatenation (input only through `htmlspecialchars`), default users in `docker-compose/init` (`admin` /
   `1234`, `John`) → `password_hash()` / `password_verify()`, prepared statements, no default users (or forced
   change)
6. `docker-compose.yml`: MySQL port and phpMyAdmin published – only for development; `chmod 777`
7. `tool.php` includes `utils/develop/ui/test/db_conn.php` (API depends on a test folder of the UI)

## Smoke test (2026-11-18, PHP built-in server, `tests/input/panorama-10.0-merger.xml`)

Works: `GET …/tool.php/address?in=<file>&location=shared&actions=display&filter=…` (JSON, 200), `?listactions`,
`type=master-key`, upload with `POST` + `configInput`, unknown type → 404 JSON with the list of types, missing `in=`
→ 404 JSON. All 99 types of `PH::$supportedUTILTypes` are accepted as endpoint. Not tested: Docker image, session /
DB login, `in=api://`.

Findings:

1. **errors of pan-os-php come back as HTTP 200**: unsupported action, unknown location → valid JSON, but status 200
   and the error only as text inside the output (usage text). Cause: `exit()` / `display_error_usage_exit()` in `UTIL`
   instead of exceptions ([util-class-refactoring.md](util-class-refactoring.md) item 4). Wanted: 4xx + `{"error": …}`
2. error messages contain the absolute server path (`file "/…/utils/api/v1/project/x.xml" does not exist`)
3. file-not-found is 404, other input errors 200 – no consistent status codes
4. `tool.php` itself: dead code (`$_POST['configapi']` branches empty, upload block with unused `$random` /
   `$upload_name`, `DELETE` with a `Location: http://localhost:8080/items` header, `PUT` / `POST` fall through to
   the same call as `GET`), the key check exists twice, `$argc` is never set, `in=` is treated as API mode when the
   value merely contains the text `api` (a file named `myapi.xml` is not prefixed with the project folder)
5. `help` copies every query key into `argv` without the key check
6. every request loads and parses the whole configuration again (about 1.5–2.5 s for the small test file) – no cache
   between requests (see [ui-config-in-browser.md](ui-config-in-browser.md))

## Postman collection (`utils/api/PAN-OS-PHP.postman_collection.json`)

Schema v2.1, 71 requests (70 `GET`, 1 `POST`), folders `utils` (43), `help` (10), `merging` (6),
`listactions/filters` (6); variables `SERVER`, `VERSION`, `INPUT`, `OUTPUT`, `MGMT-IP`, `USERNAME`, `PASSWORD`.

* covers 46 of 99 types; 53 are missing, e.g. `master-key`, `config-section`, `panorama-move`, `object-merger`,
  `rule-compare`, the `scm-*` types, `threat`, `edl`, `certificate`, `xpath`
* no request has a description, none has a test script (status / JSON check)
* 26 requests use `shadow-nojson` (text output) – the API default is JSON
* only 4 requests use `filter=`, 19 `actions=`; no example for `out=` + download of the result
* one request passes `user` / `pw` as query parameters – credentials in the URL (logs, history)
* no auth configured (matches security finding 1)
* written by hand – gets out of date with every new type

To do:

- [ ] generate the collection (and the OpenAPI description, see below) from `util_action_filter.json` + the per-type
  arguments ([shell-autocompletion.md](shell-autocompletion.md) proposal 1): one folder per type with `help`,
  `listactions`, `listfilters`, `display`
- [ ] test scripts per request (status code, valid JSON) → the collection can run as API test (newman) in CI
- [ ] descriptions; examples for upload, `out=`, download, error case
- [ ] remove credentials from query parameters; auth on collection level once the API has authentication

## Functional to do

- **API description**: OpenAPI / Swagger for `tool.php` (types, arguments, filters, actions are known in
  `util_action_filter.json` / `listactions` / `listfilters` → can be generated)
- **REST shape**: today one GET with CLI arguments; for a UI: project resources (`POST /projects`, upload, list
  configs), `GET` objects with filter / paging, `POST` actions (change list), `GET` diff, download result
- **JSON output**: stable object JSON (common model with the UI / pan-config-viewer, see
  [ui-config-in-browser.md](ui-config-in-browser.md)); errors always as JSON with HTTP status
- **SCM**: `in=scm-api://` via the API (credentials per user / project, not in the request)
- **long runs**: mergers / large configs exceed 600 s → asynchronous jobs (job ID, status, result)
- **versioning of project files**: `git-php` (Todo 2021) – history / undo per change
- tests: API tests (upload, type call, error cases, path checks) – today none for `tool.php`
- docs: one README for API + Docker (today `READMEdocker.md`, `docker-compose/howto`, Postman collection)

## Related: config-viewer prototype (2026-11-18)

`utils/develop/config-viewer/` ([README](../utils/develop/config-viewer/README.md),
[ui-config-in-browser.md](ui-config-in-browser.md)) is a second, separate API (`api.php`) that already has what is
open here for `tool.php`: login, CSRF, projects per user with `read` / `write` / `owner`, paths never taken from the
request, errors as JSON with HTTP status and without server paths, configuration loaded once. It covers 8 types and
no `in=api://`. `tool.php` is unchanged – the security findings above stay open.

- [ ] decide: move `tool.php` behind the login / project model of the config-viewer API, or replace it by that API
  step by step (decision 2 below)
- [ ] the DB / user management of the prototype (SQLite in the data directory) is a candidate for decision 3

## Open decisions

1. Authentication: session login of the web UI, API tokens, or OAuth2 / OIDC (Todo 2021).
2. Keep `tool.php` (CLI arguments in the URL) and add a REST layer, or replace it.
3. Where the DB / user management lives (today in `utils/develop/ui/test/`).
4. Fix the security findings 1–5 first (before any further API features)?
