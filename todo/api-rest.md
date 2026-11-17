# pan-os-php API (`utils/api/v1/`)

**Status:** review / hardening needed (2026-11-17)
**Code reference:** `alpha` `aa19e96`
**Related:** [ui-config-in-browser.md](ui-config-in-browser.md)

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

## Open decisions

1. Authentication: session login of the web UI, API tokens, or OAuth2 / OIDC (Todo 2021).
2. Keep `tool.php` (CLI arguments in the URL) and add a REST layer, or replace it.
3. Where the DB / user management lives (today in `utils/develop/ui/test/`).
4. Fix the security findings 1–5 first (before any further API features)?
