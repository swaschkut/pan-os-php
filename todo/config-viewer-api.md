# config-viewer as secured pan-os-php API

**Status:** planned (2026-11-20)
**Code reference:** `alpha` `2894f1f2` – `utils/develop/config-viewer/` (`api.php`, `lib/ViewerApp.php`,
`bin/service.php`, `bin/worker.php`), `utils/api/v1/tool.php`, `utils/lib/UTIL.php` (`UTIL::$sharedConfig`)
**Related:** [ui-config-in-browser.md](ui-config-in-browser.md) (prototype), [api-rest.md](api-rest.md) (findings
`tool.php`), [util-class-refactoring.md](util-class-refactoring.md) (`exit()` in `UTIL`)

## Decision (2026-11-20)

- The config-viewer **stays next to** `utils/develop/ui/` and `utils/api/v1/tool.php`; it does not replace them for
  now.
- Its API (`api.php` → `ViewerApp`) is extended so that it can offer the **whole** pan-os-php API in a secured way:
  **all types** of `PH::$supportedUTILTypes` (today 99), not only the 8 of the prototype. CDSS needs among others
  `playbook`, `stats`, `device`, `html-merger`, `securityprofile`, `rule`, `zone`.
- Every point below is required before the API is used outside a lab.

## Today

| | `tool.php` | config-viewer API |
|---|---|---|
| how pan-os-php is called | one PHP request = one `PH::callPANOSPHP()` run, `in=` / `out=` from the query | worker per version (`bin/worker.php`) loads the configuration once (`UTIL::$sharedConfig`), every read / change runs in a forked copy first |
| login | none; without session the shared folder `utils/api/v1/project/` is used; CORS `*` | login (`password_hash`, lock after 5 failures), session cookie `HttpOnly` / `SameSite=Strict`, CSRF header, HTTPS required |
| tenants | – | projects with `read` / `write` / `owner`; no access → `404`; random 128-bit ids |
| files | `in=` / `out=` from the request, `../` not blocked | `in=` is always the version file, no `out=`; random file names; data directory outside the web root; save = new version |
| types / actions | all 99 types, filters / actions unchecked | 8 types (`address`, `service`, `tag`, `rule`, `zone`, `schedule`, `securityprofile`, `securityprofilegroup`); deny patterns for actions (`ACTION_DENY_NAME`, `ACTION_DENY_ARG`); file filters rejected |
| network | `in=api://<any host>` with the stored API keys | no `in=api://` |
| XML | – | `LIBXML_NONET`; an upload with a DOCTYPE is rejected |
| errors | HTTP 200 with the error as text; server paths in messages | 4xx / 5xx with `{"error": …}`, no paths |

## Progress

| Date | Step | State |
|---|---|---|
| 2026-11-20 | **API tokens** (decision 1): table `tokens` (hash only), `Authorization: Bearer`, bound to user + project, role, expiry; one check `ViewerApp::userByToken()` (place for OIDC later); routes `projects/<pid>/tokens` | done, tests |
| 2026-11-20 | **Grants per member** (decision 5, first part): `types` and `scope` (locations) per member, enforced in `ViewerApp::queryArgs()` / `actionsArg()`; limited members: one location of the scope per request, no whole-version download / upload / delete, no move / copy actions | done, tests; open: UI (`app.js`) for grants and tokens, templates / template stacks (`zone` refused with a scope), referenced objects of `shared` / parents, device-access rights |
| 2026-11-20 | **REST resources per type** (decision 4, first part): `GET …/<cid>/<resource>[/<name>]` with paging, `POST …/<cid>/<resource>/actions`; every type with objects (action `display`, 34) is offered, the types beyond the 8 of `ViewerApp::TYPES` read only; items = `display-v0` | done, tests; open: stable JSON object model (items are the `display` fields), OpenAPI description, change for the other types (allow list per action), template / template stack argument, 20 types verified only with an empty result |
| | types without objects (`playbook`, `stats`, `html-merger`, mergers, `diff`, SCM types, …) – via jobs | open |
| | job runner + result files (decision 3) | open |
| | container per job / per worker (decision 2) | open |
| | audit log, secrets at rest, `tool.php` behind login, errors as HTTP status | open |

## Plan

### Function

1. **All types.** Every type of `PH::$supportedUTILTypes` as endpoint, with its arguments from
   `utils/lib/util_action_filter.json`. Types without the object model (`playbook`, `stats`, `html-merger`, mergers,
   `diff`, `master-key`, `config-section`, SCM types, …) need their own argument checks (section "Security", item 1).
2. **Login for machines.** Session cookie + CSRF fits the browser, not scripts (CDSS). API tokens: per user and
   project, stored hashed, expiry, role (`read` / `write`); sent as `Authorization: Bearer`. Option: OIDC client
   credentials. CSRF only for cookie sessions.
3. **Result files.** `exportToExcel`, `outputformatset`, `json-to-folder`, playbook outputs (`stagename`,
   `working-files/`), `out=` of a run: written only into the work folder of the project, random names, listed and
   downloaded via an API route. No path or file name from a request.
4. **Jobs.** Long runs (playbook on a large Panorama configuration, `stats`, mergers): start → job id → status → result
   files. Queue with a limit per project / user; cancel.
5. **Errors as HTTP status.** `exit()` / `display_error_usage_exit()` in `UTIL` → exceptions, so a pan-os-php error
   becomes 4xx with `{"error": …}` instead of text in a 200 answer ([util-class-refactoring.md](util-class-refactoring.md)
   item 4).
6. **BP JSON / playbook JSON per project.** `shadow-bpjsonfile=` and `type=playbook json=` only with files of the
   project (uploaded like a configuration, versioned), never a server path.
7. **REST resources per type** (decision 4) with an OpenAPI description; the query parameters use the names of the
   CLI arguments where possible (`location`, `filter`, `ruletype`, …), and a documented mapping CLI call → API call.

### Security

1. **Permissions per user** (decision 5: access, types, scope) and an **allow list per type and action** instead of the deny patterns: reviewed list, each action with a risk class –
   `read`, `change`, `writes file`, `network`, `secrets`. Arguments that name files or hosts are only accepted in the
   forms of "Function" 3 / 6 / item 4 below.
2. **Isolation.** Today all workers run as the web server user. Decided: one container per job (decision 2); limits
   for memory, CPU and run time; rate limits per user and token; upload limit.
3. **Secrets.** Configurations contain encrypted secrets: data directory encrypted at rest; retention and deletion
   rules; downloads in the audit log; option to run `type=master-key actions=scrub` on upload.
4. **`in=api://` / SCM** (only if offered): credentials per project, stored server side and encrypted, never in the
   request; target hosts / TSGs from an allow list per project (no SSRF).
5. **Audit log.** Login, failed logins, token use, member changes, uploads, downloads, every action / job with its
   arguments. Today only the version history exists.
6. **`tool.php` stays** (decision above) but must not be reachable without login: put it behind the same login /
   tokens or switch it off in deployments; fix the findings of [api-rest.md](api-rest.md) (path traversal, CORS `*`,
   MD5 passwords and default users of the docker-compose UI).
7. **Core review** of `UTIL::$sharedConfig` in `utils/lib/UTIL.php` (also open in
   [ui-config-in-browser.md](ui-config-in-browser.md)).
8. **XML.** Keep `LIBXML_NONET` and the DOCTYPE check for every file that comes in (configurations, BP JSON is JSON,
   playbook JSON is JSON).

### Operation

- Docker image with PHP CLI `pcntl`, `posix`, `pdo_sqlite`; start of `bin/service.php` (and a job runner).
- TLS at a reverse proxy (`PANOSPHP_VIEWER_TLS_PROXY=1`); the proxy must be the only way in.
- Tests: extend `tests/test_config_viewer.php` (100 checks today) with tokens, all types, jobs, result files, allow
  list, isolation.

## Decisions (2026-11-20)

1. **Token model:** own API tokens in SQLite first (random value, only the hash stored, expiry, bound to user +
   project, sent as `Authorization: Bearer`), built behind one check so that OIDC (client credentials and browser
   login) can be added next to it later without changing the routes.
2. **Isolation:** **one container per job.** A job sees only the folder of its project (read only for inputs, one
   output folder), with limits for memory, CPU and run time, no network unless the job is allowed to use it (item 5).
   The interactive worker of the viewer (configuration loaded once, kept in memory) also runs in its own container
   per opened version, not as the web server user.
3. **Jobs:** both ways –
   * interactive reads / changes of the viewer: in the worker of the version (configuration in memory, forked copy
     first), as today;
   * CLI-like runs (`playbook`, `stats`, `html-merger`, mergers, `diff`, exports, SCM types, …): job runner with a
     queue in SQLite (limit per user / project, status, cancel, result files); each job loads its input in its own
     container.
4. **API shape:** **REST resources per type** (for example `GET …/projects/<pid>/configs/<cid>/addresses?location=…&filter=…`,
   `POST …/projects/<pid>/playbooks/runs`), described with OpenAPI. Needs the common JSON object model first
   (open decision 3 in [ui-config-in-browser.md](ui-config-in-browser.md)); the generic run of the CLI arguments
   is not offered as public API.
5. **Permissions per user and project** – finer than today's `read` / `write` / `owner`:
   * **access:** `read` or `write` per user;
   * **types:** which pan-os-php types a user may use in this project (for example only `address`, `rule`,
     `securityprofile`; `playbook` / `stats` for CDSS); the types that reach devices or tenants (`in=api://`,
     `scm-api://`, `scm-*`, `ssh-connector`, `upload`, `traffic-log`, `session-browser`, actions `…-fastapi`,
     `reverse-dns`) are types / rights of their own and are only allowed when granted;
   * **scope:** access can be limited to device groups, templates, template stacks (Panorama) or SCM folders /
     snippets / containers; inside the scope **all objects** of the granted types.
   Grants are combinations, e.g. user A: `write` + `address`, `service`, `rule` + device group `DG-Berlin`; user B:
   `read` + all types + whole configuration.

## Open points of decision 5 (to decide while building)

- **Parents and shared:** a user limited to a device group sees objects of `shared` and of the parent device groups
  that the DG uses (references) – read only, or not at all? Writing outside the scope is never allowed.
- **Actions that act outside the scope:** for example mergers that move objects to `shared` / the parent, `move`
  actions, `type=playbook` with steps on `location=any` – rejected for scoped users, or limited to the scope?
- **Template stack ↔ template:** does a grant on a template stack include its templates (in stack order), or only the
  stack's own settings?
- **Enforcement:** the scope must be enforced server side (`location=` / `template=` / SCM folder forced, results
  filtered again), not only in the UI.
- **Device access (`in=api://`, SCM):** which devices / TSGs a project may reach (allow list per project, credentials
  encrypted per project) and whether writing into a device / tenant is allowed at all (commit with a second person?).
