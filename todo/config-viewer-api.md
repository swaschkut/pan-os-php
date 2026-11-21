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
| 2026-11-20 | **REST resources per type** (decision 4, first part): `GET …/<cid>/<resource>[/<name>]` with paging, `POST …/<cid>/<resource>/actions`; every type with objects (action `display`, 34) is offered, the types beyond the 8 of `ViewerApp::TYPES` read only; items = `display-v0` | done, tests; open: items and resource names as the SCM API schema – [json-object-model.md](json-object-model.md), OpenAPI description, change for the other types (allow list per action), template / template stack argument, 20 types verified only with an empty result |
| | types without objects (`playbook`, `stats`, `html-merger`, mergers, `diff`, SCM types, …) – via jobs | open |
| 2026-11-20 | **Job runner + result files** (decision 3, first part): queue in SQLite, `bin/jobs.php` (no shell, arguments built on the server, time limit, cancel), `POST …/<cid>/stats/runs`, `projects/<pid>/runs[/<jid>[/files/<name>]]`; first job type `stats` | done, tests |
| 2026-11-20 | **Playbook runs + project files** (function 6): `projects/<pid>/files` (playbook JSON, BP JSON), `ViewerApp::playbookCheck()` at upload and before every run (step types, arguments, plain file names, no `in` / `out` / `projectfolder`), `POST …/<cid>/playbook/runs` (`playbook`, `bp`), `stats` with the BP JSON of the project, `POST …/runs/<jid>/save` (result configuration → new version) | done, tests (18 refused playbooks); open: mergers, `diff`, container per run, the shipped `visibility.json` runs end to end in the test; the CDSS playbooks `visibility.json` / `spr_html.json` pass the check, not yet run through the API |
| 2026-11-20 | **Allow list per action** (security item 1): `action-classes.json` (built by `bin/action-classes.php` from `util_action_filter.json` and the action sources; 560 actions of 34 types: 387 change, 68 read, 62 writes-file, 8 reads-file, 35 network), used for interactive changes (`read` / `change` only) and for every action of a playbook step (file name argument by position); `"reviewed"` = types that can be changed (the 8 of the prototype), `"override"` for corrections; playbooks also accept `subqueryN=` and `shadow-ignoreInvalidAddressObjects` (10 of the 15 shipped playbooks pass; the others use `in=`, `projectfolder` or merger types) | done, tests; open: **review per type by a person** (the classes are generated), then add the other 26 types to `reviewed`; merger types in playbooks |
| 2026-11-20 | **Audit log** (security item 5): table `audit`, written in `api.php` for logins (also failed), every request that is not a plain read (also refused ones) and every download; `GET audit` (admin), `GET projects/<pid>/audit` (owner); no passwords / token secrets / file content; retention `PANOSPHP_VIEWER_AUDIT_DAYS` | done, tests; open: export / forwarding (syslog), reads of whole lists are not logged |
| 2026-11-20 | **Browser pages** (`app.js`, `style.css`): members with types / locations, API tokens (shown once), project files, runs (stats / playbook, result files, result as version), audit log (owner: project, admin: all); limited members: no runs, no whole-version operations, viewer with their types / first location | done, checked in headless Chrome (20 checks, not part of the repo tests); open: no page for the REST resources / `?computed=1` / `?bp=` |
| 2026-11-20 | **Container per run** (decision 2, first part): `lib/ViewerContainer.php`, `bin/jobs.php` with `PANOSPHP_VIEWER_CONTAINER=docker\|podman` - no network, read-only, no capabilities, limits; mounts: project folder read-only, folder of the run read-write; the web part never gets the container runtime; a wrong setting stops the job runner (no fall back) | done, `tests/test_config_viewer_container.php` with a stand-in `docker` (46 checks); **not yet run against a real Docker / Podman** (none available where it was built): the call itself, `volume-subpath` (needs a current Docker Engine; Podman not checked), file owner on Docker Desktop (macOS) |
| 2026-11-20 | **One command**: `utils/develop/config-viewer/docker-compose.yml` + `docker/Dockerfile` + `docker/start.sh` - one image, containers `web` / `service` / `jobs`, first admin user at the first start, runs in their own containers | written; compose file valid, start script run locally; **image build and start not run with a real Docker** |
| 2026-11-20 | **HTTPS**: `docker-compose.https.yml` + `docker/Caddyfile` (Caddy in front; own CA / own certificate / Let's Encrypt), client address behind the proxy (`viewerClientAddr()`), air-gap steps (save / load images) | written; compose valid, client address checked; **proxy not started with a real Docker** |
| 2026-11-20 | **One image, published**: `docker/Dockerfile` (the normal pan-os-php image) gets `php-sqlite3`, the docker client and `/data`; the compose file uses `swaschkut/pan-os-php:alpha` (`VIEWER_IMAGE`) and builds nothing; `pid: "service:web"` (workers were not found across containers). **Air gap**: `airgap/make-bundle.sh`, `airgap/install.sh`, `airgap/README.txt` | viewer in Docker confirmed by Sven (local build, before the switch to the published image); bundle scripts only with a stand-in `docker`; the other Dockerfiles (`-main_amd`, `-main_arm64v8`, …) are **not** extended |
| 2026-11-20 | **Checked on a real installation** (Sven, Docker Desktop on macOS, published image `swaschkut/pan-os-php:alpha`): one-command start, opening versions, runs in containers, playbook run by the example script, HTTPS through the proxy (own CA) | done; open: air-gap bundle (postponed), own certificate / Let's Encrypt, Linux host, Podman |
| 2026-11-20 | **Plug-in interface v1** (`lib/ViewerPlugins.php`, `examples/plugins/example/`): run types with declared fields, JSON file kinds with a check, extra playbook step types; arguments only from checked values, `in=` / `out=` fixed by the viewer; `meta.plugins`, page (Runs card, Account → Plug-ins); `ViewerApp::featureOn()` as the one place for the licence check (always yes for now). **Fix:** the worker's pid file is written atomically - a version could fail to open ("could not be loaded") when the web part read the file before the process id was in it | done, tests (364 checks), page checked in headless Chrome; open: plug-in code inside the run, routes / pages of a plug-in, non-JSON file kinds, plug-in folder in the compose file, encrypted plug-ins |
| 2026-11-20 | **Plug-in interface, additions for migration**: raw file kinds with their own size limit, run types without a version (`'input' => 'none'`, `POST …/projects/<pid>/<type>/runs`), `select` / `multi` fields, result of a run into another project (note names the origin). **Fixes:** the Cisco router / switch parsers loaded their files relative to the folder `migration` (failed from any other folder); the Docker web part now takes uploads up to `PANOSPHP_VIEWER_MAX_UPLOAD_MB` (PHP's 2 MB limit applied before) | done, tests (383 + 47 checks), page checked in headless Chrome; open: result page from a JSON of the run, link between projects (newer import), plug-in code inside the run |
| 2026-11-20 | **Plug-ins with files of their own in runs**: `'env'` of a run type (`%PLUGIN%`), plug-in folder read-only at `/plugin` in the run container (`PANOSPHP_VIEWER_CONTAINER_PLUGINS`), compose file mounts `VIEWER_PLUGINS_DIR`; `migration/parser/lib/CONVERTER.php`: `PANOSPHP_MIGRATION_PARSERS` - a vendor parser found there replaces the shipped one (first use: the private migration plug-in) | done, tests (383 + 50 checks); migration plug-in run end to end in a local viewer without Docker; **not yet in Docker** |
| 2026-11-20 | **Start script** `panosphp-viewer` (start / stop / restart / status / logs / setup / password / license / plugin / update; questions the first time, `.env`, `plugins/` next to it), `bin/license.php`, air-gap `install.sh` uses it, bundle carries `*.ppp` (`make-bundle.sh … <plug-in folder>`); job runner notices added plug-ins | done, `tests/test_config_viewer_start.php` (23 checks, stand-in docker), bundle dry run; **not yet with a real Docker** |
| 2026-11-21 | **No shared process ids between web and service**: `pid: "service:web"` removed (Docker could not start `service` when `web` was not running: "namespace path … no such file"); the web part checks workers by their files only, the service removes the files of an ended worker at once (SIGCHLD) and left-overs when it starts, stops a hanging worker on request (`stop`); a worker socket nobody listens on is cleaned up | done, tests (killed worker, hanging worker) |
| 2026-11-21 | **Installation with one file**: `install-viewer.sh` (`curl … | bash`): folder, start script, compose files, start; again = update; channel alpha / beta / dev / main. `panosphp-viewer start` pulls the images the first time (an old local image was used: "start.sh: No such file") | done, tests with `file://` downloads and a stand-in docker (32 checks); not yet with real Docker / GitHub |
| | container per worker (decision 2, second part); licences ([config-viewer-license.md](config-viewer-license.md)); Podman | open |
| | secrets at rest, `tool.php` behind login, errors as HTTP status | open |

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
