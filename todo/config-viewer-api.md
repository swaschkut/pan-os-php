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
7. **Same arguments as the CLI** where possible, so that a CLI call can be turned into an API call one to one
   (documented mapping, OpenAPI description).

### Security

1. **Allow list per type and action** instead of the deny patterns: reviewed list, each action with a risk class –
   `read`, `change`, `writes file`, `network`, `secrets`. Arguments that name files or hosts are only accepted in the
   forms of "Function" 3 / 6 / item 4 below.
2. **Isolation.** Today all workers run as the web server user. Own OS user or container per project (or per job);
   limits for memory, CPU and run time; rate limits per user and token; upload limit.
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

## Open decisions

1. Token model: own tokens in SQLite, or OIDC (client credentials) from the start?
2. Isolation: OS user per project, or one container per job?
3. Jobs: in the existing service / worker model (fork), or a separate queue process?
4. API shape: keep `api.php/<route>` and add `…/run/<type>`, or REST resources per type (see
   [api-rest.md](api-rest.md))?
5. Which types may use `in=api://` / SCM at all.
