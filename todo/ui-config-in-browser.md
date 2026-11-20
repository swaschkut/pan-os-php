# Web UI – keep the config in the browser, change and check it there

**Status:** prototype implemented and committed (2026-11-18, `alpha` `fc157d4`): `utils/develop/config-viewer/` – way A
(configuration loaded once, kept in memory on the server) + browser cache, see "Prototype" below. Decision 2 is taken;
open: decisions 1 and 3 and the follow-ups of the prototype
**Code reference:** `alpha` `fc157d4`
**Related:** [api-rest.md](api-rest.md) (pan-os-php API), [util-class-refactoring.md](util-class-refactoring.md),
`utils/develop/ui/` (existing web UI), [config-viewer README](../utils/develop/config-viewer/README.md)

Goal: move away from the CLI. The configuration (Panorama, firewall, SCM) is loaded once, kept in memory, changes are
made on it and checked directly in the UI (filter result, references, diff) before anything is written.

## Possible common way: pan-config-viewer + pan-os-php

https://github.com/fahadysf/pan-config-viewer (checked: commit `d8943f7`, 2026-10-25)

| | pan-config-viewer | pan-os-php |
|---|---|---|
| language | Python (FastAPI, Pydantic, lxml, `pan-os-python`), frontend React 18 + TypeScript, shadcn/ui, Zustand, TanStack Query | PHP library + CLI types; web UI `utils/develop/ui/` (PHP / JS); REST-like API `utils/api/v1/tool.php` |
| input | Panorama (and firewall) XML files from a folder (`config-files/`) | Panorama / firewall XML file, PAN-OS XML API (`in=api://`), SCM API (`in=scm-api://`) |
| function | **read only**: lists objects (address, service, groups, security profiles, device groups, templates, template stacks, security / NAT rules, log profiles, schedules) with location / XPath, filter operators, pagination; Swagger docs | read **and change**: ~90 types with filters and actions, mergers, BP checks, migration, SCM export / change |
| state | parsed on the server, cache (ZODB) | each call loads the config again (CLI / API call = one run) |
| API | `GET /api/v1/configs/{config}/…` only | `GET /utils/api/v1/tool.php/<type>?in=…&filter=…&actions=…` |
| license | Apache-2.0 | ISC |
| deployment | Docker / docker-compose | Docker `Dockerfile-API`, docker-compose with DB / users |

What could be shared:
- **frontend ideas / components** of pan-config-viewer (tables with server-side filter / sort / paging, object
  detail with location / XPath) as UI on top of the pan-os-php API
- **object model as JSON**: same JSON shape for objects in both tools would let the viewer show pan-os-php data
  (also from SCM, which the viewer cannot read)
- pan-os-php **filters / actions** as the "change" part the viewer does not have

To clarify: contact the author (cooperation, shared JSON model), license compatibility (Apache-2.0 ↔ ISC – both
permissive, copying code needs the Apache notice), PHP backend vs. Python backend.

## Ways to keep the config "in memory"

| Way | How | + | − |
|---|---|---|---|
| A – server session | pan-os-php API loads the config once per project / session and keeps it (process or serialized), actions change it, UI reads the result | full pan-os-php logic (filters, actions, references) | PHP per-request model: needs a long running worker or save / load per step (today `out=` file per call); large configs |
| B – project file + git | each action writes the project file, `git-php` keeps the history (Todo in `tool.php` 2021-06-24: "use git module to do all manipulation against one file within a project folder") | undo / diff per step for free, simple | load time per step |
| C – in the browser | config XML / JSON in the browser (IndexedDB), UI changes it, changes collected as a change list; pan-os-php API used for checks and to write (offline XML, Panorama XML API, SCM API) | fast UI, no server state | filter / action logic would exist twice (JS and PHP) unless the browser only collects changes |

Proposal to discuss: **C for viewing / collecting changes + B for applying** – the browser keeps the config and the
change list, the change list is sent to the pan-os-php API (actions), the result (new project file + diff) comes back
and is checked in the UI before it is written to the target.

## Prototype (2026-11-18): `utils/develop/config-viewer/`

Documentation: [README](../utils/develop/config-viewer/README.md) (how it works, security, run it, using it,
troubleshooting, data directory, API routes, processes, extending). Test: `tests/test_config_viewer.php` (100 checks).

### Requirements (from the discussion) and state

| Requirement | State |
|---|---|
| user login | done: login required, `password_hash()`, lockout after 5 failed logins, session cookie `HttpOnly` / `SameSite=Strict`, CSRF token, HTTPS required (except loopback / lab switch) |
| full separation | done: without access every project route answers 404; random ids; files under random names outside the web root |
| every user can create projects | done |
| further users can get access to a project | done: owner adds members by user name |
| read is one permission, changing must be possible too | done: `read` (view, download), `write` (upload, change, save, discard, delete versions), `owner` (members, delete project) |
| everything is loaded only once | done: one worker per opened version keeps the configuration in memory (`UTIL::$sharedConfig`); measured with `panorama-10.0-merger.xml`: first request about 2 s, further reads / changes 20–30 ms |
| working in the browser uses a cache | done: every loaded list is cached in the browser (sort, paging, quick filter there); the server keeps the configuration in memory |
| save writes the cache into a file | done: save = new version file, nothing is overwritten; discard drops the changes |
| auto save every 5 / 10 min | done: in the UI off / 5 / 10 min (new version); plus recovery copy of unsaved changes by the worker (default 5 min, and when it stops) → version `autosave (recovered …)` |

### How it is built

* `api.php` + `lib/ViewerApp.php`: JSON API, SQLite (users, projects, members, versions), permission check in one
  place (`ViewerApp::projectGet()`)
* `bin/service.php`: the only process that starts workers; the web server process starts none
* `bin/worker.php`: loads one version once; reads run in a forked copy, a change is tried in a forked copy first –
  `exit()` / `derr()` inside pan-os-php can not stop or half-change the loaded configuration
  ([util-class-refactoring.md](util-class-refactoring.md) item 4 stays open, but does not block the viewer)
* `index.html` / `app.js` / `style.css`: no external scripts, Content-Security-Policy
* `utils/lib/UTIL.php`: `UTIL::$sharedConfig` (5 guarded places; `null` = unchanged behaviour)
* pan-os-php calls: whitelist of 8 types, `in=` is always the version file, no `out=` / `in=api://`; file filters and
  file / network actions are rejected

Verified: the test (100 checks) on a fresh checkout, the UI with two users in a headless browser (owner + read
member), existing tests `test_master_key`, `test_config_section`, `test_spyware_dns_lists`, `test_threat_rule_names`,
`test_panorama_remove_template` unchanged.

**Not verified:** a large Panorama configuration, Apache / nginx / Docker, HTTPS operation, macOS (developed and
tested on Linux; the 60 character limit of the data directory path keeps the worker socket path below the unix
socket limit of both, 104 on macOS / 108 on Linux).

### Follow-ups

Next:

- [ ] test with a large Panorama configuration: load time, memory per worker, size of the lists in the browser
  (today all rows of a query go to the browser, cap 50 000); decide whether large lists need server-side paging
- [ ] run on macOS and behind Apache / nginx with HTTPS; Docker image (PHP CLI with `pcntl`), service start
- [ ] review of the `UTIL::$sharedConfig` change in `utils/lib/UTIL.php` (core)

Function:

- [ ] change a single object / a selection of rows (today: all objects of type + location + filter)
- [ ] all types (today `address`, `service`, `tag`, `rule`, `zone`, `schedule`, `securityprofile`,
  `securityprofilegroup`) – [config-viewer-api.md](config-viewer-api.md)
- [ ] diff between two versions (`type=diff`); undo of the last change before save
- [ ] object detail: references, XPath, XML
- [ ] filter builder in the UI from the filter / operator list (`meta`), like the action list today
- [ ] `in=api://` / SCM as source of a version (credentials per project, not in the request)
- [ ] several users on one loaded version: show who changed what before save (today one shared list of changes)

Security:

- [ ] reviewed allow list per action instead of the deny patterns (`ViewerApp::ACTION_DENY_NAME` / `_ARG`)
- [ ] OS level isolation between projects (today all workers run as the web server user)
- [ ] audit log (login, member changes, downloads), password reset, OIDC login
  (see [api-rest.md](api-rest.md) decision 1)
- [ ] adding a member tells the owner whether a user name exists
- [ ] `tool.php` stays without authentication – replace it by this API or protect it ([api-rest.md](api-rest.md))

Model:

- [ ] stable JSON object model (decision 3) – today the `display` JSON is flattened into rows

## Open decisions

1. ~~Build on pan-config-viewer (frontend, cooperation) or extend `utils/develop/ui/`; decide whether the prototype
   replaces `utils/develop/ui/`.~~ Decided 2026-11-20: the config-viewer **stays next to** `utils/develop/ui/` and
   `tool.php` for now; its API is extended to all pan-os-php types – [config-viewer-api.md](config-viewer-api.md).
2. ~~Way A / B / C (or the combination).~~ Taken with the prototype: way A (loaded once on the server) + browser cache;
   save writes version files (the history of way B, without git).
3. Common JSON object model – define first, as base for UI, API output (`shadow-json`) and SCM.
