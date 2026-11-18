# Web UI – keep the config in the browser, change and check it there

**Status:** prototype implemented (2026-11-18): `utils/develop/config-viewer/` – way A (configuration loaded once, kept in
memory on the server) + browser cache; see "Prototype" below. Open: decisions 1 and 3, follow-ups of the prototype
**Code reference:** `alpha` `cba66bb`
**Related:** [api-rest.md](api-rest.md) (pan-os-php API), `utils/develop/ui/` (existing web UI)

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

[README](../utils/develop/config-viewer/README.md), test `tests/test_config_viewer.php` (96 checks).

What it does: login, projects per user, members with `read` / `write`, upload, object table for 8 types (filter by
pan-os-php, sort / paging / quick filter in the browser), actions on the loaded configuration, save as new version,
discard, auto save, recovery of unsaved changes.

Decision taken for the prototype – **way A + browser cache**:

* the configuration is loaded **once** per opened version by a worker process and kept in memory
  (`UTIL::$sharedConfig`, 5 guarded places in `utils/lib/UTIL.php`; default `null` = unchanged behaviour). Measured
  with `panorama-10.0-merger.xml`: first request about 2 s, every further read / change about 20 ms
* reads run in a forked copy of the worker, a change is tried in a forked copy first: `exit()` / `derr()` inside
  pan-os-php can not stop or half-change the loaded configuration
  ([util-class-refactoring.md](util-class-refactoring.md) item 4 stays open, but does not block the viewer)
* nothing is written until **save**; save = new version file (way B history without git)
* the browser keeps every loaded list (cache per query)

Follow-ups:

- [ ] test with a large Panorama configuration: load time, memory per worker, size of the lists in the browser
  (today all rows of a query go to the browser, cap 50 000)
- [ ] more types (today `address`, `service`, `tag`, `rule`, `zone`, `schedule`, `securityprofile`,
  `securityprofilegroup`); reviewed allow list per action instead of the deny patterns
- [ ] change a single object / a selection of rows (today: all objects of type + location + filter)
- [ ] diff between two versions (`type=diff`), undo of the last change before save
- [ ] object detail: references, XPath, XML
- [ ] stable JSON object model (decision 3) – today the `display` JSON is flattened
- [ ] Docker image (PHP CLI with `pcntl`), service start, HTTPS
- [ ] `in=api://` / SCM as source of a version (credentials per project, not in the request)
- [ ] audit log, password reset, OIDC login (see [api-rest.md](api-rest.md) decision 1)
- [ ] `tool.php` stays without authentication – replace it by this API or protect it (see [api-rest.md](api-rest.md))

## Open decisions

1. Build on pan-config-viewer (frontend, cooperation) or extend `utils/develop/ui/`.
2. Way A / B / C (or the combination).
3. Common JSON object model – define first, as base for UI, API output (`shadow-json`) and SCM.
