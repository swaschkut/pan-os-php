# Web UI – keep the config in the browser, change and check it there

**Status:** idea / evaluation (2026-11-17)
**Code reference:** `alpha` `aa19e96`
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

## Open decisions

1. Build on pan-config-viewer (frontend, cooperation) or extend `utils/develop/ui/`.
2. Way A / B / C (or the combination).
3. Common JSON object model – define first, as base for UI, API output (`shadow-json`) and SCM.
