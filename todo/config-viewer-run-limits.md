# Config viewer: limits per run set by an administrator in the browser

**Status:** idea, documented 2026-11-21 - not built; maybe later.
**Related:** [config-viewer-api.md](config-viewer-api.md), [utils/api/v1/playbook/README.md](../utils/api/v1/playbook/README.md)

## Today

The limits of one run (container per run) come from `.env` next to `panosphp-viewer`, through `docker-compose.yml`
into the job runner:

| `.env` | job runner | default |
|---|---|---|
| `VIEWER_RUN_MEMORY` | `PANOSPHP_VIEWER_CONTAINER_MEMORY` (`docker run --memory`) | `2g` |
| `VIEWER_RUN_CPUS` | `PANOSPHP_VIEWER_CONTAINER_CPUS` (`--cpus`) | `2` |
| `VIEWER_RUN_TIMEOUT` | `PANOSPHP_VIEWER_JOB_TIMEOUT` (seconds) | `3600` |

Changed on the computer the viewer runs on, then `./panosphp-viewer restart`; `./panosphp-viewer status` shows what
the job runner has. A run killed for memory is shown as "out of memory" (reason `memory`).

## Wish (Sven, 2026-11-21)

An administrator changes these limits in the browser.

## Why not by changing `.env`

* `.env` is on the computer, outside the containers - the web part must not write files of the computer (that would
  be a way out of the container)
* `.env` works only after a restart

## Design

* **Account → Limits per run (admin)**: memory, CPUs, time. Stored in `viewer.sqlite` (table `settings`, like the
  predefined playbooks); every change in the audit log
* **no restart**: the job runner reads the values before **every** run and starts the container with them
  (`--memory`, `--cpus`, timeout of the run) - the next run uses the new values
* **upper bound from the computer**: an administrator in the browser must not give more memory than Docker has, or a
  run takes down the computer / the Docker VM
  * the job runner (it has the Docker socket) reads the memory Docker has (`docker info`: `MemTotal`) and keeps a
    reserve for web part, service and Docker (e.g. 1 GB); the page shows "Docker has 7.7 GB - at most 6.7 GB per run"
    and refuses more
  * optional `VIEWER_RUN_MEMORY_MAX` in `.env`: a lower bound set on purpose by whoever runs the computer
* **`.env` stays the default** (`VIEWER_RUN_MEMORY`, …) as long as no administrator set a value
* **parallel runs**: each run needs its own memory - the page shows how many runs may run at the same time
  (`PANOSPHP_VIEWER_JOBS`) and warns when limit × runs is more than Docker has; maybe also set that number there

## Open

| # | Question | Options |
|---|---|---|
| 1 | Upper bound | automatic from `docker info` / only a fixed `VIEWER_RUN_MEMORY_MAX` in `.env` / both (lower one wins) |
| 2 | Number of parallel runs in the browser too? | yes / no (stays `.env`) |
| 3 | Limits per project or per user (e.g. a large Panorama project gets more)? | no (one value) / later |
| 4 | Without containers (runs as processes): no memory limit to set - hide the card or show "not available"? | |
