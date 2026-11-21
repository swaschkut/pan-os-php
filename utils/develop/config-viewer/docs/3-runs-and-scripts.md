# Runs and scripts

## Runs

A run works on a copy of one version in its own folder and container (no network). Under **Runs** in a project:

| Run | What it does |
|---|---|
| stats | best practice figures of the configuration |
| playbook | the steps of a playbook - exports, set commands, changed configuration |
| migration (licence) | a configuration of another vendor (project file) to PAN-OS |

**Playbooks** come from two places, like the BP JSON:

- **predefined** - shipped with pan-os-php (`visibility.json`, `best-practice-set.json`, …). Offered are only the ones an
  administrator turned on under **Account → Predefined playbooks**; by default `visibility.json`. Some shipped
  playbooks can not run in the viewer (e.g. mergers) - the list says why.
- **own** - a playbook JSON uploaded under **Project files**; it is checked when it is uploaded and before every run.

**Large configurations** need a lot of memory. Under **Options for large configurations** (playbook runs):

- **Every step its own process** (`subprocess`) - needs the least memory, slower.
- **Own process above … MB** (`memorythreshold`) - only when the run already uses more than this.
- **Memory use in run.log** (`debugmemory`) - to see what each step needs.
- **Remove stage files** (`removestagefiles`) - less disk and memory.

A run stopped for memory is shown as **out of memory**, with the limit per run. The limit is set on the computer the
viewer runs on: `VIEWER_RUN_MEMORY=4g` in `.env` next to `panosphp-viewer` (default `2g`), then
`./panosphp-viewer restart`. With Docker Desktop, give the VM more memory than that (Settings → Resources).

When a run is done: **Result files** to download (e.g. `out.xml`, `set-commands.txt`, `run.log`), and
**Result as new version** - in this project or in another one.

## Scripts (API)

Everything of the page is also reachable as REST API under `api.php/…`.

- With user and password: log in, then the session cookie and the CSRF token (example script
  `examples/viewer-playbook-run.sh`: project, upload, playbook run, download).
- With an **API token** (no password in the script): one project, read or write, valid for some days.
  In the page: project → **API tokens** (not on the command line). Scripts send `Authorization: Bearer <token>`.

A token is shown only once. It never has administrator rights and works only for its project - to create a project
from a script, log in with user and password.
