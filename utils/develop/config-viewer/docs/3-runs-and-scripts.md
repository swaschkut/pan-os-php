# Runs and scripts

## Runs

A run works on a copy of one version in its own folder and container (no network). Under **Runs** in a project:

| Run | What it does |
|---|---|
| stats | best practice figures of the configuration |
| playbook | the steps of a playbook (project file) - exports, set commands, changed configuration |
| migration (licence) | a configuration of another vendor (project file) to PAN-OS |

When a run is done: **Result files** to download (e.g. `out.xml`, `set-commands.txt`, `run.log`), and
**Result as new version** - in this project or in another one.

## Scripts (API)

Everything of the page is also reachable as REST API under `api.php/…`.

- With user and password: log in, then the session cookie and the CSRF token (example script
  `examples/viewer-playbook-run.sh`: project, upload, playbook run, download).
- With an **API token** (no password in the script): one project, read or write, valid for some days.
  In the page: project → **API tokens**. On the command line:
  `./panosphp-viewer token <user> <project> [read|write] [days]`. Scripts send `Authorization: Bearer <token>`.

A token is shown only once. It never has administrator rights and works only for its project - to create a project
from a script, log in with user and password, or `./panosphp-viewer project add <user> <name>`.
