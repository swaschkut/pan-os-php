# Playbooks (`type=playbook`)

A playbook is a JSON file with a list of pan-os-php commands (`command`: one step per entry). `type=playbook` runs the
steps one after the other; every step reads the configuration the step before wrote (stage files
`<stagename><N>.xml`), the last one is copied to `out=`.

The playbooks in this folder are shipped with pan-os-php. On the command line `$$playbook$$` stands for this folder:

```bash
pan-os-php type=playbook in=panorama.xml out=result.xml json='$$playbook$$/visibility.json' stagename=stage/step- outputformatset=set-commands.txt
```

## Arguments

| Argument | What it does |
|---|---|
| `in=` | input: configuration file, or `api://<ip>` / `api://<serial>@<panorama>` |
| `out=` | output file (needed when `in=` is a file) |
| `json=` | the playbook: a file, or `$$playbook$$/<name>.json` for one of this folder |
| `stagename=` | path and prefix of the stage files (instead of `stagename` in the JSON) |
| `projectfolder=` | folder for the stage files and the output files |
| `outputformatset=` | set commands of all steps into this file |
| `outputformatscmjson=` | SCM only: one SCM API request per changed object into this file |
| `location=` | limit to VSYS / device groups (`location=any`, `location=vsys1,vsys2`) |
| `debugapi` | print the API calls |
| **`subprocess`** | **every step as its own PHP process** - the memory of a step is free again when it ends; slower, needs the least memory |
| **`memorythreshold=<MB>`** | **only a step that starts while more than `<MB>` MB are in use runs as its own process**; the others run in the same process |
| **`debugmemory`** | **memory use after every step** (script memory and, in a container, the memory of the container) |
| **`removestagefiles`** | **remove a stage file once the next step has written its own** - less disk and page cache |
| `help` | the arguments |

## Large configurations: memory

A large Panorama configuration is loaded once per step and can need several GB. Without options, all steps run in one
PHP process; memory freed after a step is not always given back, so the use grows step by step.

| Option | When |
|---|---|
| `subprocess` | the run is killed or gets slow: the safest choice, every step starts with empty memory |
| `memorythreshold=<MB>` | faster than `subprocess`: steps run in one process until the use passes `<MB>`, then a step runs on its own. Set it clearly below the limit of the container (e.g. limit 4 GB → `memorythreshold=2500`) |
| `removestagefiles` | together with one of the two: the page cache of old stage files counts as memory of the container (cgroup `memory.current`) |
| `debugmemory` | to see how much each step needs (in the log) |

Notes:

* `memorythreshold` reads the memory of the **container** (cgroup `memory.current`, v1: `memory.usage_in_bytes`).
  Outside a container (e.g. macOS without Docker) there is nothing to read, and `memorythreshold` never switches -
  use `subprocess` there.
* A step that is killed as a subprocess (exit code 137) stops the playbook with "the process was killed, most likely
  out of memory".
* PHP's own `memory_limit` is set high by pan-os-php (`lib/pan_php_framework.php`); the real limit is the container or
  the computer. A killed process / container ends with exit code 137.
* `removestagefiles`: the input file and the last stage file are kept; a later step that names an earlier stage file
  itself will not find it.

## In the config viewer

* Predefined playbooks (this folder) are offered for runs when an administrator turned them on (Account → Predefined
  playbooks; by default `visibility.json`). Playbooks with steps the viewer does not allow (mergers, own `in=`,
  `projectfolder`) can not be turned on.
* The run form has **Options for large configurations**: `subprocess`, `memorythreshold`, `debugmemory`,
  `removestagefiles` (API: body fields of the same names, e.g. `{"predefined":"visibility.json","subprocess":true}`).
* The memory one run may use is the limit of its container: `VIEWER_RUN_MEMORY` in the `.env` of the viewer (default
  `2g`). A run killed for memory is shown as **out of memory** (API: `"reason": "memory"`).

See [utils/develop/config-viewer/README.md](../../../develop/config-viewer/README.md).
