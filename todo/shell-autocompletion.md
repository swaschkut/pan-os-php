# Shell autocompletion (bash / zsh)

**Status:** review done (2026-11-18), nothing implemented. zsh was reviewed by reading the code only (not tested live)
**Code reference:** `alpha` `93a0187`, `utils/bash_autocompletion/pan-os-php.sh` (one file for bash ≥ 5 and zsh),
`utils/bash_autocompletion/enable_bash.txt`, `enable_zsh.txt`, `utils/alias.sh`, `install.sh`,
data: `utils/lib/util_action_filter.json` (written by `type=util_get-action-filter`,
`utils/lib/UTIL_GET_ACTION_FILTER.php`)
**Related:** [util-class-refactoring.md](util-class-refactoring.md)

## What works

* `type=` – complete: all 99 types come from `util_action_filter.json` (identical to `PH::$supportedUTILTypes`)
* `actions=` / `filter=` – first action name / filter field name of the type (34 types have actions, 33 have filters)
* `ruletype=`, `securityprofiletype=`, `devicetype=`, `vendor=`, `phase=` – fixed lists
* `in=`, `out=`, `file=`, `file1=`, `file2=`, `loadplugin=` – file names

## Findings

### 1. bash: the file only loads when `extglob` is on

bash and zsh part are in one `if … elif … fi`, so bash has to parse the zsh part too and fails at line 166
(`matches=(${~fpath}*(N) …)`): `bash -n pan-os-php.sh` reports a syntax error; `bash -O extglob -n` is fine. It works
today only because the bash-completion package switches `extglob` on before the file is sourced. The same package is
needed for `_get_comp_words_by_ref`.

* [ ] two files (`pan-os-php.bash`, `_pan-os-php` for zsh) or keep the zsh code out of the bash parser
* [ ] clear message when bash-completion is missing (`_get_comp_words_by_ref` not defined)
* [ ] bash < 5 (macOS default 3.2): message today; check whether bash 4 / 3.2 can be supported
* [ ] `readlink -f`: not available on macOS before 12.3

### 2. Missing in both shells

| Area | Today | Wanted |
|---|---|---|
| `actions=` | first action only | next action after `/`; arguments after `:` (names / defaults are in the JSON `args`) |
| `filter=` | field name without bracket | `(field operator value)`: operators are in the JSON (`operators`); `and` / `or` / `!` |
| type specific arguments | fixed for 5 types (`vendor-migration`, `diff`, `appid-toolbox`, `gcp`, `xpath`) | per type from data; 108 of 164 argument names declared in `utils/lib/*.php` are unknown to the completion (e.g. `hashes`, `cleartext`, `master-key`, `dry-run`, `exportcsv`) |
| 65 types without actions / filters | general argument list only | their own arguments |
| `location=` | bash: file names, zsh: nothing | `shared`, `any`; with `in=` file: device groups / vsys / templates of that file (optional) |
| shadow flags | `shadow-noscminternalapi` missing | list from the code |

### 3. Differences bash ↔ zsh

* arguments already on the command line are hidden in zsh, not in bash
* `loadpanoramapushedconfig` only in the zsh list
* `location=`: see above

### 4. Maintenance / installation

* lists for `ruletype`, `securityprofiletype`, `devicetype`, vendors, phases and the general arguments exist twice
  (bash and zsh part), by hand
* `enable_zsh.txt` contains a personal absolute path – not usable as instructions; `enable_bash.txt` only sources
  `/etc/bash_completion`
* `pan-os-php` is an alias (`utils/alias.sh`): zsh needs `setopt complete_aliases` – must be part of the instructions /
  `install.sh`
* `pa_migration-parser.sh`, `pa_docker-migration-parser.sh`: completion for aliases that are commented out in
  `alias.sh` – remove or keep?
* completion for the docker aliases (`pa_docker-panosphp…`) – not registered

## Proposal

1. [ ] **Data:** `UTIL_GET_ACTION_FILTER` also writes, per type, the supported arguments (`supportedArguments` of the
   util class) and the fixed value lists (`ruletype`, `securityprofiletype`, `devicetype`, vendors, phases, shadow
   flags) into `util_action_filter.json` – needs the type registry of
   [util-class-refactoring.md](util-class-refactoring.md) item 1 or an instance of each util class without running it
2. [ ] **Scripts:** separate bash and zsh file, both read everything from the JSON (no lists by hand)
3. [ ] `actions=`: several actions (`/`) and action arguments (`:`); bash needs `:` handling (`COMP_WORDBREAKS`)
4. [ ] `filter=`: operators
5. [ ] same behaviour in both shells (hide used arguments, same lists, `location=`)
6. [ ] `install.sh` / README: bash (Linux, macOS with brew bash) and zsh, alias handling, without personal paths
7. [ ] test: `bash -n` / `zsh -n` on both files; scripted completion test (set `COMP_WORDS` / `COMP_CWORD`, call the
   function, compare `COMPREPLY`); check that every type / argument of the code is in the JSON
   (`tests/test_actions.php` already reads the JSON)

## Open questions

* jq is required by both parts – keep the dependency or generate a flat word list file next to the JSON?
* fish / PowerShell completion wanted?
