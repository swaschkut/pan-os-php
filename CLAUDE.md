# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Working rules (all pan-os-php repositories)

These rules apply to every repository of this project: `pan-os-php` (public), `pan-os-php_scm-migration`,
`pan-os-php_migration`, `pan-os-php_license` (private).

### Delivery: patch files only

- Claude **never commits and never pushes** - not to any branch, not to any of these repositories. The maintainer
  applies the patch with `git apply` and commits / pushes himself.
- Every change is delivered as a patch file (`git diff` against the current remote head of the branch), checked with
  `git apply --check` against that head before it is handed over.
- Before building a patch: fetch the latest remote state. The maintainer often edits files directly on GitHub; a
  patch against an old head does not apply. If a patch has to sit on top of other, not yet pushed patches, say so and
  apply those first.
- Branches: `pan-os-php` → **alpha** (fetch dev and beta as well; fixes for dev / beta only when asked).
  `pan-os-php_scm-migration`, `pan-os-php_migration`, `pan-os-php_license` → **main**.
- "nur beantworten" / "nicht arbeiten" / "erst darüber reden": answer only, no code, no patch.

### Language

- Answers to the maintainer in German. Code, comments, CHANGELOG, README and documentation in English.

### Data that never goes into a repository

- **No customer configurations** and no data derived from them (configs, exports, logs, run.log, checklists of a
  customer tenant). Tests use synthetic data only. Customer files are used for diagnosis only, and nothing of them is
  quoted in code, tests, commit texts or documentation.
- The anonymiser mapping file is sensitive and is never shared with the output.
- Playbooks / best-practice JSON of customers or partners do not go into a repository or test.
- **Licence key material, in no repository at all** (not even a private one): signing keys, release keys,
  `packages.json`, `register.json`, `licences/`, `support-<kid>.key`, built packages (`*.ppp`), licences.
- PSK lists, secret lists, egress-IP API keys, `.panconfkeystore`: never in a repository.

### Secrets in the code

- API keys and secrets are never returned to the browser, never written to an audit log, stored encrypted, and are
  personal (no key shared by all users). Keys are not deleted automatically after use.
- Import from devices is read-only.

### Code

- One implementation per feature: config viewer and CLI use the same pan-os-php filters / methods - nothing is
  maintained twice.
- Public / private boundary: `pan-os-php` holds what works on **one** system (export / read, upload of a finished
  change set into one SCM tenant with its safety checks: live compare, dry-run, approval). Everything of an actual
  **migration between two systems** (project types, migration plan, transformation, PSK workflow, migration report)
  lives in the private plug-in repositories - nothing of it goes into the public repository.
- Plug-ins describe forms / tables / approval steps as data (viewer plug-in interface v2); a plug-in brings no
  JavaScript for the page.

### pan-os-php specific

- Every change gets a CHANGELOG.txt entry in the top version section of the branch (bug fixes under its first
  `BUGFIX:` line).
- Run the tests of the touched area before handing over a patch (e.g. `tests/test_config_viewer.php`,
  `tests/test_config_viewer_container.php` for the config viewer).

## What This Project Is

PAN-OS-PHP is a PHP library for managing Palo Alto Networks PAN-OS firewall and Panorama configurations — both offline XML files and live devices via the PAN-OS XML API. It also ships a large set of ready-to-run CLI utilities (`utils/`) built on top of the library.

Requirements: PHP 8.5+ with extensions `curl`, `dom`, `mbstring`, `bcmath`, `mysqli`, `yaml`, `iconv`, `openssl`, `libxml`.

## Commands

### Run via Docker (recommended)
```bash
# Pull latest image
docker pull swaschkut/pan-os-php:latest

# Start interactive container, mounting current directory as /share
docker run --name panosphp --rm -v ${PWD}:/share -v ~/.panconfkeystore:/home/ubuntu/.panconfkeystore -it swaschkut/pan-os-php:latest

# Check version inside container
pan-os-php version
```

### Run locally
```bash
# Check version
php utils/pan-os-php.php version

# Run a UTIL script against an offline XML config
php utils/pan-os-php.php type=address in=config.xml out=output.xml location=any actions=display

# Run a UTIL script against a live firewall via API
php utils/pan-os-php.php type=rule in=api://192.168.1.1 actions=display

# Run against a managed firewall via Panorama serial
php utils/pan-os-php.php type=address in=api://0018CAEC3@panorama.company.com location=any actions=display
```

### Tests
```bash
# Run util script integration tests (uses tests/input/*.xml)
php tests/test_utilscripts.php

# Run filter tests against an XML file
php tests/test_filters.php in=tests/input/panorama-10.0-merger.xml out=/dev/null location=any

# Run merger tests
php tests/test_mergers.php in=tests/input/panorama-10.0-merger.xml out=/dev/null location=any

# Run API-based tests against a live device
cd tests && bash run_api_test.sh <MGMT_IP>
```

## Open Work and Concepts

- `TODO.md` is the central list of planned work; one file per topic in `todo/<area>-<topic>.md` (status, code
  reference, plan, open decisions). New concepts and plans go there, not next to the code.
- Finished topics move to `todo/done/` with their status updated; small items without their own file are listed in
  `TODO.md`.
- Documentation of an existing tool (`README_*.md`, guides) stays next to its code; `utils/develop/` keeps the code
  under development.

## Architecture

### Library Entry Point

`lib/pan_php_framework.php` is the single include that loads every class. All scripts begin with:
```php
require_once "lib/pan_php_framework.php";
```

### Device Hierarchy

The top-level objects represent the device type:

- **`PANConf`** — a PAN-OS firewall config. Has `virtualSystems[]`, `addressStore`, `serviceStore`, `network`, etc.
- **`PanoramaConf`** — a Panorama config. Has `deviceGroups[]`, `templates[]`, `templateStacks[]`, `managedFirewallsStore`.
- **`VirtualSystem`** — child of `PANConf`; holds per-vsys rules, address/service/tag stores.
- **`DeviceGroup`** — child of `PanoramaConf`; holds pre/post rules and shared objects.
- **`Template` / `TemplateStack`** — Panorama templates containing network config.
- **`FawkesConf`** — Prisma Access / SASE config. Has `Container[]`, `DeviceCloud[]`.
- **`BuckbeakConf`** — Strata Cloud Manager (SCM) config. Has `Container[]`, `DeviceCloud[]`, `DeviceOnPrem[]`.
- **`Container`** — child of `FawkesConf` or `BuckbeakConf`; analogous to `DeviceGroup` in Panorama, holds address/service/rule stores.
- **`DeviceCloud`** / **`DeviceOnPrem`** — cloud vs. on-prem device entries within those configs.
- **`Snippet`** — reusable config building block within SCM/SASE configs.

`UTIL.php` auto-selects the correct top-level class based on the `in=` argument: `in=api://sase-api/...` → `FawkesConf`, `in=api://scm-api/...` → `BuckbeakConf`. As a result `$util->pan` can be `PANConf`, `PanoramaConf`, `FawkesConf`, or `BuckbeakConf`, and code that inspects it should use `get_class($util->pan)` rather than assuming on-prem types.

### Object Stores

Each device/vsys/device-group has typed stores that hold objects:
- `addressStore` → `Address`, `AddressGroup`
- `serviceStore` → `Service`, `ServiceGroup`
- `tagStore` → `Tag`
- `appStore` → `App`, `AppGroup`, `AppFilter`
- `ruleStore` → `SecurityRule`, `NatRule`, `DecryptionRule`, `AppOverrideRule`, etc.
- `zoneStore`, `scheduleStore`, `edlStore`, `securityProfileStore`, etc.

All objects implement `ReferenceableObject` — call `$obj->countReferences()` / `$obj->getReferences()` to track usage.

### Rule Classes

`lib/rule-classes/` contains all rule types. `RuleStore` (`lib/rule-classes/RuleStore.php`) manages the ordered list of rules. Rules reference objects from stores by pointer, so renaming an object propagates automatically via `replaceMeGlobally()`.

### Connectivity

Three API connector classes in `lib/misc-classes/`:
- `PanAPIConnector` — on-prem PAN-OS/Panorama via XML API
- `PanSaseAPIConnector` — Prisma Access / SASE
- `PanSCMAPIConnector` — Strata Cloud Manager (SCM)

API keys are stored in `~/.panconfkeystore`. The `key-manager` UTIL type manages keys.

### RQuery Filter System

`lib/misc-classes/RQuery.php` provides a text-based query/filter language used by all UTIL scripts (e.g., `filter="name contains 'web'"` or `filter="address.ip in 10.0.0.0/8"`). Each object type has a matching `*RQueryContext.php` that defines its available filter properties. Filter implementations live in `lib/misc-classes/filters/`.

### UTIL Framework

`utils/lib/UTIL.php` is the CLI bootstrap for every predefined script. It handles:
- Argument parsing (`in=`, `out=`, `location=`, `actions=`, `filter=`)
- Config loading and vsys/device-group scoping
- Output saving

Custom scripts follow `examples/template-for-your-own-scripts.php`:
```php
require_once "lib/pan_php_framework.php";
require_once "utils/lib/UTIL.php";

$util = new UTIL("custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg);
$util->utilInit();
$util->load_config();
$util->location_filter();

$pan = $util->pan;   // PANConf, PanoramaConf, FawkesConf, or BuckbeakConf
$sub = $util->sub;   // VirtualSystem, DeviceGroup, or Container

// ... your logic ...

$util->save_our_work();
```

### UTIL Types (utils/pan-os-php.php `type=`)

The main dispatcher `utils/pan-os-php.php` accepts `type=` to select a tool. Action scripts live in `utils/common/actions-*.php`; filter definitions in `lib/misc-classes/filters/filters-*.php`. Adding a new object type requires adding entries in both locations plus a `*RQueryContext.php`.

### Shadow Arguments

Global behavior flags prefixed with `shadow-` (parsed in `PH.php`):
- `shadow-json` — output as JSON instead of text
- `shadow-ignoreinvalidaddressobjects` — skip malformed address objects (useful for real-world configs)
- `shadow-enablexmlduplicatesdeletion` — deduplicate XML nodes on load
- `shadow-disableoutputformatting` — skip DOMDocument reformatting on save

### Key Helper Classes

- **`PH`** (`lib/misc-classes/PH.php`) — static class; holds parsed CLI args in `PH::$args`, version info, output formatting, `derr()`/`mwarning()` error handlers.
- **`DH`** (`lib/misc-classes/DH.php`) — static DOM helper; `DH::dom_to_xml()`, `DH::elementToPanXPath()`.
- **`derr($msg)`** — global function that exits with an error + backtrace; use throughout the library for fatal conditions.
