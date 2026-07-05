# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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
