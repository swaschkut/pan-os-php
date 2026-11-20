# Config viewer: project inputs and 3rd party migration

**Status:** requirements from Sven 2026-11-20, design proposal - nothing built, decisions open.
**Related:** [config-viewer-api.md](config-viewer-api.md), [config-viewer-license.md](config-viewer-license.md)

## Requirements (Sven, 2026-11-20)

A project gets its configuration from one of four inputs:

| # | Input | Then |
|---|---|---|
| 1 | PAN-OS XML file (Panorama / firewall / SCM export) | as today: types, filters, actions |
| 2 | online XML API: Panorama / firewall, management address + API key or user / password | as today |
| 3 | online SCM API: tenant (TSG id) + service account, also the CSV file in PANW format | as today |
| 4 | 3rd party configuration file: choose the vendor (versions / bought products that now belong to one vendor) | **migration** |

Migration (input 4):

1. after loading a **rough estimate**: how many objects of which kind, rule base, interfaces, …
2. **import by object kind** is possible, e.g. only address objects
3. after the import the data is made available **to another project** to optimise the configuration
4. the migration scripts are a **plug-in protected by a licence**, possibly **one licence per vendor**

## What exists

* `migration/parser/` - `type=vendor-migration vendor=<v> file=<3rd party file> out=<pan-os.xml> [in=<base config>]
  [routetable=<file>] [mapping=<file>] [location=]`; vendors in `CONVERTER::supportedVendors()`: ciscoasa, ciscoisr,
  ciscoswitch, cp, cp-r80, cp-beta, fortinet, srx, netscreen, sonicwall, sophos, sophosxg, huawei, stonesoft,
  sidewinder, pfsense. Base configs: `panos_baseconfig.xml`, `panorama_baseconfig.xml`.
* `migration/docs/vendor_config_export.md`, `migration/docs/vendors/*.md` - how a customer exports the configuration
  per vendor (some vendors need several files / an archive, CheckPoint and Stonesoft a mapping, some a route table).
* `utils/lib/UTIL.php` loads the migration parser at start (the reason why the image must hold `migration/`).

## To be clear before anything is protected

* The migration scripts are **public today** (ISC, GitHub, every published image). What is published stays usable
  under ISC. A licence / encryption can protect only **what comes after**: new versions, fixes, new vendors - and
  only when they leave the public repository.
* Who holds the rights to the existing parser code (own work, contributions, code that came from Expedition / PANW)?
  That decides whether later versions may be closed. To check with a lawyer.
* Technically the core must then work **without** `migration/` (today `UTIL.php` requires it at start).

## Design proposal

**Project input.** A project has a list of *sources*; a version always comes from a source or a run:
file upload (today), API import (2, 3), migration (4). Inputs 2 and 3 are **import runs** that write a version
(`type=…` with `in=api://…` / SCM, `out=` the new version) - not a live connection of the viewer.

**Migration as a plug-in** `migration` on a plug-in interface v2:

| Step | What | Needs in the interface |
|---|---|---|
| upload | 3rd party file(s) into the project: kind `migration-source` with vendor, optional route table / mapping | file kinds that are **not JSON**, several files per source, size limit, archives |
| estimate | run `migration-discover`: parses, writes `summary.json` (objects per kind, rules, NAT, interfaces, zones, routes, what is not supported / needs manual work) - no version | runs **without a version** (input is a project file); a result page from a JSON the plug-in declares |
| import | run `migration-import`: all, or chosen kinds (`address`, `service`, `rule`, …), base config Panorama / firewall, target location → result configuration | choice fields (select / multi select) |
| take over | result as a version of **this** project, or of **another project** (new or existing, where the user may write) | "result as version in project …" |
| vendor licence | feature per vendor: `migration-ciscoasa`, `migration-cp`, … - the vendor list of the page shows only the licensed ones | several features per plug-in, checked per run |

Import by kind: the converter writes a full configuration; choosing kinds is done after it (keep only the chosen
kinds, or import them into the target with the existing `…-merger` / import functions) - to decide when building,
after a look at how clean the parsers separate.

**Online inputs (2, 3)** touch three open points of [config-viewer-api.md](config-viewer-api.md):

* **secrets**: API keys / passwords / service account secrets must be stored encrypted, shown never again, usable by
  runs only ("secrets at rest" is still open);
* **network**: runs have no network today (`--network none`). An import run needs it - only to the one address of
  the source, decided per project by the owner;
* air-gapped customers: the address must be reachable from the Docker host.

## Order (proposal)

1. Interface v2 for migration: non-JSON file kinds, runs without a version, choice fields, result into another
   project. Migration plug-in on top of the **existing public** scripts: upload → estimate → import → version.
   One vendor first (which?).
2. Import by object kind; more vendors.
3. Licence + encrypted plug-in (decision 6 in config-viewer-license.md), feature per vendor; move the parser out of
   the public tree for new versions.
4. Online inputs: secrets, network per run, import runs for XML API and SCM API.

## Open decisions

1. Rights to the existing migration code - may later versions be closed? (lawyer)
2. Which vendor first; which test files may be used (synthetic ones for the repository tests).
3. Order: migration first (1-3) and online inputs after (4), or the other way round?
4. Licence per vendor: one feature per entry of `supportedVendors()`, or per vendor family (Cisco = asa + isr + switch,
   CheckPoint = cp + cp-r80, Forcepoint = stonesoft + sidewinder, Sophos = sophos + sophosxg, Juniper = srx + netscreen)?
5. "Another project": copy of the result (independent afterwards), or a link that follows the source?
