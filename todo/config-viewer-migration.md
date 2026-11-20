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

## Progress

| Date | Step | State |
|---|---|---|
| 2026-11-20 | interface: raw file kinds, runs without a version, select / multi fields, result into another project | done in pan-os-php (see config-viewer-api.md) |
| 2026-11-20 | local migration report (`report/migration-report.php` in the private repository) | done; first real report: the file is in ASA / PIX / FWSM form (`access-list <name> extended …`, `static (if,if) …`), not IOS switch form |
| 2026-11-20 | migration plug-in v0.1 (private repository, `migration/plugin.php`): upload → import (Cisco IOS router) → version in this or another project; parser `CISCOISR` in the plug-in with 4 fixes (lpd = 515, tcp / udp without a port = all ports of that protocol, icmp = application icmp / ping, wildcard mask that is no prefix = ip-wildcard object; dumps only with `debug`) | done, synthetic test (20 checks), checked on a real router configuration at Sven's side |
| | Cisco router: zones from interfaces + ACL bindings, interfaces, static routes, NAT, IKE / IPsec (crypto profiles, gateways, tunnels); ACLs that only select traffic for VPN / NAT are no security rules | next |

## Order (proposal)

1. Interface v2 for migration: non-JSON file kinds, runs without a version, choice fields, result into another
   project. Migration plug-in on top of the **existing public** scripts: upload → estimate → import → version.
   One vendor first (which?).
2. Import by object kind; more vendors.
3. Licence + encrypted plug-in (decision 6 in config-viewer-license.md), feature per vendor; move the parser out of
   the public tree for new versions.
4. Online inputs: secrets, network per run, import runs for XML API and SCM API.

## Decisions (Sven, 2026-11-20)

| # | Topic | Decision |
|---|---|---|
| 1 | Rights | the migration scripts were written by Sven and put under the public licence by him - later versions may be closed; what is published stays ISC |
| 2 | Where | the migration plug-in starts in a **new private GitHub repository** (first licensed plug-in); the public repository keeps the interface |
| 3 | First vendor | Cisco **switch / router** (`ciscoswitch`, `ciscoisr`: ACLs, object-groups) - these two are also the ones not yet moved to the class based parser |
| 4 | Licence | per **vendor family** (Cisco = asa + isr + switch, CheckPoint = cp + cp-r80, Juniper = srx + netscreen, Forcepoint = stonesoft + sidewinder, Sophos = sophos + sophosxg, …) |
| 5 | Other project | a **link**: the target project knows which import it came from and can take a newer import as a new version; the optimised versions of the target are never overwritten (meaning to confirm) |
| 6 | Customer files | real 3rd party configurations are never shared. A **local report** (run at Sven's side, no names / addresses, read before sending) is the way to show what a parser does with a real file |

## Local migration report (proposal)

A script that runs at Sven's side on a real file and writes a report that holds no customer data:

* figures of the result: objects per kind, rules, groups, what was created / skipped (from the migrated XML);
* the source file as **structure only**: how often each command form occurs, with every name, address, number and
  text replaced (`access-list <name> extended permit tcp host <ip> <ip> <mask> eq <port>`);
* which command forms the parser did **not** handle, in the same reduced form;
* PHP warnings / errors with file and line of the parser (no values);
* nothing else - no object names, no addresses, no descriptions, no comments; a check at the end that no address
  and no word outside a fixed list of vendor keywords is left.

Synthetic test files for the repository are written from these command forms.

## Open decisions

1. Order: migration first and online inputs (XML API, SCM API as a source of a project) after it, or the other way round?
2. Private repository: name, and how the plug-in gets from there into an installation while licences / encryption are
   not built (development: folder mounted through `PANOSPHP_VIEWER_PLUGINS`).
3. The core without `migration/`: when is the parser removed from the public tree (new versions only in the private
   repository)?
4. Meaning of the link between projects (decision 5).
