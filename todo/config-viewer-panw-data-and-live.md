# config-viewer: public PANW data, support portal, live data of a device

**Status:** list of Sven, 2026-11-21 - nothing built. Several topics exist in pan-os-php already (develop scripts or
types not shown in the viewer); the viewer shows their results as tables with filters, like the merger reports
(`MergerReport`, `ExportToHtmlHelper::tableData()`: one code path for command line and viewer).
**Related:** [develop-areas.md](develop-areas.md) (1.1 release notes, 1.2 CVE, 1.4 hardware compare / EoL),
[types-review-logs-xpath.md](types-review-logs-xpath.md) (session-browser, logs, xml-op-json),
[config-viewer-device-access.md](config-viewer-device-access.md) (personal keys, network allow list, read only),
[config-viewer-pandev-api.md](config-viewer-pandev-api.md).

## A. Public data (no login): a tab or an admin area "PANW data"

| # | Wish (Sven) | In pan-os-php today | For the viewer |
|---|---|---|---|
| A1 | **EoL data** as a table with filters | only the URLs (develop-areas 1.4): HW EoL, SW EoL summary on paloaltonetworks.com | download (admin, network allow list) or upload (air gap) → table: product / model / version, EoL date, last order date, …; filter, sort; mark the versions / models of the project's configurations |
| A2 | **release notes (README) of the PANW products** as tables, searchable | start: `utils/develop/panos-release-notes` + `lib/resources/panos_release_notes` (PAN-OS known / addressed issues, cache outdated: newest 11.2.5, no 11.0 / 12.x) | first a `type=` (develop-areas 1.1) with cache update; then per product (PAN-OS, Panorama, GlobalProtect, …): known / addressed issues as tables, search by text, issue ID, version |
| A3 | **CVE** - public, from the viewer | does not exist (develop-areas 1.2): security.paloaltonetworks.com `/json` (stable) or `/api` (BETA) | table of the advisories, filter by product / version / severity; "affects the version of this configuration"; link to the advisory |
| A4 | **firewall compare**: download the core data of a firewall model, show the comparison | `utils/develop/panos-hw-compare` + `info_json/pan_max_values.json` (2021, newer models missing; page needs JavaScript) | models side by side (table), per model **front panel / back panel** (pictures of the public hardware documentation - check what may be shown / linked), **link to the public documentation** (datasheet, hardware reference); **ports copper / fibre** (count and speed) - e.g. migration PA-3250 → PA-1450 or PA-3410: which target has enough ports of each kind; combine with the platform limits of a configuration (develop-areas 1.4 use cases 1-2) |
| A5 | **IANA protocol numbers** for the administrator | `type=protocoll-number-download` exists | admin run (network allow list) like App-ID / MaxMind; the result used by the runs |

Open: where the data lives (installation-wide, like App-ID / MaxMind: `central/`), update on request only, air gap =
upload; check the terms of use of each source (download, pictures).

## B. Support portal (support.paloaltonetworks.com) with the user's login

| # | Wish (Sven) |
|---|---|
| B1 | login of the user, **also 2FA / code by mail** (asked in the page, never stored) |
| B2 | per **CSP account** the user can see (several possible): the **registered firewall serials**; **search** by serial |
| B3 | **register firewalls with auth codes** - also several firewalls / auth codes at once (bundle / batch); the **address** (location of the device) is needed |
| B4 | per serial: **download the licences** (for air-gapped firewalls: upload into the device / a project) |

Open / to check first:
* there is no public, documented API of the support portal for this - check what PANW offers (e.g. an official API,
  the licensing API of a firewall `request license fetch` with internet access, the auth code activation of the
  firewall itself) and the **terms of use**; scraping the portal with a user login is fragile and may not be allowed
* the login (password, session) is the user's: personal, never stored, never in the audit log - like the API keys
* registering is a **write** on the PANW side: own switch of the administrator, a confirmation step, audit

## C. Live data of a device (XML API, read only, personal API key)

| # | Type | In pan-os-php today | For the viewer |
|---|---|---|---|
| C1 | `type=session-browser` | API, firewall; `<show><session><all>` with filter; **`actions=delete` clears sessions** | read only: show the running sessions as a table (no delete); **through Panorama as proxy**: the XML API of Panorama forwards op commands to a managed firewall (`target=<serial>`) - check with session-browser |
| C2 | `type=system-log` | API | table with filter, time range |
| C3 | `type=traffic-log` | API | table with filter, time range |
| C4 | `type=threat-log` | API | table with filter, time range |
| C5 | traffic / threat log also with `type=custom-report` | `type=custom-report` | the report as table |
| C6 | `type=xml-op-json` | API: an op command, response XML → JSON | an op command (allow list of read commands: `show …`) → the answer as JSON / table |

Rules (as the device import): personal API key of the user, network allow list of the administrator, network of the
project, **only read commands** (no `clear`, `request`, `set`, no `actions=delete`), the result only in the run;
first the review of these types ([types-review-logs-xpath.md](types-review-logs-xpath.md)).
