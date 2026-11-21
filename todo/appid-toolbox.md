# `type=appid-toolbox` - AppID migration: process, code, automated support of phase 4, config viewer

**Status:** wish of Sven, 2026-11-21 - documented, nothing built.
**Process:** [appid-toolbox/doc/AppID Toolbox - PAN-OS-PHP.pdf](../appid-toolbox/doc/AppID%20Toolbox%20-%20PAN-OS-PHP.pdf)
(© 2023 Palo Alto Networks). **Code:** `utils/lib/APPIDTOOLBOX.php` (dispatch), `appid-toolbox/lib/trait/lib_1…6_*.php`
(the phases), `appid-toolbox/lib/common.php` (stats file, tags), tests `appid-toolbox/tests/`.

## 1. The process (summary of the PDF)

Every vsys / device group is its own sub-project; phases 2-6 can run again and again (loop) until the migration is
done. No configuration freeze is needed except for phases 1 and 5.

| Phase | `phase=` | What it does | Freeze |
|---|---|---|---|
| 1 rule marking | `p1-marker`, `phase1`, `rule-marker` | marks every candidate rule with a unique ID in its description `appRID#<n>` - not marked yet, not deny, application **any**, no tag `appid#ignore` | yes (15 min) |
| 2 log analysis | `p2-generator`, `phase2`, `report-generator` | per marked rule: the applications seen in the traffic logs (and source / destination IPs) - `logHistory=` (default 60 days), `resetPreviousData` / `updatePreviousData`, `updateOnlyUnusedTagRules`, `updateOnlyActivatedRules`, `skipIfLastReportLessThanXDays`; result: `<serial>-<location>-stats.xml` (+ `-statsSrcDst.xml`) in the current folder, resumable after an interruption; **API only** (logs); no change | no (1-3 days per 1000 rules) |
| 3 rule cloning | `p3-cloner`, `phase3`, `rule-cloner` | clones every legacy rule to `<name>-app` with the applications of phase 2, **disabled**; service any when the legacy rule is application-default; problems as tags `appid#NTBR#<reason>`; `ignoreApps=`, `bundleApiCalls` | recommended (30 min) |
| 4 review | `p4`, `phase4` → **error "manual task"** | review the disabled AppID rules with the customer: fix the application list, remove the NTBR tag when done | no (1 day - …) |
| 5 activation | `p5-activation`, `phase5`, `rule-activation` | preview by default, `confirm` changes: when legacy + AppID rule share the ID, have no NTBR tags, legacy enabled, identical except the applications, AppID rule placed before: legacy renamed `appRID-<n>-<random>` + log at start, AppID rule gets the legacy name and is enabled, both tagged `appid#activated#YYYYMMDD`; summary with SKIPPED#1-9 counters | yes (10-60 min) |
| 6 cleaning | `p6-cleaner`, `phase6`, `rule-cleaner` | after phase 2 again (`updatePreviousData logHistory=90`): legacy rules not hit any more are deleted, ID / activated / cloned tags removed from the AppID rule; unused rules keep `appid#unused` (the customer decides); `daysSinceLastReport=`, `confirm`; SKIPPED#1-14 | - |

NTBR tags (need to be reviewed) set by phase 3:

| Tag | Meaning (PDF) |
|---|---|
| `appid#NTBR#hasUnknownApps` | unknown-tcp / -udp / -p2p seen - custom application or App-Override? |
| `appid#NTBR#tooManyApps` | more than 10 applications - often an internet access rule: other approach (no fixed list) |
| `appid#NTBR#unused` / `appid#unused` | no logs - not used in the log period, or rarely; refresh the statistics later |
| `appid#NTBR#onlyInvalidApps` | only incomplete / non-syn-tcp / insufficient-data - probably not used (service down, not in production) |
| `appid#NTBR#hasInsufficientData` | insufficient-data - not identified, too short; App-Override depending on the case |
| `appid#NTBR#appNotAny` | someone added applications to the legacy rule since the marking - usually take it out of the process |

## 2. What the code has (to keep in mind for anything new)

* the phases are traits of one class (`APPIDTOOLBOX`), the old single scripts (`appid-toolbox/*.php`) only call
  `PH::UTILdeprecated(...)`; `appid-toolbox/lib/old/` = the former function version
* the statistics: `DeviceGroupRuleAppUsage` (common.php) - per rule: application → hit count, update timestamp;
  `-statsSrcDst.xml`: per rule source / destination IP → count; `exportToCSV()`
* phase 2 uses `Rule::API_getAppContainerStats2()` (traffic / summary logs of the firewall or Panorama)
* phases 1, 3, 5, 6 change the configuration - online (`in=api://`, API calls per change or `bundleApiCalls`) or on a
  file (`$configInputType` offline)
* tags are created by `TH::createTags()`; the rule ID library `RuleIDTagLibrary` finds free IDs
* version check in common.php: toolbox requires a pan-os-php version below 2.2.0 (`$maximumVersion`) - check before
  the next major version

## 3. Phase 4 - automated support (proposal)

The review stays a decision of the engineer / customer; the toolbox can prepare it so that the person decides
per group of rules instead of per rule, and the decisions are applied as pan-os-php actions (traceable, repeatable).

### 3.1 Review list (data, not a manual walk through the GUI)

* new `phase=p4-review` (read only): per AppID rule (disabled clone) and its legacy rule: location, rulebase, names,
  NTBR tags, the applications with **hit counts** (stats file), source / destination of the legacy rule, top source /
  destination IPs (statsSrcDst), date of the last report - as **JSON + HTML** (the export-table / MergerReport way:
  one code path for the command line and the config viewer) and **Excel / CSV for the customer** with a column
  *decision*
* groups that are decided together: rules with the **same set of applications** (e.g. 40 rules with only
  `ssl, web-browsing`), the same NTBR reason, the same destination zone

### 3.2 Suggestions per NTBR reason (computed, shown next to the rule)

| Tag | Suggestion the toolbox can compute |
|---|---|
| `tooManyApps` | the applications by **category / subcategory / technology / risk** (App-ID database `predefined.xml` of the project); collapse to their **container application** (e.g. `facebook-base`, `facebook-chat` → `facebook`); suggest an **application filter** or **application group**; mark *internet access* rules (destination zone untrust / any, many apps) - "other approach: URL filtering, App-ID by category" |
| `hasUnknownApps` | the **ports / destination IPs** of the unknown traffic (statsSrcDst + a log query for `app eq unknown-tcp`) → candidate **App-Override** or **custom application** (port based) per destination; check whether a newer App-ID content identifies it |
| `onlyInvalidApps` / `hasInsufficientData` | hit counts per invalid app; suggest *keep legacy* / *disable after confirmation* / *App-Override* for the short sessions; last hit time of the rule (`show rule-hit-count`) |
| `unused` | refresh with a longer `logHistory`, **rule hit count / last hit** of the device (does not depend on the log retention), *keep / disable / delete with the customer* |
| `appNotAny` | default: take out of the process (remove the ID and the tag) - one click for all |

General checks for every AppID rule before activation:

* **dependencies**: applications the found ones need (`use-applications` / implicit dependencies of `predefined.xml`)
  - add the missing ones (otherwise the rule breaks after activation)
* **service**: the default ports of the applications vs. the service of the legacy rule - suggest
  **application-default** when they match (best practice), keep the ports otherwise
* **already decided elsewhere**: the same application set accepted in another rule of the same review
* **phase 5 preview** of the rule: would it be activated (no NTBR, identical, placed before) - the SKIPPED reason of
  phase 5 per rule already in the review

### 3.3 Decisions applied as actions

* each decision is a pan-os-php action on the AppID rule (and only on it - never on an active rule): `app-add`,
  `app-remove`, `app-set` / application filter / group, `service-set-appdefault`, `tag-remove:appid#NTBR#…` (= ready
  for phase 5), `tag-add:appid#ignore` + remove the ID (out of the process)
* the decisions of the customer's Excel / CSV read back (`phase=p4-apply file=…`, preview by default, `confirm`) -
  or as a **playbook** (one step per decision) so that the same decisions can run on the next loop / another device
  group
* the **summary** like phases 5 / 6: per NTBR reason open / decided / ready for activation

## 4. Config viewer

* tab **AppID migration** per project, per location (vsys / device group): the phases as runs with their arguments
  (preview / confirm), the summaries (SKIPPED counters of phases 5 / 6) as tables
* phase 2 needs the logs of the device (API, personal key, network - like the import:
  [config-viewer-device-access.md](config-viewer-device-access.md)); **offline (air gap): import of a traffic log
  export** (CSV of Panorama / firewall) to compute the same statistics file - to build
* the **stats files** are project files (not only in the folder of one run): phase 2 resumes, phases 3 / 6 read them
* phases 1, 3, 5, 6 on the loaded version (file) - as one change each in the change list / git history (one commit,
  undo as a whole); writing to the device only through the "write to devices" decision (device-access A)
* **phase 4 in the page**: the review list (3.1) as a table with filters (NTBR reason, application, group), the
  suggestions (3.2), decisions per rule or per group → actions on the AppID rules (change list, undo, playbook),
  export / import of the customer's Excel

## Open

* which suggestions first (proposal: application sets / groups, dependencies, application-default check,
  `appNotAny` in one click, the review export / import)
* offline log import: which export format (Panorama traffic log CSV, summary report CSV)
* the version limit of the toolbox (`< 2.2.0`) before the next major version
* tests: `appid-toolbox/tests/test_appid_toolbox*.php` exist - extend for p4-review / p4-apply
* older items (TODO.md, section appid-toolbox): help of `location=` / list the device groups / vsys when it is
  missing; a rule filter for p1 and p2; p5 renames the legacy rule so that its hits can be told apart - check whether
  a rename still clears the hit count on current PAN-OS (in the past it did; phase 6 relies on new logs of the new name)
