# SCM visibility workflow with pan-os-php

How to check an existing Strata Cloud Manager (SCM) configuration against the visibility playbook, see the real
differences against the tenant, and upload only the selected changes.

```
SCM tenant ──1──► export (JSON) ──2──► SCM XML ──3──► playbook visibility ──► SCM XML (visible)
                     │                                                              │
                     └──────────────────────────────4─ scm-xml-to-change ◄──────────┘
                                                            │
                                                            ▼
                                     change.json ──5─ scm-change diff= ──► diff.json ──► CDSS portal (selection)
                                                                                              │
                                     SCM tenant ◄──6─ scm-change select= execute ◄── diff_selected.json
```

All steps run with `pan-os-php type=…` (Docker image or `php utils/pan-os-php.php`). Placeholders: `<TSG>` = tenant
service group id, `<timestamp>` = export folder written in step 1, `<ui-host>` = internal UI API host of the tenant
region (browser developer tools: requests to `/api/config/v9.2/...`, default `paas-3.prod.eu.panorama.paloaltonetworks.com`).

Requirements: API credentials of the tenant (service account) in the pan-os-php key store; branch
`beta_scm-extension`.

## Description

### 1) Export the configuration from SCM

```
pan-os-php type=scm-export in=scm-api://<TSG> area=config outdir=scmtest ui-api-host=<ui-host>
```

* reads folders, snippets, devices and all configuration types through the public SCM API (read only)
* writes `scmtest/<TSG>/<timestamp>/` – one JSON file per container and type (`config/folders|snippets/<name>/NN_<type>.json`)
* additionally reads the security profile sections the public API does not return (antivirus decoder actions,
  WildFire inline ML, inline cloud analysis, rule action `default`, advanced DNS) through the internal UI API →
  `config/internal/<type>.json` (needed for a correct antivirus / WildFire evaluation; `config-internal=no` to skip)

### 2) Convert the SCM export (JSON) to SCM XML

```
pan-os-php type=scm-export-xml in=scm-export://scmtest/<TSG>/<timestamp> out=<TSG>.xml
```

* offline, nothing is sent; the same JSON → XML translation as `in=scm-api://`
* SCM specifics: virus-and-wildfire-analysis profiles (no separate antivirus / WildFire profiles), anti-spyware +
  DNS security, profile groups only in rules; security profiles complete from the internal UI API answers
* every pan-os-php utility can work on this XML (or directly with `in=scm-export://…`)

### 3) Run the visibility playbook against the SCM XML

```
pan-os-php type=playbook 'json=$$playbook$$/visibility.json' in=<TSG>.xml out=<TSG>_visible.xml
```

* detects the SCM configuration and uses the SCM variants of the steps (`"scm"` / `"platform"` in visibility.json)
* creates in folder `All`: log forwarding profile `default` (Strata Logging Service), `Alert_Only_Zone_Protection`,
  Alert-Only profiles (AS, VP, URL, FB, AVWF, DNSSEC) and the profile group `Alert-Only`
* sets alert-only values on the used profiles, the profile group `Alert-Only` on rules without profiles, log
  forwarding / zone protection on rules and zones
* check the result: `pan-os-php type=securityprofile in=<TSG>_visible.xml location=any actions=exportsptohtml:sp_after.html`

### 4) Create the change file (scm-xml-to-change)

```
pan-os-php type=scm-xml-to-change in=scm-export://scmtest/<TSG>/<timestamp> file2=<TSG>_visible.xml out=change.json
```

* compares the export (original) with the playbook result and writes the changes as change file
  (`pan-os-php-scm-change-request`): create / update per object, `_internal` for internal UI API sections
* use the **same export folder** (with timestamp) as in step 2 – otherwise wrong differences (e.g. deletes)
* `not_imported` lists what is not in the change file, with the reason – read it

### 5) Determine the real differences against the tenant (scm-change, diff)

```
pan-os-php type=scm-change in=scm-api://<TSG> changes=change.json ui-api-host=<ui-host> diff=diff.json
```

* dry-run – nothing is sent: exports the current state of the touched objects, builds the target state, plans the
  requests (dependencies, order) and checks the internal UI API sections
* `diff.json` (`pan-os-php-scm-diff`): only the objects that really change – `id`, action (`create`, `update`,
  `delete`, `update (internal)`), changed fields with `before` / `after`, internal sections with `before` / `after`,
  `blocked` reason
* blocked / failed requests are listed – `execute` refuses to start while there are any
* run files: `change/<TSG>/change-<timestamp>/` (PLAN_REPORT.md, compare/DIFF_REPORT.md, plan.json)

`diff.json` is the input for the CDSS portal: the customer / consultant keeps the objects to implement and returns
the reduced file (`diff_selected.json`) – or a JSON list of the selected `id`s.

## Upload

### 6) Apply the selection (scm-change, select, execute)

```
pan-os-php type=scm-change in=scm-api://<TSG> changes=change.json ui-api-host=<ui-host> select=diff_selected.json            # dry-run of the selection
pan-os-php type=scm-change in=scm-api://<TSG> changes=change.json ui-api-host=<ui-host> select=diff_selected.json execute
```

* only the selected objects of the change file are applied; unknown ids are reported
* `execute` asks for the TSG id as confirmation (`yes` skips it), sends the public requests in dependency order,
  then the internal UI API edits, and verifies every change by a new export
* hash check: an object changed in SCM since the export is reported as conflict, not overwritten (also for internal
  sections)
* stops at the first failed request (`continue-on-error` to continue); nothing is pushed unless `push` is given

## Known limits (2026-11-14)

* references from snippet objects (zones) to profiles in folder `All` (zone protection / log forwarding profile
  created by the playbook) – live acceptance by SCM to be confirmed with the first execute

Fixed: the Alert-Only DNS security profile contains only DNS sections; SCM configurations are evaluated with the
current feature set for inline cloud analysis (WildFire inline cloud analysis is really checked and set by the
playbook); `scm-compare` compares the internal UI API sections (`_internal.<section>`); references to predefined URL
categories are checked against the pan-os-php predefined URL categories (predefined.xml).

Details: README_pa_export.md, README_pa_xml_to_change.md, README_pa_change.md.
