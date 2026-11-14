# SCM gap remediation – visibility / best practice fixes as reviewable API change files

Concept. Status: **draft for discussion – the new parts are not implemented yet.** Builds on what exists:

* ✅ visibility / best practice checks of pan-os-php for rules, zones, zone protection profiles and security profiles
  (Panorama / firewall; for SCM via `in=scm-api://…`, security profiles complete via the internal UI API – see
  [../sase/scm/SECURITY_PROFILES_public_vs_internal_api.md](../sase/scm/SECURITY_PROFILES_public_vs_internal_api.md))
* ✅ fix actions / playbooks (`virus.best-practice-set`, `…alert-only-set`, `type=playbook json=visibility.json` …) that
  change the XML; for Panorama / firewall the result is written as **set commands** (`outputformatset=`)
* ✅ for SCM the result is written as **one SCM API request per changed object** (`outputformatscmjson=` /
  `type=scm-changes`, format `pan-os-php-scm-changes` version 1) and sent with `type=scm-apply` – see [README.md](README.md)

## 1. Goal

```
SCM tenant ──► load (public + internal API) ──► gap analysis ──► fix generation ──► changes.json (all fixes)
                                                    │                                     │
                                                    ▼                                     ▼
                                              findings report                 CDSS portal: customer / consultant
                                                                              selects the fixes to implement
                                                                                          │
                                                                                          ▼
                                                                  changes.json (subset, same syntax, fewer requests)
                                                                                          │
                                                       validate ──► apply (dry-run, then execute) ──► push (optional)
                                                                                          │
                                                                    re-load ──► gap analysis again (verification)
```

* The customer does **not** want changes applied directly. Every change is first stored as an API request in a JSON
  file.
* The CDSS portal (consumer of the file) removes the requests that shall not be implemented and writes a new file
  **with identical syntax** – only fewer requests.
* A script reads this file and sends exactly these requests to the tenant – through the **public SCM API** or, for
  parts the public API does not cover, through the **internal UI API**.

## 2. What exists and what is missing

| part | today | missing |
|---|---|---|
| checks (rules, zones, ZPP, security profiles) | ✅ pan-os-php BP / visibility | a machine readable **findings** list (check id, object, current / target value) that links each finding to its fix requests |
| fixes | ✅ fix actions / playbooks on the XML | – |
| SCM requests | ✅ `pan-os-php-scm-changes` v1, `type=scm-changes` / `outputformatscmjson=` | requests for the **internal UI API** (sections the public schema does not have are marked `review` today and not sent: e.g. vulnerability `mica-engine-vulnerability-enabled`, WildFire-AV `decoder`, `mlav-engine-filebased-enabled`, `mica-engine-wildfire-rules`) |
| selection | – | per finding / request: stable ids, groups, description – so that a portal can select and remove consistently |
| apply | ✅ `type=scm-apply` (public API, `merge`, `depends_on`, `review` skip, dry-run) | validation of a **subset** (dependency closure, file integrity, target tenant), **precondition check** against the live object (`before`), internal API requests, apply log per change, verification run |

## 3. Change file – version 2 (proposal)

Backwards compatible extension of `pan-os-php-scm-changes` v1. Everything the portal needs to select is in the file;
removing entries must not require any other edit.

```jsonc
{
  "format": "pan-os-php-scm-changes",
  "version": 2,
  "api_base": "https://api.strata.paloaltonetworks.com",
  "ui_api_host": "paas-3.prod.eu.panorama.paloaltonetworks.com",      // internal API requests
  "source": { "tsg_id": "…", "loaded_at": "…", "tool": "pan-os-php …", "profile": "visibility | best-practice" },
  "summary": { "findings": 40, "requests": 55, "public": 48, "internal": 7, "review": 2 },

  "findings": [                                       // what was found – shown / selected in the portal
    {
      "finding_id": "f-3c2a…",                        // stable: hash of check + object (+ field)
      "check": "vulnerability.inline-cloud-analysis",  // check id of pan-os-php
      "category": "best-practice | visibility",
      "severity": "high | medium | low",
      "object": { "resource": "vulnerability-protection-profiles", "name": "VP-Default",
                  "scope_type": "folder", "scope": "Mobile Users" },
      "current": "…", "target": "…",                  // human readable
      "description": "Inline cloud analysis is disabled …",
      "requests": [ "r-12", "r-13" ],                  // request ids that fix it
      "fixable": true                                  // false: report only (e.g. predefined object, missing licence)
    }
  ],

  "requests": [
    {
      "request_id": "r-12",                            // stable id (v1 "seq" stays for the order)
      "seq": 12,
      "api": "public | internal",
      "method": "PUT",
      "path": "/config/security/v1/vulnerability-protection-profiles/<id>",   // internal: /api/config/v9.2/…
      "query": {},
      "id": "<SCM id>",
      "merge": true,
      "body": { … },                                   // public: SCM schema; internal: PAN-OS structure as JSON
      "before": { … },                                 // precondition: live values must still be these
      "object": { … },                                 // as in v1
      "finding_ids": [ "f-3c2a…" ],
      "depends_on": [ "r-7" ],                         // request ids (v1: seq numbers – both accepted)
      "review": false, "warnings": []
    }
  ]
}
```

### Rules for removing (portal)

* The portal removes **findings** (or single requests). A request stays only if at least one of its findings stays.
* A remaining request whose `depends_on` request was removed is **invalid** → `validate` reports it; `apply` skips it
  (and everything depending on it). Typical case: a new (cloned) security profile (POST) and the rule / profile group
  that uses it (PUT) belong to the same finding – the portal should remove / keep them together.
* `summary` may be stale after removing – the tools recompute it, the portal does not have to.
* No other field may be changed. The portal may add a `selection` block (who, when, ticket) – it is ignored by apply
  and copied into the apply log.

## 4. Fix types and API

| object | typical fixes | API |
|---|---|---|
| security rules | log at session end, log forwarding profile, profile group / profiles, deny → drop, disabled / shadowed rules (report only) | public `security-rules` |
| zones | zone protection profile, user identification | public `zones` (folder / device) |
| zone protection profiles | flood / reconnaissance / packet based protection | public `zone-protection-profiles` |
| anti-spyware, URL, file blocking, DNS security profiles | actions, categories, packet capture, sinkhole | public |
| vulnerability protection | rules / actions (public); **inline cloud analysis** (`cloud-inline-analysis`, `mica-engine-vulnerability-enabled`) | public + **internal** |
| WildFire / antivirus | rules (public); **decoder actions, inline ML, inline cloud analysis** | public + **internal** |
| profile groups | add missing profiles | public `profile-groups` |
| predefined objects (`best-practice`, `default`, snippet `predefined`) | cannot be changed | fix = **clone** (POST of a new profile) + reference the clone in the rules / profile groups (PUT) – one finding, several requests |

Internal API writes: the UI writes with `PUT /api/config/v9.2/…` / `configByPath` (seen in a HAR: Clientless VPN,
service connection) and, for security profiles, `POST /api/config/v9.2/multiConfigure` (`command: edit`, complete
entry) / `PUT …/Objects/WildFireAndAntivirusSecurityProfiles?name=` (HAR 2026-11-14) – implemented in
`scm_pa_change.php` (`_internal`, see ../sase/scm/SECURITY_PROFILES_public_vs_internal_api.md).

## 5. Tools

| step | command (proposal) | status |
|---|---|---|
| load | `pan-os-php type=… in=scm-api://<TSG> out=scm.xml` (public + internal for profiles) | ✅ |
| gap analysis | `pan-os-php type=… actions=bp-stats …` / rule / zone checks → **findings report** (HTML / CSV) | checks ✅, findings output new |
| fix generation | `type=playbook json=visibility.json in=scm.xml out=… outputformatscmjson=changes.json` → v2 incl. findings and internal requests | v1 ✅, v2 new |
| portal | CDSS portal – select, write subset | external |
| validate | `type=scm-apply changes=selected.json validate` – format, dependency closure, `review`, target TSG, `ui_api_host` | new |
| apply | `type=scm-apply changes=selected.json tsg=<TSG> [dry-run] [push]` – dry-run: GET each object, compare `before` (conflict = object changed since the analysis), show the request; execute: send in `seq` order, public and internal | v1 ✅ (public, no precondition check), extensions new |
| verification | load again, run the checks, compare with the findings of the file → per finding: fixed / not fixed / conflict | new |
| rollback (optional) | from `before`: `changes-rollback.json` with the inverse requests | new |

Apply log (per request): status (`ok`, `skipped-removed-dependency`, `conflict`, `failed`, `review`), HTTP code, error,
finding ids – no request bodies with secrets.

## 6. Intermediate steps (proposal)

| # | step | result |
|---|---|---|
| 1 | define the **check ids** and the findings structure for the existing checks (rules, zones, ZPP, security profiles) | findings list (JSON) next to the existing output |
| 2 | **findings report** (HTML / CSV) from an SCM load | gap analysis for the customer, no changes yet |
| 3 | change file **v2**: `request_id`, `finding_ids`, `findings[]`, `api` – generated by the playbook / util run | file that a portal can work with |
| 4 | **validate** + **precondition check** (`before`) in `type=scm-apply` | safe apply of a subset |
| 5 | capture the **internal write calls** for vulnerability / WildFire-AV (HAR) and generate `api: internal` requests | inline ML / cloud analysis / decoder fixable |
| 6 | **clone strategy** for predefined profiles | best practice fixable when only predefined profiles are used |
| 7 | **verification** run and report | proof per finding |
| 8 | optional rollback file | – |

Test environment: the existing offline test (`utils/develop/scm/test/scm-offline-test.sh`, mock server) for the public
API; the lab tenant for the internal API and the end-to-end run.

## 7. Open points / to clarify

1. CDSS portal: who builds it, which fields does it need, does it accept the v2 structure (findings + requests)?
2. Granularity of the selection: per finding, per object, per request?
3. Which profile / standard: pan-os-php visibility, best practice, or a customer specific JSON (`shadow-bpjsonfile`)?
4. Approval / audit: who approved which finding – stored in the file (`selection`) or only in the portal?
5. Push: does the script push (`push`), or does the customer push in SCM after review?
6. Predefined profiles: clone naming convention (e.g. `<name>-bp`) and where the clone is created (same folder,
   parent folder, snippet).
7. Rollback required?
8. Conflict handling: object changed between analysis and apply → skip, or re-analyse automatically?
9. Language / format of the findings report for the customer.
