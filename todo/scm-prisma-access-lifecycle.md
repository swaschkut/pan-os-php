# Prisma Access lifecycle – from requirements to maturity report

Concept / target picture. Status: **draft for discussion – nothing of the new parts is implemented yet** (updated 2026-11-14: report outline 4.1, project flow 4.2, templates / text blocks 4.3; steps A + B as first version: `scm_pa_report.php` / `type=scm-report`, README_pa_report.md). Existing
building blocks are marked ✅ (see [scm-pa-export-next-steps.md](scm-pa-export-next-steps.md)).

## 1. Goal

One continuous, digital process for a Prisma Access project – from the first customer meeting to the regular maturity
check – based on **one data model** that is (almost) identical to the SCM / Prisma Access configuration:

```
 TRD ──► guided design (HLD) ──► design JSON ──► review with the customer ──► apply to tenant ──► operation
  │            │                      │            (report, network plans)          │          (adapt: manual / script)
  │            │                      │                                             │                    │
  └────────────┴──────────────────────┴──── same report generator ◄── export (as-built) ◄──────────────┘
                                                     │
                                          maturity report = as-built report
                                          + design vs. as-built diff + best practice checks
```

The same report (document, tables, network plans) is produced

* from the **design JSON** (before anything exists in the tenant) → customer validation of the HLD
* from the **export** of the tenant (after deployment / later) → as-built documentation and maturity report

Because design and export use the same format, `scm_pa_compare.php` ✅ shows what was changed compared to the agreed
design, and `scm_pa_sync.php` ✅ can apply the design to a tenant.

## 2. Phases and intermediate results

| phase | what happens | input | output | tool (status) |
|---|---|---|---|---|
| 0 | **Technical Requirements (TRD)** – first customer meeting | TRD template (today: document, not automated) | TRD as structured data (`trd.json`) + TRD document | questionnaire (new) |
| 1 | **Guided design (HLD)** – the consultant is guided through the decisions per component, with options, defaults, validation | `trd.json` | design decisions + `design/` (design JSON in export format) | design wizard (new) |
| 2 | **Design review** with the customer | design JSON | HLD document, network plans, checklist of manual items, open points | report + diagram generator (new) |
| 3 | **Apply** the design to the tenant | design JSON, secret lists | configured tenant (candidate → push) | `scm_pa_sync.php` ✅ (write path still to be tested on a live tenant) |
| 4 | **Operation / adapt** – the configuration is changed or extended, manually (SCM UI) or by script | configured tenant, change requests | changed tenant (candidate → push) | manually: SCM UI; by script: change file → `scm-change` ✅, actions of the planned Prisma Access type (building blocks 3 + 4 in [prisma-access-config.md](prisma-access-config.md), new) |
| 5 | **Maturity report** – regularly or on request | export of the tenant | as-built report (same as phase 2) + diff design ↔ as-built + best practice / visibility results | `scm_pa_export.php` ✅, `scm_pa_compare.php` ✅, pan-os-php BP checks ✅, report generator (new) |

## 3. Data model

### 3.1 Design JSON = export format

The design is stored **in the same directory / file format as the export** (`manifest.json`, `<area>/NN_<endpoint>.json`,
`config/…`), so that

* the report generator needs only one input format
* `scm_pa_compare.php` compares design ↔ export without conversion
* `scm_pa_sync.php` applies the design (plan `additive` against the empty / existing tenant)

Additionally a **design layer** for information that is not part of the SCM configuration:

```
design/
    manifest.json            like an export, "source": "design", design version / date / author
    trd.json                 requirements (phase 0)
    decisions.json           per decision: question, chosen option, reason, alternatives, open / agreed
    infra/ remote-networks/ service-connections/ mobile-users/ explicit-proxy/ config/ …   (export format)
    secret-placeholders      PSKs etc. are never in the design – only references to the secret lists
```

### 3.2 TRD data (phase 0) – first draft of the content

| block | content |
|---|---|
| customer / project | name, contacts, timeline, licenses (MU count, RN bandwidth, SC count, add-ons) |
| identity | IdP (SAML / CIE / LDAP), user groups, MFA, existing certificates / PKI |
| data centers / clouds | locations, private networks, routing (BGP / static), AS numbers, firewalls / routers (vendor for IKE / IPsec), redundancy |
| branches | count, location, bandwidth, internet-only or private access, local breakout, CPE / SD-WAN vendor, routing |
| mobile users | count, regions, agent (GlobalProtect / Prisma Access Agent), always-on, split tunnel / forwarding needs, Explicit Proxy, browser |
| DNS | internal domains, DNS servers per region, DNS proxy needs |
| IP plan | infrastructure subnet, MU IP pools, existing networks (overlap check) |
| security | policy baseline, decryption, URL / threat requirements, compliance, logging (Strata Logging Service, SIEM) |
| migration | existing solution (Panorama / other vendor), cut-over approach |

### 3.3 Design decisions (phase 1) – guided per component

The wizard asks the questions, offers options with defaults and validates. Examples:

**Infrastructure**
- infrastructure subnet (size, no overlap with the IP plan), infrastructure BGP AS, internal DNS domains / servers,
  egress / IP allow lists of partners

**Service connections (SC-CAN)**
- Prisma Access location per data center (nearest location; latency / region)
- high availability: one or two tunnels, backup SC (`backup_SC`), secondary WAN, ECMP
- routing: BGP (peer AS, `do-not-export-routes`, summarisation) or static (subnets = outbound routes), routing
  preference (default / hot potato)
- QoS, bandwidth

**Remote networks (RN-SPN)**
- location → SPN / bandwidth pool, licence units
- **internet only** (no routing, no SC needed) vs. **private access** (BGP / static routing, DNS proxy)
- tunnel HA (secondary tunnel / ECMP), IKE / IPsec profiles per CPE vendor, PSK handling (secret list)
- DNS proxy / internal domains

**Mobile users (MU-SPN)**
- agent: GlobalProtect (classic, split tunnel) or **Prisma Access Agent** (forwarding profiles)
- locations / regions, IP pools (size per region, no overlap), portal hostname
- authentication (SAML / CIE / local), HIP, app settings, always-on
- Explicit Proxy: needed? PAC / forwarding, authentication, locations

**Security policy baseline**
- folder / snippet structure, best practice profiles, decryption, URL / threat, logging

Validation rules (examples): IP overlaps (infra subnet, MU pools, DC / branch networks), AS numbers unique, licence units
vs. design (bandwidth, MU count), every private-access RN has a route to an SC, naming conventions.

## 4. Outputs

| output | content | format (options) |
|---|---|---|
| TRD document | answers of the questionnaire | Markdown / HTML → Word / PDF |
| HLD / design report | per component: decisions with reasons, configuration tables (locations, tunnels, IP plan, routing, MU, EP), checklist of manual items (certificates, IdP / CIE, licences) | same generator as the as-built report |
| network plans | overview (DCs – SC – Prisma Access – RN – MU), per area (SC / RN with tunnels, BGP, subnets; MU regions / pools) | generated: SVG / Mermaid / draw.io; **Lucidchart** via its JSON based import (Lucid Standard Import) or CSV import – to be evaluated |
| design JSON | ready to apply | export format (3.1) |
| as-built report | like the HLD, generated from an export | same generator |
| maturity report | as-built report + diff design ↔ as-built (`scm_pa_compare.php`) + best practice / visibility results + checklist status, optional score | HTML / PDF |

### 4.1 Report outline – as-built / maturity report (same structure as the HLD)

Target: close to the maturity report Palo Alto Networks produces (structure to be aligned with a sample of the PANW
report). Every section exists three times: from the **design** (HLD), from the **export** (as-built) and as **diff**
design ↔ as-built (maturity). Data source = export area / endpoint (`<area>/NN_<endpoint>.json`).

| # | section | content | export data |
|---|---|---|---|
| 1 | Summary | tenant (TSG), licences / units, components in use, maturity score, top findings, open checklist items | manifest, `infra/locations`, `remote-networks/bandwidth-allocations`, results of 2–8 |
| 2 | Infrastructure | infrastructure subnet, infrastructure BGP AS, internal DNS servers / domains, egress IPs (allow lists), locations in use | `infra/shared-infrastructure-settings`, `infra/bgp-routing`, `infra/internal-dns-servers`, `infra/locations`, egress IP export |
| 3 | Service connections | per SC: location, tunnels (primary / secondary = active / backup), backup SC, peer endpoints (IKE gateway, peer address), IKE / IPsec profiles, routing (BGP peer AS / static subnets, summarisation, no-export), QoS, SC groups, traffic steering; **network plan** DC ↔ SC ↔ Prisma Access with routing domains | `service-connections/*` (service-connections, ike-*, ipsec-*, qos-profiles, service-connection-groups, traffic-steering-rules), `ip-mapping.json` |
| 4 | Remote networks | per RN: location / SPN / bandwidth pool, internet-only vs. private access, tunnels (HA / ECMP), peer endpoints, routing (BGP / static), DNS proxy; location overview (map / table); **network plan** branches ↔ RN ↔ Prisma Access | `remote-networks/*` (remote-networks, bandwidth-allocations, ike-*, ipsec-*, qos-profiles), `ip-mapping.json` |
| 5 | Mobile users – gateways | locations / regions, IP pools (per region, overlap check), portal / gateway, authentication (SAML / CIE / local, authentication profiles, certificates), DNS, HIP | `mobile-users/mobile-agent-*`, `gp-portals`, authentication / certificate endpoints, `ip-mapping.json` |
| 5a | GlobalProtect (GPA) | agent profiles / app settings (connect method, always-on, split tunnel), tunnel profiles, agent versions, clientless apps, trusted zones | `mobile-users/mobile-agent-agent-profiles`, `-tunnel-profiles`, `-agent-versions`, `-global-settings`, `gp-*` (internal UI API) |
| 5b | Prisma Access Agent (PAA) | enabled, app settings, client authentication, forwarding profiles, staged rollout, token lifetime, project based access | `mobile-users/pa-agent-*`, `mobile-agent-enable`, `explicit-proxy/forwarding-*` |
| 6 | Explicit Proxy | settings, authentication (IP access, users), block settings, proxy server profiles, upstream proxy rules, PAC / forwarding | `explicit-proxy/*` (internal UI API) |
| 7 | Prisma Browser | user / device groups, applications / plugins, policies (sign-in, access & data, security, customization) | `prisma-browser/*` |
| 8 | Security posture | folder / snippet structure, profile groups, best practice / visibility per profile type (AV, WF, AS, DNS, VP, URL, FB), rules without profiles / logging, zone protection, log forwarding (Strata Logging Service) | `config/*` + `config/internal/*` → pan-os-php BP / visibility (`exportsptohtml`, `bp-stats`) |
| 9 | Administration | roles, service accounts, access policies (IAM) | `iam/*` |
| 10 | Checklist / open points | manual items (certificates, IdP / CIE, licences), items the API cannot read, findings with recommendation | MIGRATION_CHECKLIST.md, design `decisions.json` |

Network plans (3, 4 and an overview DC – SC – Prisma Access – RN – MU): generated from the same data – SVG / Mermaid
first, draw.io / Lucidchart import later (7.4).

### 4.2 Project flow (consultant view)

| step | what | phase | tools |
|---|---|---|---|
| 1 | **Customer requirements** | 0 TRD | document builder (4.3): TRD template, scope, question tables → TRD document ✅ first version; `trd.json` (new) |
| 2 | **Design / HLD** | 1–2 | design wizard → design JSON + `decisions.json`; report generator (4.1) → HLD + network plans (new) |
| 3 | **Generate / apply the configuration** | 3 | design JSON → `scm-sync` (infrastructure areas) / change file → `scm-change` (config) ✅ |
| 4 | **Adapt / extend the configuration** – manually or by script | 4 | SCM UI; change file → `scm-change` ✅; Prisma Access type actions ([prisma-access-config.md](prisma-access-config.md), new) |
| 5 | **Check: maturity report** | 5 | `scm-export` ✅ → report generator (4.1) as-built + `scm-compare` design ↔ as-built ✅ + BP / visibility ✅ + score (new) |

### 4.3 Document templates and text blocks (TRD, HLD, as-built)

The Word templates of the consulting team (TRD, HLD, Prisma Access as-built) are **not** stored in this repository;
they and the block libraries derived from them live in the claude.ai project folder (`templates/`). This repository
only describes the format and the generators.

Template conventions (found in the current templates):

| template | structure | template text |
|---|---|---|
| TRD | chapters per service ("… (Remove if not in scope)"), two-column question tables `Configuration Requirements / Description` with an empty answer column | red = guidance / example text, `Customer_Name`, `Consultant_Name`, `[customer]`, `[number]` … |
| HLD | modular: chapters correspond to the HLD generator blocks `{{begin "Service Connections"}} … {{end …}}` (marker names are still visible in the table of contents) – NGFW / VM-Series / SASE / Prisma Browser / CDSS … | orange italic = instruction, `<customer>`, `[LEGACY VENDOR]` … |
| As-built | chapters along the SCM navigation (Prisma Access setup, SC, ZTNA, traffic steering, MU GlobalProtect / Access Agent, Explicit Proxy, RN, IP addresses); setting / value and list tables | green italic = instruction, dark red = example text, `[CUSTOMER]` |

**Block model.** A block is a heading of the template with everything below it up to the next heading of the same or
a higher level (tree by heading level). Each block gets scope tags from its heading (`sc`, `ztna`, `rn`, `sdwan`,
`mu-gp`, `mu-paa`, `mu-ep`, `pb`, `mt`, `ngfw`, `cdss`, `data`, `adem`, `pra`, `decrypt`, `log`, `qos`); children
inherit the tags of the parent. Block library file (`pan-os-php-doc-blocks` v1): `doc_type`, `palette` (template
colours with role instruction / example / text and output action), `placeholders`, `blocks[]` with `id` (path slug),
`title`, `level`, `parent`, `tags`, `content[]` (`p` / `li` with role, `table` with header or setting labels,
`questions` for TRD tables, `image`, `toc`). Table rows are left out by default (as-built tables carry customer data).
Own text blocks: `pan-os-php-doc-snippets` v1 (`title`, `level`, `text` with `{{customer}}` …, `after_title`,
`doc_type`). Session: `pan-os-php-doc-session` v1 (project values, per template: scope, manual block selection,
placeholder replacements, answers, own blocks, colour actions).

**Document builder (web page, first version).** Guided steps Templates → Project → Scope → Blocks → Questions →
Output; runs in the browser, templates are read locally and never uploaded. Output from a Word master keeps layout,
styles, images, headers / footers: unselected blocks removed, placeholders replaced (also split across runs),
TRD answers written into the answer column, own text inserted after the chosen block, template colours kept /
normalised / removed, table of contents refreshed when Word opens the file. A block library without the master
gives a Word file with a simple layout (composing new templates from blocks).

Next steps for the builder:

1. ~~as-built data binding~~ ✅ first version: `scm-report` writes `asbuilt-data.json` (tables of the as-built
   document: list / setting-value / profile matrix, matched by heading); the builder fills the as-built template.
   The as-built and HLD Word files are filled customer documents – `make_templates.py` (project `templates/tools/`)
   turns them into templates (table data removed, customer name → `[CUSTOMER]`)
2. TRD answers → `trd.json` (3.2) and from there defaults for the design wizard (3.3) / HLD block selection
3. HLD: block selection from the TRD scope; HLD marker names as block ids when a master with markers is available
4. composing across templates (blocks of TRD + HLD in one document) with the styles of one master

## 5. Components

| component | what | status |
|---|---|---|
| export | `scm_pa_export.php` – all areas incl. internal UI API | ✅ verified |
| compare | `scm_pa_compare.php` | ✅ |
| apply | `scm_pa_sync.php` plan / apply | ✅ offline – write path to be tested (NEXT_STEPS 7.1 steps 1–3) |
| best practice | pan-os-php BP / visibility checks, SCM loader with complete profiles | ✅ |
| **report generator** | export / design → HLD / as-built document with tables and network plans | as-built from export ✅ first version (`scm-report`: Markdown, HTML, findings); from design new |
| **diagram generator** | network plans from the same data | draw.io from export ✅ first version (Lucidchart import) |
| **TRD questionnaire** | guided entry of the requirements → `trd.json` (+ document) | new |
| **design wizard** | decisions per component, defaults, validation → `decisions.json` + design JSON | new |
| **maturity report** | as-built + diff + BP + score (outline 4.1) | new (combination) |
| Prisma Browser | export ✅ (`prisma-browser/*`), report section 7 | report new |

Front end: a web page (HTML) that guides the consultant (questionnaire + wizard), works offline with local files
(customer data stays local), reads / writes JSON. Engine / generators: PHP in pan-os-php (same code for design and
export), callable from the CLI and from the web page.

## 6. Intermediate steps (proposal for the order)

| # | step | why first | result |
|---|---|---|---|
| A | **as-built report from an existing export** (infra, SC, RN, MU, EP) – document + tables | uses data that exists today (lab, customer exports); defines the report format that design and maturity reuse | first customer-ready documentation |
| B | **network plans** from the export (SVG / draw.io; evaluate Lucidchart import) | same data as A | plans for the report |
| C | **TRD schema + questionnaire** – digitise the existing TRD template | needs the template | `trd.json` + TRD document |
| D | **design data model** – design JSON (export format) + `decisions.json`; generator TRD → design JSON skeleton | A–C define what is needed | design JSON that A / B can render |
| E | **design wizard** – guided decisions, defaults, validation (SC-CAN, RN-SPN, MU-SPN, EP, GPA / PAA) | builds on D | HLD from the wizard |
| F | **apply** the design JSON to a tenant | needs the tested write path (NEXT_STEPS 7.1 steps 1–3) | deployed design |
| G | **maturity report** – A + compare design ↔ export + BP checks + score | builds on A, D, F | recurring report |

## 7. Open points / to clarify

1. ~~TRD template~~ – received (Word); templates and block libraries kept in the claude.ai project, not in the repository (4.3).
2. Language of the customer documents (German / English / both)?
3. Report format the customer receives: Word, PDF, HTML?
4. Lucidchart: account / API available? Otherwise draw.io / SVG as the first target.
5. Which parts are mandatory for the first version (e.g. SC + RN + MU, EP and policies later)?
6. Licence / sizing rules (units per location, bandwidth pools) – source?
7. Naming conventions / standards of the consultant team (folder / snippet structure, object names).
8. Does the design also cover the security policy, or only the Prisma Access infrastructure?
9. Maturity score: which criteria (BP checks, design deviation, open checklist items …)?
11. PANW maturity report: sample (anonymised) to align sections, wording, scoring and layout.
10. Where does the web page run (local file / internal web server) and who uses it (consultants only)? First version: claude.ai artifact (private) or the HTML file opened locally.
12. HLD master with the `{{begin}}` / `{{end}}` markers (the test HLD is a generated output without markers in the body).
