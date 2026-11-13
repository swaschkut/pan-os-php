# Prisma Access lifecycle – from requirements to maturity report

Concept / target picture. Status: **draft for discussion – nothing of the new parts is implemented yet.** Existing
building blocks are marked ✅ (see [NEXT_STEPS_pa_export.md](NEXT_STEPS_pa_export.md)).

## 1. Goal

One continuous, digital process for a Prisma Access project – from the first customer meeting to the regular maturity
check – based on **one data model** that is (almost) identical to the SCM / Prisma Access configuration:

```
 TRD ──► guided design (HLD) ──► design JSON ──► review with the customer ──► apply to tenant ──► operation
  │            │                      │            (report, network plans)          │              (customer changes)
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
| 4 | **Operation** – the customer changes the configuration | – | – | – |
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

## 5. Components

| component | what | status |
|---|---|---|
| export | `scm_pa_export.php` – all areas incl. internal UI API | ✅ verified |
| compare | `scm_pa_compare.php` | ✅ |
| apply | `scm_pa_sync.php` plan / apply | ✅ offline – write path to be tested (NEXT_STEPS 7.1 steps 1–3) |
| best practice | pan-os-php BP / visibility checks, SCM loader with complete profiles | ✅ |
| **report generator** | export / design → HLD / as-built document with tables and network plans | new |
| **diagram generator** | network plans from the same data | new |
| **TRD questionnaire** | guided entry of the requirements → `trd.json` (+ document) | new |
| **design wizard** | decisions per component, defaults, validation → `decisions.json` + design JSON | new |
| **maturity report** | as-built + diff + BP + score | new (combination) |

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

1. TRD template: format, current content – can it be shared (without customer data)?
2. Language of the customer documents (German / English / both)?
3. Report format the customer receives: Word, PDF, HTML?
4. Lucidchart: account / API available? Otherwise draw.io / SVG as the first target.
5. Which parts are mandatory for the first version (e.g. SC + RN + MU, EP and policies later)?
6. Licence / sizing rules (units per location, bandwidth pools) – source?
7. Naming conventions / standards of the consultant team (folder / snippet structure, object names).
8. Does the design also cover the security policy, or only the Prisma Access infrastructure?
9. Maturity score: which criteria (BP checks, design deviation, open checklist items …)?
10. Where does the web page run (local file / internal web server) and who uses it (consultants only)?
