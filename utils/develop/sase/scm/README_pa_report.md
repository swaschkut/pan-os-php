# scm_pa_report.php – Prisma Access as-built documentation

Creates an as-built documentation of a Prisma Access / SCM tenant from an export folder of `scm_pa_export.php`
(offline, read only). It follows the report outline of [todo/scm-prisma-access-lifecycle.md](../../../../todo/scm-prisma-access-lifecycle.md) 4.1.

```
pan-os-php type=scm-report in=scm-export://scmtest/<TSG>/<timestamp> [out=<directory>]
php utils/develop/sase/scm/scm_pa_report.php in=scm-export://scmtest/<TSG>/<timestamp> [out=<directory>]
```

* `in` – export folder as `scm-export://<outdir>/<TSG>/<timestamp>` (`scm-export://<outdir>/<TSG>` = newest export) – same
  notation as `scm-export-xml` and `scm-xml-to-change`; a plain path works as well (the report reads the export files
  directly, it does not load the configuration through the pan-os-php loader)
* `out` – output directory, default `<export>/report`

Recommended export for the report: `pan-os-php type=scm-export in=scm-api://<TSG> area=all outdir=scmtest ui-api-host=<ui-host> egress-api-key=<key>`
(without `area=config` the configuration section and the security rule checks are empty).

## Output

| file | content |
|---|---|
| `report.md` | Markdown (Word / PDF: `pandoc report.md -o report.docx`) |
| `report.html` | self-contained HTML, print to PDF from the browser (one section per page) |
| `prisma-access.drawio` | network plans, pages *Overview*, *Service connections*, *Remote networks*, *Mobile users* |
| `asbuilt-data.json` | tables of the Prisma Access as-built template filled from the export (`pan-os-php-asbuilt-data` v1) – input of the document builder, see below |

`prisma-access.drawio` opens in draw.io / diagrams.net (desktop or web) and imports into Lucidchart
(*File > Import > draw.io*). The plans are a generated starting point – arrange and extend them there.

## Sections

1. Summary – tenant, infrastructure subnet / AS, counts, export errors, findings
2. Findings – design and operations checks with severity (high / medium / low / info) and recommendation
3. Infrastructure – shared infrastructure settings, BGP routing, internal DNS, egress IPs per location
4. Service connections – active / backup tunnels, backup SC, BGP / static, subnets, peer endpoints, SC groups,
   traffic steering, IKE gateways, IPsec tunnels, crypto profiles
5. Remote networks – location, SPN, licence, tunnels (ECMP), routing, branch endpoints, service / egress IP,
   bandwidth allocations, IKE / IPsec / crypto
6. Mobile users – portal, regions, IP pools, locations with gateway / portal egress IPs, authentication;
   5a GlobalProtect (agent / tunnel profiles, portals, clientless apps), 5b Prisma Access Agent
7. Explicit Proxy – settings and components (internal UI API export)
8. Prisma Browser – user / device groups, applications, policies, unpublished changes
9. Configuration and security posture – folder / snippet hierarchy, objects per container, security rule statistics
10. Administration – roles, custom roles, service accounts, access policies per role
11. Checklist / open points – endpoints not exported completely, MIGRATION_CHECKLIST.md of the export

## Findings (checks)

| area | check |
|---|---|
| service connections | single service connection; SC without secondary tunnel and without backup SC; static routing |
| remote networks | no secondary tunnel; secondary tunnel with static routing |
| SC / RN crypto | weak IKE / IPsec algorithms (DES, 3DES, AES-128-CBC, MD5, SHA1, DH group 1 / 2 / 5); IKEv1; tunnel monitor disabled |
| mobile users | authentication profile without SAML and without MFA; agent connect method not always-on; local users |
| infrastructure | no internal DNS servers with service connections; egress IPs not exported |
| security policy | allow rules without profile group; allow rules with application any and service any; disabled rules |
| administration | more than 3 superuser users; service accounts with superuser |
| Prisma Browser | unpublished changes |

Security profile best practice / visibility is not repeated here – use `scm-export-xml` and
`type=securityprofile actions=exportsptohtml` (WORKFLOW_scm_visibility.md).

## As-built document (asbuilt-data.json)

`asbuilt-data.json` follows the table logic of the Prisma Access as-built document (SCM navigation: Prisma Access
setup, service connections, ZTNA, traffic steering, mobile users GlobalProtect / Prisma Access Agent, Explicit Proxy,
remote networks, IP addresses). Every entry names the heading the table stands under (plus parent heading / position
where needed) and has one of three shapes:

| type | content | example |
|---|---|---|
| `list` | `columns` + `rows` (an empty list gives "No data found for this table in the export") | service connection onboarding, administrators, internal DNS servers |
| `kv` | `values` label → value, optional `select` (row that identifies the table, e.g. `Region = Worldwide`) | infrastructure settings, routing, IP pools, network services per region |
| `matrix` | `columns` = profiles, `values` "parameter" → value per profile | GlobalProtect app settings (agent profiles), tunnel settings (tunnel profiles) |

Values follow the conventions of the document: `Not Configured`, `Prisma Access Default`, `Enabled` / `Disabled`;
`not in export` marks what the export does not contain (CSP account, licences, tenant name, ZTNA connectors, Cloud
Identity Engine). The document builder (claude.ai project, `templates/`) fills the as-built Word template with it:
load the template and `asbuilt-data.json`, document type *As-built*, output step.

## Secrets

The export redacts secrets; the report additionally masks every field named like a secret (password, pre-shared key,
API key, token, …) as `(secret)`. Pre-shared key lists (`psk-list.csv`) are never read.

## Open

* layout / wording aligned to the PANW maturity report once a sample is available
* customer output format (Word template / PDF)
