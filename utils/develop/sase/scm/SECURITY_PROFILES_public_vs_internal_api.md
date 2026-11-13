# Security profiles: public SCM API vs. internal UI API

Comparison of `vulnerability-protection-profiles` and `wildfire-anti-virus-profiles` as returned by

* the **public** SCM API: `/config/security/v1/<type>?folder=…` (used by `scm_pa_export.php` and the
  `PanSCMAPIConnector` loader of pan-os-php)
* the **internal** UI API: `https://<ui-api-host>/api/config/v9.2/Objects/VulnerabilityProtectionSecurityProfiles` /
  `…/WildFireAndAntivirusSecurityProfiles?folder=…&type=cloud|container` (used by the SCM web UI; accepts the service
  account token – see `scm_internal_api_probe.php`, `scm_internal_api_get.php`)

Verified on a lab tenant (2026-11-13) with a custom profile in `Mobile Users Explicit Proxy` and the predefined
profiles `best-practice` (snippet `predefined-snippet`) and `web-security-default` (snippet `Web-Security-Default`).

## Result

The public API returns only a subset. Missing in the public API:

| UI section | internal API (PAN-OS structure) | public API |
|---|---|---|
| WildFire / AV – **Enforcement Actions** (per protocol: ftp, http, http2, imap, pop3, smb, smtp) | `decoder.entry[]`: `@name`, `action`, `wildfire-action`, `mlav-action` | **missing** |
| WildFire / AV – **WildFire Inline ML** (models) | `mlav-engine-filebased-enabled.entry[]`: `@name` (model, e.g. `Windows Executables`, `PowerShell Script 1`), `mlav-policy-action` (`enable`, `enable(alert-only)`, `disable`) | **missing** |
| WildFire / AV – **Inline Cloud Analysis** rules | `mica-engine-wildfire-rules.entry[]`: `@name`, `action`, `direction`, `application.member[]`, `file-type.member[]` | **missing** |
| WildFire / AV – Inline Cloud Analysis on/off | `cloud-inline-analysis`: `yes` / `no` | `cloud_inline_analysis`: `true` / `false` |
| WildFire / AV – rules | `rules.entry[]`: `analysis`, `direction`, `application.member[]`, `file-type.member[]` | `rules[]`: same fields (snake_case) |
| Vulnerability – **Inline Cloud Analysis** models | `mica-engine-vulnerability-enabled.entry[]`: `@name` (e.g. `SQL Injection`, `Command Injection`), `inline-policy-action` | **missing** (to confirm with a custom profile) |
| Vulnerability – Inline Cloud Analysis on/off | `cloud-inline-analysis` | **missing** (to confirm) |
| Vulnerability – rules | `rules.entry[]`: `severity.member[]`, `cve.member[]`, `vendor-id.member[]`, `category`, `host`, `action`, `packet-capture`, `threat-name` | `rules[]`: `severity`, `cve`, `vendor_id`, `category`, `host` (+ `action`, `packet_capture`, `threat_name` – to confirm) |

Example (custom profile `WF_AV_Sven`): public API → `rules`, `cloud_inline_analysis: true`, `description`;
internal API → additionally 7 `decoder` entries (`alert`, `smb` `reset-both`), 7 `mlav-engine-filebased-enabled`
models (`enable(alert-only)`) and 1 `mica-engine-wildfire-rules` entry.

Predefined profiles: the public API does not return `best-practice` for `snippet=predefined-snippet`; the internal API
returns it (`@plugin-predefined: yes`) with all sections.

## Identity

`@uuid` of the internal API **is** the `id` of the public API (same value for the same profile) → the two answers can
be merged per object without name matching.

## Format of the internal API

PAN-OS XML structure as JSON – directly convertible to the XML that pan-os-php reads for Panorama / firewall:

| JSON | XML |
|---|---|
| `"@name": "x"` | attribute `name="x"` |
| `"entry": [ {...} ]` | `<entry name="…">…</entry>` per element |
| `"member": [ "a", "b" ]` | `<member>a</member><member>b</member>` |
| `"action": { "reset-both": {} }` | `<action><reset-both/></action>` |
| `"cloud-inline-analysis": "yes"` | `<cloud-inline-analysis>yes</cloud-inline-analysis>` |
| `@loc`, `@snippet-loc`, `@type`, `@uuid`, `@plugin-predefined` | owner / meta data – not part of the profile XML |

`VulnerabilityProfile::load_from_domxml()` already reads `cloud-inline-analysis` and
`mica-engine-vulnerability-enabled`; the AV / WildFire profile class reads the PAN-OS `decoder` /
`mlav-engine-filebased-enabled` / `mica-engine-wildfire-rules` structure.

## Options

1. **Export** (`scm_pa_export.php area=config`): for these two types additionally read the internal API per container
   and add the missing sections to the exported objects (matched by `id` = `@uuid`) → export / compare complete.
   Sync stays limited to what the public API can write.
2. **pan-os-php loader** (`in=scm-api://…`): load these two types from the internal API and convert the entries to
   PAN-OS XML → `type=securityprofile`, best practice / visibility checks see the same data as for Panorama / firewall.

## Open

- A custom vulnerability profile with Inline Cloud Analysis models and rule actions – confirm which fields the
  public API returns.
- Public API owner of `best-practice` (snippet name).
- Write support of the public API for the missing sections (otherwise these sections are manual on the target tenant).
