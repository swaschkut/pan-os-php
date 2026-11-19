# Alert-only and best-practice profiles driven by the BP JSON file

**Status:** proposal, not implemented
**Date:** 2026-11-01
**Code references:** `beta` `5575017d` (line numbers may move)
**German version:** `visibility-bp-json-driven-profiles.de.md`

## 1. Goal

The BP JSON file (`utils/api/v1/bp/scm_bp_sp_panw.json`, or a customised copy) should be the one place that decides what
"visible" (alert-only) and "best practice" mean for security profiles. Three things should follow from it:

1. **Create:** the `Alert-Only-*` profiles (and later `Outbound-*` / `Inbound-*` / `Internal-*`), e.g.
   `type=device actions=sp_spg-create-alert-only-bp`.
2. **Set:** existing profiles made visible, e.g. `type=securityprofile actions=spyware.alert-only-set`.
3. **Check:** filters such as `(object is.visibility)`, and the export (`exportToExcel`).

Today only step 3 reads the JSON file, so changing the JSON file changes the verdict but not what pan-os-php creates or
sets.

The JSON file must not be able to force a value that PAN-OS does not accept in a given version, licence or platform.
pan-os-php already encodes many such cases on purpose (section 4). They must be kept, and kept in one place.

## 2. Where we are

- **iron-skillet files removed** (`33239cc2`, `c7c0c3b5`): each object class builds its base profiles with
  `ironSkilletXml( $version )`, with the version differences as conditions in the code.
- **URL categories** (`cb9c2dc9`): `URLProfile::ironSkilletCategories()` reads `predefined.xml` (`<pan-url-categories>`),
  the same source the check uses. Categories come with the dynamic updates, not with PAN-OS, so the list is the same
  for every version. Custom categories are `Block` / `Allow` for every version.
- **Antivirus ML models** (patch `av-msoffice-shell-10.0`): `AntiVirusProfile::ironSkilletContentXml()` lists
  MSOffice and Shell from 10.0 (before: from 10.2, see G3). The versions stay visible in the class; they match
  `predefined.xml`.
- **Version comparison:** `URLProfile::ironSkilletCategories()` compares an iron-skillet version such as `"11.1"` as
  `"11.1.0"` against `minver` / `maxver`, as `version_compare()` ranks `"11.1"` below `"11.1.0"`.
- **Check tool:** `utils/develop/ironskillet/url_categories_check.php` (read-only) reports, per iron-skillet version, the
  predefined URL categories the URL profiles do not list.

## 3. Problem: the rules live in four places

| Step | Code | Reads the BP JSON file? |
|---|---|---|
| Create | `lib/object-classes/*Profile.php` `ironSkilletXml()`, called by `utils/common/actions-device.php` | no |
| Load | `lib/object-classes/trait/sp_action_{spyware,virus,wildfire}.php` `load_from_domxml_*()`, `URLProfile::load_from_domxml()` | no |
| Set | `utils/common/actions-securityprofile.php` `*.alert-only-set`, `*.best-practice-set` | only `virus.decoder.alert-only-set` (4159), `virus.inline-ml.alert-only-set` (4196), `url.best-practice-set` (6146) |
| Check | `lib/object-classes/SecurityProfile2.php`, the traits' `*_visibility()` / `*_best_practice()`, `is_visibility()`; also `exportToExcel` | yes |

**Note on "Load":** the loaders write PAN-OS defaults into the XML when an element is missing. For example, they add
`advanced-dns-security-categories` from 11.2, or `cloud-inline-analysis` `no` from 11.1. So a profile can change on load,
before any action runs.

### What the JSON `visibility` sections ask for

Most entries are conditions (`!value` = anything but this value), not values. That is enough to check, but not enough
to create or set.

| Type / section | `visibility` |
|---|---|
| virus / rule | `action`, `wildfire-action`, `mlav-action`: `!allow` |
| virus / cloud-inline | `inline-policy-action` (type `any`): `!disable` |
| spyware / rule | severities `any, critical, high, medium, low, informational`; `action`: `!allow` |
| spyware / dns | `log-level`: `!none` for `pan-dns-sec-` `adtracking, ddns, grayware, malware, phishing, proxy, recent, parked, cc` |
| spyware / advanced-dns | `log-level`: `!none` for `pan-adns-sec-dnsmisconfig, pan-adns-sec-hijacking` |
| spyware / lists | `default-paloalto-dns` `action`: `!allow` |
| spyware / cloud-inline | type `any`: `!allow`; `HTTP` and `HTTP2 Command and Control detector`: `local-deep-learning` `enable` |
| vulnerability / rule | severities as spyware; `action`: `!allow` |
| vulnerability / cloud-inline | type `any`: `!allow` |
| url / site_access | `!allow` |
| url / user_credential_submission | category `!allow`; mode `!disabled` |
| url / mica-engine | `local-inline-cat` `yes`, `cloud-inline-cat` `yes` |
| file-blocking / rule | `alert`: application `any`, filetype `any`, direction `both`, action `alert` |
| wildfire / rule | application `any`, filetype `any`, direction `both`, analysis `public-cloud` or `private-cloud` |
| wildfire / cloud-inline | application `any`, type `any`, direction `both`, action `!allow` |

## 4. PAN-OS behaviour pan-os-php already encodes (keep it)

These differences are deliberate: PAN-OS behaves differently in these versions, with or without a licence, or on SCM.
Today each one is written separately in several of the places above, and not always the same way.

The **`predefined.xml`** column shows what the file itself says about the version (`minver`). Where it says something,
it can be the source (section 6.1).

| # | PAN-OS behaviour | Create (`ironSkilletXml`) | Load | Set | Check | `predefined.xml` | Evidence |
|---|---|---|---|---|---|---|---|
| 1 | **WildFire inline ML:** none before 11.1; **11.1: the rule action cannot be `alert`, only `allow`**; `alert` from 11.2 | 11.1 `wf_inline_allow` / `allow`; from 11.2 `wf_inline_alert` / `alert`; Inbound/Internal `wf_inline_block` in 11.1 and 11.2 only | adds `cloud-inline-analysis` `no` from 11.1 (`sp_action_wildfire.php:57`) | `wildfire.inline-ml.alert-only-set` from 11.2 only, 11.1 commented out (5721–5783); `wildfire.inline-ml.best-practice-set` from 11.1 (5904, 5914) | before 11.1 `null`, **11.1 always TRUE** (`SecurityProfile2.php:238–240, 281–299`); `is_visibility` from 11.2 (`sp_action_wildfire.php:278`) | not in the file | CHANGELOG 2.1.57 "PAN-OS 11.1 - bugfix as wf mica-engine can not set for alerting"; 2.1.58 |
| 2 | **Anti-spyware inline ML** (C2 detectors) | all 5 detectors from 10.2 | adds missing Unknown-TCP/UDP detectors from 10.2 (`sp_action_spyware.php:111, 123`) | `spyware.inline-ml.alert-only-set` / `.best-practice-set` from 10.2 (4680 / 4300) | before 10.2 `null` (`SecurityProfile2.php:230`) | `mica-engine-anti-spyware minver="10.2.0"`; **HTTP, HTTP2, SSL `minver="11.1.0"`, Unknown-TCP/UDP `minver="11.0.0"`** (G8) | CHANGELOG 2.1.57 "add <cloud-inline-analysis> starting with PAN-OS 10.2" |
| 3 | **`local-deep-learning`** on the spyware detectors: from 11.2 | `enable` from 11.2 | adds `disable` from 11.2 (`sp_action_spyware.php:86, 113–132`) | not handled | **not checked** (`SecurityProfile2.php:218, 269` "todo: speciall now for LDL"), although the JSON asks for `enable` | not in the file | CHANGELOG 2.1.42 |
| 4 | **DNS security categories:** no action `alert`, visibility only through `log-level` | Alert-Only-AS: `allow` + `log-level default`; 10.0: 4 categories, from 10.1: 8 (no `pan-dns-sec-adtracking`, G11) | from 10.0 adds the 9 categories, `adtracking` included, with `default` (`sp_action_spyware.php:380–441`) | `spyware.dns.alert-only-set` (4761) | from 10.2 (`spyware_dns_security_visibility`, `sp_action_spyware.php:906`) | `pan-dns-security-categories minver="10.0.0"`, every category including `adtracking` `minver="10.0.0"` | — |
| 5 | **Advanced DNS security** (`pan-adns-sec-*`): from 11.2 | not in the profiles | adds both with `log-level default` from 11.2 (`sp_action_spyware.php:500–519`) | — | from 11.2 (`sp_action_spyware.php:948`) | not in the file | CHANGELOG 2.1.28, 2.1.43, 2.1.57 |
| 6 | **DNS security licence** | — | — | argument `has-DNS-license`: without a licence `allow`, `packet-capture disable`, **`log-level none`** (4778–4880) | does not know the licence | — | — |
| 7 | **SCM (Buckbeak):** anti-spyware without `botnet-domains` | `AntiSpywareProfile::ironSkilletXmlScm()` (11.1) | — | `spyware.dns.*-set`, `spyware.botnet.*-set` skipped (4375, 4473, 4775, 4919) | no special case | — | — |
| 8 | **Vulnerability inline ML:** from 11.0 | from 11.0 | — | `vulnerability.inline-ml.*-set` from 11.0 (5071/5081, 5195/5206) | before 11.0 `null` (`SecurityProfile2.php:200`) | `mica-engine-vulnerability minver="11.0.0"` | CHANGELOG 2.1.28 "only on PANOS version >=11.0" |
| 9 | **Antivirus ML models** (`mlav-engine-filebased-enabled`): from 10.0; `MachO`, `OOXML` from 11.1 | in the class (patch `av-msoffice-shell-10.0`): from 10.0 6 models including MSOffice, Shell; `MachO`, `OOXML` from 11.1 | adds `MSOffice`, `Shell` (`disable`) from 10.0, `MachO`, `OOXML` from 11.1 (`sp_action_virus.php:191–212`) | `virus.inline-ml.alert-only-set` reads the JSON, no version check (4179) | **before 10.2 `null`** (`SecurityProfile2.php:335`), should check from 10.0 | `mlav-engine-filebased-enabled minver="9.2.0"` (= 10.0); MSOffice, Shell without `minver`; `OOXML`, `MachO` `minver="11.1.0"` | Palo Alto: MSOffice from content 8434, Shell from content 8543, PAN-OS 10.x and later |
| 10 | **Antivirus decoders and `mlav-action`** | in the class: `http2` from 9.1, `mlav-action` from 10.0 | adds `mlav-action` `allow` from 11.1 when missing (`sp_action_virus.php:73`) | `virus.decoder.alert-only-set` reads the JSON (4159) | — | `http2 minver="9.0.0"`, `mlav-action minver="9.2.0"` | CHANGELOG 2.1.57 "virus.decoder.alert-only-set - bugfix for older PAN-OS version" |
| 11 | **URL inline categorisation** (`local-inline-cat`, `cloud-inline-cat`): from 10.2 | from 10.2 | adds `no` from 10.2 (`URLProfile.php:363, 373`) | from 10.2 (`URLProfile.php:884, 1145`) | — | `local-inline-cat minver="10.2.0"` | — |
| 12 | **URL ML engines** (`mlav-engine-urlbased-enabled`) | in 10.0 and 10.1: `Phishing Detection`, `Javascript Exploit Detection` | — | — | — | `Phishing Detection minver="10.2.0"` (G9) | — |
| 13 | **URL categories:** from the dynamic updates, not from PAN-OS | from `predefined.xml`, all versions (`cb9c2dc9`) | every predefined category starts as `allow` (`URLProfile.php:150–161`) | `url.*.alert-only-set` | against `predefined.xml` | `<pan-url-categories>` | Palo Alto: categories are visible on all PAN-OS versions and work from 9.1 |

## 5. Findings

| ID | Finding | Effect |
|---|---|---|
| G1 | `local-deep-learning` is created and loaded but not checked (#3) | a profile with `local-deep-learning disable` passes visibility, although the JSON asks for `enable` |
| G2 | Without a DNS licence `spyware.dns.alert-only-set` sets `log-level none` (#6); the check asks for `!none` and does not know the licence | after the action, the profile is not visible; the check should treat it as not applicable |
| G3 | **Done for create:** antivirus MSOffice / Shell exist from 10.0 (#9); the class now lists them from 10.0. **Open:** the check returns `null` before 10.2 | before, Alert-Only-AV and the BP profiles for 10.0 / 10.1 had MSOffice and Shell on `disable` (added by the loader); the check did not notice |
| G4 | `virus.inline-ml.alert-only-set` compares `$type == $mlav_engine_entry`, a string with a `DOMElement` (`actions-securityprofile.php:4204`) | JSON entries for one model name never match; only type `any` works |
| G5 | Most set actions do not read the JSON file (section 3) | a customised JSON file changes the verdict, not what the actions set |
| G6 | Version knowledge is repeated in up to four places, e.g. WildFire 11.1 in create, set (commented out) and check (#1) | a correction in one place is easily missed in the others |
| G7 | The loaders change the XML (section 3) | `out=` contains elements the input did not have, even when no action changed the profile |
| G8 | Spyware detectors: create, load and set add all 5 from 10.2; `predefined.xml` gives HTTP, HTTP2, SSL from 11.1.0 and Unknown-TCP/UDP from 11.0.0 (#2) | either the detectors had other names in 10.2, or pan-os-php adds detectors in 10.2 / 11.0 that PAN-OS does not know; to be confirmed |
| G9 | URL ML engine `Phishing Detection` is created for 10.0 / 10.1; `predefined.xml` gives it from 10.2.0 (#12) | same question as G8 |
| G10 | The classes build `Exception-*` profiles that no action creates: `Exception-AV` (8.1–10.1, `AntiVirusProfile.php:304`), `Exception-AS` (8.1–10.1, `AntiSpywareProfile.php:355`), `Exception-VP` with an empty `<rules/>` (10.0, 10.1, `VulnerabilityProfile.php:684`), `Exception-URL` as a copy of Outbound-URL (8.1–10.1, `URLProfile.php:1452`). `sp_spg-create-bp` creates only `Alert-Only`, `Outbound`, `Inbound`, `Internal`; `Exception` is commented out (`actions-device.php:3078/3079`) | dead code taken over from iron-skillet; their `<description>` elements are already removed (`294f7379`, `5575017d`) |
| G11 | DNS security category `pan-dns-sec-adtracking`: create (`AntiSpywareProfile::ironSkilletBotnetDomainsXml()`, `AntiSpywareProfile.php:279–312`) lists 4 categories in 10.0 and 8 from 10.1, without `adtracking`; `predefined.xml` gives it `minver="10.0.0"`; the loader adds it with `default` (`sp_action_spyware.php:380–441`); the JSON `visibility` asks for it (#4) | a created profile is only complete after loading; create and load disagree |
| G12 | Old iron-skillet 8.1 / 9.1 values kept in the classes: anti-spyware 8.1 sinkhole IPv4 `72.5.65.111` (later `sinkhole.paloaltonetworks.com`, `AntiSpywareProfile.php:282`); anti-spyware 9.1 list `default-paloalto-cloud` next to `default-paloalto-dns` (`AntiSpywareProfile.php:296`); URL 8.1 `<action>block</action>` directly in the profile (`URLProfile.php:1474`) | valid for these versions as far as known; background to be added |

## 6. Proposal: three layers

### 6.1 What PAN-OS can do (capabilities)

One place per profile type answers what exists and what is accepted, for a PAN-OS version, a licence and a platform.
This is the table in section 4, moved from the four places into code that all of them call. It would be, for example,
a static method per class:

```php
// sketch, names to be agreed
WildfireProfile::capabilities( '11.1', $options )
// => array( 'inline-ml' => array( 'available' => true, 'actions' => array( 'allow' ) ) )   // 11.1: no 'alert'
WildfireProfile::capabilities( '11.2', $options )
// => array( 'inline-ml' => array( 'available' => true, 'actions' => array( 'allow', 'alert', 'block' ) ) )
AntiSpywareProfile::capabilities( '11.2', array( 'dns-license' => false, 'scm' => false ) )
// => array( 'dns' => array( 'available' => true, 'licensed' => false, ... ), 'local-deep-learning' => true, ... )
```

Create, load, set and check ask this method instead of comparing `$version` themselves.

**Source of the capabilities:** `predefined.xml` first, wherever the file gives a version (`minver` / `maxver`). It is
the same file pan-os-php reads when loading and checking, and it is updated with the dynamic updates. This is already
done for the URL categories.

Where the versions should stay visible in the class, as decided for the antivirus decoders and models, the class keeps
them and `predefined.xml` is the reference a test compares them with.

| From `predefined.xml` (has `minver`) | Stays in the code (not in `predefined.xml`) |
|---|---|
| Antivirus: decoders (`http2`), `mlav-action`, ML models (#9, #10) | WildFire inline ML, including "11.1 only `allow`" (#1) |
| URL categories (#13), `local-inline-cat` (#11), URL ML engines (#12) | `local-deep-learning` (#3) |
| DNS security categories (#4) | Advanced DNS security (#5) |
| Spyware inline ML and detectors (#2) | DNS licence (#6), SCM (#7) |
| Vulnerability inline ML (#8) | |

Versions are compared with three parts (`"11.1"` as `"11.1.0"`), as in `URLProfile::ironSkilletCategories()`.

### 6.2 What is wanted (policy)

The BP JSON file, unchanged in format, customisable by the user: `visibility` for alert-only, `bp` for best practice.

### 6.3 From condition to value (resolution)

A function per profile type applies a JSON section to a profile, within the capabilities:

1. For each element the JSON names: if the version cannot have it, nothing is set and the element is "not applicable".
   The check returns `null` for it, as it does today, e.g. spyware inline before 10.2.
2. If the current value already meets the condition, it is kept. An existing `block` is never turned into `alert`.
3. Otherwise the first value that meets the condition **and** that the version accepts is set:

| Condition | Value set (default) |
|---|---|
| `action` `!allow` (rules, decoders, URL categories, `lists`) | `alert` |
| spyware / vulnerability `inline-policy-action` `!allow` | `alert` |
| wildfire inline `action` `!allow` | `alert` from 11.2; **11.1: only `allow` exists → not applicable** (today's "11.1 always TRUE") |
| virus inline `!disable` | `enable(alert-only)` |
| DNS `log-level` `!none` | `default`; without a DNS licence: not applicable (G2) |
| credential `mode` `!disabled` | `ip-user` |
| a fixed value (`yes`, `enable`, `alert`, `any`, `both`, `public-cloud`) | that value |

4. Which entries must exist comes from the JSON `type` lists; for URL categories and DNS categories from
   `predefined.xml`, for antivirus models from the class. It does not come from the base profile.
5. A section missing in the JSON file: nothing is set and nothing is checked (as decided for the vulnerability and
   anti-spyware rules: what the file does not ask for is not checked).

**Option (open):** a JSON section may carry concrete values to set, e.g. `"alert-only": { ... }` next to `visibility`.
They override the defaults above. When the file is loaded, pan-os-php checks that these values meet the section's own
`visibility` condition and the capabilities.

### 6.4 The three steps then

| Step | How |
|---|---|
| Create `Alert-Only-*` | base profile from the class (`ironSkilletXml()`, structure only), then the resolution with `visibility` |
| `*.alert-only-set` | the same resolution on the existing profile; the per-type logic in `actions-securityprofile.php` goes away |
| Check | `visibility` conditions; capabilities decide "not applicable" |
| Self-test | after create or set, `is.visibility` with the same JSON file must be TRUE, or `null` where not applicable |

Best practice works the same way with the `bp` sections and the `Outbound-*` / `Inbound-*` / `Internal-*` profiles.

## 7. Steps

1. **Review sections 4 and 5:** confirm each row, especially G8 to G12 and which version limits are still needed. Add rows that
   are missing (e.g. file blocking, data filtering, zone protection, log forwarding).
2. **Capabilities in code** (6.1), from `predefined.xml` first, with a test per version that compares them with today's
   behaviour.
3. **Check on capabilities:** `SecurityProfile2` and the traits ask the capabilities instead of `$version`. Close G1, G2
   and the open part of G3.
4. **Pilot URL:** resolution for `url` (site access, credential, mica-engine), used by `sp_spg-create-alert-only-bp`
   and `url.alert-only-set`.
5. **Anti-spyware:** rules, DNS, advanced DNS, lists, inline, `local-deep-learning`, licence, SCM.
6. **Vulnerability, antivirus (G4), WildFire, file blocking.**
7. **Best practice** with the `bp` sections.
8. **Remove** the version checks left in actions and loaders. Decide on G7 (loaders changing the XML).

**Tests for each step:** every version from 8.1 to 12.1 × the shipped JSON file and customised variants, i.e. a missing
section, a stricter value, and a value the version does not accept. Expected results:

- create, then check: visible;
- set on a profile that is not visible: visible afterwards;
- set on a best-practice profile: nothing downgraded.

## 8. Open questions

1. Defaults only (6.3), or also concrete values in the JSON file (`"alert-only": {...}`)?
2. How does pan-os-php know about the licence and platform when offline? Today they are action arguments
   (`has-DNS-license`). In API mode they could be read from the device.
3. G8 / G9: do the `minver` values in `predefined.xml` hold for the spyware detectors and `Phishing Detection`, or did
   older versions have the same functions under other names?
4. G7: should loading a configuration still add PAN-OS defaults to the XML, or only to memory?
5. Is 8.1 still supported for these actions?
6. G10: remove the unused `Exception-*` profiles from the classes, or keep them for a later action?
7. G12: background of the 8.1 / 9.1 values (to be added).
