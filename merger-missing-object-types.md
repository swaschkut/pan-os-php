# Missing object mergers – overview

**Status:** planning, no patch started
**Code reference:** `beta` `43fd067`

## Existing mergers

`address-merger`, `addressgroup-merger`, `service-merger`, `servicegroup-merger`, `tag-merger`,
`custom-url-category-merger`, `securityprofile-merger` (`profiletype=any|virus|spyware|…`),
`securityprofilegroup-merger`.

`rule-merger` and `html-merger` are a different kind of tool and not part of this list.

## How the list was built

From the object stores of a device group (`DeviceGroup.php`). "References tracked" means that
pan-os-php records on load which rules and groups use an object. A merger needs this to point those
users to the kept object.

## A. Objects used directly by rules (the actual need)

| # | Object | Store | Used by | References tracked / replaceable | Comparison | Effort |
|---|---|---|---|---|---|---|
| 1 | Schedule | `scheduleStore` | security, QoS, DoS, PBF rules | yes / yes via `RuleDirectReferences`, **not yet for PBF rules** | XML via `XmlCompare` | small |
| 2 | Log forwarding profile | `LogProfileStore` | rules (`log-setting`), zones in templates | yes / yes (rules) | XML | small |
| 3 | Decryption profile | `DecryptionProfileStore` | decryption rules | yes / yes | XML | small |
| 4 | EDL | `EDLStore` | address fields in rules and groups; URL category in rules and URL profiles | through the rule containers | name + type + URL | medium, needs a content model in MergeSafety |
| 5 | Application group / application filter / custom application | `appStore` | `AppRuleContainer`; groups contain applications | yes / yes through the containers | group: members; filter: criteria; custom app: XML | medium to large; the group runs on the group engine |
| 6 | HIP object / HIP profile | `HipObjectsProfileStore`, `HipProfilesProfileStore` | security rules (`source-hip` / `hip-profiles`) | **no**, the rule only keeps the XML | XML | larger: reference tracking in `SecurityRule` first |
| 7 | Custom region | `Region` objects | address fields | to be checked | value | small to medium |

## B. Remaining profile types

| # | Object | Store | Note |
|---|---|---|---|
| 8 | DNS security, virus-and-wildfire-analysis, SaaS security | Fawkes / SCM (`DNSPolicyStore`, `ThreatPolicyStore`, …) | further `profiletype` values of `securityprofile-merger`; SCM only |
| 9 | Data objects (data patterns) | `DataObjectsProfileStore` | used by data-filtering profiles, not by rules |
| 10 | GTP, SCEP, packet broker, 4× SD-WAN profiles | one `…ProfileStore` each | niche types; references and replacement still to be checked |

## C. Not merger candidates

Zones and interfaces are template configuration and stay out of scope.
Dynamic user groups are not modelled as objects in pan-os-php yet.

## D. Template objects: duplicate report first (certificates, certificate profiles, SSL/TLS service profiles)

These live in Panorama shared, templates (shared and vsys) and template stacks. Merging needs a
different logic (template stack order, overrides in the stack, references outside the rulebase),
so the first step is a read-only search: in which templates / template stacks do objects with the
same name or the same value exist?

| Object | Modelled in pan-os-php | Locations loaded | References tracked | Value for "same value" |
|---|---|---|---|---|
| Certificate | yes (`Certificate`, `CertificateStore`, `type=certificate`) | Panorama shared, template, template stack, firewall shared / vsys | only decryption rules | certificate body / public key (fingerprint); additionally common name, validity, private key present yes/no |
| SSL/TLS service profile | yes (`SSL_TLSServiceProfile`, `SSL_TLSServiceProfileStore`) | to be checked per location | no | XML via `XmlCompare` (certificate name resolved to its fingerprint) |
| Certificate profile | **no class yet** | – | no | XML via `XmlCompare` (CA certificate names resolved to their fingerprints) |

Report per object type:

* same name, same value: duplicate, candidate for moving to a common template or Panorama shared
* same name, different value: conflict; flagged when both are in the same template stack (the
  stack order decides which one a firewall gets)
* different name, same value: duplicate under another name

Output: console, `exportCSV` (HTML). No change to the configuration.

## Proposed order (one patch each)

1. Schedule, log forwarding profile and decryption profile together: one util with `objecttype=`
   (like `profiletype=`), following the security profile merger (samename / samevalue, `XmlCompare`,
   MergeSafety). PBF rules get schedule replacement at the same time.
2. EDL
3. Application group, application filter and custom application
4. Custom region
5. HIP object and HIP profile, after adding reference tracking in `SecurityRule`
6. Group B only when needed
7. Group D: duplicate report for certificates, SSL/TLS service profiles and certificate profiles
   (certificate profiles need a class and store first)

## Open decisions

* Item 1: one merger with `objecttype=`, or three separate types (`schedule-merger`,
  `logprofile-merger`, `decryptionprofile-merger`)?
* Order: keep as proposed, or drop items from the list?
* Group D: one report util with `objecttype=certificate|ssl-tls-service-profile|certificate-profile`,
  or an action in the existing `type=certificate` / `type=ssl-tls-service-profile` utils?
