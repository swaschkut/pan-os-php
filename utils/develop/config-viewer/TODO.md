# config-viewer: open points

State 2026-11-21 (GitHub `alpha` up to `ddcbf3a7`). One list of everything still open for the config viewer; the
details stay in the todo files that are linked. Done points are struck out here only when they were listed before.

---

## 1. Viewer like PAN-OS

Todo: [todo/config-viewer-panos-style-edit.md](../../../todo/config-viewer-panos-style-edit.md)

### 1.1 Fields that can not be changed - a pan-os-php action is missing

| Type / field | Missing in pan-os-php |
|---|---|
| address: type, value of ip-range / fqdn / ip-wildcard | `value-set` / change of type (only `value-replace` for ip-netmask) |
| address, service, rule: description | `description-set` (today `description-delete` + `description-append`: two actions) |
| address group: remove a member, dynamic filter | `remove-member`, an action for the filter |
| service: protocol / port | `protocol-set`, `dstport-set` |
| service group: members | `add-member` / `remove-member` (none for service groups) |
| rule: URL category | `category-add` / `category-remove` |
| NAT: persistent dynamic IP, DNAT distribution, interface IP as an object | not in `snat-set` / `dnat-set` yet |
| zone: remove the zone protection profile | an action for it; yes / no fields show no current value |
| every field except descriptions and tag comments | `,` and `:` not possible (no aliases there) |

### 1.1b References pan-os-php does not count yet

* ~~certificate-profile / certificate~~ built 2026-11-22 (CertificateUsage): certificate profiles (GlobalProtect portal /
  gateway, IKE gateway, authentication, server profiles, management - every <certificate-profile>) and certificates
  (SSL/TLS service profile, IKE local certificate, GlobalProtect, SCEP, SSL decryption forward trust / untrust, root CA
  lists) - firewall configurations, templates, template stacks; certificate-profile has displayreferences / refcount
* open: SCM (folders / snippets) - CertificateUsage::link() is not called for Container / Snippet / DeviceCloud yet
* open: SSL/TLS service profiles: who uses them (management, GlobalProtect portal / gateway, captive portal, …) - the
  same way as certificate profiles

### 1.2 Types with the generic window only (read only)

| pan-os-php has change actions - only the window is missing | pan-os-php has no change action |
|---|---|
| EDL, schedule (name actions) | threats, threat rules, DNS rules |
| security profiles (61 actions, e.g. `alert-only-set`, `best-practice-set`) | virtual wires, routing |
| security profile groups (`securityprofile-set` / `-remove`) | IKE gateways, IPSec / GRE tunnels |
| log forwarding, application (create / delete / move) | GlobalProtect portals / gateways / tunnels |
| interfaces (`name-rename`, AE group) | interface management profiles |
| zone protection profiles (`alert-only-set`) | certificates, certificate profiles |
| device (38 actions) | SSL/TLS service profiles |
| static routes, IKE / IPSec crypto (delete only), DHCP (reservation) | |

Counted from [action-classes.json](action-classes.json), class `change`.

### 1.3 More

* ~~extra columns of exportToExcel in the list~~ built 2026-11-21 (Extra columns: NestedMembers, ResolveIP, rule
  summaries, best practice, …); open: the extra columns also in the object window

* **run.log in a window** - shown in the page (as the LDAP results), not only as a download
* **search text in the whole XML** (as `type=xpath`): exact / contains / regex; element names, values or attributes
  (`name=`); limited to a location / template; the hits with their XPath and a link to the object window
* more network / device types editable as soon as their actions are reviewed (`action-classes.json` `reviewed`)

### 1.3b Menu areas of PAN-OS still missing in the viewer (checked 2026-11-22)

Compared with the PAN-OS menus Objects / Policies / Network / Device (screenshots of Sven, PAN-OS 11.x).

**Objects**

| Area | pan-os-php today | Viewer: what is needed |
|---|---|---|
| Regions | in the AddressStore (`Region`, filter `object is.region`); only custom regions (with `<address>`) | menu entry type=address with `(object is.region)`; Addresses also with `!(object is.region)` |
| HIP Objects / HIP Profiles | loaded (`HipObjectsProfileStore` / `HipProfilesProfileStore`); `type=profile profiletype=hip-objects / hip-profiles` | menu entries type=profile + profiletype (as securityprofiletype) |
| Decryption Profile | loaded (`DecryptionProfileStore`); `type=profile profiletype=decryption` | as above |
| Custom Objects > Data Patterns | loaded (`DataObjectsProfileStore`, `<profiles><data-objects>`), not in `PROFILEUTIL::$profileTypeStores` | pan-os-php: profiletype `data-objects`; then menu entry |
| Custom Objects > Spyware / Vulnerability | not loaded: ThreatStore has only the predefined threats of predefined.xml; `<threats><spyware|vulnerability>` of shared / vsys / device group / container is not read | pan-os-php: load the custom signatures (Threat with "custom"), type=threat filter `object is.custom`, references (exceptions in profiles) |
| Security Profiles > DoS Protection | not loaded (`DoSProtectionProfile` in SecurityProfileStore with xpathRoot `XYZ`) | pan-os-php: load `<profiles><dos-protection>`, references from DoS rules; then profiletype |
| Dynamic User Groups | not loaded (only in ConfigObjectSplit / the container template) | pan-os-php: new class + store (filter on tags as a dynamic address group), references from rules (source user) |
| Authentication (objects) | not loaded (`<authentication-object>`, authentication enforcement) | pan-os-php: new class + store, references from authentication rules |
| Devices (objects, IoT device objects) | not loaded - not the same as the managed devices of type=device | pan-os-php: new class + store; low priority |
| more: GTP, SCEP, Packet Broker, SD-WAN Path Quality / SaaS Quality / Traffic Distribution / Error Correction | loaded (stores of VirtualSystem / Container), not in `type=profile` | add to `PROFILEUTIL::$profileTypeStores`; SD-WAN link management as a submenu |

SCM: the same areas exist in SCM (folders / snippets); for each one check on pan.dev the resource of the Config API
(regions, dynamic-user-groups, hip-objects, hip-profiles, decryption-profiles, authentication enforcement, data
patterns (DLP), custom spyware / vulnerability signatures, DoS protection) and add it to `SCM_RESOURCES` /
PanSCMAPIConnector (today hip-* and decryption are commented out there).

**Policies**

* Captive Portal was replaced by Authentication (PAN-OS 8.0): Captive Portal only for a configuration below 8.0, from
  8.0 on and for SCM only Authentication (the entry depends on the version of the configuration).
* Policy Optimizer (new app viewer, rules without app controls, unused apps, rule usage): live data of a device, not of
  the configuration - see 8b.

**Network**: almost complete. Missing: VLANs, Routing Profiles of the logical router (BGP, BFD, OSPF, OSPFv3, RIPv2,
Filters, Multicast), DNS Proxy, GlobalProtect MDM / Clientless Apps / Clientless App Groups, QoS, LLDP, GlobalProtect
IPSec Crypto, Monitor / QoS / LLDP profiles, SD-WAN Interface Profile - check which ones pan-os-php reads.

**Device** - the tab is still almost empty (Devices, Certificates, Certificate Profiles, SSL/TLS Service Profiles, the
button System settings). Plan: the menu like PAN-OS, the entries from what exists:

| PAN-OS entry | Source |
|---|---|
| Setup, High Availability, Administrators, Admin Roles, Access Domain, Password Profiles, Authentication Profile / Sequence, Log Settings, Server Profiles (LDAP, RADIUS, TACACS+, Kerberos, SAML IdP, Syslog, SNMP Trap, Email) | type=config-section (already there - as own menu entries instead of one button) |
| Certificates, Certificate Profile, SSL/TLS Service Profile | already there |
| SCEP | SCEPProfileStore (loaded) - profiletype `scep` |
| Virtual Systems, Shared Gateways | locations of the configuration; a list with the settings of each vsys |
| OCSP Responder, SSL Decryption Exclusion, SSH Service Profile, Response Pages, Server Profiles HTTP / Netflow / SCP / DNS / MFA, Local User Database (users, groups), Scheduled Log Export, User Identification, VM Information Sources, Data Redistribution, Device Quarantine, IoT Security | new config-section sections (read, later set) |
| Config Audit, Software, GlobalProtect Client, Dynamic Updates, Plugins, Licenses, Support, Master Key and Diagnostics, Policy Recommendation, Troubleshooting | not configuration: live data of a device (op commands, support file) - see 8b |

Monitor (logs, ACC, App Scope, reports, …): not part of the configuration; only live data (see 8b).

### 1.4 object-merger / rule-merger in the viewer

* ~~step 1~~ built 2026-11-21: tab **Merger** - object-merger, rule-merger, merger-possible-report as runs on a copy;
  the report as tables (merged, not merged with the reason) from `exportJSON` (pan-os-php `MergerReport`, the same
  data as the HTML of `exportCSV`); result as new version
* ~~Explain~~ built 2026-11-21: button **Explain** at rows refused by the effective-policy check (MergeSafety
  `lastDetail`: resolution per level before / after, members, simulated changes, cause in words)
* open: Explain for the other refusals of MergeSafety (unreplaceable user, textual EDL / profile users) - today only
  the effective-policy check carries the detail; Explain from the object window (where-used → "why not mergeable")
* ~~small variant~~ built 2026-11-21: **Result as new version** of a run = one commit on the history of the version
  it ran on (run + settings, per object `Merged:` / `Not-merged:`); the History of the object window shows it, also at
  the kept object of a merge
* open (big variant): **merger on the loaded version** - the merger runs in the worker on the memory as one change
  instead of a job on a copy: it appears in the change list (unsaved, with Undo / discard like every change), one
  commit with every merged / removed object and every reference that was replaced; the commit message per object as
  in the small variant (Merged / Not-merged with reason, Explain data); undo of the whole merge or of one merged object
  (git revert of its entries: the removed object back, its references back - only when nothing later touched them);
  a merge step in a playbook (today `*-merger` steps are refused); the report (merged / not merged / Explain) next to
  the change list instead of the run list; large configurations: progress and cancel in the worker (git step 3)
* open: members limited to locations (today the tab needs the whole configuration, like every run)
* open: playbook steps `*-merger` (refused today)
* pan-os-php: the single `xyz-merger` types deprecated in favour of `type=object-merger`
  ([todo/merger-deprecate-single-types.md](../../../todo/merger-deprecate-single-types.md), planned)

---

## 2. git on object level

Todo: [todo/config-viewer-panos-style-edit.md](../../../todo/config-viewer-panos-style-edit.md), "Changes with git,
on object level". Built: steps 1-3 and 4a.

* **step 4b - branches:**
  * import from a device on its own branch: the diff to the version = what changed on the device (drift); merged into
    the work with the merge driver, conflicts per field as "mine or the device's"
  * a branch per user: today all members change the same memory (one change list) - decide first whether it is
    wanted (a worker per user, or a merge of the change lists when saving)
  * objects of templates (Network / Device) as entries of their own (today in `_rest.xml`: no history / merge of
    their own)
* a version recovered from the autosave file, or made by a run (playbook, plug-in), starts a new history without the
  commits before
* undo only for unsaved changes of the loaded version
* an undo of a large configuration takes as long as opening the version (pan-os-php loads again)
* `history.git` holds the configuration like the version files - part of the encryption topic (5.)

---

## 3. APIs documented on pan.dev, with the user's service account

Todo: [todo/config-viewer-pandev-api.md](../../../todo/config-viewer-pandev-api.md) - idea, nothing built.

* catalogue from the OpenAPI specs of pan.dev (GitHub `PaloAltoNetworks/pan.dev`, folder `openapi-specs`), download
  or upload (air gap) - which APIs exist is given by pan.dev, not by pan-os-php
* with the SCM service account (personal key store entry `scm`): SCM (tenancy, IAM, subscription, configuration
  SASE / NGFW / Cloud NGFW, insights, monitoring, incidents, posture, ADEM, …) and Prisma SASE
* other products with their own authentication (Threat Vault, Prisma Cloud, IoT, DNS Security, …): listed, greyed out
  until there is a key kind for them
* read only: `GET` and reviewed `POST` queries; as a run with network to the server of the spec only
* coverage report: which SCM configuration paths the SCM import reads already, which not
* open decisions: source / version of the specs, allow list of `POST` queries, which other key kinds first, 403 shown
  as "no right of the role", results only in the run or also in the project

---

## 4. Access to devices

Todo: [todo/config-viewer-device-access.md](../../../todo/config-viewer-device-access.md)

| # | Open |
|---|---|
| A | writing to a device (`out=api://`, `type=upload`, `config-commit`): own administrator switch "write to devices" (off), per project, maybe per user; review step (diff / set commands first), audit; never by a playbook |
| B | set commands per SSH (`type=ssh-connector`): personal SSH credentials as a new key kind; the same switches as A |
| C | firewall through Panorama (`api://<serial>@<panorama>`) |
| D | API key from user + password (`type=key-manager`); needs network from the web part |
| E | network limited to the targets for real: today the viewer checks the allow list; a docker network with egress rules would be stronger |
| F | encryption of the key store (the key of the installation lies in the volume today) |
| G | more named entries for runs, e.g. `bpa-apikey` for bpa-generator |
| H | DNS servers per project and per user: FQDN address objects, LDAP (finding the domain controllers), device names of an import; order user / project / installation to decide; a run that only resolves gets network for DNS only (port 53); run.log names the DNS servers used. Today: installation-wide `VIEWER_RUN_DNS` only |

---

## 5. Data at rest

Todo: [todo/config-viewer-encryption.md](../../../todo/config-viewer-encryption.md) - analysis done, no decision,
nothing built.

* today everything in the volume is plain text (database, projects, working copies, now also `history.git`); a
  Docker administrator can read it all
* to decide: encryption in the viewer bound to administrators or per project; emergency data key (offline); backup
  command `./panosphp-viewer backup` (encrypted file)

---

## 6. Limits per run

Todo: [todo/config-viewer-run-limits.md](../../../todo/config-viewer-run-limits.md) - idea, not built.

* memory, CPUs, time per run set by an administrator in the browser instead of `.env`; stored in the viewer, read
  before every run (no restart)
* upper bound from `docker info` / `VIEWER_RUN_MEMORY_MAX`; `.env` stays the default

---

## 7. Licences and migration

* **licences** ([todo/config-viewer-license.md](../../../todo/config-viewer-license.md)): ~~`keygen`~~ done (public
  key `sven-2026` in `lib/resources/license/keys.json`); open: packages into the air-gap bundle, the licence of the
  first customer; decision 6 (encrypted plug-ins)
* **migration** ([todo/config-viewer-migration.md](../../../todo/config-viewer-migration.md)): requirements and design
  only, several decisions open; first vendor Cisco switch / ISR; online inputs need secrets at rest and network

---

## 8. API of the viewer

Todo: [todo/config-viewer-api.md](../../../todo/config-viewer-api.md)

* types without objects (mergers, `diff`, SCM types, …) only through jobs
* container per worker (decision 2, second part)
* Podman
* secrets at rest
* `tool.php` behind the login
* errors as HTTP status

---

## 8b. Public PANW data, support portal, live data of a device

Todo: [todo/config-viewer-panw-data-and-live.md](../../../todo/config-viewer-panw-data-and-live.md) - list of Sven,
2026-11-21, nothing built.

* public data as tables with filters: EoL, release notes of the PANW products, CVE, firewall compare (front / back
  panel, documentation link, ports copper / fibre for a migration), IANA protocol numbers (admin)
* support portal with the user's login (2FA): serials per CSP account, search, register with auth codes (batch,
  address), licences per serial - official API / terms of use to check first
* live data (read only, personal key): session-browser (through Panorama?), system / traffic / threat log,
  custom-report, xml-op-json

---

## 9. Other

* **IronSkillet 12.2** ([todo/ironskillet-url-http-header-logging-12.2.md](../../../todo/ironskillet-url-http-header-logging-12.2.md)):
  URL HTTP header logging - the XML element names are not known yet
* **LDAP:** the query failed at the TLS handshake with a domain controller that was not available at that time - hence
  the automatic choice of the server from DNS; to check on the real installation that another DC answers now
* ~~Effective view of a location~~ built 2026-11-22: Location + "+ parents (effective view)" (<location>:effective) -
  the levels from shared / All down to the location (SCM: with the snippets of each folder), column level and
  effective (used / overridden by <location>), hidden copies struck through; Panorama: the nearest copy wins, with
  "ancestor-objects-take-precedence" the highest; SCM: the nearest (no ancestor precedence in SCM; of two snippets
  the first attached wins - the order of attachedSnippets is used). Addresses / services / tags: which copy
  wins is the lookup of pan-os-php itself (store find of the location: an EDL before region / address group /
  address of the same name, parents, snippets, predefined; ancestor precedence: PH::resolveNameForFirewalls); other
  types: the nearest level.
* ~~Variables of firewalls~~ built 2026-11-22 (variable-set / variable-remove, DeviceVariables, section Variables).
  Open: API mode (in=api:// / scm-api://: send the change), scm_pa_xml_to_change.php for changed variables, the
  variables a template stack inherits on Panorama in a vsys of a template (only template level is read)
* **System information** - step 1 built 2026-11-22: "System settings" (read only) from the config sections
  (management, system, HA, administrators, password complexity, access domains, admin roles, authentication profiles
  / sequences, server profiles, log settings; SCM NGFW device settings loaded from /config/device/v1). Next: changes
  per section (config-section set / add-member, reviewed per section), the effective SCM value (folder chain as for
  variables), Panorama template stack: the settings of its templates combined, a firewall vsys of a template.
  The original plan:
* **System information of a firewall / Panorama / SCM tenant** (wish 2026-11-22) - a view "System" in the viewer
  (read first, changes later), built on type=config-section (generic, registry utils/common/config_sections.json) so
  that the CLI shows the same:
  - in pan-os-php today: PanoramaConf / PANConf read only rule-require-audit-comment, ancestor-objects-take-precedence,
    wildfire public-cloud-server (+ firewall: advance-routing, timezone); type=device actions=system-mgt-config_users
    lists the local administrators (text only); config-section: deployment-update-schedule,
    config-bundle-export-schedule, permitted-ip; type=master-key (master key / encrypted values); certificates
  - missing (to add as config sections, shown in the viewer as "System"):
    * management settings: ancestor precedence, audit comment, shared objects / commit options, idle timeout,
      login banner, password complexity, max sessions / lockout (deviceconfig/setting/management, mgt-config/password-complexity)
    * administrators: mgt-config/users (role, profile / access domain, authentication profile, public key - never the
      password hash), admin roles, access domains (Panorama), authentication profiles / sequences, server profiles
      (LDAP, RADIUS, TACACS+, SAML, Kerberos) of the device
    * system: hostname, management IP / netmask / gateway, DNS, NTP, timezone, domain, login banner, update server,
      Panorama servers of a firewall, HA (high-availability), log settings / syslog / SNMP / email server profiles,
      service route, permitted IP (exists)
    * dynamic updates schedules of a firewall (deviceconfig/system/update-schedule), content versions
    * SCM: tenant settings of the setup API (/config/setup/v1: folders, snippets, devices, labels, variables - the
      first ones are read), device settings (/config/device/v1 ...: to check on pan.dev which ones exist)
  - viewer: a menu entry "System" with the sections as read-only windows; secrets (hashes, keys, PSK) never shown;
    then changes through config-section set / add-member (reviewed per section in action-classes.json)

* **SCM tab** (concept 2026-11-22: SCM_TAB.md) - a tab SCM per project (one tenant / TSG): Prisma Access (egress IP,
  infrastructure, service connections, remote networks, mobile users GlobalProtect / PAA / gateway, explicit proxy,
  Prisma Browser), Identity & Access (service accounts), CIE, config versions + push status, variables, deployment
  (locations, bandwidth, BGP, traffic steering), trusted tenants, licences / instances, insights, audit logs, BPA.
  Data: import of a scm_pa_export directory (versioned), live refresh per page with the personal key, compare of two
  states; later an as-is report. Changes only through change files + review per area + live compare right before the
  upload (conflicts, e.g. an address of the same name created meanwhile) + scm_pa_change.php - never directly.
  Built: egress IP on the CLI (scm_egress_ip.php, SCMEgressIP) and the tab SCM with Prisma Access > Egress IP (import,
  live run egress-ip, compare) and Prisma Access > Infrastructure (states from the SCM import - area=config,infra - and
  live run scm-pa, View / Compare with scm_pa_compare.php), Service Connection, Remote Networks, Mobile User Gateway /
  GlobalProtect / PAA / Explicit Proxy, Prisma Browser, Service accounts (SCM_PA_PAGES); the egress-IP API key of the
  SCM API into the key store of the user; the egress IPs with the import (egressip, env auto). Open: ui-api-host
  per project (region of the internal UI API), CIE, config versions, deployment, tenant, monitoring, BPA.
