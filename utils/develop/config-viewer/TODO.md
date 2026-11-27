# config-viewer: open points

State 2026-11-21 (GitHub `alpha` up to `ddcbf3a7`). One list of everything still open for the config viewer; the
details stay in the todo files that are linked. Done points are struck out here only when they were listed before.

---

## 1. Viewer like PAN-OS

Todo: [todo/config-viewer-panos-style-edit.md](../../../todo/config-viewer-panos-style-edit.md)

### 1.1 Fields that can not be changed - a pan-os-php action is missing

State 2026-11-25 (`alpha` up to `405cac7a`).

| Type / field | Missing in pan-os-php |
|---|---|
| NAT: persistent dynamic IP, DNAT distribution, interface IP as an object, service, destination interface, NAT type | not in `snat-set` / `dnat-set` yet |
| zone: remove the zone protection profile, user-ID ACLs (include / exclude) | an action for them; yes / no fields show no current value |
| security profiles: data filtering, DNS security (SCM), virus-and-wildfire-analysis (SCM), action block-ip (track by / duration) | not in `detail-entry-*` yet |
| other rule types: PBF, decryption, application override, authentication, DoS, QoS, tunnel inspection, SD-WAN | their own fields (actions of type=rule for the common fields only) |
| interface: mode (layer3 / layer2 / virtual wire / tap), IPv6 | an action for them |
| routing protocols (BGP, OSPF, RIP, multicast, redistribution) | none |
| every field except descriptions and tag comments | `,` and `:` not possible (no aliases there; central textAliases for every action, IPv6) |

Built 2026-11-24 (common actions `utils/common/actions-common.php`): ~~address `value-set` (every type, also the change
of type)~~, ~~`description-set` (address, service, rule, tag, …)~~, ~~address group / service group `add-member` /
`remove-member`~~, ~~service `protocol-set` / `dstport-set`~~, ~~rule `category-add` / `category-remove` /
`category-set-any`~~, ~~zone `interface-add` / `interface-remove`~~, ~~`name-rename` of the network types (references
renamed)~~, ~~network types: interface, zone protection, interface management profile, IKE / IPSec, GRE, DHCP, virtual
wire, routing, static route, GlobalProtect portal / gateway (field actions)~~; read only for good: tmp objects,
predefined objects (location `predefined`), GlobalProtect gateway tunnels, threats, threat rules, DNS rules.
Built 2026-11-25: ~~EDL `type-set`, `source-set`, `recurring-set`, `description-set`, `certificate-profile-set`,
`exception-add` / `-remove`, `expand-domain-set`, `name-rename`~~, ~~schedule `range-add` / `range-remove` / `type-set`,
`name-rename`~~, ~~log forwarding `match-add` / `-remove` / `-set`, `match-send-add` / `-remove`, `description-set`,
`enhanced-application-logging-set`, `name-rename` (rules / zones)~~, ~~security profiles `detail-entry-add` / `-remove` /
`-set` (antivirus decoders / exceptions, anti-spyware and vulnerability rules / threat exceptions / DNS categories,
file blocking and WildFire rules), `detail-option-set`, `url.credential-action-set`~~ (`SecurityProfileFields`).

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
| ~~EDL, schedule~~ windows built 2026-11-25 | certificates, certificate profiles |
| ~~security profiles~~ window built 2026-11-25 (Details) | SSL/TLS service profiles |
| ~~security profile groups~~ window built 2026-11-25 (Details: one profile per type) | |
| ~~log forwarding~~, ~~application~~ windows built 2026-11-25 (application: create of a custom app / group / filter still open) | |
| device (41 actions) | |

Built 2026-11-24: windows of the network types (interfaces, zone protection / interface management profiles, IKE /
IPSec, GRE, DHCP, virtual wires, routing, static routes, GlobalProtect). Read only for good (no window to change):
threats, threat rules, DNS rules, GlobalProtect gateway tunnels.

Counted from [action-classes.json](action-classes.json), class `change`.

### 1.3 More

* ~~extra columns of exportToExcel in the list~~ built 2026-11-21 (Extra columns: NestedMembers, ResolveIP, rule
  summaries, best practice, …); open: the extra columns also in the object window

* **run.log in a window** - shown in the page (as the LDAP results), not only as a download
* **search text in the whole XML** (as `type=xpath`): exact / contains / regex; element names, values or attributes
  (`name=`); limited to a location / template; the hits with their XPath and a link to the object window
* more types editable as soon as their actions are reviewed (`action-classes.json` `reviewed`)
* NAT -> security (built 2026-11-25, `NatSecurityMatch`, NAT rule window): open - SCM (containers / snippets), IPv6
  NAT rule types (nat64, nptv6), the vendor knowledge of the migration (private plug-in `pan-os-php_migration`)
* **XML view in general: fold every large part** (wish 2026-11-25) - today an XML of more than 20 lines can be folded
  down to the 2nd level only; wanted: every element whose content is larger than about 30-40 lines can be folded, on
  every level (e.g. one interface, one router, one static-route list), with expand / collapse all
* **Virtual / logical router window: static routes** (wish 2026-11-25)
  - show the existing static routes of the router clearly: one table (name, destination, next hop type / value,
    interface, metric, admin distance, route table, BFD / path monitor), for a logical router per VRF
  - per static route a link to its own window (type=static-route) to change it
  - remove a static route from the router window (per row)
  - "add static route": the fields are shown, but there is no button to add more - today only one route per change;
    wanted: a button "+ static route" for several new routes in one change (each row checked before it is sent)

### 1.3b Menu areas of PAN-OS still missing in the viewer (checked 2026-11-22)

Compared with the PAN-OS menus Objects / Policies / Network / Device (screenshots of Sven, PAN-OS 11.x).

**Objects**

| Area | pan-os-php today | Viewer: what is needed |
|---|---|---|
| ~~Regions~~ | built 2026-11-25: type=region (custom and predefined), menu entry "Regions" with a window | - |
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

## 8c. Administration: certificate, login with LDAP / Entra ID (wish 2026-11-25)

* **Install a certificate in the admin area** - today the HTTPS certificate is set only with `setup` / `.env`
  (Caddy's own CA, `VIEWER_CERTS` with `cert.pem` + `key.pem`, Let's Encrypt). Wanted: Account → Administration →
  Certificate (administrator only):
  - upload PEM (certificate + chain, private key - also encrypted with a passphrase) or PKCS#12 (`.p12` / `.pfx`)
  - checks before it is used: key matches the certificate, chain complete, not expired / not yet valid, the DNS name
    of the viewer in the SAN, key size / algorithm; show subject, issuer, SAN, validity, fingerprint
  - the proxy (Caddy) takes it over without a restart (reload); the previous certificate is kept for a roll back
  - also a CSR from the viewer (key created on the server, never leaves it) for a company CA
  - the private key is stored encrypted, never returned to the browser, never in the audit log; the audit log names
    the change (who, when, fingerprint); a warning to the administrators some days before it expires
  - air gap: no internet needed; Let's Encrypt stays a `setup` choice
* **Login with LDAP / Active Directory** (users of the viewer - not the LDAP tab of a project, which asks the
  customer's directory with the personal account):
  - server(s), LDAPS / StartTLS (CA certificate to trust, uploaded as above), base DN, bind (service account, stored
    encrypted) or direct bind with the user's UPN, user filter
  - group → role mapping (administrator / user; project membership stays in the viewer), nested AD groups
  - the user is created at the first login (just in time); disabled / removed in the directory: no login; the
    password is never stored in the viewer
  - a local administrator always stays (break glass), also when LDAP is not reachable; login lock (5 failures) and
    audit log as for local users
* **Login with Microsoft Entra ID** (OpenID Connect, authorization code flow with PKCE):
  - tenant ID, client ID, client secret or certificate (stored encrypted; the certificate from the admin area),
    redirect URI of the viewer
  - group / app-role claims → role mapping as for LDAP; MFA / conditional access stay with Entra ID
  - same rules: local break-glass administrator, users created at the first login, audit log
  - later maybe generic OIDC / SAML (Okta, ADFS, …)
* API tokens and the personal API keys (key store) stay as they are - they are not replaced by the directory login.

## 8d. Entra ID queries of a user, as the LDAP queries (wish 2026-11-27)

The LDAP tab asks the customer's directory with the personal LDAP account of the user. The same is wanted for
**Microsoft Entra ID** (Microsoft Graph) - many customers have their users and groups only there. Not built.

* **What the user can do - as with LDAP:**
  - saved queries per user, project tab next to LDAP, result in the page and as JSON / CSV
  - the modes of `type=ldap-query`: validation (do these users exist, are they enabled), user-groups, common-groups,
    group-members (also nested: `transitiveMemberOf` / `transitiveMembers`)
  - the check of the users of the rules (as `user-check-ldap`): users / groups of the security rules that do not
    exist or are disabled in Entra ID, with the optional remove into a new version
* **pan-os-php:** one implementation for CLI and viewer - `type=entra-query` (and a rule action as
  `user-check-ldap`), read only (GET): `/users/<upn>`, `/users/<id>/memberOf`, `/users/<id>/transitiveMemberOf`,
  `/groups/<id>/members`, `/groups/<id>/transitiveMembers`, `accountEnabled`; paging (`@odata.nextLink`), throttling
  (HTTP 429, `Retry-After`); values in `$filter` escaped
* **Login: device code flow, with the user's own account** - no password of the user in the viewer, MFA and
  conditional access stay with Entra ID:
  1. the run asks `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/devicecode` for a code
  2. the page shows the code and the address `https://microsoft.com/devicelogin` to the user who started the run
     (only to him); he signs in in his browser
  3. the run polls `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token` (interval and expiry as the answer
     says, about 15 minutes) and then asks `https://graph.microsoft.com/v1.0/…`
  - `<tenant>`: the tenant ID / domain of the customer, or `organizations`
* **Which client ID:**
  - without an app registration: the public client of Microsoft "Microsoft Graph Command Line Tools"
    (`14d82eec-204b-4c2f-b7e8-296a70dab67e`, the one of the Graph PowerShell SDK) - works in a tenant as long as the
    administrator has not blocked it; good for a first test
  - with an app registration of the customer (public client, device code flow allowed): client ID per installation
    or per project - the way for regular use, the Entra administrator can limit and review it
  - both selectable; the viewer says in the page which one a query uses
* **Permissions (delegated, least privilege - to check on a real tenant, e.g. with the Graph Explorer):**
  - own groups: `User.Read` (`/me/memberOf`)
  - other users and group members: `User.ReadBasic.All` / `User.Read.All`, `GroupMember.Read.All` - these usually
    need the consent of an administrator; the page must say clearly "consent of the administrator is missing"
    (error `AADSTS65001` and friends) instead of a plain failure
  - never a write permission
* **Secrets:** the refresh token (`offline_access`) is a personal key of the user (new key kind, e.g. `entra`, target
  = tenant), stored encrypted, never returned to the browser, never in the audit log or in run.log; the access token
  lives only in the run; "sign out" deletes the stored token; without a stored token every query starts with the
  device code
* **Network:** a run with network, as the LDAP runs - admin switch, project switch, allow list; the targets are
  `login.microsoftonline.com` and `graph.microsoft.com` (national clouds: `login.microsoftonline.us` /
  `graph.microsoft.us`, `login.partner.microsoftonline.cn` / `microsoftgraph.chinacloudapi.cn`) and nothing else
* **Names:** the rules of a firewall name users and groups as the group mapping / Cloud Identity Engine writes them
  (`domain\user`, UPN, group DN or CIE group name) - which Entra attribute fits (`userPrincipalName`,
  `onPremisesSamAccountName`, `onPremisesDistinguishedName`, `displayName`) is a choice of the query, as the
  attribute of an LDAP query
* **Not the same as the login to the viewer** with Entra ID (8c, OpenID Connect): that one signs the user in to the
  viewer; this one asks the customer's directory, which can be another tenant. An app registration can serve both.
* **Tests:** a stand-in for the two Microsoft servers with synthetic answers (device code, token, Graph pages,
  429, missing consent); no data of a real tenant in the repository
* **Open:** how long a stored refresh token may be used (Entra: 90 days sliding by default, the customer's policy
  can be shorter); whether the device code flow is blocked by conditional access at customers (Microsoft recommends
  to restrict it) - then only the customer's own app registration with another flow helps

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
  SCM API into the key store of the user; the egress IPs with the import (egressip, env auto); binding of a project
  (PAN-OS / one SCM TSG), "From the SCM imports", "Read all live". Open: ui-api-host
  per project (region of the internal UI API), CIE, config versions, deployment, tenant, monitoring, BPA.
* ~~scope of the SCM import~~ built 2026-11-22. Project types between two systems (tenant migration, tenant sync,
  Panorama → SCM): plug-in scm-migration (private) - here only the plug-in interface v2 (data driven forms / tables /
  approval steps) they need.
