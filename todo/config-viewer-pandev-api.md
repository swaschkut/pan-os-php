# config-viewer: read the APIs documented on pan.dev with the user's service account

**Status:** idea / requirement of Sven, 2026-11-21 - nothing built.
**Related:** [config-viewer-device-access.md](config-viewer-device-access.md) (personal keys, network allow list, import
read only), [json-object-model.md](json-object-model.md) (SCM schema), `lib/misc-classes/PanSCMAPIConnector.php`,
`type=scm-export`.

## Wish (Sven, 2026-11-21)

In the config viewer: with the **service account of the user** (personal key store entry `scm`: client id, client
secret, TSG) ask the APIs of Palo Alto Networks - **which APIs there are is given by pan.dev**, not by a list in
pan-os-php. Today the starting point is the Strata Cloud Manager developer guide (https://pan.dev/scm/docs/home/),
but pan.dev documents many more APIs.

## What pan.dev offers (looked up 2026-11-21)

* pan.dev is open source (GitHub `PaloAltoNetworks/pan.dev`, MIT); the reference pages are generated from **OpenAPI
  spec files** in its folder `openapi-specs` - the machine-readable source for "which APIs, which paths, which
  parameters, which server, which authentication". Each spec says when it was created (pan.dev: "This Open API spec
  file was created on …").
* **Strata Cloud Manager** (https://pan.dev/scm/docs/home/) - one common authentication (OAuth 2.0 client credentials
  of a service account, bearer token, scope = TSG):
  * Shared services: Tenancy, Identity and Access Management, Authentication, Subscription
  * Configuration management: SASE, NGFW, Cloud NGFW, ZTNA Connector, Prisma SD-WAN
  * Monitoring: Strata Insights, Aggregate Monitoring, Multitenant Notifications, Autonomous DEM
  * further in the navigation: Incidents, Posture, Advanced DNS Security Resolver, NGFW Operations, NGTS, Secure
    Agentless Access
* **Prisma SASE** (https://pan.dev/sase/api/): Tenancy, IAM, Authentication, Subscription, Activation, Aggregate
  Monitoring, Multitenant Notifications, Service Provider Interconnect, Prisma Browser for MSPs, SASE 5G, Configuration
  Orchestration, SSPM, Identity SSPM, MSP PayGo; Prisma Access Configuration, Prisma Access Insights 1.0 / 2.0 / 3.0,
  Prisma Browser Management, Service Status
* **Other products with their own authentication** (not the SCM service account): PAN-OS XML / REST API (the device
  itself - already in pan-os-php), Cloud NGFW for AWS, Strata Logging Service, AIOps BPA, Threat Vault, IoT, DNS
  Security, DLP, Email DLP, Prisma Cloud / Compute, Cortex XSOAR, Expedition, Prisma AIRS, Prisma SD-WAN legacy

## Proposal

1. **API catalogue from pan.dev** (installation, administrator - like the App-ID database):
   * download the OpenAPI specs of `openapi-specs` (GitHub, a fixed tag / commit, checked) or **upload** them (air
     gap); stored in the volume with date and source; updated on request, never by itself
   * from each spec: title, version, date, servers, security schemes, paths with method, parameters, response schema
   * the viewer shows the catalogue as a tree: product → API → path; only what the specs contain - nothing hard-coded
2. **Authentication from the spec**: every API whose security scheme is the SCM OAuth (client credentials) can be
   asked with the user's own `scm` entry (token for the TSG of the entry; the token is cached for its lifetime, never
   stored, never shown). APIs with another scheme (API key of Threat Vault, Prisma Cloud, …) are listed but greyed out
   until there is a key kind for them (new kinds in the key store, same rules: personal, encrypted, never returned).
3. **Read only** (decision of the device import: "dass keine falschen Daten raus gehen"):
   * only `GET` by default; the methods come from the spec
   * some read APIs are `POST` queries (e.g. insights / log queries) - **open:** an allow list of such query paths,
     reviewed one by one like `action-classes.json` (`reviewed`), never a generic POST / PUT / DELETE
4. **Ask an API** (project tab, like LDAP): choose path, fill the parameters of the spec (folder, limit, offset, …),
   run as a **run** (container, network only to the server of the spec and the auth host - allow list of the
   administrator, network switch of the project), result as JSON file of the run + table view; paging by the spec
   (`limit` / `offset`); rate limits of the SCM best practices respected (pause, retry-after)
5. **Results**: JSON files of the run (no secrets in them, the token never in run.log); optional: configuration APIs
   (SCM config) as a new version through the existing SCM import (`PanSCMAPIConnector` / `scm-export`) - the generic
   view does not replace the import, it shows everything else (tenancy, subscriptions, insights, incidents, posture …)
6. **Coverage report**: which paths of the SCM config specs pan-os-php already reads / writes (`PanSCMAPIConnector`
   types) and which not - a list to extend the SCM import from the specs instead of by hand

## Open decisions

* source of the specs: GitHub `openapi-specs` (which tag / branch), or the spec files linked on the pan.dev pages;
  air gap: upload of a bundle
* which `POST` query endpoints may be used read only (list per API, reviewed)
* key kinds for the APIs that do not use the SCM service account (which first?)
* the role of the service account decides what answers (IAM roles of SCM) - show a 403 per API as "no right", not as
  an error of the viewer
* store results only in the run, or also per project (history of e.g. subscriptions / licences over time)
