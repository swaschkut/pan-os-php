# Config viewer: licences (editions and features)

**Status:** decisions taken 2026-11-20, nothing built yet. **On hold (Sven, 2026-11-20):** the open decision on the strength (6) is postponed - do not build before it is taken.
**Related:** [config-viewer-api.md](config-viewer-api.md)

## Decisions (Sven, 2026-11-20)

| # | Topic | Decision |
|---|---|---|
| 1 | Customers | run **air-gapped**: no online check, no licence server; everything must work from a file |
| 2 | Basic | **everything built until today** (viewer, API, tokens, grants, runs, audit log, HTTPS) - works without a licence |
| 3 | Licensed features | future work, each one a feature name: `migration`, `cdss`, more to come |
| 4 | Bound to | the **customer** only (name in the licence) - not to an installation, not to a number of users |
| 5 | Withdraw | no immediate withdrawal offline; see "Withdraw" below |
| 6 | Strength (proposal, not yet confirmed) | step 1: signed licence file checked in the open code; built so that step 2 (licensed features as a separate, not public add-on) fits later |

## What a licence can and can not do

pan-os-php is open source (ISC) and runs at the customer. A check in code the customer holds can be removed by
changing the code. So the goal is: **nobody can make or extend a licence** (signature), honest customers are unlocked
cleanly, and going around it needs a deliberate change of the code (breach of contract). A feature nobody can use
without paying needs step 2: its code is not in the public image at all.

## Design

* **Licence = small signed file** (Ed25519, PHP `sodium`). The private key stays with Sven - never in the repository
  or an image. The viewer holds the public key(s) only (two slots, so that the key can be changed).
* Content: `id`, `customer`, `features` (list of names), `issued`, `valid_until`, optional `note`. Format: one text
  block (base64 of the JSON + signature) that can be mailed or carried on a stick.
* **Create:** command line tool at Sven's side: `license.php keygen`, `license.php create --customer … --features
  migration,cdss --days 365`, `license.php show <file>`. Every created licence is appended to a local register
  (id, customer, features, dates) - that is the management.
* **Install:** the admin uploads the file in the viewer (Account → Licence) or it is mounted / given by environment;
  the page shows customer, features, end date. API: `GET license`, `PUT license` (admin).
* **Check:** one place in `ViewerApp` (`needFeature( 'migration' )`), next to the checks of roles and types. Routes,
  run types and playbook step types name the feature they need; the browser page only hides.
* **Run time:** `valid_until` is signed. Warning in the page from 30 days before; after the end the licensed features
  stop (basic goes on, data stays readable). Grace period: to decide.
* **Clock:** the viewer remembers the newest time it has seen; a clock set back before that makes licensed features
  stop.
* **Withdraw (air gap):** (a) short run times, renewed by a new file - a licence that is not renewed ends by itself;
  (b) a list of withdrawn licence ids that ships with every new image / release. Both together; nothing immediate.
* **Trial:** a licence with a short run time, same mechanism.

## Open

1. Confirm strength: step 1 now (decision 6)?
2. Run time by default (12 months?) and grace period after the end (0 / 14 / 30 days?).
3. Where the register of created licences lives (file next to the private key / small database).
4. Feature names and what exactly belongs to `migration` and `cdss` (routes, run types, playbook steps).
5. Legal: selling the viewer / add-ons next to the ISC core, contributions of others - to check with a lawyer.

## Steps

1. `lib/ViewerLicense.php` (verify), `bin/license.php` (keygen / create / show / register), tests (forged, changed,
   expired, clock set back, withdrawn id).
2. `GET` / `PUT license`, page under Account, `needFeature()`, `meta` tells the page which features are on.
3. First licensed feature uses it.
