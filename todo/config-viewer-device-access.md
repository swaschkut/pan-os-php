# Config viewer: access to devices (import, later write / SSH)

**Status:** step 1 (import, read only) built 2026-11-21; writing and SSH open.
**Related:** [config-viewer-api.md](config-viewer-api.md), [config-viewer-encryption.md](config-viewer-encryption.md),
[docs/6-import-from-devices.md](../utils/develop/config-viewer/docs/6-import-from-devices.md)

## Decisions (Sven, 2026-11-21)

| # | Topic | Decision |
|---|---|---|
| 1 | Network | own permission area of the administrator: **global switch** (off by default) **plus per project** (owner) |
| 2 | Targets | administrator keeps an **allow list** and a **deny list** (deny wins) |
| 3 | Keys | **personal**: a user has his own key for a firewall / Panorama / SCM tenant; never shared between users |
| 4 | Key life | keys are **not** removed after a run - the user needs them again (next import, later writing, SSH) |
| 5 | Direction | **import only** for now - an important setting so that no wrong data leaves the viewer |
| 6 | Scope | firewall / Panorama (XML API) and SCM |

## Built (step 1)

* settings `network` (enabled, allow, deny) - `GET|PUT network` (admin); `projects.network` - `PUT projects/<pid>/network`
  (owner)
* table `user_keys` (kind `panos` / `scm`, target, label, secret encrypted with `keys.secret` of the data directory -
  sodium secretbox, hint = last 4 characters) - `GET|POST keys`, `DELETE keys/<kid>`; not with an API token; the
  secret is never sent back and never in the audit log
* run type `import` (`POST projects/<pid>/import/runs`, body `kid`, `source` candidate / running): write permission,
  checks at start and again when the run starts; steps with `network` only for the download (container:
  `PANOSPHP_VIEWER_CONTAINER_NETWORK`, default `bridge`; all other runs `none`); key store `.panconfkeystore` with
  only this entry in the folder of the run, removed at the end (also on cancel / runner restart), never a result
  file; the secret is replaced in `run.log`; `out.xml` becomes a new version

## Built (step 1b, 2026-11-21): the whole key store

* kinds `panos` (with port), `scm`, `egressip`, `named` (`ldap-password`, `bpa-apikey`, `license-apikey`,
  `maxmind-licensekey`, `gcp-mysql-password`), `other` (any further entry name, kept as it is)
* `POST keys/import`: an existing `.panconfkeystore` of a customer is taken over (upsert per kind + target)
* imports use `panos` / `scm`; the other entries are stored for the runs that need them (open: which runs get which
  entries - G below)

## Open

| # | Topic | Notes |
|---|---|---|
| A | Writing to a device (`out=api://`, `type=upload`, `config-commit`) | own administrator switch "write to devices" (off), per project, maybe per user; a review step (diff / set commands shown before), audit; never by a playbook |
| B | Set commands per SSH (`type=ssh-connector`) | personal SSH credentials (password / key) as a new key kind; same switches as A; only the set commands of a chosen run result |
| C | Firewall through Panorama (`api://<serial>@<panorama>`) | key of the Panorama, target serial; allow list on the Panorama host |
| D | Key generation from user + password (`type=key-manager`) | needs network from the web part - today the user brings the API key |
| E | Network limited to the targets | today: the container gets a normal network; the allow list is checked by the viewer, not by a firewall rule - a dedicated docker network with egress rules would be stronger |
| G | Named entries in runs | e.g. `maxmind-licensekey` for a MaxMind update, `ldap-password` for LDAP runs, `bpa-apikey` for bpa-generator: the run gets only the entry it needs, like an import |
| F | Encryption of the key store | today the key of the installation lies in the volume (protects a copied database, not a copied volume) - see config-viewer-encryption.md |
