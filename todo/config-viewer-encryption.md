# Config viewer: data at rest - who can read it, encryption

**Status:** open - analysis done 2026-11-21, no decision yet, nothing built.
**Related:** [config-viewer-api.md](config-viewer-api.md), [config-viewer-license.md](config-viewer-license.md),
[README of the viewer](../utils/develop/config-viewer/README.md)

Question (Sven, 2026-11-21): can the Docker volume be encrypted and bound to the administrator, so that uploaded data
is neither lost nor read by others - and does that keep the Docker admin out?

## Today: what is in the volume (all plain text)

Docker volume `panosphp-viewer-data`, mounted as `/data` in `web`, `service` and `jobs`:

| Content | Where |
|---|---|
| uploaded configurations (XML), all versions | `projects/<pid>/…` |
| project files (playbook JSON, BP JSON) | `projects/<pid>/files/` |
| run results (changed XML, set commands, logs, migration output) | `projects/<pid>/jobs/` |
| working and recovery copies of open sessions | `projects/<pid>/work/` |
| users (password hashes), projects, members, token hashes, audit log | `viewer.sqlite` |
| licence, one-time code of a new installation | `license.txt`, `first-admin.code` |

## Today: who can read it

**On the computer (outside the viewer) - everything, without a password:**

* whoever may use Docker: `docker run -v panosphp-viewer-data:/x …` or `docker compose exec web sh`, running or stopped
  * Mac / Docker Desktop: the macOS user who runs Docker Desktop (other macOS users: no)
  * Linux / Docker Engine: root, `sudo` users, **every member of the group `docker`** (= root)
  * Linux / rootless Podman: the owner of the containers
* files on disk: Mac - the disk image of the Docker Desktop VM in `~/Library/Containers/com.docker.docker/…`
  (the user, macOS admins); Linux - `/var/lib/docker/volumes/…` (root)
* stolen / disposed disk, server backups, VM snapshots, Time Machine (if the VM image is not excluded) - anybody,
  when the disk is not encrypted

**Containers of the viewer:** `web`, `service`, `jobs` mount the whole volume - a hole in the PHP code reaches all
projects. `jobs` also has the Docker socket (= root on the computer); it takes no requests from outside. A run
container sees only its own project folder, read-only, without network.

**In the browser:**

* owner and members of a project (role read / write / owner, limits per member); API tokens: their project only
* **an administrator is no super user for projects** - the project check knows owner and membership only, a foreign
  project is not listed and answers `404`
* but an administrator can
  * give a user a **new password** (Account → Users, since patch 37) and log in as that user - in the audit log with
    the administrator's name, the user notices because the old password stops working, but it is not prevented
  * read the **audit log of all projects** - no file content, but project / file names and request fields such as
    filters (`(name eq 10.1.1.1)`), i.e. small pieces of configurations
  * delete a user and with it the user's projects (destroy, not read)

## What encryption can do - and what not

| Who | Encryption helps? |
|---|---|
| thief, backup team, VM snapshot, disposed disk | yes |
| Docker admin, curious, afterwards, viewer stopped or locked | yes (key not on the computer) |
| Docker admin who wants it and has time | **no** - only a hurdle and traces |

Why not against a determined Docker admin (= root on the computer):

1. while the viewer is unlocked the key is in the memory of the service - root can read it (`docker exec`, `gdb`, `/proc`)
2. what is being worked on is plain text in the container (tmpfs) - root can read it
3. root can change the image or the running container to record passwords at the next login and then open every key -
   also per-project keys bound to owner and members

pan-os-php must read and change the configuration on the server, so encryption that only the browser can undo is not
possible. **The Docker admin must be trusted - he has the role of the operator.** This must be said to customers;
encryption must not be sold as protection against the operator.

## Options

**A - disk encryption (FileVault / LUKS).** No code. Protects against theft, disposed disks and (encrypted) backups.
Recommended as a requirement in the customer guide in any case.

**B - encryption in the viewer, bound to the administrators.**

* one data key; configurations, versions, project files, run results encrypted in the volume (sodium, like the `.ppp`
  packages)
* the data key is never in the volume in clear - wrapped with the password of every administrator (key slots, like LUKS)
* after every start the viewer is **locked** until an administrator logs in; the key then lives only in the memory of
  the service, never on disk or in `.env`
* plain text only in tmpfs while a file is used (worker, runs)
* new administrator: key slot added by a logged-in administrator; removed administrator: slot deleted; password change:
  slot re-wrapped
* `viewer.sqlite` stays plain (names, audit log - no configuration content)
* consequences: after a restart no API-token script works until an administrator has logged in once; a new password
  for an administrator by another administrator needs a new key slot (possible because the other one is logged in);
  larger change over several patches (worker, runs, downloads, versions, migration of existing data)
* an administrator can still decrypt everything (by design)

**B' - per-project keys, bound to owner and members.**

* an administrator can not read foreign projects, also not with a new password for the user
* a user who forgets the password loses his projects unless another member holds the key or there is an emergency key
* "new password by the administrator" = the user gets in again, his encrypted projects stay closed
* more complex than B (key per project, key slots per member, members added by someone who holds the key)

**Not lost - independent of the encryption:**

* without an emergency key: all key holders forget their password = **data gone for good** (nobody can help)
* **emergency data key** (offline, printed / safe): restores data into a new installation; can not create users or
  reset passwords - different from the login recovery code Sven declined on 2026-11-21
* **backup command** `./panosphp-viewer backup`: an encrypted file that can be copied away safely - against
  `docker volume rm` and broken disks

**Small additions (independent, quick):**

* notice for a user after the login: "your password was set by administrator X on …" - the password detour is not silent
* image check at start: compare the digest of the running image and report a change (shows, does not prevent, tampering)
* customer guide: only the operators of the viewer in the group `docker`; ideally an own computer / VM for the viewer

## Open decisions

| # | Question | Options |
|---|---|---|
| 1 | Build encryption in the viewer? | A only (disk encryption + guide) / B (administrators) / B' (per project) |
| 2 | Emergency data key? | yes (offline) / no (all passwords lost = data lost) |
| 3 | Backup command | now / later |
| 4 | Notice after a password reset by an administrator | yes / no |
| 5 | Image digest check at start | yes / no |
| 6 | Customer guide: Docker admin = operator, `docker` group, disk encryption | yes (recommended in any case) |

## Plan when B / B' is decided (sketch)

1. key handling in `ViewerApp` (data key, key slots with Argon2id from the passwords, lock / unlock in the service)
2. encrypted storage for configs, versions, project files, run results; plain text only in tmpfs (compose: tmpfs mounts)
3. worker and job runner: get the key from the service, never from disk
4. UI: "locked - an administrator must log in", key slots with users / members
5. migration of existing plain data, emergency key, backup command
6. tests: volume copy without password unreadable, lock after restart, key slots on add / remove / password change
