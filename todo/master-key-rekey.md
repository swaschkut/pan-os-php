# Re-encrypt all secrets of a configuration from a custom master key to the default master key

**Status:** implemented (2026-11-18): `type=master-key` with display (flags `hashes`, `cleartext`), `actions=rekey`
(encryption level 1) and `actions=scrub` (lab copy) – [utils/README_master-key.md](../utils/README_master-key.md),
`utils/lib/MASTER_KEY__.php`, `utils/common/ConfigSecrets.php`, `utils/common/ConfigSecretsScrub.php`,
`tests/test_master_key.php`. Open: lab verification and follow-ups, see "Open items" below
**Code reference:** `alpha` `aea719d`
**Related:** `lib/helper-classes/PanosCrypto.php`, [panorama-move-concept.md](panorama-move-concept.md) section 7a
(`master-key=same|different`), SCM export (`utils/develop/sase/scm/lib/SCMPrismaAccessExport.php`), action `display-psk` style use in
`utils/common/actions-ikegateway.php` (argument `master-key`)

## Goal

Input: a firewall / Panorama configuration (XML file or `in=api://`) whose secrets are encrypted with a **custom
master key**, and that master key. Output: the same configuration with **every** encrypted value re-encrypted with the
**default master key** – so the configuration can be loaded on a device / Panorama / tool that uses the default master
key (lab, replacement device, migration target, SCM import) without re-entering every secret.

Generic form: `old key → new key` (custom → default is the main case; default → custom and custom → custom work the
same way).

## Building blocks already in alpha

`PanosCrypto` (used by `SCMPrismaAccessExport`, `actions-ikegateway.php`, the plug-in scm-migration):

* format `-` + base64(version `0x01`) + base64(SHA-1 of the clear text, 28 chars) + base64(ciphertext),
  e.g. `-AQ==…=…==`
* AES-256-CBC, key derived from the master key (default `p1a2l3o4a5l6t7o8` when no key is given), zero IV
* `decrypt( $value, $masterKey )` checks the SHA-1 → wrong master key is detected; returns `""` on failure
  (the doc comment says `false`)
* `encrypt( $clear, $masterKey )`
* checked 2026-11-18: the IKE template value `-AQ==A4vEGnxsZCP7poqzjhJD4Gc+tbE=DS4xndFfZiigUHPCm4ASFQ==` decrypts with
  the default key to `DEMO`; encrypt / decrypt round trip with a custom key works, decrypt with the default key then
  fails as expected

## Proposal

New type `type=master-key`:

| argument | |
|---|---|
| `in=` / `out=` | firewall or Panorama configuration (offline); `in=api://` reads the candidate configuration (writing back over the API is not proposed – see open decisions) |
| `master-key-old=` / `master-key-old-file=` | custom master key of the input (file / environment variable preferred, so the key is not in the shell history / process list) |
| `master-key-new=` / `master-key-new-file=` | target key, default: default master key |
| `actions=` | `display` (default: list every encrypted value – XPath, length, decryptable yes / no – **never the value**) \| `rekey` \| `verify` (all values decrypt with the given key?) |

`rekey`:

1. walk the whole XML (all text nodes, not only the types pan-os-php models): value matches the encrypted format →
   decrypt with the old key (SHA-1 check), encrypt with the new key, replace the text
2. values that do not decrypt (other key, other format / version, e.g. AES-256-GCM of encryption level 2 – format to be
   verified) stay unchanged and are listed; exit code ≠ 0 when at least one value failed, unless `allow-partial`
3. report (`report=` folder / JSON): count per element type (pre-shared keys, passwords of server profiles, private
   keys of certificates, SNMP, BGP / OSPF auth, …), list of XPaths changed / failed – never clear text
4. reload the output with pan-os-php as validation

Not touched: hashed values (`phash` of local admins, `$1$` / `$5$` …) – these are hashes, not master-key encrypted
(done: flag `hashes` lists their XPath and algorithm, weak MD5 / DES marked).

## Security

* the output encrypted with the **default** master key is as good as clear text (the default key is public) – the
  report and the README must say so; output only to a file the user chooses, no copies in temp folders
* the master key never in the output, the report or the logs; prefer `…-file=` / environment variable over the command
  line
* the tool never prints decrypted values (also not with `debug`)

## Use cases / integration

* panorama-move 7a: today `master-key=different` removes the encrypted fields and lists them in `SECRETS_CHECKLIST.md`;
  with both keys known: option `master-key=rekey` (old / new key) re-encrypts them instead – no manual re-entry
* SCM import / Prisma Access export: they already take a master key to decrypt – common argument names and file
  handling
* replacement / lab device with default master key: load the customer configuration without re-entering secrets

## Steps

1. **done** – scan + `display` (read only): XPath, location, field, format version, key state (default / given /
   unknown) of every encrypted value; flag `cleartext` shows the decrypted value for the values the default (public)
   or the given master key can read (lab, like `type=ike-gateway psk-cleartext`); `key=` filter, `master-key-file=` / `master-key=`, `exportToHtml`, JSON; the
   "verify" of the proposal is the key state + `key=unknown`; works on the XML as stored (no object model); tests with
   generated values (default key, custom key, other key, unknown version, malformed, look-alikes, no value in any
   output)
2. **done** – `actions=rekey` offline for AES-256-CBC: `master-key-file=` / `master-key=` (key of the input) →
   `new-master-key-file=` / `new-master-key=` (default: default master key), `out=` required; each value is decrypted
   with the given **or** the default key (mixed configurations), status per value (`rekeyed`, `already-target-key`,
   `failed`, `unsupported`); with failed / unsupported values nothing is written and the exit code is ≠ 0 unless
   `allow-partial`; note when the target is the default key; tests: custom → default, custom → new key, default →
   custom, round trip, second run, nothing but the secrets changes, output loads, no value / key in any output
3. AES-256-GCM (encryption level 2, PAN-OS 10.0+): **detection done** (2026-11-18) – values use the prefix `-#…`
   (confirmed with a real level-2 configuration) and are listed as `aes-256-gcm` / not supported; `rekey` refuses a
   configuration that still holds such values (or leaves them unchanged with `allow-partial`). **Decrypt / re-encrypt
   is open**: the GCM key derivation is not implemented and must come from an authoritative reference (PAN-OS
   documentation or a documented implementation), not from analysing ciphertext. Workaround for a migration: set the
   source device to encryption level 1 first (`request encryption-level re-encrypt yes level 1`)
3a. **done** (2026-11-18) – `actions=scrub`: lab copy for commit validation. The real need behind the topic: load a
   customer configuration (custom master key, level 1 or 2) on a lab Panorama with the default master key and commit.
   Every encrypted value is replaced by a placeholder (default master key, AES-256-CBC), certificates with private key
   by new certificates with the same name / subject (chain kept where the issuer is in the configuration). No master
   key needed, nothing decrypted, independent of the source format (so AES-256-GCM is no blocker for this use case).
   **Open: verify on a lab Panorama** – load + commit of a scrubbed configuration; `subject-hash` / `issuer-hash` kept
   from the old certificate; behaviour of a level-2 target with AES-256-CBC values; option for the administrators
   (`phash`) of the input
4. panorama-move `master-key=rekey`
5. cleanup in `PanosCrypto`: doc comment of `decrypt()` (`""` instead of `false`), commented CLI runner / example at the
   end of the file

## Open items (state 2026-11-18)

| # | item | kind |
|---|---|---|
| 1 | `scrub`: load and commit a lab copy on a lab Panorama – does PAN-OS accept the replaced certificates (`subject-hash` / `issuer-hash` are kept from the old certificate), the placeholders, and a target device on encryption level 2 | lab test |
| 2 | `rekey`: check with a configuration exported from a device that uses a custom master key (`display` with `master-key-file=` must show "given master key"); so far only the default master key is confirmed against a real device | lab test |
| 3 | encryption level 2: stays "detected, not supported" for `rekey` / `cleartext`; workaround: set the source device to level 1 before the export, or use `scrub` | decided, no work planned |
| 4 | panorama-move: option `master-key=rekey` (instead of removing the encrypted fields with `master-key=different`) – after 1 and 2 | code, small |
| 5 | `PanosCrypto.php`: doc comment of `decrypt()` (returns `""`, not `false`), remove the commented CLI runner / example at the end of the file | code, small |
| 6 | `scrub`: administrators of the input stay (`phash` unchanged) – option to add / keep a lab administrator | idea, not decided |
| 7 | `in=api://`: read only today; writing changed values back to a device is not planned | decision |
| 8 | README section "What PAN-OS provides" (levels, CLI commands, documentation links) | patch sent, to be committed |

## Open decisions

1. (decided 2026-11-18) Arguments: `master-key-file=` / `master-key=` for the key of the input, `new-master-key-file=` /
   `new-master-key=` for the target key, `out=`.
2. AES-256-GCM (encryption level 2, PAN-OS 10.0+): support it (format / key derivation to be verified with a real
   configuration) or report such values as "not supported".
3. `in=api://`: read only, or also write the re-encrypted values back (would change secrets on a live device).
4. HSM-protected master keys cannot be handled offline – only reported.
