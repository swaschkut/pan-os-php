# Re-encrypt all secrets of a configuration from a custom master key to the default master key

**Status:** planned (2026-11-18)
**Code reference:** `alpha` `3df2eeb`
**Related:** `lib/helper-classes/PanosCrypto.php`, [panorama-move-concept.md](panorama-move-concept.md) section 7a
(`master-key=same|different`), SCM importers (`lib/misc-classes/SCMImporter.php`,
`utils/develop/sase/scm/lib/SCMPrismaAccessExport.php`), action `display-psk` style use in
`utils/common/actions-ikegateway.php` (argument `master-key`)

## Goal

Input: a firewall / Panorama configuration (XML file or `in=api://`) whose secrets are encrypted with a **custom
master key**, and that master key. Output: the same configuration with **every** encrypted value re-encrypted with the
**default master key** – so the configuration can be loaded on a device / Panorama / tool that uses the default master
key (lab, replacement device, migration target, SCM import) without re-entering every secret.

Generic form: `old key → new key` (custom → default is the main case; default → custom and custom → custom work the
same way).

## Building blocks already in alpha

`PanosCrypto` (used by `SCMImporter`, `SCMPrismaAccessExport`, `actions-ikegateway.php`):

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

New type (name open, e.g. `type=master-key`):

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

Not touched: hashed values (`phash` of local admins, `$1$` / `$5$` …) – these are hashes, not master-key encrypted.

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

1. scan + `display` / `verify` (read only)
2. `rekey` offline + report + validation by reload
3. tests: fixture with values encrypted with a custom key (generated with `PanosCrypto::encrypt`), the known default
   vector (`DEMO`), a value with a wrong key, a non-encrypted value that only looks similar
4. panorama-move `master-key=rekey`
5. cleanup in `PanosCrypto`: doc comment of `decrypt()` (`""` instead of `false`), commented CLI runner / example at the
   end of the file

## Open decisions

1. Name of the type and of the arguments (`master-key-old` / `master-key-new`, or `master-key` / `target-master-key`).
2. AES-256-GCM (encryption level 2, PAN-OS 10.0+): support it (format / key derivation to be verified with a real
   configuration) or report such values as "not supported".
3. `in=api://`: read only, or also write the re-encrypted values back (would change secrets on a live device).
4. HSM-protected master keys cannot be handled offline – only reported.
