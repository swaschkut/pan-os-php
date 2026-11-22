# Support file (TSF of pan-os-php)

Decisions (2026-11-22, Sven):

- encrypted for a **public support key** - own key pair, made and kept like the licence keys (private repository
  `pan-os-php_migration`, `license/license.php support-keygen`); public keys: `lib/resources/support/keys.json`
- anonymisation: offered, **off by default**; the mapping stays with the customer (file of the run, never in the TSF)
- the whole configuration: the customer may add it (option, per support file); secrets are always replaced
- order: base + merger case + CLI reader with report and mini configuration first; then the browser error collector
  and "open support file" in the viewer

## Built (2026-11-22)

- `lib/misc-classes/SupportFile.php`: format 1 - line 1 magic, line 2 JSON header (kid, created, size, sealed file key,
  nonce), XChaCha20-Poly1305 of the zip with the header as additional data; file key sealed for the X25519 public key
  (sodium). `keygen()` (same key file as the licence tool), `decrypt()`; tests: `PANOSPHP_SUPPORT_TEST_KEYS`
- `utils/common/ConfigExcerpt.php`: the small configuration for names - every copy in every location, the groups up,
  the members down, the rules (pre / post / vsys, every type); the hierarchy (device groups + readonly parent-dg);
  loadable by pan-os-php
- `type=support-file` / `type=support-file-read` (`utils/lib/SUPPORTFILE__.php`): create (in, result, report, names,
  rules, full, anonymize + mapping, extra, note; secrets replaced - `removeSecrets()` with the secret tags of
  ConfigAnonymizer; anonymised: one ConfigAnonymizer for every XML, JSON / text by the mapping, leak scan per file),
  read (decrypt, manifest check, unpack, `report.html`)
- viewer: run type `support-file` - `supportStage()` puts the case (run.json, run logs, merger.json, out.xml), project,
  runs, audit, viewer data and the browser errors into `.support/` of the run (hidden: not a file of the run); tab
  **Support file**, button **Support file for this run** in merger reports; browser error collector (last 100: script
  errors, refused API calls - only in memory, sent with a support file)
- licence tool (private repository): `support-keygen`, `support-pubkey [--panosphp]`, `support-open`
- tests: `tests/test_support_file.php`, viewer test 12m (support file of a merger run, anonymised + whole configuration)

## Open

- "Open support file" in the viewer of the support: the TSF as a read-only project (report, the excerpt as version,
  the merger report with Explain)
- the case of other runs: playbook (the steps, the stage files), import (no configuration of the device - only
  run.log), rule-merger (rules by name are in the excerpt; their objects as tmp objects)
- excerpt of SCM configurations (folders / snippets) and of templates (network objects: zones, interfaces)
- upload to the support from the viewer (network, allow list) instead of download + mail
- size: a support file is made in memory (zip, encryption) - for very large configurations with *whole configuration*
  a streamed format (secretstream) would be better
