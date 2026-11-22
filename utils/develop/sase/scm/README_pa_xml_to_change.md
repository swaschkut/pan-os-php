# pan-os-php utilities on an SCM export – `in=scm-export://` and `scm_pa_xml_to_change.php`

The pan-os-php utilities (object merger, playbooks such as full visibility, `type=address|service|rule|tag|… actions=…`)
work on XML. With `in=scm-export://<folder>` they read a folder written by `scm_pa_export.php` – offline, nothing is
sent. `scm_pa_xml_to_change.php` turns their result into a change request; `scm_pa_change.php` uploads it with
dry-run, hash check and verification.

```
scm_pa_export.php ──► export folder (JSON)
      │
      ▼  in=scm-export://<export folder>          (offline, same JSON -> XML loader as in=scm-api://)
pan-os-php utilities  ──►  out=changed.xml       (chains: next utility with in=changed.xml)
      │
      ▼  scm_pa_xml_to_change.php in=scm-export://<export folder> file2=changed.xml out=change.json
change.json  ──►  scm_pa_change.php in=scm-api://<TSG> changes=change.json   (dry-run, then execute)
```

Example – address merger of one folder:

```
php utils/develop/sase/scm/scm_pa_export.php in=scm-api://1234 area=config outdir=export     # -> export/1234/<timestamp>/
php utils/pan-os-php.php type=address-merger in=scm-export://export/1234 location=Lab out=merged.xml
php utils/develop/sase/scm/scm_pa_xml_to_change.php in=scm-export://export/1234 file2=merged.xml out=change.json
php utils/develop/sase/scm/scm_pa_change.php in=scm-api://1234 changes=change.json              # dry-run
php utils/develop/sase/scm/scm_pa_change.php in=scm-api://1234 changes=change.json execute
```

All steps with `pan-os-php type=…` (the SCM scripts are registered as types; arguments as with `php <script>`):

| type | script |
|---|---|
| `scm-export` | scm_pa_export.php |
| `scm-export-xml` | the export as one XML (UTIL type) |
| `scm-xml-to-change` | scm_pa_xml_to_change.php |
| `scm-change` | scm_pa_change.php (`diff=`, `select=`, `execute`) |
| `scm-panorama-to-change` | scm_pa_panorama_to_change.php |
| `scm-compare` / `scm-sync` | scm_pa_compare.php / scm_pa_sync.php |

```
pan-os-php type=scm-export in=scm-api://1234 area=config outdir=export ui-api-host=<region host>
pan-os-php type=scm-export-xml in=scm-export://export/1234/<timestamp> out=1234.xml
pan-os-php type=playbook 'json=$$playbook$$/visibility.json' in=1234.xml out=1234_visible.xml
pan-os-php type=scm-xml-to-change in=scm-export://export/1234/<timestamp> file2=1234_visible.xml out=change.json
pan-os-php type=scm-change in=scm-api://1234 changes=change.json diff=diff.json          # dry-run + differences
pan-os-php type=scm-change in=scm-api://1234 changes=change.json select=diff_selected.json execute
```

Use the same export folder (with timestamp) for `scm-export-xml` and `scm-xml-to-change`.

## in=scm-export://

`<folder>`: the export folder `<outdir>/<TSG>/<timestamp>/`, or `<outdir>/<TSG>` – then the newest export of that TSG
with a config area is used (the tools print which one).

* every utility that works with `in=scm-api://` (UTIL based types, the mergers) – containers, snippets, devices and
  objects from `config/01_folders.json`, `config/02_snippets.json` and `config/folders|snippets|devices/<container>/`
* `location=` works as with `scm-api://`; the result is written with `out=` like an XML file
* offline: no credentials, no API request – a utility that would send something stops with a message
* loaded types: tags, addresses, address groups, external dynamic lists, regions, services, service groups,
  schedules, application groups / filters / custom applications, log forwarding / zone protection / security profiles,
  profile groups, zones, security and NAT rules (the address / service types and the mergers load NAT rules too, so
  their references are replaced)
* security profiles (vulnerability, virus-and-wildfire, anti-spyware, DNS security) are loaded complete – decoder
  actions, inline ML, inline cloud analysis, rule action `default`, advanced DNS – when the export has their internal
  UI API answers (`config/internal/<type>.json`, scm_pa_export.php default, `ui-api-host=` for the tenant region);
  an older export without them: public fields only

The whole export as one XML (all containers, all types the loader knows – the original of
`scm_pa_xml_to_change.php`):

```
pan-os-php type=scm-export-xml in=scm-export://export/1234 out=1234.xml
```

## SCM profile semantics in pan-os-php

SCM has no antivirus and no wildfire profiles and splits PAN-OS anti-spyware:

| PAN-OS | SCM (BuckbeakConf) |
|---|---|
| antivirus + wildfire-analysis | one virus-and-wildfire-analysis profile |
| anti-spyware (incl. DNS signatures / botnet domains) | anti-spyware + dns-security profile |

On an SCM configuration the PAN-OS names map to it:

* `type=securityprofile securityprofiletype=virus` / `wildfire-analysis` → virus-and-wildfire-analysis profiles
  (the `virus.*` / `wildfire.*` actions support them); `securityprofiletype=spyware` → anti-spyware and dns-security
  profiles
* profile groups: `securityProfile-Set` / `-Remove` with `virus` / `wildfire` set the virus-and-wildfire-analysis
  slot (also `virus-and-wildfire`, `dns-security`); filters `av-profile.is.set` / `wf-profile.is.set` test that
  slot (`avwf-profile.is.set`, `dnssec-profile.is.set` as well)
* BP / visibility / adoption of a group: virus-and-wildfire-analysis, anti-spyware, dns-security, vulnerability,
  url-filtering, file-blocking must be set and pass; an anti-spyware profile is checked without its DNS part (that
  is the dns-security profile)
* filters / statistics `av ...` and `wf ...` on a virus-and-wildfire-analysis profile check only its antivirus part
  (decoder actions, cloud inline analysis) or its WildFire part (rules, cloud inline analysis 11.2+); `avwf ...`
  checks the whole profile

## Playbooks on SCM

`type=playbook` detects an SCM input (`scm-api://`, `scm-export://`, or an XML whose `<config>` carries
`buckbeak` / `fawkes-config-version`). Per step of the playbook JSON:

* `"scm": { "actions": …, "filter": …, … }` replaces these arguments on SCM; `"scm": false` skips the step on SCM
* `"platform": "scm"` / `"panos"` runs the step only on that platform

`visibility.json` uses it: rule steps with single profiles are skipped (SCM rules reference profile groups only);
the profile steps use `virus-and-wildfire.alert-only-set` (instead of `virus.` / `wildfire.alert-only-set`, which
only change PAN-OS antivirus / wildfire profiles) and `dns-security.alert-only-set` (`spyware.alert-only-set` changes
anti-spyware profiles only); the group steps set `Alert-Only-AVWF` and `Alert-Only-DNSSEC`. On SCM `logforwardingprofile-create-bp` creates
`default` in folder `All` (one match list per log type, All Logs – Strata Logging Service) and
`zpp-create-alert-only-bp` creates `Alert_Only_Zone_Protection` in `All`.

```
pan-os-php type=playbook in=scm-export://export/1234 out=visibility.xml
php utils/develop/sase/scm/scm_pa_xml_to_change.php in=scm-export://export/1234 file2=visibility.xml out=change.json
```

The antivirus enforcement actions (`decoder`), WildFire inline ML and inline cloud analysis are internal UI API
sections: with an export that holds them (`config/internal/`) the playbook sets them and the change file writes them
(`_internal`); with an older export the report shows "[SCM no export - missing settings]" – export again. Open: the
iron-skillet content of some Alert-Only profiles (mica engine, cloud inline analysis, AV decoders,
anti-spyware action `default`) has no public SCM field – those change requests are marked for review.

## scm_pa_xml_to_change.php

The original is loaded from the same export with the same loader (all containers, all types), so only the changes
of the utilities show up:

| difference | change request |
|---|---|
| new object | create (all fields) |
| changed object | update with the changed fields (rules with `position`) |
| object gone | `_delete` – only if the changed XML still holds objects of that type in that container (a type a utility did not load is never deleted) and the object is not referenced by a type pan-os-php does not load (NAT / decryption / … rules: the utility did not replace these references) – else listed in `not_imported` |
| changed internal UI API section of a security profile (decoder, inline ML, inline cloud analysis, rule action `default`, advanced DNS) | `_internal` with the complete entry and `base` (the export entry) – scm_pa_change.php writes it through the internal UI API after the public request and reports a section changed in SCM since the export as conflict; only in folders and only if the export has the internal answer of the profile, else `not_imported` |
| renamed object, removed scalar field, folder / snippet changes, requests to review | not in the change request → `not_imported` with the reason |

`original=<file>` also writes the original XML.

The age of the export matters: `scm_pa_change.php` checks with its hash check that the objects it changes are still
as in its own export; objects changed in SCM since then are reported as conflict, not overwritten.
