# pan-os-php type=config-section

Generic access to device / Panorama settings with named entries that pan-os-php does not model as objects, e.g.
`deviceconfig/system/deployment-update-schedule`. The sections are declared in
[`utils/common/config_sections.json`](common/config_sections.json) – a new section needs no code.

Code: `utils/lib/CONFIG_SECTION__.php` (type), `utils/common/ConfigSection.php` (shared class, also used by
`type=panorama-move`). Tests: `tests/test_config_section.php`.

## Sections (registry)

| section | path (below the device entry) | scope | references |
|---|---|---|---|
| `deployment-update-schedule` | `deviceconfig/system/deployment-update-schedule` | Panorama | yes |
| `config-bundle-export-schedule` | `deviceconfig/system/config-bundle-export-schedule` | Panorama | yes |
| `permitted-ip` | `deviceconfig/system/permitted-ip` | Panorama, firewall, template | no |

`section=list` shows the registry. Registry fields: `path` (relative to `/config/devices/entry[@name='localhost.localdomain']`,
or to the template config with `template=`), `scope` (`panorama`, `firewall`, `template`), `references` (text values
and entry names are matched against device group / template / template stack names and managed firewall serials).

The type does not need to know the elements inside an entry: fields are read generically (flattened paths).

## Usage

```bash
pan-os-php type=config-section section=list
pan-os-php type=config-section in=panorama.xml section=deployment-update-schedule                      # display (default)
pan-os-php type=config-section in=panorama.xml section=deployment-update-schedule actions=references   # only references
pan-os-php type=config-section in=panorama.xml section=deployment-update-schedule entry=nightly actions=get:set
pan-os-php type=config-section in=panorama.xml section=deployment-update-schedule actions=exportToHtml:dus.html
pan-os-php type=config-section in=panorama.xml out=new.xml section=deployment-update-schedule entry=nightly \
    'actions=remove-member:devices,007100000290/set:recurring.daily.at,04:00'
pan-os-php type=config-section in=panorama.xml out=new.xml section=permitted-ip template="Paris Datacenter" \
    entry=10.0.0.0/8 actions=set:description,mgmt
pan-os-php type=config-section in=api://panorama section=deployment-update-schedule entry=old actions=delete
```

| argument | |
|---|---|
| `section=` | section of the registry, `list` |
| `entry=` | entries (comma separated), default all; `set` / `add-member` on a missing entry creates it |
| `template=` | Panorama: the section inside a template (scope `template`) |
| `actions=` | separated by `/` (a literal `/` in a file name as `//`) |
| `shadow-json` | JSON output (`display`: name, fields, references) |

| action | |
|---|---|
| `display` | fields of each entry (path → value, member lists joined) and references |
| `references` | only the references (device group / template / template stack / firewall) |
| `get:xml` \| `get:set` \| `get:json` | entry as XML, as set commands, as JSON |
| `exportToHtml:FILE` | one row per entry, one column per field (+ references), `ExportToHtmlHelper` |
| `set:PATH,VALUE` | set a single value (elements created when missing) |
| `add-member:PATH,VALUE` / `remove-member:PATH,VALUE` | member lists |
| `remove-field:PATH` | remove an element of the entry |
| `delete` | delete the entry |

PATH: element names joined by `.`, named entries as `[name]` (e.g. `protocol.scp.hostname`, `a.[x].b`).

Changes: offline only with `out=`; with `in=api://` the changed entries are sent with `edit` / `delete` to the
candidate configuration (commit separately).

Encrypted values (`-AQ==…`) are never displayed: `*** encrypted ***` in display / HTML, `<encrypted>` in set commands.

## Use in panorama-move

`type=panorama-move` reads every Panorama section with `references: yes`. Entries of file1 that reference moved device
groups / templates / template stacks / firewalls are reported (info finding, `plan.json`
`panorama_settings_referencing_moved`, follow-up with the `get:set` call to recreate them in Panorama B); on execute the
references to moved items are removed from the entries in file1. The entries are not transferred to file2.

## Limits

* element names inside the entries of `deployment-update-schedule` / `config-bundle-export-schedule` are not checked
  against a schema (the tests use example structures) – set commands follow the XML as it is
* references are found by text value (a value that equals a device group name counts as reference)
* `in=api://`: the whole configuration is loaded first (as for all types)
