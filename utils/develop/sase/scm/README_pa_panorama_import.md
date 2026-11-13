# Panorama → SCM: shared, device-groups, templates / template-stacks

Upload a Panorama configuration (XML file) into a Strata Cloud Manager tenant:

```
Panorama                                   SCM
shared                               ──►   folder All
  DG level 1 … 4                     ──►   ngfw-shared ("All Firewalls") / folder level 1 … 4
template, template-stack             ──►   snippet
firewall → DG, firewall → stack      ──►   DG folder ◄── snippets: stack, then its templates (stack order)
```

* Panorama shared goes to `All`: templates / template-stacks can use shared objects (e.g. addresses) in Panorama;
  in SCM the snippets see the objects of `All`.
* Device-group levels: max. 4 below shared in Panorama, max. 4 folder levels below `ngfw-shared` in SCM – the
  default `dg-parent=ngfw-shared` fits every Panorama hierarchy.
* Snippets of a device-group folder: from the firewalls of the device-group – each firewall's template-stack, then
  the templates of that stack in stack order. The first snippet is the top one (wins), as the stack wins over its
  templates in Panorama. Firewalls of one device-group with different stacks: all are attached in this order, warning.
* The firewalls themselves (serial → device in the folder) are not part of this step.

Two steps, both existing building blocks:

```
Panorama XML ──► scm_pa_panorama_to_change.php ──► change.json ──► scm_pa_change.php (dry-run, execute, verify)
                 (SCMImporter + SCMChangeGenerator                  (export of the affected containers, plan,
                  of type=scm-import: XML → SCM API fields)          hash check, verification per object, rule /
                                                                     snippet order)
```

```
cd utils/develop/sase/scm
php scm_pa_panorama_to_change.php in=panorama.xml out=change.json [dg-parent=ngfw-shared] [device-group=DG1,DG2]
    [shared=all|folder|skip] [no-templates] [no-rules] [no-zones]
php scm_pa_change.php in=scm-api://<TSG> changes=change.json                                   # dry-run
php scm_pa_change.php in=scm-api://<TSG> changes=change.json execute continue-on-error         # write + verify
```

| Panorama | SCM |
|---|---|
| shared | `shared=all` (default): folder `All`; `shared=folder`: the `dg-parent` folder; `shared=skip` |
| device-group (top level) | folder below `dg-parent` (default `ngfw-shared`) |
| child device-group | folder below the folder of its parent device-group |
| template / template-stack | snippet (same name; a stack with the name of a template: `<name>-stack`) with zones (interfaces removed), zone protection profiles, objects of vsys1 / shared of the template |
| firewall → device-group + template-stack | `snippets` of the device-group folder: stack, then its templates |
| objects: tags, addresses, address groups, services, service groups, schedules, log forwarding profiles, custom URL categories, security profiles (anti-spyware, vulnerability, URL, file blocking, DNS security), profile groups | objects of the folder (SCM field names) |
| security pre / post rules | `security-rules` with `position` pre / post, in Panorama order |
| zone of a rule that is in no attached snippet / parent folder | created in the device-group folder (definition from the templates or empty layer3 zone); `no-zones` switches it off |

`no-templates`: device-groups only – then the zones of the rules are created in the device-group folders.

Not in the snippets yet: interfaces, virtual routers / logical routers, other network and device settings of the
templates (SCM: NGFW network / device settings – a later step together with the firewalls).

## change.json

The usual change request of [scm_pa_change.php](README_pa_change.md) plus:

* `source`: file, date, `dg_parent`, import summary
* `not_imported`: objects / rules that cannot be sent as they are (with the reason) – e.g. fields the public SCM API
  does not have (vulnerability / anti-spyware inline cloud analysis, profile groups with antivirus / WildFire),
  references to predefined profiles (`default`), rules with single security profiles instead of a profile group
  (SCM rules only take a profile group), rules that use such an object
* `warnings`: what is not imported at all (custom applications, antivirus / WildFire profiles, data filtering,
  NAT / decryption / … rules), removed rule group tags

`scm_pa_change.php` ignores `source`, `not_imported` and `warnings`.

## Translation details

* `group-tag` of rules (display grouping of the rule list) has no SCM field → removed, listed in `warnings`
* `saas-user-list` / `saas-tenant-list` with only `any` (PAN-OS default) → removed
* rule `target` without firewalls → removed; with firewalls → warning (SCM rules have no target)
* Panorama uuids are removed

## Live findings (lab tenant, 2026-11-13, 478 requests: 453 created, 25 failed → fixed)

| SCM answer | cause | fix |
|---|---|---|
| tag `"color" must be one of [Red, Green, …]` | PAN-OS writes `color1` … `color42` | translated to the SCM color names (`SCMChangeGenerator::$tagColors`) |
| URL category `missing 'type'` | PAN-OS before 9.0: no `<type>` (always a URL list) | `type: "URL List"`, empty `list` added |
| URL access profile `credential_enforcement.mode.ip_user must be of type object` | `<ip-user/>` → `{}` was decoded as PHP array and sent as `[]` | the sync / change apply sends `{}` where the SCM schema has an object (`SCMPrismaAccessSync::restoreEmptyObjects`) |
| log forwarding profile `missing node 'match-list'` | Panorama profile without match list (forwards nothing) | not importable (review) – zones / rules that use it as well |
| rule `tag … is not a valid reference`, zone `log-setting … is not a valid reference` | follow-up of the failed tags / log forwarding profiles | – |

Open: whether SCM accepts an object in a folder with the name of an object in `All` (Panorama: device-group object
with the name of a shared object, here URL category `Custom-No-Decrypt`) – both failed for the missing type.

## Notes for the first run

* Rules reference custom applications (not imported): SCM may refuse such rules. `continue-on-error` creates the
  rest; `no-rules` uploads the objects only.
* Panorama shared rules go to `All` with `shared=all` – they apply to Prisma Access as well (warning).
* `dg-parent` below `ngfw-shared` (e.g. a lab folder `pan-os-php-test`): takes folder levels from the device-group
  tree – with a level-1 folder only 3 device-group levels fit. A deeper hierarchy is refused (converter and
  `scm_pa_change.php` check the 4 levels). Existing folder → unchanged; missing → created below `ngfw-shared`.
* A second run with the same file finds nothing to do (all "unchanged").
* Folders without a firewall cannot be pushed (candidate configuration only).

The same options exist in `type=scm-import` (`scope=device-groups|templates dg-parent=… device-group=… shared=global|folder|skip`),
which writes the `pan-os-php-scm-changes` file for `type=scm-apply` instead.
