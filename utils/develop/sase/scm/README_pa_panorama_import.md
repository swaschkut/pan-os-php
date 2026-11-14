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

## Security profiles (prepared for SCM before the translation)

Rules:

* A reference is never removed because the referenced object is missing: the missing object is created – copy of the
  PAN-OS predefined profile if there is one, else a placeholder (name, content unknown / not writable) – and listed
  in `placeholders` of the change file.
* Content that cannot be imported (no SCM field) is listed per object in `incomplete` (what is missing and why).
* Objects that cannot be created at all (no SCM API) stay with their reference and are listed in `not_imported`,
  together with what uses them.

| Panorama | SCM |
|---|---|
| rule with single security profiles | SCM rules take profile groups only: the rule gets a profile group – an existing one with the same profiles, else a new `secProfGroupN` in the scope of the rule (same logic as the rule action `securityProfile-replace-by-Group`) |
| profile group with antivirus and / or WildFire profile | one `wildfire-anti-virus-profiles` profile in the scope of the group, name: the antivirus or WildFire profile name, both: `<AV>_<WF>`. Content: WildFire rules (predefined `default`: any / any / both / public-cloud; antivirus only: no WildFire rule), antivirus threat / MLAV exceptions and packet capture |
| spyware profile with `botnet-domains` | `botnet-domains` moved to a `dns-security-profiles` profile with the same name; profile groups with this spyware profile get it as `dns_security` |
| spyware / vulnerability rule action `default`; antivirus decoder actions / inline ML / inline cloud analysis, vulnerability `mica-engine-vulnerability-enabled` / `cloud-inline-analysis`, spyware inline `local-deep-learning`, DNS `advanced-dns-security-categories` | not in the public SCM API: the public request creates the profile without them (action `default` as empty action), the complete profile (PAN-OS structure) is in `_internal` of the entry and `scm_pa_change.php` writes it through the internal UI API right after the public requests (`multiConfigure` edit, see README_pa_change.md); verification reads it back through the internal API |
| antivirus application exceptions | no SCM field known → `incomplete` |
| profile in a profile group that is not in the configuration (e.g. `default`, `strict file blocking`) | created in the scope of the group: copy of the PAN-OS predefined profile (`lib/object-classes/predefined.xml`), else an empty placeholder → `placeholders` |
| antivirus / WildFire part of a combined profile not in the configuration | PAN-OS predefined `default` content, else placeholder → `placeholders` |
| data filtering profile in a profile group | SCM API cannot create data filtering profiles (enterprise DLP): reference kept, group and the rules that use it in `not_imported` |
| rule `group-tag` | no SCM field → rule in `incomplete` |
| zone interfaces | → zone in `incomplete` (device variables per firewall, next step) |
| log forwarding profile without match list | SCM requires a match list: placeholder match list `pan-os-php-placeholder` (traffic, `All Logs`, no destination – forwards nothing, as before) → `placeholders` |
| custom application | `applications` with category, subcategory, technology, risk, description and the characteristics (evasive, …); signatures, default ports, timeouts … not imported → `placeholders` |
| zone used by rules, not in a template (`no-templates` / no stack) | empty layer3 zone → `placeholders` |

## change.json

The usual change request of [scm_pa_change.php](README_pa_change.md) plus:

* `source`: file, date, `dg_parent`, import summary
* `_internal` at a profile: the complete profile for the internal UI API (see above)
* `placeholders`: objects created because something refers to them (PAN-OS predefined copy / placeholder) with the
  reason
* `incomplete`: imported objects with content that has no SCM field
* `not_imported`: objects that cannot be created (with the reason) and what refers to them
* `warnings`: what is not part of this step (NAT / decryption / … rules, data filtering profiles …)

`scm_pa_change.php` does not send `source`, `placeholders`, `incomplete`, `not_imported`, `warnings` and shows their
numbers.

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

* Panorama shared rules go to `All` with `shared=all` – they apply to Prisma Access as well (warning).
* `dg-parent` below `ngfw-shared` (e.g. a lab folder `pan-os-php-test`): takes folder levels from the device-group
  tree – with a level-1 folder only 3 device-group levels fit. A deeper hierarchy is refused (converter and
  `scm_pa_change.php` check the 4 levels). Existing folder → unchanged; missing → created below `ngfw-shared`.
* A second run with the same file finds nothing to do (all "unchanged").
* Folders without a firewall cannot be pushed (candidate configuration only).

The same options exist in `type=scm-import` (`scope=device-groups|templates dg-parent=… device-group=… shared=global|folder|skip`),
which writes the `pan-os-php-scm-changes` file for `type=scm-apply` instead.
