# Concept: Panorama → SCM migration firewall by firewall

Status: concept (2026-11-14). Steps 1 and 3 run with the existing tools; step 2 (onboarding) is new.

```
1) import       Panorama XML ──► change.json ──► SCM   (everything SCM can take: folders, snippets, objects, profiles,
                                                         rules, zones, interface variables …)
2) onboard FW1  serial ──► device in its device-group folder, interface variable values + addresses of the device
3) sync         Panorama XML (newer export) ──► change.json ──► SCM   (delta: changes in Panorama since step 1,
                                                                         device-groups and templates / snippets)
4) onboard FW2  as 2)
   …            3) and 2) again until the last firewall is in SCM; then Panorama is no longer the source
```

During the migration Panorama stays the source of the configuration ("Panorama → SCM, one way"). Changes are made in
Panorama and brought over with step 3 – until the last firewall is migrated. Changes made directly in SCM are
detected (hash check) and not overwritten.

## 1) Import

`scm_pa_panorama_to_change.php` + `scm_pa_change.php` (README_pa_panorama_import.md). The change file also lists:

* `placeholders`, `incomplete`, `not_imported` – review lists
* `interface_variables` – interface variable → Panorama interface per snippet
* `firewalls` – per serial: `folder` (device-group), `template_stack`, `snippets` (stack, then templates) and
  `interfaces`: variable → `interface`, `ip` (as in the template, Panorama template variables resolved: device value
  of the stack > stack variable > template variable), `ip_source`

  Interface address as address object name: Panorama – a template refers to shared objects only. SCM – the name is
  kept (snippet and `firewalls[].interfaces[].ip`), SCM resolves it on the device: the object of the folder
  (device-group hierarchy) wins over the one of `All`. `address_objects` only shows the resolution: `scm` (closest
  object in the device-group hierarchy, else shared) and, if a device-group object with the same name has another
  value than the shared one, `panorama` (what the firewall got from Panorama) plus a warning – a dependency of the
  PAN-OS / SCM design, the consultant decides. To verify live: SCM accepts an address object name of `All` as
  interface address in a snippet.

## 2) Onboarding of one firewall (new: `scm_pa_onboard.php`, planned)

Precondition: the firewall is associated with the tenant (device association / ZTP – not possible through the
configuration API: `devices` has PUT only).

```
php scm_pa_onboard.php in=scm-api://<TSG> changes=change.json serial=<serial> [execute] [push]
```

1. device exists in SCM? else stop: "not onboarded – associate the device first"
2. device → folder of its device-group (`PUT /config/setup/v1/devices/{id}` `folder`)
3. interface variables of the device: value per variable from `firewalls[].interfaces` (`$ethernet1_1` →
   `ethernet1/1`) – **API unknown, HAR needed** (UI: set the value of an interface variable at a device)
4. device specific addresses: the template addresses are in the snippet now (for one firewall per stack correct);
   with several firewalls on one template-stack (Panorama template variables per device) the addresses go to the
   device (device level interface configuration / variables) – same HAR
5. verify (read back), optional push of the folder (first firewall in the folder → push possible)

Report per firewall: done / not onboarded / values not set.

## 3) Sync Panorama → SCM

Same two commands as step 1 with a newer Panorama export. Already today:

* new objects / rules → create; changed → update (hash check: an object changed in SCM since the last run is a
  conflict, not overwritten); unchanged → nothing
* rule order of the file is verified

Missing for a real sync:

* **deletes**: an object removed in Panorama must be removed in SCM – but only objects the import created, never
  objects created in SCM. Plan: run state file per tenant (`<outdir>/<TSG>/panorama-import-state.json`: every object
  the import wrote, with container and hash). Sync: in state, not in the new change file → `_delete` (reference
  check first; a referenced object is reported, not deleted).
* **renames**: Panorama rename = delete + create in SCM (uuid differs) – rule references are rewritten by Panorama,
  so the new rule body refers to the new name.
* **rule moves**: order differences are reported today; moving existing rules (`/move`) to be added.
* scope: `device-group=` restricts the sync to the device-groups of the migrated firewalls (optional).

## 4) Further firewalls

Step 2 per firewall. A firewall whose template-stack / device-group is already imported needs no new snippet data –
only its device values. A new template-stack / device-group comes with the sync (step 3).

## Open

| item | needed |
|---|---|
| interface variable value per device | HAR: UI, device → interface variable value |
| move device into folder | HAR or test with `PUT devices/{id}` |
| Panorama template variables in interface addresses (`$ip-out`) | SCM variables in the snippet (`/config/setup/v1/variables`, type ip-netmask) with the template value, device value at the device |
| NAT, decryption rules, logical routers / static routes, IKE / IPsec, device settings (DNS, NTP …) | further import steps (SCM supported) |
| data filtering (Enterprise DLP) | HAR of a tenant with DLP license |
| Panorama side after onboarding | out of scope of the tools (firewall removed from Panorama management by the consultant) |
