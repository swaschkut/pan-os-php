# Changes from pan-os-php to Strata Cloud Manager (SCM API)

For Panorama and firewalls, pan-os-php writes its changes as set commands (`outputformatset=`).
For SCM it writes one SCM API request per changed object into a JSON file, and `type=scm-apply` sends that file.

## Workflow

```bash
# 1. download the SCM configuration as XML
pan-os-php type=address in=scm-api://<TSG_ID> location=any out=scm.xml

# 2. change it offline, e.g. with a playbook; outputformatscmjson= writes the SCM API requests at the end
pan-os-php type=playbook json=visibility.json in=scm.xml out=scm-visibility.xml outputformatscmjson=changes.json
#    or compare any two SCM XML files yourself
pan-os-php type=scm-changes file1=scm.xml file2=scm-visibility.xml out=changes.json

# 3. check, then send to the SCM candidate configuration
pan-os-php type=scm-apply changes=changes.json dry-run
pan-os-php type=scm-apply changes=changes.json tsg=<TSG_ID>

# 4. push the candidate configuration in SCM
```

`type=scm-apply` uses the `client_id` / `client_secret` that `in=scm-api://<TSG_ID>` stored in `~/.panconfkeystore`.

## Import a Panorama or firewall configuration (e.g. to fill a test tenant)

```bash
# Panorama
pan-os-php type=scm-import in=panorama.xml scm=scm.xml out=scm-import.xml changes=import.json [shared=snippet|global]
# firewall: into a new folder (optionally attaching the onboarded firewall) or into a snippet
pan-os-php type=scm-import in=firewall.xml target=folder [serial=SERIAL] scm=scm.xml out=scm-import.xml changes=import.json
pan-os-php type=scm-import in=firewall.xml target=snippet [name=NAME] scm=scm.xml out=scm-import.xml changes=import.json

pan-os-php type=scm-apply changes=import.json tsg=<TSG_ID> [dry-run]
```

Panorama without firewalls: `scope=device-groups` (shared + device-groups) or `scope=templates` (+ templates /
template-stacks as snippets, attached to the device-group folders: stack, then its templates – from the firewalls of
the device-group); `dg-parent=<folder below ngfw-shared>` (default ngfw-shared, max. 4 folder levels below it),
`device-group=DG1,DG2`, `shared=global|folder|skip`. The same import as change request for
`scm_pa_change.php`: `utils/develop/sase/scm/scm_pa_panorama_to_change.php` (README_pa_panorama_import.md there).

`scm=` is the download of the target tenant (without it an empty SCM configuration is used); `out=` is that
configuration with the import, the base for the next changes (playbook on `scm-import.xml`).

| Panorama | SCM |
|---|---|
| shared | a snippet attached to `All` (`shared=snippet`, default, name `shared-snippet=`) or directly `All` (`shared=global`) |
| device-group | folder below the firewall folder (`ngfw-shared`); the device-group hierarchy is kept |
| template | snippet |
| template-stack (its own configuration) | snippet |
| managed firewall | device in the folder of its device-group, with the snippets of its template-stack attached: the stack on top, then its templates in stack order (in SCM the top snippet wins, as the stack wins over its templates in Panorama) |

| Firewall | SCM |
|---|---|
| shared + one vsys (`vsys=`, default vsys1) | `target=folder`: new folder below the firewall folder (name: `name=` or hostname); `target=snippet`: new snippet |

Imported: tags, addresses, address groups, services, service groups, schedules, log forwarding profiles, custom URL
categories, security profiles (anti-spyware, vulnerability, URL filtering, file blocking, DNS security), profile
groups, security rules (firewall `rulebase` becomes pre-rules), zones and zone protection profiles (PAN-OS field names
are translated to the SCM names). Not imported, reported with their number: NAT, decryption, PBF, QoS, authentication
and application override rules, EDLs, custom applications, data filtering and decryption profiles, antivirus and
WildFire profiles (SCM combines them in one profile type).

- Zone interfaces are removed (interfaces are not imported); `keep-zone-interfaces` keeps them.
- A name that exists at the target already is not copied; the existing object stays (warning).
- Panorama and PAN-OS uuids are removed: they are not SCM ids.
- Firewalls cannot be created through the API. The device request attaches an onboarded firewall to its folder and
  snippets; for a firewall that is not onboarded it is skipped (`skipped-missing`).
- Objects marked `review` are not sent. They do not exist in SCM afterwards, so later changes to them fail.

## The changes file

```json
{
  "format": "pan-os-php-scm-changes",
  "version": 1,
  "api_base": "https://api.strata.paloaltonetworks.com",
  "summary": { "POST": 10, "PUT": 7, "DELETE": 0, "review": 8 },
  "warnings": [ "..." ],
  "requests": [
    {
      "seq": 13,
      "method": "PUT",
      "path": "/config/security/v1/profile-groups/pg-1",
      "id": "pg-1",
      "query": {},
      "merge": true,
      "body": { "file_blocking": ["Alert-Only-FB"], "url_filtering": ["Alert-Only-URL"] },
      "before": { "file_blocking": null, "url_filtering": null },
      "object": { "resource": "profile-groups", "name": "best-practice", "scope_type": "folder",
                  "scope": "ngfw-shared", "position": null,
                  "xpath": "/config/devices/entry[@name='localhost.localdomain']/container/entry[@name='ngfw-shared']/profile-group/entry[@name='best-practice']" },
      "lookup": { "name": "best-practice", "folder": "ngfw-shared" },
      "depends_on": [7, 8],
      "review": false,
      "warnings": []
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `seq` | order to send in: POST, then PUT, then DELETE; snippets and folders (parents first) before their objects, referenced objects before the objects that use them, rules in their order, devices last, deletes in reverse |
| `method`, `path`, `query` | the SCM API call. `folder` / `snippet` / `device` is part of the POST body, as the SCM API expects |
| `id` | SCM id, taken from the `uuid` attribute the download writes into the XML. `null`: resolve it through `lookup` |
| `merge` | PUT only. An SCM PUT replaces the whole object, and the XML does not hold every field SCM has (e.g. the description of security profiles). So: GET the object, apply the fields of `body` (`null` removes a field), PUT the result |
| `merge_lists` | `{"snippets": "keep-others"}` (folders, devices): the listed snippets go on top in this order, snippets the live object has besides them stay below, so e.g. the predefined snippet is kept |
| `skip_if_missing` | devices: skipped when the firewall is not onboarded in SCM |
| `body` | POST: the full new object. PUT: only the changed top-level fields |
| `before` | the old values of the changed fields, for review only |
| `object.xpath` | where the object is in the XML |
| `depends_on` | `seq` of POSTs this request needs; `type=scm-apply` skips the request if one of them did not succeed |
| `review` | the change could not be translated completely, see `warnings`; `type=scm-apply` skips it unless `include-review` |

## How bodies are built

`lib/resources/scm/scm-ngfw-config-schema.json` holds the request schema of each resource, generated from the official
SCM OpenAPI specs with `utils/develop/scm/build-scm-schema.py`. An XML element becomes a JSON field when the schema has
it (`-` becomes `_`, `yes`/`no` booleans, `<member>` lists, `<entry name=>` lists of objects). A field the schema does
not have is not sent; when it carries configuration, the request is marked `review`.

A request is also marked `review` when it references an object (profile group, security profile, log forwarding
profile, zone protection profile) that is neither in the configuration nor created by this change set, or when it
depends on a POST that needs review.

## Supported resources

tags, addresses, address-groups, services, service-groups, schedules, log-forwarding-profiles, url-categories,
anti-spyware-profiles, vulnerability-protection-profiles, wildfire-anti-virus-profiles, url-access-profiles,
file-blocking-profiles, dns-security-profiles, profile-groups, zone-protection-profiles, zones, security-rules;
setup: new snippets and folders (POST), snippets attached to and the parent of folders and devices (PUT).

Changes in other parts of a folder, snippet or device are reported in `warnings`, not sent. Deleting folders,
snippets or devices, detaching snippets and moving rules are not translated.

## Offline test

```bash
utils/develop/scm/test/scm-offline-test.sh
```

Builds an SCM XML from `test/scm-fixtures.json` with the real import code, runs the visibility playbook and single
util changes, imports `tests/input/panorama-10.0-manageddevice-nodg.xml` and a firewall configuration, and sends
everything to a local SCM mock server (`test/scm-mock-server.php`, state from `test/scm-mock-state.py`).
