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
| `seq` | order to send in: POST, then PUT, then DELETE; referenced objects before the objects that use them, deletes in reverse |
| `method`, `path`, `query` | the SCM API call. `folder` / `snippet` / `device` is part of the POST body, as the SCM API expects |
| `id` | SCM id, taken from the `uuid` attribute the download writes into the XML. `null`: resolve it through `lookup` |
| `merge` | PUT only. An SCM PUT replaces the whole object, and the XML does not hold every field SCM has (e.g. the description of security profiles). So: GET the object, apply the fields of `body` (`null` removes a field), PUT the result |
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
file-blocking-profiles, dns-security-profiles, profile-groups, zone-protection-profiles, zones, security-rules.

Changes in other parts of a folder, snippet or device are reported in `warnings`, not sent. Creating or deleting
folders, snippets or devices and moving rules are not translated.

## Offline test

```bash
utils/develop/scm/test/scm-offline-test.sh
```

Builds an SCM XML from `test/scm-fixtures.json` with the real import code, runs the visibility playbook and single
util changes, and sends the result to a local SCM mock server (`test/scm-mock-server.php`).
