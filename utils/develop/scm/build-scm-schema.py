#!/usr/bin/env python3
"""
Build lib/resources/scm/scm-ngfw-config-schema.json from the official SCM OpenAPI specs.

The specs live in https://github.com/PaloAltoNetworks/pan.dev under openapi-specs/scm/config/ngfw.

  git clone --depth 1 --filter=blob:none --sparse https://github.com/PaloAltoNetworks/pan.dev.git
  cd pan.dev && git sparse-checkout set openapi-specs/scm
  python3 build-scm-schema.py /path/to/pan.dev /path/to/pan-os-php/lib/resources/scm/scm-ngfw-config-schema.json

The result is a compact field tree per resource (API path, POST query parameters, request body schema).
pan-os-php uses it to build and validate the JSON bodies of SCM API requests.
"""
import json
import subprocess
import sys

import yaml

FILES = {
    'objects': 'objects/objects_R3.yaml',
    'security': 'security/security-services.yaml',
    'network': 'network/network-services.yaml',
    'setup': 'setup/config-setup_R3.yaml',
}
WANT = {
    'objects': ['addresses', 'address-groups', 'services', 'service-groups', 'tags', 'schedules',
                'log-forwarding-profiles'],
    'security': ['security-rules', 'profile-groups', 'anti-spyware-profiles', 'wildfire-anti-virus-profiles',
                 'vulnerability-protection-profiles', 'url-access-profiles', 'file-blocking-profiles',
                 'dns-security-profiles', 'url-categories'],
    'network': ['zones', 'zone-protection-profiles'],
    # folders and snippets are created (POST), devices only updated (PUT: folder, snippets)
    'setup': ['folders', 'snippets', 'devices'],
}


def res(doc, x):
    while isinstance(x, dict) and '$ref' in x:
        y = doc
        for p in x['$ref'].split('/')[1:]:
            y = y[p]
        x = y
    return x


def conv(doc, s, depth=0):
    s = res(doc, s)
    if depth > 14:
        return {'type': 'any'}
    t = s.get('type')
    if t == 'array':
        return {'type': 'array', 'items': conv(doc, s.get('items', {}), depth + 1)}

    props = {}
    req = list(s.get('required', []))
    objlike = t == 'object' or 'properties' in s
    for n, p in s.get('properties', {}).items():
        props[n] = conv(doc, p, depth + 1)

    scalar = None
    for comb in ('allOf', 'oneOf', 'anyOf'):
        for part in s.get(comb, []):
            part_r = res(doc, part)
            c = conv(doc, part_r, depth + 1)
            title = part_r.get('title')
            # a variant without type of its own that only groups alternatives (address_type, container_type) is merged
            wrapper = 'type' not in part_r and 'properties' not in part_r
            if title and objlike and comb != 'allOf' and not wrapper and title not in c.get('properties', {}):
                # the specs describe alternatives (zone types layer3 / tap / ..., flood red / syn_cookies, ...)
                # as oneOf variants named by 'title': the variant is the value of a field of that name
                props.setdefault(title, c)
            elif c.get('type') == 'object' and c.get('properties'):
                # a variant that holds the field itself (e.g. title 'folder' with property 'folder')
                objlike = True
                for n, p in c['properties'].items():
                    props.setdefault(n, p)
                if comb == 'allOf':
                    req += c.get('required', [])
            elif not objlike:
                scalar = c

    if objlike:
        o = {'type': 'object', 'properties': props}
        if req:
            o['required'] = sorted(set(req))
        return o
    if scalar:
        return scalar
    out = {'type': t or 'any'}
    if 'enum' in s:
        out['enum'] = s['enum']
    if s.get('readOnly'):
        out['readOnly'] = True
    return out


def main(pandev, out):
    base_dir = pandev.rstrip('/') + '/openapi-specs/scm/config/ngfw/'
    try:
        rev = subprocess.check_output(['git', '-C', pandev, 'log', '-1', '--format=%h %cs'], text=True).strip()
    except Exception:
        rev = 'unknown'

    api = {}
    for group, fname in FILES.items():
        doc = yaml.safe_load(open(base_dir + fname))
        base = doc['servers'][0]['url'].replace('https://api.strata.paloaltonetworks.com', '')
        for r in WANT[group]:
            ops = doc['paths'].get('/' + r, {})
            if 'post' in ops:
                op = ops['post']
                methods = ['POST', 'PUT', 'DELETE']
            else:
                op = doc['paths']['/' + r + '/{id}']['put']
                methods = ['PUT']
            body = res(doc, op['requestBody'])
            sch = res(doc, body['content']['application/json']['schema'])
            api[r] = {
                'path': base + '/' + r,
                'methods': methods,
                'post_query': [res(doc, p).get('name') for p in op.get('parameters', [])] if 'post' in ops else [],
                'schema': conv(doc, sch),
            }

    data = {
        'source': 'github.com/PaloAltoNetworks/pan.dev @' + rev + ' openapi-specs/scm/config/ngfw: '
                  + ', '.join(FILES.values()),
        'api_base': 'https://api.strata.paloaltonetworks.com',
        'resources': api,
    }
    with open(out, 'w') as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
        fh.write('\n')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
