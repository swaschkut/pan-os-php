#!/usr/bin/env python3
"""
Initial state of scm-mock-server.php from scm-fixtures.json:
the objects of the fixtures, their folders and snippets, and the onboarded devices.

  python3 scm-mock-state.py scm-fixtures.json state.json [onboarded serial ...]

Devices cannot be created through the SCM API; the serials given here are onboarded in the mock
in addition to the devices of the fixtures.
"""
import json
import sys

fx = json.load(open(sys.argv[1]))
state = {}
for key, objs in fx['res'].items():
    for o in objs:
        state.setdefault(key.split('|')[0], {})[o['id']] = o

for f in fx['setup']['folders']:
    if f.get('type') in ('on-prem', 'cloud'):
        state.setdefault('devices', {})[f['id']] = {'id': f['id'], 'name': f['name'], 'folder': f['parent'], 'snippets': []}
    else:
        snippets = f.get('snippets', [])
        if f['name'] == 'All' and not snippets:
            snippets = ['predefined-snippet']   # as in a tenant: the predefined snippet is attached to All
        state.setdefault('folders', {})[f['id']] = {'id': f['id'], 'name': f['name'], 'parent': f.get('parent', ''),
                                                    'snippets': snippets}
for s in fx['setup']['snippets']:
    state.setdefault('snippets', {})[s['id']] = {'id': s['id'], 'name': s['name'], 'type': s.get('type', 'custom')}
for i, serial in enumerate(sys.argv[3:]):
    state.setdefault('devices', {})['onboarded-%d' % i] = {'id': 'onboarded-%d' % i, 'name': serial, 'folder': 'ngfw-shared', 'snippets': []}

json.dump(state, open(sys.argv[2], 'w'))
