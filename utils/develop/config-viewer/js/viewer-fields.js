/*
 * pan-os-php config viewer - browser part, the fields of the object windows of the viewer (what a window shows of an
 * object and the pan-os-php action a changed field becomes).
 * Part of app.js (showViewer) in a file of its own: declarations only - nothing runs when the file is loaded.
 */
'use strict';

// a link to an object in a new window: the list of its type with only it, and its window opened
// the connections of a device for its window (objLinks): [label, devicetype of the other device, names, extra links]
const DEVICE_LINKS = {
    DeviceGroup: r => [['Parent device group', 'devicegroup', Array.isArray(r.hierarchy) && r.hierarchy.length > 2 ? r.hierarchy[r.hierarchy.length - 2] : null],
        ['Child device groups', 'devicegroup', r.children],
        // each firewall with its template stack and the templates of the stack (priority order)
        ['Firewalls', 'manageddevice', r.devices, n => {
            const ts = r.templatestacks && r.templatestacks[n];
            if (!ts) return [];
            const tpls = r.stacktemplates && Array.isArray(r.stacktemplates[ts]) ? r.stacktemplates[ts] : [];
            return [['template stack', 'templatestack', ts], ...tpls.map((t, i) => ['template ' + (i + 1), 'template', t])];
        }]],
    TemplateStack: r => [['Templates (first = highest priority)', 'template', r.templates],
        ['Firewalls', 'manageddevice', r.devices, n => r.devicegroups && r.devicegroups[n] ? [['device group', 'devicegroup', r.devicegroups[n]]] : []]],
    ManagedDevice: r => [['Device group', 'devicegroup', r.dg], ['Template stack', 'templatestack', r.templatestack],
        ['Templates of the stack', 'template', r.templates], ['Template', 'template', r['device-template']],
        // SCM: the on-prem device (folder of the firewall) and the container of its vsys
        ['On-prem device', 'deviceonprem', r['on-prem']], ['Vsys container', 'container', r.vsyscontainer]],
    LogCollectorGroup: r => [['Log collectors', 'logcollector', r.collectors],
        ['Firewalls (Device Log Forwarding)', 'manageddevice', r.devices, n => (r.logforwarding && r.logforwarding[n] || []).map(c => ['log collector', 'logcollector', c])]],
    LogCollector: r => [['Collector groups', 'logcollectorgroup', r.collectorgroups], ['Firewalls that send logs to it', 'manageddevice', r.devices]],
    // SCM: folders (containers) with parent, children, devices below and attached snippets; a snippet: where it is attached
    Container: r => [['Parent container', 'container', r.parent], ['Child containers', 'container', r.children],
        ['Cloud devices', 'devicecloud', r.clouds], ['On-prem devices', 'deviceonprem', r.onprem], ['Snippets', 'snippet', r.snippets]],
    DeviceCloud: r => [['Parent container', 'container', r.parent], ['Snippets', 'snippet', r.snippets]],
    DeviceOnPrem: r => [['Parent container', 'container', r.parent], ['Snippets', 'snippet', r.snippets], ['Managed device', 'manageddevice', r.manageddevice]],
    Snippet: r => [['Attached to containers', 'container', r.containers], ['Attached to cloud devices', 'devicecloud', r.clouds], ['Attached to on-prem devices', 'deviceonprem', r.onprem]],
};

const DEVICE_KIND = { ManagedDevice: 'manageddevice', TemplateStack: 'templatestack', Template: 'template', DeviceGroup: 'devicegroup',
    Container: 'container', DeviceCloud: 'devicecloud', DeviceOnPrem: 'deviceonprem', Snippet: 'snippet' };

// ---- object window (overlay, as the edit dialog of PAN-OS): each field is applied when it is left after a change -
// as one pan-os-php action on exactly this object (location of the object, filter (name eq …)); see
// todo/config-viewer-panos-style-edit.md
function actArg(v) {
    // pan-os-php: "," separates the arguments, ":" the action from its arguments, "/" the actions ("//" = a "/")
    if (/[,:\x00-\x1f]/.test(v)) throw new Error('"," and ":" can not be used in a value here (they separate the arguments of a pan-os-php action)');
    return v.replace(/\//g, '//');
}

// the assignments of Panorama as PAN-OS keeps them - on the device group / template stack (<devices>, <templates>),
// with the actions of pan-os-php type=device; a firewall: its device group / template stack changed by those
// actions (out of the old one, into the new one)
function deviceFields(row) {
    const list = v => Array.isArray(v) ? v.map(String) : (v ? [String(v)] : []);
    const serial = v => { v = v.trim(); if (!/^[A-Za-z0-9]+$/.test(v)) throw new Error('a serial number: letters and digits'); return v; };
    if (row.type === 'DeviceGroup')
        return [{ key: 'dg-devices', label: 'Firewalls', kind: 'list', value: list(row.devices), needs: ['devicegroup-addserial'], needsRemove: ['devicegroup-removeserial'],
                add: x => 'devicegroup-addserial:' + actArg(row.name) + ',' + serial(x), remove: x => 'devicegroup-removeserial:' + actArg(row.name) + ',' + x,
                note: 'serial number; a firewall is in one device group - remove it from the other one first' },
            { key: 'dg-parent', label: 'Parent device group', kind: 'text', value: Array.isArray(row.hierarchy) && row.hierarchy.length > 2 ? row.hierarchy[row.hierarchy.length - 2] : '',
                placeholder: 'empty = shared', needs: ['devicegroup-setparentdg'], act: (o, n) => 'devicegroup-setparentdg:' + actArg(row.name) + ',' + (n === '' ? 'shared' : actArg(n)) }];
    if (row.type === 'TemplateStack')
        return [{ key: 'ts-templates', label: 'Templates', kind: 'list', value: list(row.templates), needs: ['template-add'], needsRemove: ['template-remove'],
                add: x => 'template-add:' + actArg(x.trim()), remove: x => 'template-remove:' + actArg(x),
                note: 'first = highest priority; a template is added at the bottom (pan-os-php template-add)' },
            { key: 'ts-devices', label: 'Firewalls', kind: 'list', value: list(row.devices), needs: ['templatestack-addserial'], needsRemove: ['templatestack-removeserial'],
                add: x => 'templatestack-addserial:' + actArg(row.name) + ',' + serial(x), remove: x => 'templatestack-removeserial:' + actArg(row.name) + ',' + x,
                note: 'serial number; a firewall is in one template stack - remove it from the other one first' }];
    if (row.type === 'ManagedDevice') {
        const move = (add, remove) => (o, n) => [o ? remove + ':' + actArg(o) + ',' + row.name : null, n ? add + ':' + actArg(n) + ',' + row.name : null].filter(x => x).join('/');
        return [{ key: 'md-dg', label: 'Device group', kind: 'text', value: row.dg || '', placeholder: 'none', needs: ['devicegroup-addserial', 'devicegroup-removeserial'],
                act: move('devicegroup-addserial', 'devicegroup-removeserial'), note: 'kept in the device group (<devices>): out of the old one, into the new one' },
            { key: 'md-ts', label: 'Template stack', kind: 'text', value: row.templatestack || '', placeholder: 'none', needs: ['templatestack-addserial', 'templatestack-removeserial'],
                act: move('templatestack-addserial', 'templatestack-removeserial'), note: 'kept in the template stack (<devices>): out of the old one, into the new one' }];
    }
    return [];
}

// ctx: what the fields of a rule need of the viewer - { ruletype (the rule type of the menu entry, .value),
// locationInfo (kind of the configuration) }
function windowFields(kind, row, m, ctx) {
    m = m || {};
    const name = { key: 'name', label: 'Name', kind: 'text', value: row.name, needs: ['name-rename'], rename: true,
        act: (o, n) => { if (n === '') throw new Error('a name is needed'); return 'name-rename:' + actArg(n); } };
    const desc = { key: 'description', label: 'Description', kind: 'text', value: row.description || '', needs: ['description-set'],
        act: (o, n) => n === '' ? 'description-set' : 'description-set:' + ruleText(n) };
    const tags = { key: 'tag', label: 'Tags', kind: 'list', value: Array.isArray(m.tag) ? m.tag : [], needs: ['tag-add'], needsRemove: ['tag-remove'],
        add: t => 'tag-add:' + actArg(t), remove: t => 'tag-remove:' + actArg(t) };
    const loc = { key: 'location', label: 'Location', kind: 'ro', value: row.location };
    if (kind === 'address')
        return [name, ['ip-netmask', 'ip-range', 'ip-wildcard', 'fqdn'].includes(row.type)
            ? { key: 'value', label: 'Type / value', kind: 'parts', value: { type: row.type, value: row.value || '' }, needs: ['value-set'],
                note: 'e.g. 10.0.0.0/24, 2001:db8::/32, 10.0.0.1-10.0.0.99, 10.0.0.1/0.255.0.255, www.example.com',
                parts: [{ key: 'type', kind: 'select', label: 'type', choices: [['ip-netmask', 'ip-netmask'], ['ip-range', 'ip-range'], ['ip-wildcard', 'ip-wildcard'], ['fqdn', 'fqdn']] },
                    { key: 'value', kind: 'text', label: 'value' }],
                act: (o, v) => { const n = v.value.trim(); if (n === '') return { hint: 'enter the value' }; if (n === o.value && v.type === o.type) return '';
                    if (v.type !== o.type && n === o.value) return { hint: 'enter the value for ' + v.type };
                    return 'value-set:' + ruleText(n) + ',' + v.type; } }
            : { key: 'value', label: 'Type / value', kind: 'ro', value: (row.type || '') + ' ' + (row.value || '') },
            desc, tags, loc];
    if (kind === 'addressgroup')
        return [name, { key: 'type', label: 'Type', kind: 'ro', value: row.type },
            Array.isArray(m.static) ? { key: 'members', label: 'Members', kind: 'list', value: m.static, needs: ['add-member'], needsRemove: ['remove-member'],
                add: x => 'add-member:' + actArg(x), remove: x => 'remove-member:' + actArg(x),
                note: 'an object / group of the location or above it; the last member can not be removed' }
                : { key: 'filter', label: 'Dynamic filter', kind: 'ro', value: row.filter || '', note: 'no pan-os-php action to change it yet' },
            desc, tags, loc];
    if (kind === 'service') {
        const timeout = (key, label, action, def) => ({ key, label, kind: 'text', value: row[key] || '', needs: [action], placeholder: 'default ' + def + ' (= inherit)',
            act: (o, n) => { if (n === '') throw new Error('empty: use "Inherit all timeouts"'); if (!/^[0-9]+$/.test(n)) throw new Error('seconds (digits)'); return action + ':' + n; } });
        const proto = String(m.protocol && typeof m.protocol === 'object' ? Object.keys(m.protocol)[0] || '' : (row.protocol || ''));
        const pm = m.protocol && typeof m.protocol === 'object' && m.protocol[proto] && typeof m.protocol[proto] === 'object' ? m.protocol[proto] : {};
        const dport = pm.port !== undefined ? String(pm.port) : (row.dport || '');
        return [name, ['tcp', 'udp'].includes(proto) ? { key: 'protocol', label: 'Protocol', kind: 'select', value: proto, choices: ['tcp', 'udp'], needs: ['protocol-set'],
                note: 'udp: the half-close / time-wait timeouts go back to inherit', act: (o, n) => 'protocol-set:' + n }
                : { key: 'value', label: 'Protocol / port', kind: 'ro', value: row.value || '' },
            ['tcp', 'udp'].includes(proto) ? { key: 'dport', label: 'Destination port', kind: 'text', value: dport, needs: ['dstport-set'], note: 'ports / ranges, e.g. 80,443,8000-8080',
                act: (o, n) => { const p = n.replace(/\s/g, ''); if (!/^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$/.test(p)) throw new Error('ports / ranges, e.g. 80,443,8000-8080'); return 'dstport-set:' + p.replace(/,/g, '|'); } } : null,
            desc, tags,
            { key: 'sourceport', label: 'Source port', kind: 'text', value: row.sourceport || '', needs: ['sourceport-set', 'sourceport-delete'],
                act: (o, n) => n === '' ? 'sourceport-delete' : 'sourceport-set:' + actArg(n) },
            timeout('timeout', 'Timeout', 'timeout-set', 3600), timeout('halfclosetimeout', 'Half-close timeout', 'timeout-halfclose-set', 120),
            timeout('timewaittimeout', 'Time-wait timeout', 'timeout-timewait-set', 15),
            { key: 'timeouts', label: '', kind: 'button', text: 'Inherit all timeouts', needs: ['timeout-inherit'], act: () => 'timeout-inherit' }, loc].filter(f => f);
    }
    if (kind === 'servicegroup')
        return [name, { key: 'members', label: 'Members', kind: 'list', value: Array.isArray(m.members) ? m.members : [], needs: ['add-member'], needsRemove: ['remove-member'],
                add: x => 'add-member:' + actArg(x), remove: x => 'remove-member:' + actArg(x),
                note: 'a service / service group of the location or above it; the last member can not be removed' },
            tags, loc];
    if (kind === 'rule') return ruleFields(row, m, name, loc, ctx);
    if (kind === 'zone') {
        const bool = (key, label, action) => ({ key, label, kind: 'select', value: '', choices: ['', 'yes', 'no'], needs: [action],
            note: 'the current value is not in the list of pan-os-php - choose to set it', act: (o, n) => n === '' ? '' : action + ':' + (n === 'yes' ? 'true' : 'false') });
        return [name, { key: 'type', label: 'Type', kind: 'ro', value: m.network ? Object.keys(m.network).join(', ') : (row.type || '') },
            (() => {
                const zt = m.network && typeof m.network === 'object' ? Object.keys(m.network).find(k => ['layer3', 'layer2', 'virtual_wire', 'tap'].includes(k)) : null;
                return zt ? { key: 'interfaces', label: 'Interfaces', kind: 'list', value: Array.isArray(m.network[zt]) ? m.network[zt].map(String) : [], needs: ['interface-add'], needsRemove: ['interface-remove'],
                    add: x => 'interface-add:' + actArg(x), remove: x => 'interface-remove:' + actArg(x), note: 'an interface of the zone type, imported into the vsys, in no other zone' }
                    : { key: 'interfaces', label: 'Interfaces', kind: 'ro', value: fmtTree(m.network) || fmtTree(row.interfaces) || '-' };
            })(),
            { key: 'zpp', label: 'Zone protection profile', kind: 'text', value: row.zpp || '', needs: ['zpp-set'],
                act: (o, n) => { if (n === '') throw new Error('removing it: no pan-os-php action yet'); return 'zpp-set:' + actArg(n); } },
            { key: 'log', label: 'Log setting', kind: 'text', value: row.log || '', placeholder: 'empty = PAN-OS default', needs: ['logsetting-set'], act: (o, n) => 'logsetting-set:' + (n === '' ? 'none' : actArg(n)) },
            bool('userid', 'User identification', 'userid-enable'), bool('pbp', 'Packet buffer protection', 'packetbufferprotection-set'),
            row.template ? { key: 'template', label: 'Template', kind: 'ro', value: row.template } : null, loc].filter(f => f);
    }
    if (['ikegateway', 'ikeprofile', 'ipsecprofile', 'ipsectunnel', 'interface', 'imp', 'zpp', 'routing', 'sroute', 'gre', 'dhcp', 'vwire', 'gpportal', 'gpgateway'].includes(kind)) {
        // the object stays at the firewall / template (location shared); the vsys that import it are named
        const f = networkFields(kind, row, m, loc);
        if (row.vsys) { const v = { key: 'vsys', label: 'Imported by vsys', kind: 'ro', value: row.vsys }, i = f.indexOf(loc); if (i < 0) f.push(v); else f.splice(i, 0, v); }
        return f;
    }
    if (kind === 'generic') {
        // every other type: all its fields, read only - the list row and what the structured model adds
        const skip = ['name', 'location', 'template', 'refcount', 'store', 'model'];
        const edit = deviceFields(row);
        // a device: its connections (device group, template stack, templates, firewalls, log collectors) are in
        // the section "Connections" of the window, with a link each
        if (DEVICE_LINKS[row.type]) skip.push('templates', 'devices', 'dg', 'templatestack', 'device-template', 'collectors', 'collectorgroups', 'devicegroups', 'logforwarding', 'children', 'hierarchy', 'templatestacks', 'stacktemplates', 'parent', 'clouds', 'onprem', 'snippets', 'containers', 'manageddevice', 'on-prem', 'vsyscontainer', 'variables', 'effective', 'devicevariables');
        const fields = [{ key: 'name', label: 'Name', kind: 'ro', value: row.name }];
        // an application: its details (category, technology, risk, ports, …) as fields of their own
        if (Array.isArray(row.app) && row.app.length === 1 && row.app[0] && typeof row.app[0] === 'object') {
            const d = Object.values(row.app[0])[0];
            if (d && typeof d === 'object') {
                for (const [k, v] of Object.entries(d)) if (k !== 'name' && v !== '' && v !== null) fields.push({ key: 'app-' + k, label: k, kind: 'ro', value: typeof v === 'object' ? fmtTree(v) : String(v) });
                skip.push('app');
            }
        }
        for (const [k, v] of Object.entries(row)) if (!skip.includes(k)) fields.push({ key: k, label: k, kind: 'ro', value: typeof v === 'object' && v !== null && !Array.isArray(v) ? fmtTree(v) : (Array.isArray(v) ? fmtTree(v) : (v === null ? '' : String(v))) });
        for (const [k, v] of Object.entries(m)) if (!(k in row) && !['name', 'device_group', 'template', 'vsys', 'folder', 'snippet'].includes(k))
            fields.push({ key: 'm-' + k, label: k, kind: 'ro', value: typeof v === 'object' && v !== null ? fmtTree(v) : String(v) });
        if (row.template) fields.push({ key: 'template', label: 'Template', kind: 'ro', value: row.template });
        fields.push(...edit, loc);
        return fields;
    }
    if (kind === 'tag') {
        const cs = (state.meta.types.tag.actions['color-set'] || [])[0];
        return [name,
            { key: 'color', label: 'Color', kind: 'select', value: row.color || 'none', choices: cs && cs.choices ? cs.choices : [], needs: ['color-set'], act: (o, n) => 'color-set:' + actArg(n) },
            { key: 'comments', label: 'Comments', kind: 'text', value: row.comments || '', needs: ['comments-delete', 'comments-add'],
                act: (o, n) => n === '' ? 'comments-delete' : (o === '' ? '' : 'comments-delete/') + 'comments-add:' + ruleText(n) }, loc];
    }
    return [name, loc];
}

// IKE gateway, IKE / IPsec crypto profile, IPsec tunnel: the values of the model, each changed by its pan-os-php
// action (type=ike-gateway / ike-profile / ipsec-profile / ipsec-tunnel …-set); what has no action stays read only
function networkFields(kind, row, m, loc) {
    const yn = v => v === true || v === 'yes' ? 'yes' : (v === false || v === 'no' ? 'no' : '');
    const get = (o, ...path) => path.reduce((x, k) => (x && typeof x === 'object' ? x[k] : undefined), o);
    const words = v => Array.isArray(v) ? v.map(String) : (v === undefined || v === null || v === '' ? [] : [String(v)]);
    const keywords = (n, what) => { const l = n.split(/[\s,|]+/).map(x => x.trim()).filter(x => x); if (!l.length) throw new Error(what + ': at least one'); return l.map(actArg).join('|'); };
    const sel = (key, label, value, choices, action, note) => ({ key, label, kind: 'select', value, choices, needs: [action], note,
        act: (o, n) => n === '' ? '' : action + ':' + n });
    const flag = (key, label, value, action, argPrefix) => ({ key, label, kind: 'select', value: yn(value), choices: ['yes', 'no'], needs: [action],
        act: (o, n) => n === '' ? '' : action + ':' + (argPrefix || '') + n });
    const name = (key, label, value, action, suffix, note) => ({ key, label, kind: 'text', value: value || '', needs: [action], note,
        act: (o, n) => { if (n === '') throw new Error(label + ': a name is needed'); return action + ':' + actArg(n) + (suffix || ''); } });
    const amount = (key, label, value, action, units, optional) => {
        const unit = value && typeof value === 'object' ? Object.keys(value)[0] || '' : '';
        return { key, label, kind: 'parts', value: { unit, value: unit ? String(value[unit]) : '' }, needs: [action],
            parts: [{ key: 'unit', kind: 'select', label: 'unit', choices: (optional ? [['', 'none']] : []).concat(units.map(u => [u, u])) },
                { key: 'value', kind: 'text', label: 'value', show: v => v.unit !== '' }],
            act: (o, v) => {
                if (v.unit === '') return o.unit === '' ? '' : action;
                if (!/^[0-9]+$/.test(v.value.trim())) return { hint: 'a number' };
                return action + ':' + v.unit + ',' + v.value.trim();
            } };
    };
    const ident = (which) => {
        const id = m[which + '_id'] || {};
        return { key: which + '-id', label: which === 'local' ? 'Local identification' : 'Peer identification', kind: 'parts', value: { type: id.type || '', id: id.id || '' },
            needs: [which + '-id-set'],
            parts: [{ key: 'type', kind: 'select', label: 'type', choices: [['', 'none'], ['ipaddr', 'IP address'], ['fqdn', 'FQDN'], ['ufqdn', 'user FQDN'], ['keyid', 'key ID'], ['dn', 'distinguished name']] },
                { key: 'id', kind: 'text', label: 'id', show: v => v.type !== '' }],
            act: (o, v) => {
                if (v.type === '') return o.type === '' ? '' : which + '-id-set';
                if (!v.id.trim()) return { hint: 'enter the id' };
                return which + '-id-set:' + v.type + ',' + actArg(v.id.trim());
            } };
    };
    // the other values of the model, read only (nothing is left out)
    const rest = (used) => Object.entries(m).filter(([k]) => !used.includes(k) && !['name', 'device_group', 'template', 'template_stack', 'vsys', 'folder', 'snippet', 'device', '_panosphp'].includes(k))
        .map(([k, v]) => ({ key: 'm-' + k, label: k, kind: 'ro', value: typeof v === 'object' && v !== null ? fmtTree(v) : String(v) }));
    const ro = (key, label, value, note) => ({ key, label, kind: 'ro', value: value === undefined || value === null ? '' : value, note });
    // the name: name-rename (the users that name the object are changed too); an interface / DHCP: its interface, read only
    const nameRo = ['interface', 'dhcp'].includes(kind) ? ro('name', 'Name', row.name)
        : { key: 'name', label: 'Name', kind: 'text', value: row.name, needs: ['name-rename'], rename: true, note: 'renamed everywhere it is used',
            act: (o, n) => { if (n === '') throw new Error('a name is needed'); return 'name-rename:' + actArg(n); } };
    if (kind === 'ikegateway') {
        const pa = m.peer_address || {};
        const paType = pa.ip !== undefined ? 'ip' : pa.fqdn !== undefined ? 'fqdn' : pa.dynamic !== undefined ? 'dynamic' : '';
        const psk = get(m, 'authentication', 'pre_shared_key', 'key');
        return [nameRo,
            sel('version', 'IKE version', get(m, 'protocol', 'version') || '', ['ikev1', 'ikev2', 'ikev2-preferred'], 'version-set'),
            name('ike2', 'IKE crypto profile (IKEv2)', get(m, 'protocol', 'ikev2', 'ike_crypto_profile'), 'ike-crypto-profile-set', ',ikev2', 'must exist here or above (parent folder / snippet / template)'),
            name('ike1', 'IKE crypto profile (IKEv1)', get(m, 'protocol', 'ikev1', 'ike_crypto_profile'), 'ike-crypto-profile-set', ',ikev1'),
            { key: 'peer', label: 'Peer address', kind: 'parts', value: { type: paType, value: pa.ip || pa.fqdn || '' }, needs: ['peer-address-set'],
                parts: [{ key: 'type', kind: 'select', label: 'type', choices: [['ip', 'IP'], ['fqdn', 'FQDN'], ['dynamic', 'dynamic']] },
                    { key: 'value', kind: 'text', label: 'value', show: v => v.type !== 'dynamic' }],
                act: (o, v) => {
                    if (v.type === 'dynamic') return o.type === 'dynamic' ? '' : 'peer-address-set:dynamic';
                    if (!v.value.trim()) return { hint: 'enter the ' + (v.type === 'ip' ? 'IP address' : 'FQDN') };
                    return 'peer-address-set:' + v.type + ',' + actArg(v.value.trim());
                } },
            name('lif', 'Local interface', get(m, 'local_address', 'interface'), 'local-interface-set'),
            { key: 'lip', label: 'Local IP', kind: 'text', value: get(m, 'local_address', 'ip') || '', placeholder: 'empty = none', needs: ['local-ip-set'],
                act: (o, n) => n === '' ? 'local-ip-set' : 'local-ip-set:' + actArg(n) },
            ident('local'), ident('peer'),
            flag('natt', 'NAT traversal', get(m, 'protocol_common', 'nat_traversal', 'enable'), 'nat-traversal-set'),
            flag('frag', 'Fragmentation', get(m, 'protocol_common', 'fragmentation', 'enable'), 'fragmentation-set'),
            flag('passive', 'Passive mode', get(m, 'protocol_common', 'passive_mode'), 'passive-mode-set'),
            flag('dpd2', 'Dead peer detection (IKEv2)', get(m, 'protocol', 'ikev2', 'dpd', 'enable'), 'dpd-set', 'ikev2,'),
            flag('dpd1', 'Dead peer detection (IKEv1)', get(m, 'protocol', 'ikev1', 'dpd', 'enable'), 'dpd-set', 'ikev1,'),
            sel('xmode', 'Exchange mode (IKEv1)', get(m, 'protocol', 'ikev1', 'exchange_mode') || '', ['auto', 'main', 'aggressive'], 'exchange-mode-set'),
            flag('disabled', 'Disabled', m.disabled, 'disabled-set'),
            ro('psk', 'Pre-shared key', psk !== undefined ? psk : (m.authentication ? fmtTree(m.authentication) : ''), 'encrypted, as the configuration has it - not changed here; the clear text: run "IKE gateways / PSK list"'),
            ...rest(['authentication', 'peer_address', 'local_address', 'local_id', 'peer_id', 'protocol', 'protocol_common', 'disabled']), loc];
    }
    if (kind === 'ikeprofile')
        return [nameRo,
            { key: 'enc', label: 'Encryption', kind: 'text', value: words(m.encryption).join(', '), needs: ['encryption-set'], note: 'one or more, e.g. aes-256-cbc, aes-128-cbc', act: (o, n) => 'encryption-set:' + keywords(n, 'encryption') },
            { key: 'hash', label: 'Authentication (hash)', kind: 'text', value: words(m.hash).join(', '), needs: ['hash-set'], note: 'one or more, e.g. sha256, sha384', act: (o, n) => 'hash-set:' + keywords(n, 'hash') },
            { key: 'dh', label: 'DH group', kind: 'text', value: words(m.dh_group).join(', '), needs: ['dh-group-set'], note: 'one or more, e.g. group14, group19', act: (o, n) => 'dh-group-set:' + keywords(n, 'DH group') },
            amount('life', 'Key lifetime', m.lifetime, 'lifetime-set', ['seconds', 'minutes', 'hours', 'days']),
            { key: 'amult', label: 'IKEv2 authentication multiple', kind: 'text', value: m.authentication_multiple !== undefined ? String(m.authentication_multiple) : '', needs: ['authentication-multiple-set'],
                placeholder: '0-50', act: (o, n) => { if (!/^[0-9]+$/.test(n)) throw new Error('0-50'); return 'authentication-multiple-set:' + n; } },
            ...rest(['encryption', 'hash', 'dh_group', 'lifetime', 'authentication_multiple']), loc];
    if (kind === 'ipsecprofile')
        return [nameRo,
            { key: 'enc', label: 'ESP encryption', kind: 'text', value: words(get(m, 'esp', 'encryption')).join(', '), needs: ['esp-encryption-set'], note: 'one or more, e.g. aes-256-gcm, aes-128-gcm (an AH profile becomes ESP)',
                act: (o, n) => 'esp-encryption-set:' + keywords(n, 'encryption') },
            { key: 'auth', label: 'ESP authentication', kind: 'text', value: words(get(m, 'esp', 'authentication')).join(', '), needs: ['esp-authentication-set'], note: 'one or more, e.g. sha256 - or none',
                act: (o, n) => 'esp-authentication-set:' + keywords(n, 'authentication') },
            { key: 'dh', label: 'DH group', kind: 'text', value: m.dh_group !== undefined ? String(m.dh_group) : '', needs: ['dh-group-set'], note: 'no-pfs or a group, e.g. group14',
                act: (o, n) => { if (!/^[a-z0-9-]+$/.test(n)) throw new Error('no-pfs or a group'); return 'dh-group-set:' + n; } },
            amount('life', 'Lifetime', m.lifetime, 'lifetime-set', ['seconds', 'minutes', 'hours', 'days']),
            amount('size', 'Lifesize', m.lifesize, 'lifesize-set', ['kb', 'mb', 'gb', 'tb'], true),
            ...rest(['esp', 'dh_group', 'lifetime', 'lifesize']), loc];
    if (kind === 'interface') {
        // ethernet / aggregate: the layer3 settings below layer3 (another mode: read only); a sub-interface, loopback,
        // tunnel, VLAN: below the entry
        const eth = /^(Ethernet|AggregateEthernet)Interface$/.test(String(row.type || '')) || m.layer3 !== undefined || m.layer2 !== undefined || m.aggregate_group !== undefined;
        const sub = eth && String(row.name).includes('.');
        const main = eth && !sub;
        const l3 = main ? m.layer3 : m;
        const used = ['comment', 'link_state'].concat(main ? ['layer3'] : ['ip', 'mtu', 'interface_management_profile', 'adjust_tcp_mss', 'tag']);
        const f = [nameRo, ro('class', 'Type', row.type || ''),
            { key: 'comment', label: 'Comment', kind: 'text', value: m.comment || '', needs: ['comment-set'], act: (o, n) => n === '' ? 'comment-set' : 'comment-set:' + actArg(n) }];
        if (main) f.push(sel('link', 'Link state', m.link_state || '', ['auto', 'up', 'down'], 'link-state-set'));
        if (sub) f.push({ key: 'tag', label: 'VLAN tag', kind: 'text', value: m.tag !== undefined ? String(m.tag) : '', needs: ['tag-set'],
            act: (o, n) => { if (!/^[0-9]+$/.test(n)) throw new Error('1-4094'); return 'tag-set:' + n; } });
        if (l3 && typeof l3 === 'object')
            f.push({ key: 'ip', label: 'IPv4 addresses', kind: 'list', value: (Array.isArray(l3.ip) ? l3.ip : []).map(x => x.name || String(x)), needs: ['ip-add'], needsRemove: ['ip-remove'],
                    note: 'address with mask, e.g. 10.0.0.1/24 (or an address object)', add: x => 'ip-add:' + actArg(x), remove: x => 'ip-remove:' + actArg(x) },
                { key: 'mtu', label: 'MTU', kind: 'text', value: l3.mtu !== undefined ? String(l3.mtu) : '', placeholder: 'empty = default', needs: ['mtu-set'],
                    act: (o, n) => { if (n !== '' && !/^[0-9]+$/.test(n)) throw new Error('576-9216'); return n === '' ? 'mtu-set' : 'mtu-set:' + n; } },
                { key: 'imp', label: 'Interface management profile', kind: 'text', value: l3.interface_management_profile || '', placeholder: 'empty = none', needs: ['interface-management-profile-set'],
                    note: 'must exist here or above', act: (o, n) => n === '' ? 'interface-management-profile-set' : 'interface-management-profile-set:' + actArg(n) },
                flag('mss', 'Adjust TCP MSS', get(l3, 'adjust_tcp_mss', 'enable'), 'adjust-tcp-mss-set'));
        else
            f.push(ro('mode', 'Mode', Object.keys(m).filter(k => ['layer2', 'virtual_wire', 'tap', 'ha', 'aggregate_group', 'decrypt_mirror', 'log_card'].includes(k)).join(', '),
                'not layer3: IP, MTU, profile can not be set here'));
        const extra = main && l3 && typeof l3 === 'object' ? Object.entries(l3).filter(([k]) => !['ip', 'mtu', 'interface_management_profile', 'adjust_tcp_mss'].includes(k))
            .map(([k, v]) => ro('l3-' + k, 'layer3 ' + k, typeof v === 'object' && v !== null ? fmtTree(v) : String(v))) : [];
        return [...f, ...extra, ...rest(used), loc];
    }
    if (kind === 'imp') {
        const services = ['ping', 'telnet', 'ssh', 'http', 'https', 'snmp', 'response-pages', 'http-ocsp', 'userid-service', 'userid-syslog-listener-ssl', 'userid-syslog-listener-udp'];
        const key = sv => sv.replace(/-/g, '_');
        return [nameRo, ...services.map(sv => flag('svc-' + sv, sv, m[key(sv)], 'service-set', sv + ',')),
            { key: 'pip', label: 'Permitted IP addresses', kind: 'list', value: (Array.isArray(m.permitted_ip) ? m.permitted_ip : []).map(x => x.name || String(x)), needs: ['permitted-ip-add'], needsRemove: ['permitted-ip-remove'],
                note: 'address / network, e.g. 10.0.0.0/8 - empty list: every address', add: x => 'permitted-ip-add:' + actArg(x), remove: x => 'permitted-ip-remove:' + actArg(x) },
            ...rest(services.map(key).concat(['permitted_ip'])), loc];
    }
    if (kind === 'zpp') {
        const fl = m.flood || {};
        const flood = t => {
            const v = fl[t.replace(/-/g, '_')] || {};
            const mode = v.syn_cookies ? 'syn-cookies' : 'red';
            const r = v.syn_cookies || v.red || {};
            return { key: 'flood-' + t, label: 'Flood ' + t, kind: 'parts', needs: ['flood-set'],
                value: { enable: yn(v.enable) || 'no', alarm: r.alarm_rate !== undefined ? String(r.alarm_rate) : '', activate: r.activate_rate !== undefined ? String(r.activate_rate) : '',
                    maximal: r.maximal_rate !== undefined ? String(r.maximal_rate) : '', mode },
                parts: [{ key: 'enable', kind: 'select', label: 'enabled', choices: [['no', 'no'], ['yes', 'yes']] }]
                    .concat(t === 'tcp-syn' ? [{ key: 'mode', kind: 'select', label: 'action', choices: [['red', 'random early drop'], ['syn-cookies', 'SYN cookies']] }] : [])
                    .concat([{ key: 'alarm', kind: 'text', label: 'alarm /s' }, { key: 'activate', kind: 'text', label: 'activate /s' }, { key: 'maximal', kind: 'text', label: 'maximal /s' }]),
                act: (o, x) => {
                    for (const k of ['alarm', 'activate', 'maximal']) if (x[k] !== '' && !/^[0-9]+$/.test(x[k].trim())) return { hint: k + ': a number' };
                    return 'flood-set:' + t + ',' + x.enable + ',' + x.alarm.trim() + ',' + x.activate.trim() + ',' + x.maximal.trim() + (t === 'tcp-syn' ? ',' + x.mode : '');
                } };
        };
        const scans = Array.isArray(m.scan) ? m.scan : [];
        const scan = (nm, id) => {
            const e = scans.find(x => String(x.name) === id) || {};
            const act = e.action && typeof e.action === 'object' ? Object.keys(e.action)[0] || '' : '';
            const bip = act && e.action[act] && typeof e.action[act] === 'object' ? e.action[act] : {};
            return { key: 'scan-' + nm, label: 'Scan ' + nm, kind: 'parts', needs: ['scan-set'],
                value: { action: act.replace(/_/g, '-'), interval: e.interval !== undefined ? String(e.interval) : '', threshold: e.threshold !== undefined ? String(e.threshold) : '',
                    track: (bip.track_by || '').replace(/_/g, '-'), duration: bip.duration !== undefined ? String(bip.duration) : '' },
                parts: [{ key: 'action', kind: 'select', label: 'action', choices: [['', '-'], ['allow', 'allow'], ['alert', 'alert'], ['block', 'block'], ['block-ip', 'block IP']] },
                    { key: 'interval', kind: 'text', label: 'interval s', show: v => v.action !== '' }, { key: 'threshold', kind: 'text', label: 'threshold', show: v => v.action !== '' },
                    { key: 'track', kind: 'select', label: 'track by', choices: [['source', 'source'], ['source-and-destination', 'source and destination']], show: v => v.action === 'block-ip' },
                    { key: 'duration', kind: 'text', label: 'duration s', show: v => v.action === 'block-ip' }],
                act: (o, x) => {
                    if (x.action === '') return '';
                    if (x.action === 'block-ip' && !/^[0-9]+$/.test(x.duration.trim())) return { hint: 'block IP: duration in seconds' };
                    return 'scan-set:' + nm + ',' + x.action + ',' + x.interval.trim() + ',' + x.threshold.trim() + (x.action === 'block-ip' ? ',' + (x.track || 'source') + ',' + x.duration.trim() : '');
                } };
        };
        const PACKET = ['discard-ip-spoof', 'discard-ip-frag', 'strict-ip-check', 'discard-strict-source-routing', 'discard-loose-source-routing', 'discard-timestamp',
            'discard-record-route', 'discard-security', 'discard-stream-id', 'discard-unknown-option', 'discard-malformed-option', 'discard-overlapping-tcp-segment-mismatch',
            'discard-tcp-split-handshake', 'discard-tcp-syn-with-data', 'discard-tcp-synack-with-data', 'tcp-reject-non-syn', 'asymmetric-path', 'remove-tcp-timestamp',
            'strip-tcp-fast-open-and-data', 'strip-mptcp-option', 'discard-icmp-ping-zero-id', 'discard-icmp-frag', 'discard-icmp-large-packet', 'discard-icmp-error',
            'suppress-icmp-timeexceeded', 'suppress-icmp-needfrag', 'routing-header-0', 'routing-header-1', 'routing-header-3', 'routing-header-4-252', 'routing-header-253',
            'routing-header-254', 'routing-header-255', 'ipv4-compatible-address', 'options-invalid-ipv6-discard', 'reserved-field-set-discard', 'anycast-source',
            'needless-fragment-hdr', 'icmpv6-too-big-small-mtu-discard', 'hop-by-hop-hdr', 'routing-hdr', 'dest-option-hdr', 'dest-unreach', 'pkt-too-big', 'time-exceeded',
            'param-problem', 'redirect'];
        return [nameRo,
            { key: 'desc', label: 'Description', kind: 'text', value: m.description || '', needs: ['description-set'], act: (o, n) => n === '' ? 'description-set' : 'description-set:' + actArg(n) },
            ...['tcp-syn', 'udp', 'icmp', 'icmpv6', 'other-ip'].map(flood),
            scan('tcp-port-scan', '8001'), scan('host-sweep', '8002'), scan('udp-port-scan', '8003'),
            { key: 'packet', label: 'Packet based protection', kind: 'parts', value: { option: '', value: 'yes' }, needs: ['packet-set'],
                note: 'set one option - the current values are listed below',
                parts: [{ key: 'option', kind: 'select', label: 'option', choices: [['', '- choose -']].concat(PACKET.map(x => [x, x])) },
                    { key: 'value', kind: 'select', label: 'value', choices: [['yes', 'yes'], ['no', 'no'], ['global', 'global'], ['drop', 'drop'], ['bypass', 'bypass']] }],
                act: (o, x) => x.option === '' ? '' : 'packet-set:' + x.option + ',' + x.value },
            ...rest(['description', 'flood', 'scan']), loc];
    }
    // a text field: empty removes the value (action without argument), else action:value
    const opt = (key, label, value, action, note, check) => ({ key, label, kind: 'text', value: value === undefined || value === null ? '' : String(value), needs: [action], note,
        placeholder: 'empty = none', act: (o, n) => { if (n !== '' && check && !check.test(n)) throw new Error(note || label); return n === '' ? action : action + ':' + actArg(n); } });
    const req = (key, label, value, action, note, check) => ({ key, label, kind: 'text', value: value === undefined || value === null ? '' : String(value), needs: [action], note,
        act: (o, n) => { if (n === '' || (check && !check.test(n))) throw new Error(note || label + ': a value is needed'); return action + ':' + actArg(n); } });
    const members = v => (Array.isArray(v) ? v : words(v)).map(x => x && typeof x === 'object' ? x.name || fmtTree(x) : String(x));
    const num = /^[0-9]+$/;
    if (kind === 'routing') {
        // a logical router keeps its settings in vrf "default"
        const lr = Array.isArray(m.vrf);
        const b = lr ? (m.vrf.find(v => String(v.name) === 'default') || {}) : m;
        const routes = Array.isArray(get(b, 'routing_table', 'ip', 'static_route')) ? get(b, 'routing_table', 'ip', 'static_route') : [];
        const ad = b.admin_dists && typeof b.admin_dists === 'object' ? b.admin_dists : {};
        const DISTS = ['static', 'static-ipv6', 'ospf-int', 'ospf-ext', 'ospfv3-int', 'ospfv3-ext', 'ibgp', 'ebgp', 'rip'];
        const hop = r => { const n = r.nexthop && typeof r.nexthop === 'object' ? Object.keys(r.nexthop)[0] || '' : ''; return n ? n.replace(/_/g, '-') + (typeof r.nexthop[n] === 'object' ? '' : ' ' + r.nexthop[n]) : 'none'; };
        return [nameRo, ro('class', 'Type', lr ? 'logical router (advanced routing) - vrf default' : 'virtual router'),
            { key: 'if', label: 'Interfaces', kind: 'list', value: members(b.interface), needs: ['interface-add'], needsRemove: ['interface-remove'],
                note: 'an interface of the location (it must exist)', add: x => 'interface-add:' + actArg(x), remove: x => 'interface-remove:' + actArg(x) },
            flag('ecmp', 'ECMP', get(b, 'ecmp', 'enable'), 'ecmp-set'),
            { key: 'ad', label: 'Administrative distance', kind: 'parts', value: { type: 'static', value: ad.static !== undefined ? String(ad.static) : '' }, needs: ['admin-distance-set'],
                note: 'current: ' + (Object.keys(ad).length ? Object.entries(ad).map(([k, v]) => k.replace(/_/g, '-') + ' ' + v).join(', ') : 'defaults') + ' - empty value: default',
                parts: [{ key: 'type', kind: 'select', label: 'protocol', choices: DISTS.map(x => [x, x]) }, { key: 'value', kind: 'text', label: '10-240' }],
                act: (o, v) => { if (v.value.trim() !== '' && !num.test(v.value.trim())) return { hint: '10-240' }; if (v.type === o.type && v.value === o.value) return '';
                    if (v.type !== o.type && v.value === o.value && v.value !== '') return { hint: 'enter the distance for ' + v.type + ' (empty: default)' }; return 'admin-distance-set:' + v.type + (v.value.trim() !== '' ? ',' + v.value.trim() : ''); } },
            ro('routes', 'Static routes', routes.map(r => r.name + ': ' + (r.destination || '') + ' → ' + hop(r) + (r.interface ? ' (' + r.interface + ')' : '')).join('\n'), 'change a route in Static Routes'),
            { key: 'radd', label: 'Add a static route', kind: 'parts', value: { name: '', dest: '', type: 'ip-address', hop: '', iface: '', metric: '' }, needs: ['static-route-add'],
                parts: [{ key: 'name', kind: 'text', label: 'name' }, { key: 'dest', kind: 'text', label: 'destination (10.0.0.0/8)' },
                    { key: 'type', kind: 'select', label: 'next hop', choices: [['ip-address', 'IP address'], ['next-vr', 'next VR'], ['discard', 'discard'], ['none', 'none']] },
                    { key: 'hop', kind: 'text', label: 'next hop', show: v => v.type === 'ip-address' || v.type === 'next-vr' },
                    { key: 'iface', kind: 'text', label: 'interface' }, { key: 'metric', kind: 'text', label: 'metric' }],
                act: (o, v) => {
                    if (v.name.trim() === '' && v.dest.trim() === '') return '';
                    if (v.name.trim() === '' || v.dest.trim() === '') return { hint: 'name and destination' };
                    if ((v.type === 'ip-address' || v.type === 'next-vr') && v.hop.trim() === '') return { hint: 'enter the next hop' };
                    if (v.metric.trim() !== '' && !num.test(v.metric.trim())) return { hint: 'metric: a number' };
                    return 'static-route-add:' + [v.name, v.dest, v.type, v.hop, v.iface, v.metric].map(x => actArg(x.trim())).join(',');
                } },
            ...rest(['interface', 'routing_table', 'ecmp', 'admin_dists', 'vrf']), loc];
    }
    if (kind === 'sroute') {
        const nh = m.nexthop && typeof m.nexthop === 'object' ? Object.keys(m.nexthop)[0] || '' : '';
        const rt = m.route_table && typeof m.route_table === 'object' ? (Object.keys(m.route_table)[0] || '').replace(/_/g, '-') : '';
        return [nameRo,
            req('dest', 'Destination', m.destination, 'destination-set', 'IPv4 network, e.g. 10.0.0.0/8, or an address object'),
            { key: 'nh', label: 'Next hop', kind: 'parts', value: { type: nh ? nh.replace(/_/g, '-') : 'none', value: nh && typeof m.nexthop[nh] !== 'object' ? String(m.nexthop[nh]) : '' }, needs: ['nexthop-set'],
                parts: [{ key: 'type', kind: 'select', label: 'type', choices: [['ip-address', 'IP address'], ['next-vr', 'next VR'], ['discard', 'discard'], ['none', 'none']] },
                    { key: 'value', kind: 'text', label: 'value', show: v => v.type === 'ip-address' || v.type === 'next-vr' }],
                act: (o, v) => { if ((v.type === 'ip-address' || v.type === 'next-vr') && v.value.trim() === '') return { hint: 'enter the next hop' };
                    return 'nexthop-set:' + v.type + (v.type === 'ip-address' || v.type === 'next-vr' ? ',' + actArg(v.value.trim()) : ''); } },
            opt('if', 'Interface', m.interface, 'interface-set', 'must exist'),
            req('metric', 'Metric', m.metric, 'metric-set', '1-65535', num),
            opt('ad', 'Administrative distance', m.admin_dist, 'admin-distance-set', '10-240 (empty: default of the router)', num),
            sel('rt', 'Route table', rt, ['unicast', 'multicast', 'both', 'no-install'], 'route-table-set'),
            ...rest(['destination', 'nexthop', 'interface', 'metric', 'admin_dist', 'route_table']), loc];
    }
    if (kind === 'gre') {
        const ka = m.keep_alive || {};
        return [nameRo,
            req('lif', 'Local interface', get(m, 'local_address', 'interface'), 'local-interface-set', 'must exist'),
            opt('lip', 'Local IP', get(m, 'local_address', 'ip'), 'local-ip-set', 'address with mask, e.g. 10.0.0.1/24, or an address object'),
            req('peer', 'Peer address', get(m, 'peer_address', 'ip'), 'peer-address-set', 'IPv4 address or address object'),
            req('tif', 'Tunnel interface', m.tunnel_interface, 'tunnel-interface-set', 'must exist'),
            req('ttl', 'TTL', m.ttl, 'ttl-set', '1-255', num),
            flag('tos', 'Copy TOS header', m.copy_tos, 'copy-tos-set'),
            flag('dis', 'Disabled', m.disabled, 'disabled-set'),
            { key: 'ka', label: 'Keep alive', kind: 'parts', needs: ['keep-alive-set'],
                value: { enable: yn(ka.enable) || 'no', interval: ka.interval !== undefined ? String(ka.interval) : '', retry: ka.retry !== undefined ? String(ka.retry) : '', hold: ka.hold_timer !== undefined ? String(ka.hold_timer) : '' },
                parts: [{ key: 'enable', kind: 'select', label: 'enabled', choices: [['no', 'no'], ['yes', 'yes']] },
                    { key: 'interval', kind: 'text', label: 'interval s' }, { key: 'retry', kind: 'text', label: 'retry' }, { key: 'hold', kind: 'text', label: 'hold timer' }],
                act: (o, v) => { for (const k of ['interval', 'retry', 'hold']) if (v[k].trim() !== '' && !num.test(v[k].trim())) return { hint: k + ': a number' };
                    return 'keep-alive-set:' + v.enable + ',' + v.interval.trim() + ',' + v.retry.trim() + ',' + v.hold.trim(); } },
            ...rest(['local_address', 'peer_address', 'tunnel_interface', 'ttl', 'copy_tos', 'disabled', 'keep_alive']), loc];
    }
    if (kind === 'dhcp') {
        if (m.relay) {
            const r4 = get(m, 'relay', 'ip') || {};
            return [nameRo, ro('class', 'Type', 'DHCP relay'),
                flag('relay', 'Relay (IPv4) enabled', r4.enabled, 'relay-set'),
                { key: 'rs', label: 'Relay servers', kind: 'list', value: members(r4.server), needs: ['relay-server-add'], needsRemove: ['relay-server-remove'],
                    note: 'IPv4 address of a DHCP server', add: x => 'relay-server-add:' + actArg(x), remove: x => 'relay-server-remove:' + actArg(x) },
                ...rest(['relay']), loc];
        }
        const sv = m.server || {};
        const op = sv.option || {};
        const lease = op.lease && typeof op.lease === 'object' ? op.lease : {};
        const res = Array.isArray(sv.reserved) ? sv.reserved : [];
        return [nameRo, ro('class', 'Type', 'DHCP server'),
            sel('mode', 'Mode', sv.mode || '', ['auto', 'enabled', 'disabled'], 'mode-set'),
            { key: 'pool', label: 'IP pools', kind: 'list', value: members(sv.ip_pool), needs: ['ip-pool-add'], needsRemove: ['ip-pool-remove'],
                note: 'a range (10.0.0.10-10.0.0.99) or a network (10.0.0.0/24)', add: x => 'ip-pool-add:' + actArg(x), remove: x => 'ip-pool-remove:' + actArg(x) },
            opt('gw', 'Gateway', op.gateway, 'gateway-set', 'IPv4 address'),
            opt('mask', 'Subnet mask', op.subnet_mask, 'subnet-mask-set', 'e.g. 255.255.255.0'),
            { key: 'dns', label: 'DNS servers', kind: 'parts', value: { p: get(op, 'dns', 'primary') || '', s: get(op, 'dns', 'secondary') || '' }, needs: ['dns-set'],
                parts: [{ key: 'p', kind: 'text', label: 'primary' }, { key: 's', kind: 'text', label: 'secondary' }],
                act: (o, v) => 'dns-set:' + actArg(v.p.trim()) + ',' + actArg(v.s.trim()) },
            { key: 'lease', label: 'Lease', kind: 'parts', value: { type: lease.timeout !== undefined ? 'timeout' : (lease.unlimited !== undefined ? 'unlimited' : ''), min: lease.timeout !== undefined ? String(lease.timeout) : '' }, needs: ['lease-set'],
                parts: [{ key: 'type', kind: 'select', label: 'lease', choices: [['', '-'], ['unlimited', 'unlimited'], ['timeout', 'timeout']] }, { key: 'min', kind: 'text', label: 'minutes', show: v => v.type === 'timeout' }],
                act: (o, v) => { if (v.type === '') return ''; if (v.type === 'timeout' && !num.test(v.min.trim())) return { hint: 'minutes' }; return 'lease-set:' + v.type + (v.type === 'timeout' ? ',' + v.min.trim() : ''); } },
            { key: 'res', label: 'Reserved addresses', kind: 'list', value: res.map(r => r.name + ' ' + (r.mac || '') + (r.description ? ' ' + r.description : '')), needs: ['reservation-add'], needsRemove: ['reservation-remove'],
                note: 'add: IP MAC [description], e.g. 10.0.0.50 00-11-22-33-44-55 printer',
                add: x => { const p = x.trim().split(/\s+/); if (p.length < 2) throw new Error('IP MAC [description]'); return 'reservation-add:' + actArg(p[0]) + ',' + actArg(p[1].replace(/:/g, '-')) + ',' + actArg(p.slice(2).join(' ')); },
                remove: x => 'reservation-remove:' + actArg(x.split(' ')[0]) },
            ...rest(['server']), loc];
    }
    if (kind === 'vwire') {
        const vwIf = (i, v) => ({ key: 'if' + i, label: 'Interface ' + i, kind: 'text', value: v || '', needs: ['interface-set'], note: 'a virtual-wire interface',
            act: (o, n) => { if (n === '') throw new Error('an interface'); return 'interface-set:' + i + ',' + actArg(n); } });
        return [nameRo,
            vwIf(1, m.interface1), vwIf(2, m.interface2),
            { key: 'tags', label: 'Tag allowed', kind: 'text', value: m.tag_allowed !== undefined ? String(m.tag_allowed) : '', needs: ['tag-allowed-set'], placeholder: 'empty = untagged only',
                note: 'tags / ranges, e.g. 0,10-20', act: (o, n) => { if (n !== '' && !/^[0-9]+(-[0-9]+)?([,|][0-9]+(-[0-9]+)?)*$/.test(n.replace(/\s/g, ''))) throw new Error('e.g. 0,10-20'); return n === '' ? 'tag-allowed-set' : 'tag-allowed-set:' + n.replace(/\s/g, '').replace(/,/g, '|'); } },
            flag('mc', 'Multicast firewalling', get(m, 'multicast_firewalling', 'enable'), 'multicast-firewalling-set'),
            flag('ls', 'Link state pass through', get(m, 'link_state_pass_through', 'enable'), 'link-state-pass-through-set'),
            ...rest(['interface1', 'interface2', 'tag_allowed', 'multicast_firewalling', 'link_state_pass_through']), loc];
    }
    if (kind === 'gpportal' || kind === 'gpgateway') {
        const b = kind === 'gpportal' ? (m.portal_config || {}) : m;
        const la = b.local_address || {};
        const f = [nameRo,
            req('lif', 'Local interface', la.interface, 'local-interface-set', 'an interface of the vsys'),
            opt('lip', 'Local IPv4 address', get(la, 'ip', 'ipv4'), 'local-ip-set', 'address with mask, or an address object'),
            opt('ssl', 'SSL/TLS service profile', b.ssl_tls_service_profile, 'ssl-tls-profile-set', 'of the vsys or shared')];
        if (kind === 'gpportal') {
            const pcRest = Object.entries(b).filter(([k]) => !['local_address', 'ssl_tls_service_profile'].includes(k))
                .map(([k, v]) => ro('pc-' + k, 'portal ' + k, typeof v === 'object' && v !== null ? fmtTree(v) : String(v)));
            return [...f, ...pcRest, ...rest(['portal_config']), loc];
        }
        f.push(req('tif', 'Tunnel interface', m.remote_user_tunnel, 'tunnel-interface-set', 'a tunnel interface of the vsys'));
        const cfgs = Array.isArray(m.remote_user_tunnel_configs) ? m.remote_user_tunnel_configs : [];
        for (const c of cfgs) {
            const cn = String(c.name);
            const lists = [['ip-pool', 'IP pool', c.ip_pool], ['access-route', 'access routes', get(c, 'split_tunneling', 'access_route')], ['exclude-access-route', 'excluded access routes', get(c, 'split_tunneling', 'exclude_access_route')]];
            for (const [l, label, v] of lists)
                f.push({ key: 'c-' + cn + '-' + l, label: 'Client setting ' + cn + ': ' + label, kind: 'list', value: members(v), needs: ['client-' + l + '-add'], needsRemove: ['client-' + l + '-remove'],
                    note: 'network (10.0.0.0/8), range or address object', add: x => 'client-' + l + '-add:' + actArg(cn) + ',' + actArg(x), remove: x => 'client-' + l + '-remove:' + actArg(cn) + ',' + actArg(x) });
            const other = Object.entries(c).filter(([k]) => !['name', 'ip_pool', 'split_tunneling'].includes(k)).concat(Object.entries(c.split_tunneling || {}).filter(([k]) => !['access_route', 'exclude_access_route'].includes(k)));
            if (other.length) f.push(ro('c-' + cn + '-rest', 'Client setting ' + cn + ': other', other.map(([k, v]) => k + ': ' + (typeof v === 'object' && v !== null ? fmtTree(v) : String(v))).join('\n')));
        }
        return [...f, ...rest(['local_address', 'ssl_tls_service_profile', 'remote_user_tunnel', 'remote_user_tunnel_configs']), loc];
    }
    // IPsec tunnel
    const ak = m.auto_key || {};
    const proxies = Array.isArray(ak.proxy_id) ? ak.proxy_id : [];
    const tm = m.tunnel_monitor || {};
    return [nameRo,
        name('gw', 'IKE gateway', Array.isArray(ak.ike_gateway) && ak.ike_gateway[0] ? ak.ike_gateway[0].name : '', 'ike-gateway-set', '', 'must exist here or above (parent folder / snippet / template)'),
        name('prof', 'IPsec crypto profile', ak.ipsec_crypto_profile, 'ipsec-crypto-profile-set'),
        name('tif', 'Tunnel interface', m.tunnel_interface, 'tunnel-interface-set'),
        { key: 'proxy', label: 'Proxy IDs', kind: 'list', value: proxies.map(p => p.name + ': ' + (p.local || '') + ' → ' + (p.remote || '')), needs: ['proxy-id-add'], needsRemove: ['proxy-id-remove'],
            note: 'add: name local remote (e.g. p2 10.2.0.0/24 10.3.0.0/24 - protocol any)',
            add: x => { const p = x.split(/\s+/); if (p.length !== 3) throw new Error('name local remote'); return 'proxy-id-add:' + p.map(actArg).join(','); },
            remove: x => 'proxy-id-remove:' + actArg(x.split(': ')[0]) },
        flag('ar', 'Anti replay', m.anti_replay, 'anti-replay-set'),
        flag('tos', 'Copy TOS header', m.copy_tos, 'copy-tos-set'),
        { key: 'tmon', label: 'Tunnel monitor', kind: 'parts', value: { enable: yn(tm.enable) || 'no', dest: tm.destination_ip || '' }, needs: ['tunnel-monitor-set'],
            parts: [{ key: 'enable', kind: 'select', label: 'enabled', choices: [['no', 'no'], ['yes', 'yes']] }, { key: 'dest', kind: 'text', label: 'destination IP', show: v => v.enable === 'yes' }],
            act: (o, v) => {
                if (v.enable === 'no') return o.enable === 'no' ? '' : 'tunnel-monitor-set:no';
                if (!v.dest.trim()) return { hint: 'enter the destination IP' };
                return 'tunnel-monitor-set:yes,' + actArg(v.dest.trim());
            } },
        flag('disabled', 'Disabled', m.disabled, 'disabled-set'),
        ...rest(['auto_key', 'tunnel_interface', 'anti_replay', 'copy_tos', 'tunnel_monitor', 'disabled']), loc];
}

// a rule (every rule type): the fields its model has; list fields as add / remove (+ "any"), single values as -set
function ruleText(v) {
    // a description (rule, address, service) or tag comments: pan-os-php replaces these aliases (PH::textAliases)
    if (/[\x00-\x1f]/.test(v)) throw new Error('no line breaks here');
    return v.replace(/\$\$/g, '$ $').replace(/,/g, '$$$$comma$$$$').replace(/\//g, '$$$$forwardslash$$$$').replace(/:/g, '$$$$colon$$$$').replace(/\|/g, '$$$$pipe$$$$');
}

function listOf(v) {
    if (Array.isArray(v)) return v.map(String);
    if (v === undefined || v === null || v === '' || v === '**ANY**') return [];
    return String(v).split(',').map(x => x.trim()).filter(x => x);
}

// a nested value of the model as one readable line: "static_ip: translated_address new test 2"
// the XML of an object: up to 20 lines as text; longer - the elements of the first and second level can be folded
// (open at first; a click on the start tag folds / unfolds), below that as text
function xmlView(text) {
    if (text.split('\n').length <= 20) return el('pre', { class: 'objxml', text });
    const doc = new DOMParser().parseFromString(text, 'application/xml');
    if (doc.getElementsByTagName('parsererror').length) return el('pre', { class: 'objxml', text });
    const ser = new XMLSerializer();
    const indent = d => '  '.repeat(d);
    const startTag = n => '<' + n.nodeName + [...n.attributes].map(a => ' ' + a.name + '="' + a.value + '"').join('') + '>';
    const node = (n, d) => {
        const kids = [...n.childNodes].filter(c => c.nodeType === 1);
        if (d > 2 || kids.length === 0) {
            const t = ser.serializeToString(n).replace(/ xmlns="[^"]*"/, '');
            return el('pre', { class: 'objxml xmlleaf', text: t.split('\n').map(l => indent(d) + l.replace(/^\s+/, '')).join('\n') });
        }
        const det = el('details', { class: 'xmlnode', open: true },
            el('summary', { class: 'objxml', text: indent(d) + startTag(n) + '  (' + kids.length + ')' }),
            kids.map(c => node(c, d + 1)),
            el('pre', { class: 'objxml xmlleaf', text: indent(d) + '</' + n.nodeName + '>' }));
        return det;
    };
    return el('div', { class: 'xmltree' }, node(doc.documentElement, 0));
}

function fmtTree(v) {
    if (v === null || v === undefined || v === '') return '';
    if (Array.isArray(v)) return v.map(fmtTree).filter(x => x).join(', ');
    if (typeof v === 'object') return Object.entries(v).map(([k, x]) => { const t = fmtTree(x); return t === '' ? k : k + ' ' + t; }).join('; ');
    return String(v);
}

// NAT: source / destination translation as one field each with parts; a change of a part is applied as soon as the
// parts together are complete (snat-set / snat-remove, dnat-set / dnat-remove)
function natSource(row, m) {
    const st = m.source_translation || {};
    const dipp = st.dynamic_ip_and_port, dip = st.dynamic_ip, sip = st.static_ip;
    const cur = dipp ? (dipp.interface_address ? 'interface' : 'dynamic-ip-and-port') : dip ? 'dynamic-ip' : sip ? 'static-ip' : 'none';
    const hosts = dipp && !dipp.interface_address ? listOf(dipp.translated_address) : dip ? listOf(dip.translated_address) : sip ? listOf(sip.translated_address) : [];
    const bid = row.snat && row.snat['static-ip'] ? String(row.snat['static-ip'].bidir) : (sip && sip.bi_directional ? String(sip.bi_directional) : 'no');
    const vals = { type: cur, addresses: hosts.join(', '), interface: dipp && dipp.interface_address ? (dipp.interface_address.interface || '') : '',
        ip: dipp && dipp.interface_address ? (dipp.interface_address.ip || dipp.interface_address.floating_ip || '') : '', bidir: bid === 'yes' || bid === 'true' ? 'yes' : 'no' };
    return { key: 'snat', label: 'Source translation', kind: 'parts', value: vals, needs: ['snat-set', 'snat-remove'],
        parts: [
            { key: 'type', kind: 'select', label: 'type', choices: [['none', 'none'], ['dynamic-ip-and-port', 'dynamic IP and port - addresses'], ['interface', 'dynamic IP and port - interface address'], ['dynamic-ip', 'dynamic IP'], ['static-ip', 'static IP']] },
            { key: 'addresses', kind: 'text', label: 'translated address(es)', placeholder: 'address objects, separated by ","', show: v => ['dynamic-ip-and-port', 'dynamic-ip', 'static-ip'].includes(v.type) },
            { key: 'interface', kind: 'text', label: 'interface', placeholder: 'ethernet1/1', show: v => v.type === 'interface' },
            { key: 'ip', kind: 'text', label: 'IP (optional)', placeholder: 'an address object', show: v => v.type === 'interface' },
            { key: 'bidir', kind: 'select', label: 'bi-directional', choices: [['no', 'no'], ['yes', 'yes']], show: v => v.type === 'static-ip' }],
        act: (o, v) => {
            if (v.type === 'none') return o.type === 'none' ? '' : 'snat-remove';
            const names = v.addresses.split(',').map(x => x.trim()).filter(x => x);
            if (v.type === 'interface') {
                if (!v.interface.trim()) return { hint: 'enter the interface' };
                return 'snat-set:dynamic-ip-and-port,' + (v.ip.trim() ? actArg(v.ip.trim()) : '-') + ',' + actArg(v.interface.trim());
            }
            if (names.length === 0) return { hint: 'enter the translated address' + (v.type === 'static-ip' ? '' : '(es)') };
            if (v.type === 'static-ip' && names.length !== 1) return { hint: 'static IP: exactly one translated address' };
            return 'snat-set:' + v.type + ',' + names.map(actArg).join('|') + (v.type === 'static-ip' ? ',-,' + v.bidir : '');
        } };
}

function natDestination(row, m) {
    const dyn = m.dynamic_destination_translation;
    const type = dyn ? 'dynamic' : (m.translated_address !== undefined || m.destination_translation ? 'static' : 'none');
    const d = dyn || m.destination_translation || {};
    const vals = { type, address: String(dyn ? (d.translated_address || '') : (m.translated_address !== undefined ? m.translated_address : (d.translated_address || ''))),
        port: String(dyn ? (d.translated_port || '') : (m.translated_port !== undefined ? m.translated_port : (d.translated_port || ''))) };
    return { key: 'dnat', label: 'Destination translation', kind: 'parts', value: vals, needs: ['dnat-set', 'dnat-remove'],
        parts: [
            { key: 'type', kind: 'select', label: 'type', choices: [['none', 'none'], ['static', 'static IP'], ['dynamic', 'dynamic IP (with session distribution)']] },
            { key: 'address', kind: 'text', label: 'translated address', placeholder: 'an address object', show: v => v.type !== 'none' },
            { key: 'port', kind: 'text', label: 'translated port (optional)', placeholder: '1-65535', show: v => v.type !== 'none' }],
        act: (o, v) => {
            if (v.type === 'none') return o.type === 'none' ? '' : 'dnat-remove';
            if (!v.address.trim()) return { hint: 'enter the translated address' };
            if (v.port.trim() && !/^[0-9]{1,5}$/.test(v.port.trim())) throw new Error('port: 1-65535');
            return 'dnat-set:' + v.type + ',' + actArg(v.address.trim()) + (v.port.trim() ? ',' + v.port.trim() : '');
        } };
}

function ruleFields(row, m, name, loc, ctx) {
    const { ruletype, locationInfo } = ctx;
    const get = (o, ...path) => path.reduce((x, k) => (x && typeof x === 'object' ? x[k] : undefined), o);
    const yesno = (v) => String(v) === 'true' || String(v) === 'yes' ? 'yes' : 'no';
    const list = (key, label, value, a) => Array.isArray(value) ? { key, label, kind: 'list', value: value.filter(x => x !== 'any'), any: value.includes('any') || value.length === 0,
        needs: [a + '-add'], needsRemove: [a + '-remove'], add: x => a + '-add:' + actArg(x), remove: x => a + '-remove:' + actArg(x),
        buttons: [[a + '-set-any', 'set to any']].concat(a === 'service' ? [['service-set-appdefault', 'application-default']] : []) }
        : (value === undefined ? null : { key, label, kind: 'ro', value: listOf(value).join(', ') || 'any' });
    const log = row.logsetting && typeof row.logsetting === 'object' ? row.logsetting : {};
    const sec = ruletype.value === 'security';
    // the default security rules (intrazone / interzone): fixed name and place
    const fixed = ruletype.value === 'defaultsecurity';
    return [fixed ? { key: 'name', label: 'Name', kind: 'ro', value: row.name } : name,
        { key: 'description', label: 'Description', kind: 'text', value: row.description || '', needs: ['description-set'],
            act: (o, n) => n === '' ? 'description-set' : 'description-set:' + ruleText(n) },
        { key: 'tag', label: 'Tags', kind: 'list', value: Array.isArray(m.tag) ? m.tag : listOf(row.tag), needs: ['tag-add'], needsRemove: ['tag-remove'],
            add: t => 'tag-add:' + actArg(t), remove: t => 'tag-remove:' + actArg(t) },
        row.disabled !== undefined ? { key: 'disabled', label: 'Disabled', kind: 'select', value: yesno(row.disabled), choices: ['no', 'yes'], needs: ['disabled-set'],
            act: (o, n) => 'disabled-set:' + (n === 'yes' ? 'true' : 'false') } : null,
        { key: 'rulebase', label: 'Rulebase / position', kind: 'ro', value: [m.rulebase, m.position].filter(x => x !== undefined && x !== null).join(' / ') },
        fixed ? null : { key: 'move', label: 'Move', kind: 'buttons', buttons: [['position-move-to-top', 'to the top'], ['position-move-to-bottom', 'to the bottom']] },
        fixed ? null : { key: 'before', label: 'Move before rule', kind: 'text', value: '', placeholder: 'name of a rule', needs: ['position-move-before'], act: (o, n) => n === '' ? '' : 'position-move-before:' + actArg(n) },
        fixed ? null : { key: 'after', label: 'Move after rule', kind: 'text', value: '', placeholder: 'name of a rule', needs: ['position-move-after'], act: (o, n) => n === '' ? '' : 'position-move-after:' + actArg(n) },
        list('from', 'Source zone', m.from !== undefined ? m.from : row.from, 'from'),
        list('to', 'Destination zone', m.to !== undefined ? m.to : row.to, 'to'),
        list('source', 'Source address', m.source !== undefined ? m.source : row.source, 'src'),
        row.sourcenegated !== undefined ? { key: 'sourcenegated', label: 'Negate source', kind: 'select', value: yesno(row.sourcenegated), choices: ['no', 'yes'], needs: ['src-negate-set'], act: (o, n) => 'src-negate-set:' + n } : null,
        list('source_user', 'Source user', m.source_user, 'user'),
        list('destination', 'Destination address', m.destination !== undefined ? m.destination : row.destination, 'dst'),
        row.destinationnegated !== undefined ? { key: 'destinationnegated', label: 'Negate destination', kind: 'select', value: yesno(row.destinationnegated), choices: ['no', 'yes'], needs: ['dst-negate-set'], act: (o, n) => 'dst-negate-set:' + n } : null,
        list('application', 'Application', m.application, 'app'),
        m.service !== undefined || row.service !== undefined ? list('service', 'Service', m.service !== undefined ? m.service : row.service, 'service') : null,
        m.category !== undefined || row.urlcategory !== undefined || ['security', 'decryption'].includes(ruletype.value) ? (() => {
            const cats = listOf(m.category !== undefined ? m.category : (row.urlcategory || [])).map(x => x.replace('**ANY**', 'any'));
            return { key: 'category', label: 'URL category', kind: 'list', value: cats.filter(x => x !== 'any'), any: cats.length === 0 || cats.includes('any'),
                needs: ['category-add'], needsRemove: ['category-remove'], add: x => 'category-add:' + actArg(x), remove: x => 'category-remove:' + actArg(x),
                buttons: [['category-set-any', 'set to any']], note: 'custom URL category, EDL (URL) or predefined category; the last one: set to any' };
        })() : null,
        m.action !== undefined && sec ? { key: 'action', label: 'Action', kind: 'select', value: m.action, choices: ['allow', 'deny', 'drop', 'reset-client', 'reset-server', 'reset-both'], needs: ['action-set'], act: (o, n) => 'action-set:' + n }
            : ( m.action !== undefined ? { key: 'action', label: 'Action', kind: 'ro', value: m.action } : null),
        sec ? { key: 'profilegroup', label: 'Profile group', kind: 'text', value: row.securityprofilegroup && row.securityprofilegroup !== 'null' ? row.securityprofilegroup : '', needs: ['securityprofile-group-set', 'securityprofile-remove'],
            act: (o, n) => n === '' ? 'securityprofile-remove:any' : 'securityprofile-group-set:' + actArg(n) } : null,
        // the profiles one by one (SecurityRule::SECPROF_TYPES); setting one replaces a profile group, a group replaces them
        ...(sec || fixed ? (() => {
            const ps = get(m, 'profile_setting', 'profiles') || {};
            const types = ['virus', 'spyware', 'vulnerability', 'url-filtering', 'file-blocking', 'wildfire', 'data-filtering'];
            for (const t of ['virus-and-wildfire', 'dns-security']) if (ps[t.replace(/-/g, '_')] !== undefined || (locationInfo && locationInfo.config === 'scm')) types.push(t);
            return types.map(t => ({ key: 'sp-' + t, label: 'Profile: ' + t, kind: 'text', value: listOf(ps[t.replace(/-/g, '_')]).join(''), pick: 'profile-' + t,
                needs: ['securityprofile-profile-set', 'securityprofile-remove'], placeholder: 'empty = none',
                act: (o, n) => n === '' ? 'securityprofile-remove:' + t : 'securityprofile-profile-set:' + t + ',' + actArg(n) }));
        })() : []),
        sec ? { key: 'logsetting', label: 'Log forwarding', kind: 'text', value: m.log_setting || '', needs: ['logsetting-set', 'logsetting-disable'], placeholder: 'empty = none', act: (o, n) => n === '' ? 'logsetting-disable' : 'logsetting-set:' + actArg(n) } : null,
        sec ? { key: 'logstart', label: 'Log at session start', kind: 'select', value: yesno(log.start), choices: ['no', 'yes'], needs: ['logstart-enable', 'logstart-disable'], act: (o, n) => n === 'yes' ? 'logstart-enable' : 'logstart-disable' } : null,
        sec ? { key: 'logend', label: 'Log at session end', kind: 'select', value: yesno(log.end), choices: ['no', 'yes'], needs: ['logend-enable', 'logend-disable'], act: (o, n) => n === 'yes' ? 'logend-enable' : 'logend-disable' } : null,
        sec ? { key: 'schedule', label: 'Schedule', kind: 'text', value: m.schedule || '', needs: ['schedule-set', 'schedule-remove'], act: (o, n) => n === '' ? 'schedule-remove' : 'schedule-set:' + actArg(n) } : null,
        sec && !fixed ? { key: 'ruletype', label: 'Rule type', kind: 'select', value: m.rule_type || 'universal', choices: ['universal', 'intrazone', 'interzone'], needs: ['ruletype-change'],
            act: (o, n) => 'ruletype-change:' + n } : null,
        sec && !fixed ? { key: 'hip', label: 'Source HIP profile', kind: 'text', value: listOf(m.source_hip !== undefined ? m.source_hip : m.hip_profiles).join(', '), pick: 'hip-profile',
            needs: ['hip-set'], placeholder: 'any', note: 'one profile (any, no-hip or a HIP profile)', act: (o, n) => 'hip-set:' + actArg(n === '' ? 'any' : n) } : null,
        sec && !fixed ? (() => {
            const mk = get(m, 'qos', 'marking') || {};
            const t = Object.keys(mk)[0] || '';
            const DSCP = ['af11', 'af12', 'af13', 'af21', 'af22', 'af23', 'af31', 'af32', 'af33', 'af41', 'af42', 'af43', 'cs0', 'cs1', 'cs2', 'cs3', 'cs4', 'cs5', 'cs6', 'cs7', 'ef'];
            const CS = ['cs0', 'cs1', 'cs2', 'cs3', 'cs4', 'cs5', 'cs6', 'cs7'];
            return { key: 'qos', label: 'QoS marking', kind: 'parts', value: { type: t.replace(/_/g, '-'), value: t && typeof mk[t] !== 'object' ? String(mk[t]) : '' },
                needs: ['qosmarking-set', 'qosmarking-remove'],
                parts: [{ key: 'type', kind: 'select', label: 'marking', choices: [['', 'none'], ['ip-dscp', 'IP DSCP'], ['ip-precedence', 'IP precedence'], ['follow-c2s-flow', 'follow client-to-server flow']] },
                    { key: 'value', kind: 'select', label: 'value', choices: DSCP.map(x => [x, x]), show: v => v.type === 'ip-dscp' },
                    { key: 'value', kind: 'select', label: 'value', choices: CS.map(x => [x, x]), show: v => v.type === 'ip-precedence' }],
                act: (o, v) => {
                    if (v.type === '') return o.type === '' ? '' : 'qosmarking-remove';
                    if (v.type === 'follow-c2s-flow') return 'qosmarking-set:follow-c2s-flow,';
                    const allowed = v.type === 'ip-dscp' ? DSCP : CS;
                    const val = allowed.includes(v.value) ? v.value : allowed[0];
                    return 'qosmarking-set:' + v.type + ',' + val;
                } };
        })() : null,
        sec && !fixed ? { key: 'dsri', label: 'Disable server response inspection', kind: 'select', value: ['yes', 'true', true].includes(get(m, 'option', 'disable_server_response_inspection')) ? 'yes' : 'no',
            choices: ['no', 'yes'], needs: ['dsri-set'], act: (o, n) => 'dsri-set:' + n } : null,
        // Panorama: the firewalls the rule is pushed to (target) - "serial" or "serial vsys"
        m.target !== undefined || (locationInfo && locationInfo.config === 'panorama') ? (() => {
            const tg = m.target || {};
            const devs = [];
            for (const d of Array.isArray(tg.devices) ? tg.devices : (tg.devices && typeof tg.devices === 'object' ? [tg.devices] : [])) {
                const serial = typeof d === 'object' ? String(d.name || '') : String(d);
                const vs = typeof d === 'object' && d.vsys ? (Array.isArray(d.vsys) ? d.vsys : [d.vsys]).map(x => typeof x === 'object' ? x.name : x) : [];
                if (vs.length) for (const v of vs) devs.push(serial + ' ' + v); else devs.push(serial);
            }
            const dev = x => { const p = x.trim().split(/\s+/); if (!/^[0-9A-Za-z-]+$/.test(p[0])) throw new Error('serial [vsys]'); return actArg(p[0]) + (p[1] ? ',' + actArg(p[1]) : ''); };
            return { key: 'target', label: 'Target firewalls', kind: 'list', value: devs, any: devs.length === 0, pick: 'firewall',
                needs: ['target-add-device'], needsRemove: ['target-remove-device'], add: x => 'target-add-device:' + dev(x), remove: x => 'target-remove-device:' + dev(x),
                buttons: [['target-set-any', 'all firewalls']], note: 'serial, or serial and vsys; empty = all firewalls of the device group' };
        })() : null,
        m.target !== undefined || (locationInfo && locationInfo.config === 'panorama') ? { key: 'tnegate', label: 'Target negate', kind: 'select',
            value: ['yes', 'true', true].includes(get(m, 'target', 'negate')) ? 'yes' : 'no', choices: ['no', 'yes'], needs: ['target-negate-set'], act: (o, n) => 'target-negate-set:' + n } : null,
        ruletype.value === 'nat' ? natSource(row, m) : null,
        ruletype.value === 'nat' ? natDestination(row, m) : null,
        m.uuid ? { key: 'uuid', label: 'UUID', kind: 'ro', value: m.uuid } : null,
        loc].filter(f => f);
}

// ---- multi-edit: a change of one object (a line of the change list) on more objects - filter suggestions from the
// properties of the object, the number of matches live, then the same action with the wider filter (one more line)
function filterSuggestions(type, rt, row, m, name) {
    const f = (state.meta.types[type] || {}).filters || {};
    const has = (field, op) => !!f[field] && (!op || f[field][op] !== undefined);
    const out = [];
    const add = (field, op, text, label, on) => { if (has(field, op)) out.push({ text, label, on: !!on }); };
    const pre = (String(name).match(/^[A-Za-z]+/) || [''])[0];
    if (pre && pre !== name) add('name', 'regex', '(name regex /^' + pre + '/)', 'name begins with "' + pre + '"');
    if (type === 'address' || type === 'service') {
        const grp = /group/i.test(String(row.type || ''));
        add('object', 'is.group', grp ? '(object is.group)' : '!(object is.group)', grp ? 'groups only' : 'no groups', true);
        if (!grp && row.value) add('value', 'string.eq', '(value string.eq ' + row.value + ')', 'same value ' + row.value);
        if (type === 'address' && ['ip-netmask', 'ip-range', 'fqdn', 'ip-wildcard'].includes(row.type)) add('object', 'is.' + row.type, '(object is.' + row.type + ')', 'type ' + row.type);
        if (type === 'service' && /^(tcp|udp)\//.test(row.value || '')) add('object', 'is.' + row.value.slice(0, 3), '(object is.' + row.value.slice(0, 3) + ')', row.value.slice(0, 3) + ' services');
    }
    if (type === 'tag' && row.color) add('color', 'eq', '(color eq ' + row.color + ')', 'color ' + row.color);
    for (const t of (Array.isArray(m.tag) ? m.tag : [])) add('tag', 'has', '(tag has ' + t + ')', 'tag ' + t);
    if (type !== 'rule') add('object', 'is.unused', '(object is.unused)', 'unused objects');
    if (type === 'rule') {
        const lists = [['from', 'from', 'source zone'], ['to', 'to', 'destination zone'], ['src', 'source', 'source'], ['dst', 'destination', 'destination'],
            ['app', 'application', 'application'], ['service', 'service', 'service'], ['user', 'source_user', 'user']];
        for (const [field, key, label] of lists) {
            const v = Array.isArray(m[key]) ? m[key] : [];
            if (v.length === 0 || v.includes('any')) add(field, 'is.any', '(' + field + ' is.any)', label + ' is any');
            else for (const x of v.slice(0, 6)) add(field, 'has', '(' + field + ' has ' + x + ')', label + ' has ' + x);
        }
        if (m.action) add('action', 'is.' + m.action, '(action is.' + m.action + ')', 'action ' + m.action);
        if (m.rulebase === 'pre' || m.rulebase === 'post') add('rule', 'is.' + m.rulebase + 'rule', '(rule is.' + m.rulebase + 'rule)', m.rulebase + ' rules');
        add('rule', String(row.disabled) === 'true' ? 'is.disabled' : 'is.enabled', String(row.disabled) === 'true' ? '(rule is.disabled)' : '(rule is.enabled)', String(row.disabled) === 'true' ? 'disabled rules' : 'enabled rules');
    }
    return out;
}
