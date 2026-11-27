/*
 * pan-os-php config viewer (prototype) - browser part.
 * No external scripts. All text goes into the page with textContent (never as HTML).
 * The browser keeps every loaded object list in memory (cache per query) and sorts / pages / quick-filters there;
 * the server keeps the configuration loaded in memory. Nothing is written to a file until "Save".
 */
'use strict';

const API = 'api.php';
const state = { user: null, admin: false, csrf: null, meta: null, project: null, config: null, cache: new Map(), view: null, timers: [] };

// ---------------------------------------------------------------- helpers
function el(tag, props, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
        if (k === 'class') e.className = v;
        else if (k === 'text') e.textContent = v;
        else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
        else if (v === true) e.setAttribute(k, '');
        else if (v !== false && v !== null && v !== undefined) e.setAttribute(k, v);
    }
    for (const c of children.flat()) if (c !== null && c !== undefined) e.append(c);
    return e;
}
function field(label, input) { return el('label', {}, label, input); }
// a group of inputs (checkboxes) with a title - no <label> around it (a click on the title would tick the first box)
function groupField(title, box) { return el('div', { class: 'groupfield' }, el('span', { class: 'grouptitle', text: title }), box); }
function message(text, kind) {
    const m = document.getElementById('message');
    m.hidden = !text;
    m.textContent = text || '';
    m.className = kind || 'info';
}
function fmtTime(ts) { return ts ? new Date(ts * 1000).toLocaleString() : ''; }
function fmtSize(n) { return n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.ceil(n / 1024) + ' kB'; }

// ---- errors of this page for a support file (the last 100: script errors, refused API calls) - only in memory
const browserErrors = [];
function browserError(kind, text) {
    browserErrors.push({ time: new Date().toISOString(), kind, text: String(text).slice(0, 2000), page: location.hash.split('&')[0].slice(0, 200) });
    if (browserErrors.length > 100) browserErrors.shift();
}
window.addEventListener('error', (ev) => browserError('script', (ev.message || 'error') + (ev.filename ? ' at ' + ev.filename.split('/').pop() + ':' + ev.lineno + ':' + ev.colno : '')));
window.addEventListener('unhandledrejection', (ev) => browserError('promise', ev.reason && ev.reason.message ? ev.reason.message : String(ev.reason)));

async function api(method, path, body) {
    const opt = { method, credentials: 'same-origin', headers: {} };
    if (method !== 'GET' && state.csrf) opt.headers['X-CSRF-Token'] = state.csrf;
    if (body instanceof FormData) opt.body = body;
    else if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    const res = await fetch(API + '/' + path, opt);
    let data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    if (res.status === 401 && state.user) { leave(); showLogin(); throw new Error('session ended - please log in again'); }
    if (!res.ok) {
        const e = new Error(data && data.error ? data.error : 'request failed (' + res.status + ')'); if (data && data.details) e.details = data.details;
        if (data && data.fields) e.fields = data.fields;
        browserError('api', method + ' ' + path.split('?')[0] + ' -> ' + res.status + ': ' + e.message);
        throw e;
    }
    return data;
}
async function run(fn) {
    try { message(''); await fn(); } catch (e) { message(e.message, 'error'); }
}
function clearTimers() { state.timers.forEach(clearInterval); state.timers = []; }
function leave() { clearTimers(); state.user = null; state.csrf = null; state.cache.clear(); state.project = null; state.config = null; document.getElementById('nav').hidden = true; }
function main(...nodes) { clearTimers(); const m = document.getElementById('main'); m.replaceChildren(...nodes.flat()); }

// ---------------------------------------------------------------- parts in files of their own (js/, loaded by index.html before this file):
// js/account.js, js/projects.js, js/plugin-pages.js, js/editors.js, js/ldap.js, js/scm.js, js/merger.js, js/project-tools.js

// ---------------------------------------------------------------- viewer / editor
// preset (a link "Open" of a reference, in a new window): type, entry (menu entry of the object's class), ruletype, securityprofiletype, location, filter
// ---------------------------------------------------------------- the menu of the viewer (as in PAN-OS)
// an entry: a pan-os-php type (+ rule type, + a filter of its own); 'window': the object opens in the object window
const VIEWER_MENU_SECTIONS = ['Objects', 'Policies', 'Network', 'Device', 'Other'];
const VIEWER_MENU = [
    ['Objects', 'addresses', 'Addresses', 'address', { filter: '!(object is.group) and !(object is.region)', window: 'address', one: 'Address' }],
    ['Objects', 'address-groups', 'Address Groups', 'address', { filter: '(object is.group)', window: 'addressgroup', one: 'Address Group', classes: ['AddressGroup'] }],
    ['Objects', 'regions', 'Regions', 'region'],
    ['Objects', 'services', 'Services', 'service', { filter: '!(object is.group)', window: 'service', one: 'Service' }],
    ['Objects', 'service-groups', 'Service Groups', 'service', { filter: '(object is.group)', window: 'servicegroup', one: 'Service Group', classes: ['ServiceGroup'] }],
    ['Objects', 'tags', 'Tags', 'tag', { window: 'tag', one: 'Tag' }],
    ['Objects', 'applications', 'Applications', 'application'],
    ['Objects', 'edls', 'External Dynamic Lists', 'edl'],
    ['Objects', 'schedules', 'Schedules', 'schedule'],
    ['Objects', 'security-profiles', 'Security Profiles', 'securityprofile'],
    ['Objects', 'security-profile-groups', 'Security Profile Groups', 'securityprofilegroup'],
    ['Objects', 'log-forwarding', 'Log Forwarding', 'log-profile'],
    ['Objects', 'threats', 'Threats', 'threat'],
    ['Policies', 'rule-security', 'Security', 'rule', { ruletype: 'security', window: 'rule', one: 'Security rule' }],
    ['Policies', 'rule-nat', 'NAT', 'rule', { ruletype: 'nat', window: 'rule', one: 'NAT rule' }],
    ['Policies', 'rule-qos', 'QoS', 'rule', { ruletype: 'qos', window: 'rule', one: 'QoS rule' }],
    ['Policies', 'rule-pbf', 'Policy Based Forwarding', 'rule', { ruletype: 'pbf', window: 'rule', one: 'Policy Based Forwarding rule' }],
    ['Policies', 'rule-decryption', 'Decryption', 'rule', { ruletype: 'decryption', window: 'rule', one: 'Decryption rule' }],
    ['Policies', 'rule-networkpacketbroker', 'Network Packet Broker', 'rule', { ruletype: 'networkpacketbroker', window: 'rule', one: 'Network Packet Broker rule' }],
    ['Policies', 'rule-tunnelinspection', 'Tunnel Inspection', 'rule', { ruletype: 'tunnelinspection', window: 'rule', one: 'Tunnel Inspection rule' }],
    ['Policies', 'rule-appoverride', 'Application Override', 'rule', { ruletype: 'appoverride', window: 'rule', one: 'Application Override rule' }],
    ['Policies', 'rule-authentication', 'Authentication', 'rule', { ruletype: 'authentication', window: 'rule', one: 'Authentication rule' }],
    ['Policies', 'rule-dos', 'DoS Protection', 'rule', { ruletype: 'dos', window: 'rule', one: 'DoS Protection rule' }],
    ['Policies', 'rule-sdwan', 'SD-WAN', 'rule', { ruletype: 'sdwan', window: 'rule', one: 'SD-WAN rule' }],
    ['Policies', 'rule-captiveportal', 'Captive Portal', 'rule', { ruletype: 'captiveportal', window: 'rule', one: 'Captive Portal rule' }],
    ['Policies', 'rule-defaultsecurity', 'Default Security Rules', 'rule', { ruletype: 'defaultsecurity', window: 'rule', one: 'Default Security Rules rule' }],
    ['Network', 'zones', 'Zones', 'zone', { window: 'zone', one: 'Zone' }],
    ['Network', 'interfaces', 'Interfaces', 'interface', { window: 'interface', one: 'Interface' }],
    ['Network', 'virtual-wires', 'Virtual Wires', 'virtualwire', { window: 'vwire', one: 'Virtual wire' }],
    ['Network', 'routing', 'Virtual Routers / Routing', 'routing', { window: 'routing', one: 'Router' }],
    ['Network', 'static-routes', 'Static Routes', 'static-route', { window: 'sroute', one: 'Static route' }],
    ['Network', 'ike-gateways', 'IKE Gateways', 'ike-gateway', { window: 'ikegateway', one: 'IKE gateway' }],
    ['Network', 'ipsec-tunnels', 'IPSec Tunnels', 'ipsec-tunnel', { window: 'ipsectunnel', one: 'IPsec tunnel' }],
    ['Network', 'gre-tunnels', 'GRE Tunnels', 'gre-tunnel', { window: 'gre', one: 'GRE tunnel' }],
    ['Network', 'dhcp', 'DHCP', 'dhcp', { window: 'dhcp', one: 'DHCP' }],
    ['Network', 'gp-portals', 'GlobalProtect Portals', 'gp-portal', { window: 'gpportal', one: 'GlobalProtect portal' }],
    ['Network', 'gp-gateways', 'GlobalProtect Gateways', 'gp-gateway', { window: 'gpgateway', one: 'GlobalProtect gateway' }],
    ['Network', 'gp-gateway-tunnels', 'GlobalProtect Gateway Tunnels', 'gpgateway-tunnel'],
    ['Network', 'ike-profiles', 'IKE Crypto Profiles', 'ike-profile', { window: 'ikeprofile', one: 'IKE crypto profile' }],
    ['Network', 'ipsec-profiles', 'IPSec Crypto Profiles', 'ipsec-profile', { window: 'ipsecprofile', one: 'IPsec crypto profile' }],
    ['Network', 'interface-mgmt-profiles', 'Interface Management Profiles', 'interface-management-profile', { window: 'imp', one: 'Interface management profile' }],
    ['Network', 'zone-protection-profiles', 'Zone Protection Profiles', 'zone-protection-profile', { window: 'zpp', one: 'Zone protection profile' }],
    ['Device', 'devices', 'Devices', 'device'],
    ['Device', 'certificates', 'Certificates', 'certificate'],
    ['Device', 'certificate-profiles', 'Certificate Profiles', 'certificate-profile'],
    ['Device', 'ssl-tls-profiles', 'SSL/TLS Service Profiles', 'ssl-tls-service-profile'],
    // DNS rules are comparable to the threat rules (no policies): both under Other
    ['Other', 'threat-rules', 'Threat Rules', 'threat-rule'],
    ['Other', 'dns-rules', 'DNS Rules', 'dns-rule'],
];
/** the entries the user can open: types of the meta (and of a limited access); every other type of the meta under "Other" */
// the fields that name other objects: window kind -> field key -> kind of pan-os-php ObjectCandidates (the drop down
// offers what the object can take: its location and the locations above it - vsys / device group / SCM folder, template)
const FIELD_PICKS = {
    addressgroup: { members: 'address', tag: 'tag' }, servicegroup: { members: 'service', tag: 'tag' }, address: { tag: 'tag' }, service: { tag: 'tag' },
    rule: { from: 'zone', to: 'zone', source: 'address', destination: 'address', service: 'service', application: 'application', tag: 'tag',
        category: 'url-category', schedule: 'schedule', profilegroup: 'securityprofilegroup', logsetting: 'log-profile' },
    zone: { interfaces: 'interface', zpp: 'zone-protection-profile', log: 'log-profile' },
    ikegateway: { ike1: 'ike-crypto-profile', ike2: 'ike-crypto-profile', lif: 'interface' },
    ipsectunnel: { gw: 'ike-gateway', prof: 'ipsec-crypto-profile', tif: 'tunnel-interface' },
    interface: { imp: 'interface-management-profile' }, routing: { if: 'interface' }, sroute: { if: 'interface' },
    gre: { lif: 'interface', tif: 'tunnel-interface' }, vwire: { if1: 'interface', if2: 'interface' },
    gpportal: { lif: 'interface' }, gpgateway: { lif: 'interface', tif: 'tunnel-interface' },
};
// several entries of one pan-os-php type (addresses / address groups, services / service groups): "classes" names the
// PHP classes of an entry; an object of another class goes to the entry of the type without "classes"
function viewerEntryFor(entries, type, ruletype, cls) {
    const same = entries.filter(e => e.type === type && (type !== 'rule' || e.ruletype === (ruletype || 'security')));
    return same.find(e => cls && (e.classes || []).includes(cls)) || same.find(e => !e.classes) || same[0] || entries.find(e => e.type === type) || null;
}
function viewerMenu(types) {
    // every entry opens its objects in a window: an own one (fields with actions) or the generic one (all fields, read only)
    const list = VIEWER_MENU.filter(m => types.includes(m[3])).map(m => Object.assign({ section: m[0], id: m[1], label: m[2], type: m[3], window: 'generic' }, m[4] || {}));
    for (const t of types) if (!VIEWER_MENU.some(m => m[3] === t)) list.push({ section: 'Other', id: 'type-' + t, label: t, type: t, window: 'generic' });
    return list;
}

async function showViewer(config, preset) {
    const p = state.project, pid = p.pid, canWrite = p.role !== 'read';
    state.config = config; state.cache.clear();
    const view = { rows: [], columns: [], sort: null, desc: false, page: 1, size: 50, quick: '', refs: new Map() };
    const base = () => 'projects/' + pid + '/configs/' + state.config.cid;

    // the menu on the left as in PAN-OS (Objects, Policies, Network, Device): an entry = a pan-os-php type (+ rule type / a
    // filter of its own); access limited to some types: only their entries
    const types = (p.types || Object.keys(state.meta.types)).filter(t => state.meta.types[t]);
    const entries = viewerMenu(types);
    state.viewerEntry = state.viewerEntry || {};
    let cur = entries.find(e => e.id === state.viewerEntry[pid]) || entries[0];
    const type = { get value() { return cur.type; } };
    const ruletype = { get value() { return cur.ruletype || 'security'; } };
    const menu = el('nav', { class: 'vmenu', 'aria-label': 'object types' });
    // PAN-OS before 8.0: captive portal rules; from 8.0 on (and SCM): authentication rules - captive portal only for a
    // Panorama / firewall configuration older than 8.0 (until the version is known: authentication)
    function entryOffered(e) {
        const v = locationInfo.version;
        const old = (locationInfo.config === 'panorama' || locationInfo.config === 'firewall') && Number.isInteger(v) && v < 80;
        if (e.ruletype === 'captiveportal') return old;
        if (e.ruletype === 'authentication') return !old;
        return true;
    }
    function drawMenu() {
        const limitedHere = !!(p.types || p.scope);
        menu.replaceChildren(...[limitedHere ? null : el('div', { class: 'vsec' }, el('div', { class: 'vsechead', text: 'System' }),
            el('button', { type: 'button', class: 'ventry', text: 'System settings', title: 'management, system, administrators, authentication, logging, updates (type=config-section)',
                onclick: () => run(showSystem) }))].filter(x => x), ...VIEWER_MENU_SECTIONS.map(sec => {
            const list = entries.filter(e => e.section === sec && (entryOffered(e) || e.id === cur.id));
            return list.length === 0 ? null : el('div', { class: 'vsec' }, el('div', { class: 'vsechead', text: sec }),
                list.map(e => el('button', { type: 'button', class: 'ventry' + (e.id === cur.id ? ' on' : ''), text: e.label, title: e.type + (e.ruletype ? ' / ' + e.ruletype : '') + (e.filter ? ' - ' + e.filter : ''),
                    onclick: () => run(async () => { if (e.id === cur.id && !cur.noBase) return; cur = e; state.viewerEntry[pid] = e.id; filter.value = ''; typeChanged(); drawMenu(); await load(false); }) })));
        }).filter(x => x));
    }
    const sptype = el('select', {}, state.meta.securityprofiletypes.map(t => el('option', { value: t, text: t })));
    // the profile type of one profile (its class, the 'type' of its row): its window and references read exactly this
    // profile - with "any" (or SCM: virus) not the first profile of the same name (an URL profile, …)
    const spTypeOf = r => (r && (state.meta.securityprofileclasses || {})[r.type]) || sptype.value;
    // the profile types of the configuration: Panorama / firewall antivirus and WildFire analysis, SCM one
    // virus-and-wildfire-analysis profile (virus / wildfire-analysis of an older link: that one)
    function drawSpTypes(config) {
        const list = config === 'scm' && state.meta.securityprofiletypes_scm ? state.meta.securityprofiletypes_scm : state.meta.securityprofiletypes;
        let was = sptype.value;
        if (config === 'scm' && (was === 'virus' || was === 'wildfire-analysis')) was = 'virus-and-wildfire-analysis';
        sptype.replaceChildren(...list.map(t => el('option', { value: t, text: t })));
        if (!list.includes(was)) sptype.append(el('option', { value: was, text: was }));
        sptype.value = was;
    }
    // locations: 'any' and those of the version (Panorama: shared + device groups, firewall: shared + vsys, SCM: containers +
    // snippets), known once the version is loaded; a member limited to locations gets only those
    const location = el('select', {}, (p.scope || ['any']).map(l => el('option', { value: l, text: l })));
    // a long location list (many device groups / folders): a filter above it - the options that contain the text, an
    // optgroup without a match is hidden; Enter takes the first match; "any" stays
    const locFilter = el('input', { type: 'search', placeholder: 'filter locations …', autocomplete: 'off', spellcheck: false, 'aria-label': 'filter the locations', class: 'locfilter' });
    const locCount = el('span', { class: 'muted loccount' });
    function filterLocations() {
        const q = locFilter.value.trim().toLowerCase();
        let shown = 0, all = 0;
        for (const o of location.querySelectorAll('option')) {
            if (o.value === 'any') { o.hidden = false; continue; }
            all++;
            o.hidden = q !== '' && !o.text.toLowerCase().includes(q) && o.value !== location.value;
            if (!o.hidden) shown++;
        }
        // a hit stays below its parents: the parents of a shown location are shown as well (not counted as hits)
        if (q !== '') {
            const byName = new Map([...location.querySelectorAll('option')].map(o => [o.value, o]));
            for (const o of [...byName.values()].filter(o => !o.hidden))
                for (let up = byName.get(o.dataset.parent), i = 0; up && i < 50; up = byName.get(up.dataset.parent), i++) up.hidden = false;
        }
        for (const g of location.querySelectorAll('optgroup')) g.hidden = [...g.children].every(o => o.hidden);
        locCount.textContent = q ? shown + ' of ' + all : '';
        locFilter.hidden = all < 8 && q === '';
    }
    locFilter.addEventListener('input', filterLocations);
    locFilter.addEventListener('keydown', (ev) => {
        if (ev.key !== 'Enter') return;
        ev.preventDefault();
        const q = locFilter.value.trim().toLowerCase();
        const hit = [...location.querySelectorAll('option')].find(o => o.value !== 'any' && o.text.toLowerCase().includes(q));
        if (hit) { location.value = hit.value; location.dispatchEvent(new Event('change')); filterLocations(); }
    });
    filterLocations();
    let locationsLoaded = false;
    let locData = null;
    const locationInfo = { config: null, ancestor: false, version: null, predefined: [] };
    // Panorama, network types (zones, interfaces, routers, …): no device groups - template= picks the template /
    // template stack; location: shared (= the PANConf of the template, where the objects live) or one of its vsys
    // (what the vsys imports)
    const tplSel = el('select', {}, el('option', { value: 'any', text: 'any (all templates)' }));
    const tplField = field('Template', tplSel);
    tplField.hidden = true;
    function networkTemplates() {
        return cur && cur.section === 'Network' && locationInfo.config === 'panorama' && locData && (locData.templates || []).length ? locData.templates : null;
    }
    function drawTemplates() {
        const tl = networkTemplates();
        tplField.hidden = !tl;
        if (!tl) return;
        const was = view.template || tplSel.value || 'any';
        const kinds = { 'template': 'templates', 'template-stack': 'template stacks' };
        tplSel.replaceChildren(el('option', { value: 'any', text: 'any (all templates)' }),
            ...Object.keys(kinds).filter(k => tl.some(t => t.kind === k)).map(k => el('optgroup', { label: kinds[k] },
                tl.filter(t => t.kind === k).map(t => el('option', { value: t.name, text: t.name })))));
        tplSel.value = [...tplSel.options].some(o => o.value === was) ? was : 'any';
        view.template = tplSel.value === 'any' ? null : tplSel.value;
    }
    function drawLocationOptions() {
        if (!locData || !locData.locations.length) return;
        const r = locData, was = location.value, tl = networkTemplates();
        // SCM: the locations come with a group ('all', 'prisma-access', …) and in the order of the choice - All (the
        // global folder, as shared of Panorama), the Prisma Access folders, the containers, the firewalls, the snippets
        const kinds = { 'shared': 'shared', 'device-group': 'device groups', 'vsys': 'vsys', 'shared-gateway': 'shared gateways', 'all': 'All (global folder)', 'prisma-access': 'Prisma Access folders', 'container': 'containers (folders) and their firewalls', 'cloud': 'Prisma Access folders', 'on-prem': 'firewalls (on-prem)', 'snippet': 'snippets' };
        let groups;
        if (tl) {
            const vs = [...new Set(tl.filter(t => tplSel.value === 'any' || t.name === tplSel.value).flatMap(t => t.vsys || []))];
            groups = [el('optgroup', { label: 'template' }, el('option', { value: 'shared', text: 'shared (the template itself)' })),
                ...(vs.length ? [el('optgroup', { label: 'vsys (imported)' }, vs.map(v => el('option', { value: v, text: v })))] : [])];
        } else
            // the hierarchy: the locations come in the order of the tree, a child device group / folder / firewall with
            // its depth - indented (a select keeps only non-breaking spaces); the value stays the name, the whole path
            // is the tooltip
            groups = [...new Set(r.locations.map(l => l.group || l.kind))].map(k => el('optgroup', { label: kinds[k] || k },
                r.locations.filter(l => (l.group || l.kind) === k).map(l => {
                    const o = el('option', { value: l.name, text: l.depth > 0 ? '\u00a0'.repeat(l.depth * 3 - 2) + '\u2514\u00a0' + l.name : l.name });
                    if (l.parent) o.dataset.parent = l.parent;
                    if (l.parent) {
                        const path = [l.name];
                        for (let up = r.locations.find(x => x.name === l.parent), i = 0; up && i < 50; up = up.parent ? r.locations.find(x => x.name === up.parent) : null, i++) path.unshift(up.name);
                        o.title = path.join(' / ');
                    }
                    return o;
                })));
        location.replaceChildren(...(r.any ? [el('option', { value: 'any', text: 'any (all locations)' })] : []), ...groups);
        drawPredefined();
        location.value = [...location.options].some(o => o.value === was) ? was : location.options[0].value;
        drawDgScope();
        filterLocations();
    }
    tplSel.addEventListener('change', () => { view.template = tplSel.value === 'any' ? null : tplSel.value; drawLocationOptions(); });
    async function loadLocations() {
        if (locationsLoaded) return;
        locationsLoaded = true;
        const r = await api('GET', base() + '/locations').catch(() => null);
        if (r) Object.assign(locationInfo, { config: r.config, ancestor: !!r.ancestor, version: Number.isInteger(r.version) ? r.version : null,
            predefined: Array.isArray(r.predefined) ? r.predefined : [] });
        if (r) {
            // the rule base of this PAN-OS version: authentication (8.0 and later) / captive portal (before)
            if (!entryOffered(cur) && cur.ruletype) {
                const other = entries.find(e => e.type === 'rule' && e.ruletype === (cur.ruletype === 'captiveportal' ? 'authentication' : 'captiveportal'));
                if (other) { cur = other; state.viewerEntry[pid] = other.id; typeChanged(); setTimeout(() => run(() => load(false)), 0); }
            }
            drawMenu();
        }
        if (r) drawSpTypes(r.config);
        if (!r || !r.locations.length) return;
        locData = r;
        drawTemplates();
        drawLocationOptions();
    }
    // Panorama: a device group with its child device groups (pan-os-php location=<DG>:includechilddgs) or only its
    // child device groups (location=<DG>:excludemaindg) - offered when a device group is chosen as location; not with
    // access limited to locations (a child device group may be outside the scope)
    const dgScope = el('select', {}, el('option', { value: '', text: 'only this device group' }),
        el('option', { value: 'includechilddgs', text: '+ all child device groups (includechilddgs)' }),
        el('option', { value: 'excludemaindg', text: 'only the child device groups (excludemaindg)' }),
        // the effective view (viewer): the location and all levels above it, the copy that wins per name marked
        el('option', { value: 'effective', text: '+ parents (effective view)' }),
        // the effective view with the predefined objects of the type as the level above all (object types)
        el('option', { value: 'effective-predefined', text: '+ parents + predefined (effective view + predefined)' }));
    // the effective view, with or without the predefined objects
    const effectiveView = () => (dgScope.value === 'effective' || dgScope.value === 'effective-predefined') && !dgScopeField.hidden;
    const dgScopeField = field('Device groups', dgScope);
    // same name on other levels (pan-os-php filters is.overriden / is.overriding - as object-merger sees it): the copy
    // that hides another one and the hidden one; the list shows both in the columns "overrides" / "overridden in"
    const sameName = el('select', { 'aria-label': 'same name on other levels' }, el('option', { value: '', text: 'all objects' }),
        el('option', { value: 'both', text: 'overridden or overriding' }), el('option', { value: 'overridden', text: 'overridden (hidden by another level)' }),
        el('option', { value: 'overriding', text: 'overriding (hides another level)' }));
    const sameNameField = field('Same name', sameName);
    sameName.addEventListener('change', () => run(() => load(false)));
    function drawSameName() {
        const f = (state.meta.types[type.value] || {}).filters || {};
        sameNameField.hidden = !(f.object && f.object['is.overriden'] && f.object['is.overriding'] && f.object['is.overriden.for'] && f.object['is.overriding.for']);
        if (sameNameField.hidden) sameName.value = '';
    }
    dgScopeField.hidden = true;
    // the kind of a location for the choice: a device group, shared of Panorama (all device groups are below it), an
    // SCM container (folder: containers, cloud / on-prem devices below it), a cloud folder / firewall of SCM, a snippet,
    // a vsys; null: no choice (any, predefined)
    function scopeKind(name) {
        const o = [...location.options].find(x => x.value === name);
        const group = o && o.parentElement && o.parentElement.tagName === 'OPTGROUP' ? o.parentElement.label : '';
        if (group === 'device groups') return 'dg';
        // an SCM container, in whatever group of the choice it is listed (All, Prisma Access folders, containers)
        const info = !networkTemplates() && locData ? locData.locations.find(l => l.name === name) : null;
        if (info && info.kind === 'container') return 'container';
        // the other locations of SCM have nothing below them, but levels above: a cloud folder of Prisma Access (Mobile
        // Users, Remote Networks, …) and a firewall have the effective view, a snippet the predefined objects
        if (info && (info.kind === 'cloud' || info.kind === 'on-prem')) return 'device';
        if (info && info.kind === 'snippet') return 'snippet';
        if (name === 'shared' && [...location.querySelectorAll('optgroup')].some(g => g.label === 'device groups')) return 'shared';
        if (group === 'vsys' || group === 'shared gateways') return 'vsys';
        return null;
    }
    function drawDgScope() {
        const kind = scopeKind(location.value);
        dgScopeField.hidden = !!p.scope || kind === null;
        if (dgScopeField.hidden) { dgScope.value = ''; return; }
        // the last entry (… + predefined): only for the object types - rules and network types have no predefined objects
        const pre = cur.section === 'Objects' && !networkTemplates();
        const t = { dg: ['only this device group', '+ all child device groups', 'only the child device groups', '+ parents up to shared (effective view)',
                pre ? '+ parents up to shared + predefined (effective view + predefined)' : null],
            shared: ['only shared', '+ all device groups', 'only the device groups', null, pre ? '+ predefined (effective view + predefined)' : null],
            container: ['only this container', '+ all child containers / devices', 'only the child containers / devices', '+ snippets and parents up to All (effective view)',
                pre ? '+ snippets and parents up to All + predefined (effective view + predefined)' : null],
            device: ['only this folder / firewall', null, null, '+ snippets and parents up to All (effective view)',
                pre ? '+ snippets and parents up to All + predefined (effective view + predefined)' : null],
            snippet: ['only this snippet', null, null, null, pre ? '+ predefined (effective view + predefined)' : null],
            vsys: ['only this vsys', null, null, '+ shared (effective view)', pre ? '+ shared + predefined (effective view + predefined)' : null] }[kind];
        // a snippet outside of the object types has only "only this snippet": no choice to show
        if (t.filter(x => x !== null).length < 2) { dgScopeField.hidden = true; dgScope.value = ''; return; }
        [...dgScope.options].forEach((o, i) => { o.hidden = t[i] === null; if (t[i] !== null) o.text = t[i] + (o.value && !/^effective/.test(o.value) ? ' (' + o.value + ')' : ''); });
        if (dgScope.selectedOptions[0] && dgScope.selectedOptions[0].hidden) dgScope.value = '';
        dgScopeField.firstChild.textContent = kind === 'container' ? 'Containers' : (kind === 'vsys' || kind === 'device' || kind === 'snippet' ? 'Scope' : 'Device groups');
    }
    location.addEventListener('change', drawDgScope);
    const filter = el('input', { placeholder: '(name contains web) and (object is.unused) - type for fields and operators', maxlength: 2000, autocomplete: 'off', spellcheck: false });
    const filterBox = suggest(filter, (text, pos) => filterSuggest(state.meta.types[type.value].filters || {}, text, pos));
    const quick = el('input', { placeholder: 'text in any column', oninput: () => { view.quick = quick.value.toLowerCase(); view.page = 1; draw(); } });
    const spField = field('Profile type', sptype);
    // type=device: which devices (device groups, templates, …; the hierarchy of a device group in its window)
    const devtype = el('select', {}, (state.meta.devicetypes || ['any']).map(t => el('option', { value: t, text: t })));
    const devField = field('Device type', devtype);
    // "Extra columns": additional fields of pan-os-php exportToExcel of the type (NestedMembers, ResolveIP, rule
    // summaries, best practice, …) - computed on the server when ticked and shown as columns of the list (per type)
    state.extraCols = state.extraCols || {};
    const extraBox = el('details', { class: 'extracols' });
    function drawExtra() {
        const cols = (state.meta.types[type.value] || {}).columns || [];
        const key = type.value;
        const chosen = state.extraCols[key] || [];
        extraBox.hidden = cols.length === 0;
        const boxes = cols.map(c => el('input', { type: 'checkbox', value: c, checked: chosen.includes(c) }));
        const apply = () => run(async () => { state.extraCols[key] = boxes.filter(b => b.checked).map(b => b.value); drawExtra(); await load(false); });
        boxes.forEach(b => b.addEventListener('change', apply));
        extraBox.replaceChildren(el('summary', { text: 'Extra columns' + (chosen.length ? ' (' + chosen.length + ')' : '') }),
            el('div', { class: 'checks' }, boxes.map(b => el('label', {}, b, ' ' + b.value)),
                el('button', { type: 'button', class: 'small', text: 'none', onclick: () => { boxes.forEach(b => { b.checked = false; }); apply(); } })),
            el('p', { class: 'muted', text: 'pan-os-php exportToExcel - additional fields, computed for the objects of the list (slower for many objects)' }));
    }
    const heading = el('h3', { class: 'vheading' });
    const info = el('span', { class: 'muted' });
    const tableWrap = el('div', { class: 'tablewrap' });
    const pager = el('div', { class: 'pager' });
    const status = el('span', { class: 'badge', text: 'not loaded yet' });
    const autosaveInfo = el('span', { class: 'muted' });
    const saveBtn = el('button', { class: 'primary', type: 'button', text: 'Save as new version', disabled: true, onclick: () => run(save) });
    const discardBtn = el('button', { class: 'danger', type: 'button', text: 'Discard changes', disabled: true, onclick: () => run(async () => {
        if (!confirm('Discard all unsaved changes?')) return;
        await api('POST', base() + '/discard'); state.cache.clear(); setStatus({ loaded: false, dirty: false, changes: [] }); await load(true);
    }) });
    const autosave = el('select', {}, el('option', { value: '0', text: 'off' }), el('option', { value: '5', text: 'every 5 min' }), el('option', { value: '10', text: 'every 10 min' }));
    const changeList = el('ul', {});
    const log = el('pre', { class: 'log', hidden: true });
    let lastStatus = null;

    // the types with predefined objects (pan-os-php UTIL::predefinedTypes, from GET …/locations): location "predefined"
    // - only to read them (they are also listed at shared); never a target. Also with access limited to locations
    // (predefined objects belong to no location). SCM: the predefined snippet is a location of its own (regions: here)
    function drawPredefined() {
        const pre = location.querySelector('option[value="predefined"]');
        // offered for every object type, on firewall, Panorama and SCM - a type without predefined objects (address,
        // tag, …) lists nothing there; not for the templates of Panorama (network types)
        if ((cur.section === 'Objects' || locationInfo.predefined.includes(type.value)) && !networkTemplates()) {
            // hierarchy: after "any", before shared / All (predefined objects are above them)
            if (!pre) {
                const opt = el('option', { value: 'predefined', text: 'predefined (read only)' });
                const any = location.querySelector('option[value="any"]');
                if (any) any.after(opt); else location.prepend(opt);
            }
        } else if (pre) {
            if (location.value === 'predefined') location.value = location.options[0].value;
            pre.remove();
        }
    }
    function typeChanged() {
        view.template = null;
        // Panorama network types: the chosen template stays; other types: device groups again
        drawTemplates();
        drawLocationOptions();
        drawPredefined();
        spField.hidden = type.value !== 'securityprofile';
        devField.hidden = type.value !== 'device';
        drawSameName();
        drawExtra();
        heading.textContent = cur.section + ' › ' + cur.label;
        action.value = '';
        actionChanged();
    }
    function query() {
        // the filter of the menu entry (e.g. address groups: (object is.group)) and the one typed
        const own0 = filter.value.trim();
        // the effective view of a location: same name as the firewalls of THIS location see it (is.overriden.for /
        // is.overriding.for <location> - its levels only); else the whole hierarchy (is.overriden / is.overriding)
        const eff = effectiveView() && location.value && location.value !== 'any';
        const sfx = eff ? '.for ' + location.value : '';
        const sn = sameNameField.hidden ? '' : { both: '(object is.overriden' + sfx + ') or (object is.overriding' + sfx + ')', overridden: '(object is.overriden' + sfx + ')',
            overriding: '(object is.overriding' + sfx + ')' }[sameName.value] || '';
        // both copies of a name next to each other (from the top level down)
        if (eff && sn && !view.sortSet) { view.sort = 'name'; view.desc = false; }
        const own = sn ? (own0 ? '(' + own0 + ') and (' + sn + ')' : sn) : own0;
        const f = cur.filter && !cur.noBase ? (own ? '(' + cur.filter + ') and (' + own + ')' : cur.filter) : own;
        const q = new URLSearchParams({ type: type.value, location: (location.value || 'any') + (dgScope.value && !dgScopeField.hidden ? ':' + dgScope.value : ''), filter: f });
        if (type.value === 'rule') q.set('ruletype', ruletype.value);
        if (type.value === 'securityprofile') q.set('securityprofiletype', sptype.value);
        if (type.value === 'device') q.set('devicetype', devtype.value);
        if (view.template) q.set('template', view.template);
        const extra = (state.extraCols || {})[type.value] || [];
        if (extra.length) q.set('columns', extra.join('|'));
        return q;
    }
    function setStatus(s) {
        if (!s) return;
        lastStatus = s;
        const n = (s.changes || []).length;
        status.textContent = s.dirty ? n + ' unsaved change' + (n === 1 ? '' : 's') : (s.loaded === false ? 'not loaded' : 'no unsaved changes');
        status.className = 'badge' + (s.dirty ? ' dirty' : '');
        saveBtn.disabled = !(canWrite && s.dirty); discardBtn.disabled = !(canWrite && s.dirty);
        autosaveInfo.textContent = s.autosaved ? 'recovery copy written ' + fmtTime(s.autosaved) : '';
        changeList.replaceChildren(...(s.changes || []).map((c, i) => typeof c === 'string' ? el('li', { text: c }) : c.type === 'undo' ?
            el('li', { class: 'undo' }, el('span', { class: 'muted', text: fmtTime(c.time) + ' ' + (c.user || '') + ' - ' }), el('code', { text: 'undo' }),
                el('span', { text: ' of change ' + ((c.index || 0) + 1) + ': ' + (c.undoes || '') })) :
            el('li', { class: c.undone ? 'undone' : '' }, el('span', { class: 'muted', text: (i + 1) + '. ' + fmtTime(c.time) + ' ' + (c.user || '') + ' - ' }), el('code', { text: c.type + (c.ruletype ? '/' + c.ruletype : '') }), ' ',
                el('span', { text: (c.template ? 'template ' + c.template + ' / ' : '') + (c.location || 'any') + (c.filter ? ' ' + c.filter : '') + ' → ' }), el('code', { text: c.actions || '' }),
                c.field ? el('span', { class: 'muted', text: c.field === 'multi-edit' ? ' (multi-edit)' : ' (field ' + c.field + ')' }) : null,
                // a change of one object: the same action on more objects (filter from the properties of the object)
                canWrite && !c.undone && /^\(name eq .+\)$/.test(c.filter || '') && c.actions ? el('button', { type: 'button', class: 'small', text: 'Multi-edit …',
                    title: 'the same action on more objects', onclick: () => run(() => openMultiEdit(c)) }) : null,
                // undo of this change (git history of the version): taken back on the current state, the others stay
                c.undone ? el('span', { class: 'muted', text: ' (undone)' }) : canWrite && c.commit ? el('button', { type: 'button', class: 'small', text: 'Undo',
                    title: 'take this change back - the later changes stay', onclick: () => run(() => undoChange(i, c)) }) : null)));
    }
    async function undoChange(i, c) {
        if (!confirm('Take back change ' + (i + 1) + '?\n' + c.type + ' ' + (c.location || '') + ' ' + (c.filter || '') + ' → ' + (c.actions || ''))) return;
        const r = await api('POST', base() + '/undo', { index: i });
        state.cache.clear();
        setStatus(Object.assign({ loaded: true }, r.status || {}));
        await load(true);
        const notes = [];
        if (r.unresolved && r.unresolved.length) notes.push('Used but not there any more after the undo: ' + r.unresolved.join(', '));
        if (r.warning) notes.push(r.warning);
        if (notes.length) alert(notes.join('\n\n'));
    }
    async function load(force) {
        const key = query().toString();
        let data = force ? null : state.cache.get(key);
        const fromCache = !!data;
        if (!data) {
            info.textContent = 'loading ...';
            const t = performance.now();
            data = await api('GET', base() + '/objects?' + key);
            data.ms = Math.round(performance.now() - t);
            state.cache.set(key, data);
        }
        setStatus(data.status ? Object.assign({ loaded: true }, data.status) : lastStatus);
        // the store of an object (AddressStore, …) says nothing in a list of one menu entry
        view.rows = data.rows; view.columns = data.columns.filter(c => c !== 'store'); view.page = 1;
        view.query = key; view.type = type.value; view.refs.clear();
        if (!view.columns.includes(view.sort)) view.sort = null;
        loadLocations();
        info.textContent = data.total + ' objects' + (data.truncated ? ' (first ' + data.rows.length + ' shown)' : '') + (fromCache ? ' - from browser cache' : ' - ' + data.ms + ' ms')
            + (view.template ? ' - only template ' + view.template + ' (another type shows all)' : '')
            // the effective view: which copy of a name wins (Panorama setting "ancestor objects take precedence")
            + (effectiveView() ? ' - effective view' + (dgScope.value === 'effective-predefined' ? ' + predefined' : '') + ': ' + (locationInfo.config === 'panorama'
                ? (locationInfo.ancestor ? 'ancestor objects take precedence (the highest copy wins)' : 'the nearest copy wins (ancestor precedence off)')
                : 'the nearest copy wins') : '');
        draw();
        // a link "Open ↗" of a reference: the window of that object
        const want = view.openAfterLoad;
        view.openAfterLoad = null;
        if (want) {
            const r = view.rows.find(x => x.name === want.name && (!want.location || x.location === want.location) && (x.template || '') === want.template && (x.profile || '') === want.profile)
                || view.rows.find(x => x.name === want.name);
            if (r) await openObject(r);
            else message('the object ' + want.name + ' is not in this version (any more)', 'error');
        }
    }
    // ---- references of one object (actions=displayreferences): below its row; "Open" shows the user in a new window
    async function toggleRefs(r, key) {
        if (view.refs.has(key)) { view.refs.delete(key); draw(); return; }
        view.refs.set(key, null); draw();
        const q = new URLSearchParams(view.query);
        q.set('name', r.name);
        if (q.get('type') === 'securityprofile') q.set('securityprofiletype', spTypeOf(r));
        if (r.location) q.set('location', r.location);
        if (r.profile) q.set('profile', r.profile);
        if (r.template) q.set('template', r.template);
        q.delete('filter');
        try { view.refs.set(key, await api('GET', base() + '/references?' + q.toString())); }
        catch (e) { view.refs.set(key, { error: e.message }); }
        if (view.refs.has(key)) draw();
    }
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
    function openLink(ref) {
        // an object of a template: pan-os-php finds a vsys of a template only with location=any (+ template) - the
        // list then shows all locations of the template, "at" says which row to open
        const h = new URLSearchParams({ p: pid, c: state.config.cid, type: ref.type, location: ref.template ? 'any' : ref.location, filter: '(name eq ' + ref.name + ')', open: ref.name });
        // the entry of the object's class: an address group opens as address group (not in the list / window of addresses)
        const e = viewerEntryFor(entries, ref.type, ref.ruletype, ref.class);
        if (e) h.set('entry', e.id);
        if (ref.template && ref.location) h.set('at', ref.location);
        for (const k of ['ruletype', 'securityprofiletype', 'devicetype', 'template', 'profile']) if (ref[k]) h.set(k, ref[k]);
        return window.location.pathname + '#' + h.toString();
    }
    // the references of one object as a box (list rows and the object window): who uses it, each with "Open ↗"
    function refsTable(refs) {
        return table(['Used by', 'Location', 'Name', 'Where', ''], refs.map(ref => el('tr', {},
            el('td', { text: ref.type && (viewerEntryFor(entries, ref.type, ref.ruletype, ref.class) || {}).classes ? viewerEntryFor(entries, ref.type, ref.ruletype, ref.class).one
                : ref.type ? ref.type + (ref.ruletype ? ' (' + ref.ruletype + ')' : '') + (ref.securityprofiletype ? ' (' + ref.securityprofiletype + ')' : '') + (ref.devicetype ? ' (' + ref.devicetype + ')' : '') : ref.class }),
            el('td', { text: (ref.location || '') + (ref.template ? ' (template ' + ref.template + ')' : '') }),
            el('td', { text: ref.name + (ref.profile ? ' (profile ' + ref.profile + ')' : '') }),
            el('td', { class: 'wrap', text: [ref.rulebase ? ref.rulebase + ' rule' : null, ...(ref.fields || [])].filter(x => x).join(', ') }),
            el('td', {}, ref.open ? el('a', { href: openLink(ref), target: '_blank', rel: 'noopener', text: 'Open ↗', title: 'show this ' + ref.type + ' in a new window' })
                : el('span', { class: 'muted', text: ref.type ? '' : 'no window', title: 'the viewer has no list for ' + ref.class })))));
    }
    function refsBox(d) {
        if (d === null) return el('div', { class: 'refs muted', text: 'reading the references ...' });
        if (d.error) return el('div', { class: 'refs error', text: d.error });
        if (!d.objects.length) return el('div', { class: 'refs muted', text: 'object not found' });
        return el('div', { class: 'refs' }, d.objects.map(o => el('div', {},
            el('div', { class: 'muted', text: (d.objects.length > 1 ? o.location + ': ' : '') + (o.references.length ? 'used by ' + o.references.length + ':' : 'not used (no references)')
                + (o.hidden ? ' - ' + o.hidden + ' more outside your types / locations' : '') }),
            o.references.length ? refsTable(o.references) : null)));
    }
    // a value of a list cell: lists and nested values (e.g. the details of an application) as text - never "[object Object]"
    function cell(v) { return v !== null && typeof v === 'object' ? fmtTree(v) : (v === null || v === undefined ? '' : String(v)); }
    function draw() {
        let rows = view.rows;
        if (view.quick) rows = rows.filter(r => view.columns.some(c => cell(r[c]).toLowerCase().includes(view.quick)));
        if (view.sort) {
            const c = view.sort, d = view.desc ? -1 : 1;
            rows = rows.slice().sort((a, b) => d * cell(a[c]).localeCompare(cell(b[c]), undefined, { numeric: true, sensitivity: 'base' }));
        }
        const pages = Math.max(1, Math.ceil(rows.length / view.size));
        view.page = Math.min(view.page, pages);
        const slice = rows.slice((view.page - 1) * view.size, view.page * view.size);
        tableWrap.replaceChildren(el('table', {},
            el('thead', {}, el('tr', {}, view.columns.map(c => el('th', { text: c + (view.sort === c ? (view.desc ? ' ▼' : ' ▲') : ''), onclick: () => {
                view.sortSet = true; if (view.sort === c) view.desc = !view.desc; else { view.sort = c; view.desc = false; }
                draw();
            } })), state.meta.types[view.type] && state.meta.types[view.type].references && !view.columns.includes('refcount') ? el('th', { text: 'references' }) : null)),
            el('tbody', {}, slice.flatMap(r => {
                // refcount (types with references): the number is the button that shows the users below the row;
                // 0 - nothing to show; no number (not counted) - the button still works
                const refs = state.meta.types[view.type] && state.meta.types[view.type].references && typeof r.name === 'string' && r.name !== '';
                // one row = one object: the same name in another template / security profile is another row (before
                // the key had neither - the references of one were shown at every row of that name)
                const key = (r.location || '') + '|' + (r.template || '') + '|' + (r.profile ? r.profile + '/' : '') + r.name;
                const refButton = () => r.refcount === 0 ? el('span', { class: 'muted', text: '0', title: 'not used' })
                    : el('button', { type: 'button', class: 'small refbtn' + (view.refs.has(key) ? ' on' : ''), text: (typeof r.refcount === 'number' ? r.refcount : '?') + (view.refs.has(key) ? ' ▾' : ' ▸'),
                        title: (view.refs.has(key) ? 'hide' : 'show') + ' where this object is used (pan-os-php displayreferences)', onclick: () => run(() => toggleRefs(r, key)) });
                // an object of a type with an object window: a click opens it (as the edit dialog of PAN-OS)
                const win = cur.window && typeof r.name === 'string' && r.name !== '' && r.location;
                const row = el('tr', win ? { class: 'clickable' + (typeof r.effective === 'string' && r.effective !== 'used' ? ' overridden' : ''), title: 'open ' + r.name, onclick: (ev) => { if (ev.target.closest('button, a')) return; run(() => openObject(r)); } } : {}, view.columns.map(c => {
                    if (c === 'refcount' && refs) return el('td', { class: 'refcell' }, refButton());
                    const t = cell(r[c]);
                    // effective view: the copy a firewall of the location gets, or the one it is hidden by
                    if (c === 'effective' && t) return el('td', {}, el('span', { class: 'badge ' + (t === 'used' ? 'effused' : 'effover'), text: t }));
                    return el('td', { text: t, title: t.length > 40 ? t : null });
                }), refs && !view.columns.includes('refcount') ? el('td', { class: 'refcell' }, refButton()) : null);
                return view.refs.has(key) ? [row, el('tr', { class: 'refrow' }, el('td', { colspan: view.columns.length + 1 }, refsBox(view.refs.get(key))))] : [row];
            }))));
        pager.replaceChildren(
            el('button', { type: 'button', text: '‹ Previous', disabled: view.page <= 1, onclick: () => { view.page--; draw(); } }),
            el('span', { text: 'page ' + view.page + ' of ' + pages + (view.quick ? ' - ' + rows.length + ' match the quick filter' : '') }),
            el('button', { type: 'button', text: 'Next ›', disabled: view.page >= pages, onclick: () => { view.page++; draw(); } }));
    }
    async function save() {
        const r = await api('POST', base() + '/save');
        if (r.saved) {
            state.config = Object.assign({}, state.config, { cid: r.cid });
            title.textContent = 'Version of ' + fmtTime(Date.now() / 1000) + ' - ' + state.config.name;
            message('saved as a new version');
        }
        setStatus(Object.assign({ loaded: true }, r.status));
    }

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
    function windowFields(kind, row, m) {
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
        if (kind === 'rule') return ruleFields(row, m, name, loc);
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
    function ruleFields(row, m, name, loc) {
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
    async function fetchObject(name, loc, template, profile, cls) {
        const q = new URLSearchParams({ type: cur.type, location: loc, name });
        if (template) q.set('template', template);
        if (profile) q.set('profile', profile);
        if (cur.type === 'rule') q.set('ruletype', ruletype.value);
        if (cur.type === 'securityprofile') q.set('securityprofiletype', spTypeOf({ type: cls }));
        return api('GET', base() + '/object?' + q.toString());
    }
    // System: the settings of the firewall / Panorama (or a template of it) / SCM folder, snippet or device - every
    // config section of pan-os-php (type=config-section, utils/common/config_sections.json) that applies; read only,
    // secrets never shown
    async function showSystem() {
        const box = el('div', { class: 'objwin syswin', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'system settings' });
        const overlay = el('div', { class: 'objoverlay', onclick: (ev) => { if (ev.target === overlay) close(); } }, box);
        const onKey = (ev) => { if (ev.key === 'Escape') close(); };
        function close() { document.removeEventListener('keydown', onKey); overlay.remove(); }
        document.addEventListener('keydown', onKey);
        document.body.append(overlay);
        const want = { template: '', location: '' };
        const sysErrors = {}, sysDone = {}, openSecs = new Set();
        // one change: pan-os-php type=config-section on the loaded configuration (change list, history, undo)
        async function sysChange(x, action, entry, path, value) {
            delete sysErrors[x.name]; delete sysDone[x.name];
            try {
                const body = { section: x.name, action, entry, path, value };
                if (want.template) body.template = want.template;
                if (want.location) body.location = want.location;
                const res = await api('POST', base() + '/system/change', body);
                setStatus(Object.assign({ loaded: true }, res.status));
                state.cache.clear();
                sysDone[x.name] = action + (path ? ' ' + path : '') + (value ? ' = ' + value : '') + (entry ? ' (' + entry + ')' : '');
            } catch (e) { sysErrors[x.name] = e.message; }
            openSecs.add(x.name);
            await draw();
        }
        function addField(x, entry) {
            const k = el('input', { placeholder: 'field, e.g. idle-timeout or a.b.c', autocomplete: 'off', spellcheck: false, 'aria-label': 'new field of ' + x.name });
            const v = el('input', { placeholder: 'value', autocomplete: 'off', spellcheck: false, 'aria-label': 'value of the new field of ' + x.name });
            return el('div', { class: 'row' }, k, v, el('button', { type: 'button', class: 'small', text: 'Set', onclick: () => { if (k.value.trim() && v.value.trim()) sysChange(x, 'set', entry, k.value.trim(), v.value.trim()); } }));
        }
        function addEntry(x) {
            const n = el('input', { placeholder: 'new entry name', autocomplete: 'off', spellcheck: false, 'aria-label': 'new entry of ' + x.name });
            const k = el('input', { placeholder: 'field', autocomplete: 'off', spellcheck: false, 'aria-label': 'field of the new entry of ' + x.name });
            const v = el('input', { placeholder: 'value', autocomplete: 'off', spellcheck: false, 'aria-label': 'value of the new entry of ' + x.name });
            return el('div', { class: 'row' }, n, k, v, el('button', { type: 'button', class: 'small', text: 'Add entry', onclick: () => { if (n.value.trim() && k.value.trim() && v.value.trim()) sysChange(x, 'set', n.value.trim(), k.value.trim(), v.value.trim()); } }));
        }
        const GROUPS = ['Management', 'System', 'Administrators', 'Authentication', 'Logging', 'Updates and schedules', 'Other'];
        async function draw() {
            box.replaceChildren(el('p', { class: 'muted', text: 'reading the system settings ...' }));
            const q = new URLSearchParams();
            for (const k of ['template', 'location']) if (want[k]) q.set(k, want[k]);
            let r;
            try { r = await api('GET', base() + '/system?' + q.toString()); }
            catch (e) { box.replaceChildren(el('div', { class: 'objhead' }, el('h3', { text: 'System settings' }), el('button', { type: 'button', class: 'objclose', text: '✕', onclick: close })), el('div', { class: 'error', text: e.message })); return; }
            // which part: Panorama itself or one of its templates; SCM: a folder / snippet / device (default All)
            let chooser = null;
            if (r.config === 'panorama' || r.config === 'scm') {
                const sel = el('select', { 'aria-label': r.config === 'scm' ? 'folder' : 'template' },
                    r.config === 'panorama' ? el('option', { value: '', text: 'Panorama' }) : null,
                    (r.choices || []).map(c => el('option', { value: c, text: (r.config === 'panorama' ? 'template ' : '') + c })));
                sel.value = r.config === 'scm' ? (r.location || 'All') : (r.template || '');
                sel.addEventListener('change', () => { if (r.config === 'scm') want.location = sel.value; else want.template = sel.value; draw(); });
                chooser = field(r.config === 'scm' ? 'Folder / snippet / device' : 'Settings of', sel);
            }
            const title = r.config === 'scm' ? 'SCM: ' + (r.location || 'All') : (r.template ? 'template ' + r.template : (r.config === 'panorama' ? 'Panorama' : 'firewall'));
            const facts = [];
            if (r.config === 'panorama' && !r.template)
                facts.push('ancestor objects take precedence: ' + (r.ancestor ? 'yes - the highest copy of a name wins' : 'no - the nearest copy of a name wins (default)'));
            const groups = GROUPS.map(g => {
                const secs = (r.sections || []).filter(x => (GROUPS.includes(x.group) ? x.group : 'Other') === g);
                if (!secs.length) return null;
                return el('div', { class: 'sysgroup' }, el('h4', { text: g }), secs.map(x => {
                    const n = x.entries.length;
                    const ed = !!x.editable && canWrite;
                    const entryBody = (e) => {
                        const ent = x.kind === 'settings' ? '' : e.name;
                        const members = e.members || [];
                        const rows = Object.entries(e.fields).map(([k, v]) => {
                            const secret = /^\*\*\* (hidden|encrypted) \*\*\*$/.test(v);
                            let cell;
                            if (!ed || secret) cell = el('td', { text: v });
                            else if (members.includes(k)) {
                                const add = el('input', { placeholder: 'add …', autocomplete: 'off', 'aria-label': 'add to ' + k });
                                add.addEventListener('change', () => { if (add.value.trim()) sysChange(x, 'add-member', ent, k, add.value.trim()); });
                                cell = el('td', {}, el('div', { class: 'chips' }, v.split(', ').filter(m => m).map(m => el('span', { class: 'chip' }, m,
                                    el('button', { type: 'button', class: 'chipx', text: '✕', 'aria-label': 'remove ' + m, onclick: () => sysChange(x, 'remove-member', ent, k, m) }))), add));
                            } else {
                                const i = el('input', { value: v === '(set)' ? '' : v, placeholder: v === '(set)' ? '(set - no value)' : '', autocomplete: 'off', spellcheck: false, 'aria-label': k });
                                i.addEventListener('change', () => { if (i.value.trim() !== '' && i.value.trim() !== v) sysChange(x, 'set', ent, k, i.value.trim()); });
                                i.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); i.blur(); } });
                                cell = el('td', {}, i);
                            }
                            return el('tr', {}, el('th', { text: k }), cell,
                                ed && !secret ? el('td', {}, el('button', { type: 'button', class: 'small', text: '✕', title: 'remove the field ' + k, 'aria-label': 'remove field ' + k, onclick: () => sysChange(x, 'remove-field', ent, k, '') })) : null);
                        });
                        return el('div', { class: 'sysentry' },
                            x.kind === 'settings' ? null : el('div', { class: 'sysname' }, e.name, ed ? el('button', { type: 'button', class: 'small danger', text: 'Delete', style: 'margin-left:.6em',
                                onclick: () => { if (confirm('Delete ' + e.name + ' of ' + x.name + '?')) sysChange(x, 'delete', e.name, '', ''); } }) : null),
                            rows.length ? el('table', { class: 'objfields' }, el('tbody', {}, rows)) : el('p', { class: 'muted', text: '(empty)' }),
                            ed ? addField(x, ent) : null,
                            (e.references || []).length ? el('p', { class: 'muted', text: 'references: ' + e.references.map(rf => rf.kind + ' ' + rf.name).join(', ') }) : null);
                    };
                    const body = el('div', {}, n === 0 ? el('p', { class: 'muted', text: 'not set' }) : x.entries.map(entryBody),
                        ed && x.kind === 'settings' && n === 0 ? addField(x, '') : null,
                        ed && x.kind !== 'settings' ? addEntry(x) : null,
                        sysErrors[x.name] ? el('div', { class: 'error', text: sysErrors[x.name] }) : null,
                        sysDone[x.name] ? el('div', { class: 'muted objact' }, '✓ ', el('code', { text: sysDone[x.name] })) : null);
                    const d = el('details', { class: 'objsection' }, el('summary', {}, x.name + (x.kind === 'settings' ? '' : ' (' + n + ')') + ' ', el('span', { class: 'muted', text: '- ' + x.description })),
                        el('p', { class: 'muted', text: x.path }), body);
                    d.open = (n > 0 && x.kind === 'settings') || !!sysErrors[x.name] || !!sysDone[x.name] || openSecs.has(x.name);
                    d.addEventListener('toggle', () => { if (d.open) openSecs.add(x.name); else openSecs.delete(x.name); });
                    return d;
                }));
            }).filter(x => x);
            box.replaceChildren(
                el('div', { class: 'objhead' }, el('h3', { text: 'System settings - ' + title }), el('button', { type: 'button', class: 'objclose', text: '✕', 'aria-label': 'close', onclick: close })),
                chooser, ...facts.map(f => el('p', { class: 'sysfact', text: f })),
                el('p', { class: 'muted', text: 'As pan-os-php type=config-section shows them (section=list); passwords, keys and secrets are never shown. '
                    + (canWrite ? 'Sections reviewed in action-classes.json can be changed: a field is applied when you leave it (config-section set / add-member / remove-member / remove-field) - nothing is written until "Save as new version".' : 'Read only.') }),
                ...groups, el('div', { class: 'row' }, el('button', { type: 'button', text: 'Close', onclick: close })));
        }
        await draw();
    }
    async function openObject(r) {
        // the generic window shows the list row when the object can not be read on its own (e.g. a type without a name filter)
        let obj = cur.window === 'generic' ? await fetchObject(r.name, r.location, r.template, r.profile, r.type).catch(() => ({ row: r, model: null }))
            : await fetchObject(r.name, r.location, r.template, r.profile, r.type);
        // a read-only object (temporary, predefined, GlobalProtect gateway tunnel - pan-os-php CallContext::readOnlyReason):
        // every field read only, also for a member with write
        const writable = canWrite && !obj.row.readonly;
        const offered = state.meta.types[cur.type].actions || {};
        const done = {}, errors = {}, pending = {}, hints = {};
        const box = el('div', { class: 'objwin', role: 'dialog', 'aria-modal': 'true', 'aria-label': cur.label + ' ' + r.name });
        const overlay = el('div', { class: 'objoverlay', onclick: (ev) => { if (ev.target === overlay) close(); } }, box);
        const onKey = (ev) => { if (ev.key === 'Escape') close(); };
        let changed = false;
        function close() { document.removeEventListener('keydown', onKey); overlay.remove(); if (changed) run(() => load(true)); }
        async function apply(f, actions) {
            const body = { type: cur.type, location: obj.row.location, filter: '(name eq ' + obj.row.name + ')', actions, field: f.key };
            if (obj.row.template) {
                // an object of a template: pan-os-php takes location=any with the template - only when the name is unique in it
                body.template = obj.row.template; body.location = 'any';
                const n = await api('GET', base() + '/objects?' + new URLSearchParams({ type: cur.type, location: 'any', template: obj.row.template, filter: body.filter }).toString());
                if (n.total !== 1) throw new Error('"' + obj.row.name + '" is ' + n.total + ' times in template ' + obj.row.template + ' (several vsys) - change it with a filter instead');
            }
            if (cur.type === 'rule') body.ruletype = ruletype.value;
            // a security profile: only this one (else "any": every profile of this name in the location - an URL profile too)
            if (cur.type === 'securityprofile') body.securityprofiletype = spTypeOf(obj.row);
            const res = await api('POST', base() + '/change', body);
            setStatus(Object.assign({ loaded: true }, res.status));
            state.cache.clear(); changed = true;
            done[f.key] = actions;
            return res;
        }
        async function change(f, newValue) {
            delete errors[f.key];
            if (newValue === String(f.value)) { render(); return; }
            try {
                const actions = f.act(String(f.value), newValue);
                if (!actions) return;
                await apply(f, actions);
                obj = await fetchObject(f.rename ? newValue : obj.row.name, obj.row.location, obj.row.template, obj.row.profile, obj.row.type);
            } catch (e) { errors[f.key] = e.message; }
            render();
        }
        // what a field can take (GET …/candidates): groups by location, nearest first - once per kind and window
        const candCache = {};
        function candidates(kind) {
            if (!candCache[kind]) {
                const q = new URLSearchParams({ type: cur.type, location: obj.row.location, name: obj.row.name, kind });
                if (cur.type === 'rule') q.set('ruletype', ruletype.value);
                if (cur.type === 'securityprofile') q.set('securityprofiletype', spTypeOf(obj.row));
                for (const k of ['template', 'profile']) if (obj.row[k]) q.set(k, obj.row[k]);
                candCache[kind] = api('GET', base() + '/candidates?' + q.toString()).then(r => r.groups || []).catch(() => null);
            }
            return candCache[kind];
        }
        // a text field that names an object: the candidates as suggestions (free text stays possible)
        function pickList(f, input) {
            const dl = el('datalist', { id: 'pick-' + f.key + '-' + Math.random().toString(36).slice(2) });
            input.setAttribute('list', dl.id);
            candidates(f.pick).then(gs => { if (gs) dl.append(...gs.flatMap(g => g.names.map(n => el('option', { value: n, label: g.location })))); });
            return el('span', { class: 'pick' }, input, dl);
        }
        async function listChange(f, actions) {
            delete errors[f.key];
            try { await apply(f, actions); obj = await fetchObject(obj.row.name, obj.row.location, obj.row.template, obj.row.profile, obj.row.type); } catch (e) { errors[f.key] = e.message; }
            render();
        }
        function control(f) {
            if (f.kind === 'buttons') {
                const bs = f.buttons.filter(b => writable && offered[b[0]]);
                return bs.length ? el('div', { class: 'row' }, bs.map(b => el('button', { type: 'button', text: b[1], onclick: () => run(() => listChange(f, b[0])) })))
                    : el('span', { class: 'muted', text: 'read only' });
            }
            const can = writable && f.kind !== 'ro' && (f.needs || []).every(a => offered[a]);
            if (f.kind === 'ro' || !can)
                return el('span', { class: 'objro', text: Array.isArray(f.value) ? f.value.join(', ') : String(f.value === undefined ? '' : f.value) });
            if (f.kind === 'text') {
                const i = el('input', { value: f.value, autocomplete: 'off', spellcheck: false, 'aria-label': f.label, placeholder: f.placeholder || null });
                // applied when the field is left after a change (or Enter) - one action, no common OK
                i.addEventListener('change', () => run(() => change(f, i.value.trim())));
                i.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); i.blur(); } });
                return f.pick ? pickList(f, i) : i;
            }
            if (f.kind === 'select') {
                const sel = el('select', { 'aria-label': f.label }, (f.choices.includes(f.value) ? f.choices : [f.value, ...f.choices]).map(c => el('option', { value: c, text: c })));
                sel.value = f.value;
                sel.addEventListener('change', () => run(() => change(f, sel.value)));
                return sel;
            }
            if (f.kind === 'button')
                return el('button', { type: 'button', text: f.text, onclick: () => run(() => listChange(f, f.act())) });
            if (f.kind === 'parts') {
                // several parts of one setting (NAT): a change of a part is applied when the parts together are complete
                const vals = Object.assign({}, pending[f.key] || f.value);
                const wrap = el('div', { class: 'parts' });
                const draw = () => wrap.replaceChildren(...f.parts.filter(pt => !pt.show || pt.show(vals)).map(pt => {
                    const c = pt.kind === 'select' ? el('select', { 'aria-label': pt.label }, pt.choices.map(([v, t]) => el('option', { value: v, text: t })))
                        : el('input', { value: vals[pt.key] || '', placeholder: pt.placeholder || null, autocomplete: 'off', spellcheck: false, 'aria-label': pt.label });
                    c.value = vals[pt.key] || '';
                    c.addEventListener('change', () => run(async () => {
                        vals[pt.key] = c.value; pending[f.key] = Object.assign({}, vals);
                        let a;
                        try { a = f.act(f.value, vals); } catch (e) { errors[f.key] = e.message; render(); return; }
                        if (a && typeof a === 'object') { hints[f.key] = a.hint; delete errors[f.key]; draw(); hintEl.textContent = a.hint; return; }
                        delete hints[f.key];
                        if (!a) { draw(); return; }
                        await listChange(f, a);
                        delete pending[f.key];
                        render();
                    }));
                    if (pt.kind !== 'select') c.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); c.blur(); } });
                    return el('label', { class: 'part' }, el('span', { class: 'muted', text: pt.label }), c);
                }));
                const hintEl = el('div', { class: 'muted', text: hints[f.key] || '' });
                draw();
                return el('div', {}, wrap, hintEl);
            }
            // list: the members with ✕ (if there is an action to remove), a field to add one
            const canRemove = f.remove && (f.needsRemove || []).every(a => offered[a]);
            const add = el('input', { placeholder: 'add …', autocomplete: 'off', spellcheck: false, 'aria-label': 'add to ' + f.label });
            add.addEventListener('change', () => { const v = add.value.trim(); if (v) run(async () => { try { await listChange(f, f.add(v)); } catch (e) { errors[f.key] = e.message; render(); } }); });
            add.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); add.blur(); } });
            const extra = (f.buttons || []).filter(b => offered[b[0]]).map(b => el('button', { type: 'button', class: 'small', text: b[1], onclick: () => run(() => listChange(f, b[0])) }));
            // the objects the field can take (own store, the locations above, template): a drop down by location - without the ones in the list
            let pick = null;
            if (f.pick) {
                pick = el('select', { class: 'pick', 'aria-label': 'choose to add to ' + f.label }, el('option', { value: '', text: 'reading the list …' }));
                candidates(f.pick).then(gs => {
                    const have = new Set(f.value.map(String));
                    const groups = (gs || []).map(g => ({ location: g.location, names: g.names.filter(n => !have.has(n)) })).filter(g => g.names.length);
                    pick.replaceChildren(el('option', { value: '', text: gs === null ? '(no list - type the name)' : groups.length ? 'add from the list …' : 'nothing more to add' }),
                        ...groups.map(g => el('optgroup', { label: g.location }, g.names.map(n => el('option', { value: n, text: n })))));
                });
                pick.addEventListener('change', () => { const v = pick.value; if (v) run(async () => { try { await listChange(f, f.add(v)); } catch (e) { errors[f.key] = e.message; render(); } }); });
            }
            return el('div', { class: 'chips' }, f.any ? el('span', { class: 'chip any', text: 'any' }) : null, f.value.map(v => el('span', { class: 'chip' }, v,
                canRemove ? el('button', { type: 'button', class: 'chipx', text: '✕', title: 'remove ' + v, 'aria-label': 'remove ' + v, onclick: () => run(async () => {
                    try { await listChange(f, f.remove(v)); } catch (e) { errors[f.key] = e.message; render(); } }) }) : null)), pick, add, extra);
        }
        function render() {
            const picks = FIELD_PICKS[cur.window] || {};
            const fields = windowFields(cur.window, obj.row, obj.model).map(f => f && !f.pick && picks[f.key] ? Object.assign(f, { pick: picks[f.key] }) : f);
            box.replaceChildren(
                el('div', { class: 'objhead' }, el('h3', { text: (cur.one || cur.label) + ': ' + obj.row.name }), obj.row.template ? el('span', { class: 'badge', text: 'template ' + obj.row.template }) : null, el('span', { class: 'badge', text: obj.row.location }),
                    el('button', { type: 'button', class: 'objclose', text: '✕', 'aria-label': 'close', onclick: close })),
                obj.row.readonly ? el('p', { class: 'badge', text: 'read only: ' + obj.row.readonly }) : null,
                el('table', { class: 'objfields' }, el('tbody', {}, fields.map(f => {
                    const can = f.kind === 'buttons' || (writable && f.kind !== 'ro' && (f.needs || []).every(a => offered[a]));
                    return el('tr', {}, el('th', { text: f.label }), el('td', {}, control(f),
                        errors[f.key] ? el('div', { class: 'error', text: errors[f.key] }) : null,
                        done[f.key] ? el('div', { class: 'muted objact' }, '✓ ', el('code', { text: done[f.key] })) : null,
                        f.note && (f.kind === 'ro' || f.kind === 'list' || !can) ? el('div', { class: 'muted', text: f.note }) : null,
                        !writable || f.kind === 'ro' || can ? null : el('div', { class: 'muted', text: 'read only: no pan-os-php action for it here (' + (f.needs || []).filter(a => !offered[a]).join(', ') + ')' })));
                }))),
                el('p', { class: 'muted', text: writable ? 'A field is applied when you leave it after a change (or press Enter) - as one pan-os-php action on this object; nothing is written until "Save as new version".' : 'read only' }),
                // replaceChildren() writes null as the text "null" - only the sections there are
                ...[objDetails(), objHierarchy(), objLinks(), objVariables(), objNatSecurity(), objRefs(), objXml(), objHistory()].filter(x => x),
                el('div', { class: 'row' }, el('button', { type: 'button', text: 'Close', onclick: close })));
        }
        // the XML of the object (as it is in memory) and its history (git: every commit that changed its entry)
        const opened = {};
        function section(key, title, body) {
            const d = el('details', { class: 'objsection' }, el('summary', { text: title }), body);
            // the hierarchy of a device group is open unless closed (XML / history: closed unless opened)
            d.open = key === 'hierarchy' || key === 'refs' || key === 'links' || key === 'vars' || key === 'details' ? opened[key] !== false : !!opened[key];
            d.addEventListener('toggle', () => { opened[key] = d.open; });
            return d;
        }
        // the details of an object from pan-os-php ('fields' of display: values and choices from the classes of the
        // field actions - nothing of PAN-OS is kept here): a security profile - its lists (rules, exceptions,
        // decoders, DNS categories) as tables, its options, URL categories. Every change: one action on this object.
        function objDetails() {
            const F = obj.fields;
            if (!F || !['securityprofile', 'edl', 'schedule', 'log-profile', 'region', 'securityprofilegroup', 'application'].includes(F.kind)) return null;
            const can = a => writable && !!offered[a];
            const err = key => errors[key] ? el('p', { class: 'error', text: errors[key] }) : null;
            const act = (key, action) => run(() => listChange({ key }, action));
            const arg = v => ruleText(String(v));
            const parts = [];
            const ctl = (key, value, choices, action, label) => {
                // a value: a select with the choices (the current one also when it is not among them), else a text;
                // action: the prefix the value is appended to, or a function value -> action
                const build = typeof action === 'function' ? action : v => action + v;
                const name = (typeof action === 'function' ? action('x') : action).split(':')[0];
                const shown = Array.isArray(value) ? value.join('+') : String(value ?? '');
                if (!can(name)) return el('span', { class: 'objro', text: shown });
                if (choices && !Array.isArray(value)) {
                    const list = choices.includes(shown) ? choices : [shown, ...choices];
                    const sel = el('select', { 'aria-label': label }, list.map(c => el('option', { value: c, text: c || '(not set)' })));
                    sel.value = shown;
                    sel.addEventListener('change', () => { if (sel.value) act(key, build(arg(sel.value))); });
                    return sel;
                }
                const i = el('input', { value: shown, autocomplete: 'off', spellcheck: false, 'aria-label': label,
                    title: choices ? 'one or more of: ' + choices.join(', ') + ' - joined with +' : (Array.isArray(value) ? 'several values joined with +' : null) });
                i.addEventListener('change', () => { if (i.value.trim() !== shown) act(key, build(i.value.trim().split('+').map(x => arg(x.trim())).join('+'))); });
                i.addEventListener('keydown', ev => { if (ev.key === 'Enter') { ev.preventDefault(); i.blur(); } });
                return i;
            };
            const delBtn = (key, label, action) => can(action.split(':')[0])
                ? el('button', { type: 'button', text: '✕', title: action.split(':')[0], 'aria-label': 'remove ' + label, onclick: () => act(key, action) }) : null;
            const addRow = (key, actName, inputs, label, build) => can(actName)
                ? el('div', { class: 'row' }, ...inputs, el('button', { type: 'button', text: label, title: actName, onclick: () => { const a = build(); if (a) act(key, a); } })) : null;
            const inp = (label, placeholder) => el('input', { autocomplete: 'off', spellcheck: false, 'aria-label': label, placeholder: placeholder || null });
            const sel = (label, choices, value) => { const x = el('select', { 'aria-label': label }, choices.map(c => el('option', { value: c, text: c }))); if (value !== undefined) x.value = value; return x; };
            const kv = rows => table(['field', 'value'], rows.filter(x => x).map(([l, c]) => el('tr', {}, el('td', { text: l }), el('td', {}, c))));
            const nameRow = () => ['name', ctl('fd-name', obj.row.name, null, 'name-rename:', 'name')];
            if (F.kind === 'edl') {
                // EDL: type, source, update interval (hour / day), description, certificate profile, exceptions, expand domain
                const predefined = F.type.startsWith('predefined-');
                const iv = sel('update interval', F.intervals, F.recurring.interval);
                const at = sel('at hour', ['', ...Array.from({ length: 24 }, (_, h) => String(h).padStart(2, '0'))], F.recurring.at);
                const dayList = F.recurring.interval === 'monthly' ? Array.from({ length: 31 }, (_, d) => String(d + 1)) : F.weekdays;
                const day = sel('day', ['', ...dayList], F.recurring.day);
                const applyRec = () => {
                    const v = iv.value, needAt = ['daily', 'weekly', 'monthly'].includes(v), needDay = ['weekly', 'monthly'].includes(v);
                    // not complete yet: wait for the other part
                    if ((needAt && !at.value) || (needDay && !day.value)) return;
                    act('fd-rec', 'recurring-set:' + v + (needAt ? ',' + at.value : '') + (needDay ? ',' + day.value : ''));
                };
                // daily / weekly / monthly: the hour (and day) are chosen next - no new drawing until then
                const dayChoices = v => v === 'monthly' ? Array.from({ length: 31 }, (_, d) => String(d + 1)) : F.weekdays;
                iv.addEventListener('change', () => {
                    if (['five-minute', 'hourly'].includes(iv.value)) return applyRec();
                    day.replaceChildren(...['', ...dayChoices(iv.value)].map(c => el('option', { value: c, text: c })));
                    day.hidden = iv.value === 'daily';
                });
                day.hidden = F.recurring.interval !== 'weekly' && F.recurring.interval !== 'monthly';
                at.addEventListener('change', applyRec);
                day.addEventListener('change', applyRec);
                const recCtl = predefined ? el('span', { class: 'objro', text: '(predefined list)' })
                    : can('recurring-set') ? el('div', { class: 'row' }, iv, ' at ', at, ' day ', day)
                    : el('span', { class: 'objro', text: [F.recurring.interval, F.recurring.at, F.recurring.day].filter(x => x).join(' ') });
                parts.push(kv([nameRow(),
                    ['type', ctl('fd-type', F.type, F.types, 'type-set:', 'type')],
                    ['source', ctl('fd-src', F.source, null, 'source-set:', 'source')],
                    ['update', recCtl],
                    ['description', ctl('fd-desc', F.description, null, 'description-set:', 'description')],
                    predefined ? null : ['certificate profile', ctl('fd-cp', F['certificate-profile'] || 'none', null, 'certificate-profile-set:', 'certificate profile')],
                    F.type === 'domain' ? ['expand domain', ctl('fd-exp', F['expand-domain'] ? 'yes' : 'no', ['yes', 'no'], v => 'expand-domain-set:' + (v === 'yes' ? 'true' : 'false'), 'expand domain')] : null]));
                for (const k of ['fd-name', 'fd-type', 'fd-src', 'fd-rec', 'fd-desc', 'fd-cp', 'fd-exp']) parts.push(err(k));
                parts.push(el('h4', { text: 'exception list' }));
                parts.push(F.exceptions.length ? table(['entry', ''], F.exceptions.map(x => el('tr', {}, el('td', { text: x }), el('td', {}, delBtn('fd-exc', x, 'exception-remove:' + arg(x))))))
                    : el('p', { class: 'muted', text: 'no entries' }));
                const ne = inp('new exception', 'IP / domain / URL');
                parts.push(addRow('fd-exc', 'exception-add', [ne], 'Add exception', () => ne.value.trim() ? 'exception-add:' + arg(ne.value.trim()) : null), err('fd-exc'));
                return section('details', 'Details', el('div', { class: 'spdetails' }, ...parts.filter(x => x)));
            }
            if (F.kind === 'application') {
                // custom application / application group / application filter (ApplicationFields): options, then the
                // lists (ports, members, categories, …) with ✕ and add; a text that names an application: suggestions
                const withList = (input, pick) => {
                    if (!pick) return [input];
                    const id = 'app-' + pick + '-' + Math.random().toString(36).slice(2), dl = el('datalist', { id });
                    input.setAttribute('list', id);
                    candidates(pick).then(gs => { if (gs) dl.append(...gs.flatMap(g => g.names.map(n => el('option', { value: n, label: g.location })))); });
                    return [input, dl];
                };
                const rows = [nameRow()];
                for (const [o, O] of Object.entries(F.options || {})) {
                    const key = 'fd-o-' + o, action = 'detail-option-set:' + arg(o) + ',';
                    let c;
                    if (O.choices && O.choices.length) c = ctl(key, O.value, O.choices, action, o);
                    else if (!can('detail-option-set')) c = el('span', { class: 'objro', text: O.value || '' });
                    else {
                        const i = el('input', { value: O.value, autocomplete: 'off', spellcheck: false, 'aria-label': o, placeholder: O.kind === 'number' ? 'empty = not set' : '' });
                        i.addEventListener('change', () => { if (i.value.trim() !== O.value) act(key, action + arg(i.value.trim())); });
                        i.addEventListener('keydown', ev => { if (ev.key === 'Enter') { ev.preventDefault(); i.blur(); } });
                        c = el('div', { class: 'row' }, ...withList(i, O.pick));
                    }
                    rows.push([o, c]);
                }
                parts.push(kv(rows), err('fd-name'), ...Object.keys(F.options || {}).map(o => err('fd-o-' + o)));
                if (F.signature) parts.push(el('p', { class: 'muted', text: 'signatures: in the XML (not changed here)' }));
                for (const [l, L] of Object.entries(F.lists || {})) {
                    const key = 'fd-l-' + l;
                    parts.push(el('h4', { text: l === 'port' ? 'default ports' : l === 'member' ? 'members' : l }));
                    parts.push(L.entries.length ? table([l, ''], L.entries.map(x => el('tr', {}, el('td', { text: x }), el('td', {}, delBtn(key, x, 'detail-entry-remove:' + arg(l) + ',' + arg(x))))))
                        : el('p', { class: 'muted', text: 'no entries' }));
                    const free = L.choices && L.choices.length ? L.choices.filter(c => !L.entries.includes(c)) : null;
                    const ni = free ? sel('new ' + l, free) : inp('new ' + l, l === 'port' ? 'tcp/443 or udp/5000-5010' : l === 'tag' ? 'tag' : 'application');
                    parts.push(addRow(key, 'detail-entry-add', free ? [ni] : withList(ni, L.pick), 'Add ' + l,
                        () => ni.value.trim() ? 'detail-entry-add:' + arg(l) + ',' + arg(ni.value.trim()) : null), err(key));
                }
                return section('details', 'Details', el('div', { class: 'spdetails' }, ...parts.filter(x => x)));
            }
            if (F.kind === 'securityprofilegroup') {
                // profile group: one profile per type - the profiles of the location, above it and the predefined
                // ones as suggestions; ✕ removes the profile of the type
                const rows = F.slots.map(S => {
                    const key = 'fd-sp-' + S.slot;
                    let c;
                    if (!can('securityprofile-set')) c = el('span', { class: 'objro', text: S.value || '(none)' });
                    else {
                        const listId = 'spg-' + S.slot + '-' + Math.random().toString(36).slice(2);
                        const dl = el('datalist', { id: listId });
                        const i = el('input', { value: S.value, autocomplete: 'off', spellcheck: false, 'aria-label': S.slot, placeholder: '(none)', list: listId });
                        if (S.pick) candidates(S.pick).then(gs => { if (gs) dl.append(...gs.flatMap(g => g.names.map(n => el('option', { value: n, label: g.location })))); });
                        i.addEventListener('change', () => { const v = i.value.trim(); if (v !== S.value) act(key, v === '' ? 'securityprofile-remove:' + S.type : 'securityprofile-set:' + S.type + ',' + arg(v)); });
                        i.addEventListener('keydown', ev => { if (ev.key === 'Enter') { ev.preventDefault(); i.blur(); } });
                        c = el('div', { class: 'row' }, i, dl, S.value && can('securityprofile-remove') ? delBtn(key, S.slot, 'securityprofile-remove:' + S.type) : null);
                    }
                    return [S.slot, c];
                });
                parts.push(kv([nameRow(), ...rows]), err('fd-name'), ...F.slots.map(S => err('fd-sp-' + S.slot)));
                if (F.slots.some(S => S.value) && can('securityprofile-remove'))
                    parts.push(el('div', { class: 'row' }, el('button', { type: 'button', text: 'Remove all profiles', title: 'securityprofile-remove:any', onclick: () => act('fd-spall', 'securityprofile-remove:any') })), err('fd-spall'));
                return section('details', 'Details', el('div', { class: 'spdetails' }, ...parts.filter(x => x)));
            }
            if (F.kind === 'region') {
                // region: predefined (country code, read only) or custom - geo-location and addresses
                if (F.predefined) {
                    parts.push(kv([['name', el('span', { class: 'objro', text: obj.row.name })], ['country', el('span', { class: 'objro', text: F.country })],
                        ['addresses', el('span', { class: 'objro', text: 'only known on the firewall (country database)' })]]));
                    return section('details', 'Details', el('div', { class: 'spdetails' }, ...parts.filter(x => x)));
                }
                const hasGeo = F.latitude !== null || F.longitude !== null;
                const la = inp('latitude', '-90 .. 90'), lo = inp('longitude', '-180 .. 180');
                la.value = F.latitude ?? ''; lo.value = F.longitude ?? '';
                const geoCtl = can('geo-location-set')
                    ? el('div', { class: 'row' }, la, lo,
                        el('button', { type: 'button', text: 'Set', title: 'geo-location-set', onclick: () => { if (la.value.trim() && lo.value.trim()) act('fd-geo', 'geo-location-set:' + arg(la.value.trim()) + ',' + arg(lo.value.trim())); } }),
                        hasGeo ? delBtn('fd-geo', 'geo-location', 'geo-location-remove') : null)
                    : el('span', { class: 'objro', text: hasGeo ? F.latitude + ', ' + F.longitude : '(not set)' });
                parts.push(kv([nameRow(), ['geo-location', geoCtl]]));
                for (const k of ['fd-name', 'fd-geo']) parts.push(err(k));
                parts.push(el('h4', { text: 'addresses' }));
                parts.push(F.addresses.length ? table(['address', ''], F.addresses.map(x => el('tr', {}, el('td', { text: x }), el('td', {}, delBtn('fd-addr', x, 'address-remove:' + arg(x))))))
                    : el('p', { class: 'muted', text: 'no addresses' }));
                const na = inp('new address', 'ip-netmask / ip-range');
                parts.push(addRow('fd-addr', 'address-add', [na], 'Add address', () => na.value.trim() ? 'address-add:' + arg(na.value.trim()) : null), err('fd-addr'));
                return section('details', 'Details', el('div', { class: 'spdetails' }, ...parts.filter(x => x)));
            }
            if (F.kind === 'schedule') {
                // schedule: its ranges (one type), a range more, the type with one range
                parts.push(kv([nameRow(), ['type', el('span', { class: 'objro', text: F.type })]]), err('fd-name'));
                const rangeAct = r => arg(r.type) + ',' + (r.day ? arg(r.day) : '-') + ',' + arg(r.range);
                parts.push(el('h4', { text: 'ranges' }));
                parts.push(table(['day', 'range', ''], F.ranges.map(r => el('tr', {}, el('td', { text: r.day || '' }), el('td', { text: r.range }),
                    el('td', {}, F.ranges.length > 1 ? delBtn('fd-rng', r.range, 'range-remove:' + rangeAct(r)) : null)))));
                const fmt = t => t === 'non-recurring' ? 'YYYY/MM/DD@HH:MM-YYYY/MM/DD@HH:MM' : 'HH:MM-HH:MM';
                const d1 = sel('day', F.days), r1 = inp('new range', fmt(F.type));
                parts.push(addRow('fd-rng', 'range-add', [...(F.type === 'weekly' ? [d1] : []), r1], 'Add range',
                    () => r1.value.trim() ? 'range-add:' + rangeAct({ type: F.type, day: F.type === 'weekly' ? d1.value : '', range: r1.value.trim() }) : null), err('fd-rng'));
                const t2 = sel('new type', F.types, F.type), d2 = sel('day of the new type', F.days), r2 = inp('range of the new type', 'range');
                t2.addEventListener('change', () => { d2.hidden = t2.value !== 'weekly'; r2.placeholder = fmt(t2.value); });
                d2.hidden = t2.value !== 'weekly';
                parts.push(el('h4', { text: 'change the type (every range goes, this one stays)' }));
                parts.push(addRow('fd-type', 'type-set', [t2, d2, r2], 'Set type', () => r2.value.trim() ? 'type-set:' + rangeAct({ type: t2.value, day: t2.value === 'weekly' ? d2.value : '', range: r2.value.trim() }) : null), err('fd-type'));
                return section('details', 'Details', el('div', { class: 'spdetails' }, ...parts.filter(x => x)));
            }
            if (F.kind === 'log-profile') {
                // log forwarding: description, enhanced logging, the match list (log type, filter, panorama, quarantine,
                // server profiles per kind)
                parts.push(kv([nameRow(),
                    ['description', ctl('fd-desc', F.description, null, 'description-set:', 'description')],
                    ['enhanced application logging', ctl('fd-eal', F['enhanced-application-logging'] ? 'yes' : 'no', ['yes', 'no'], v => 'enhanced-application-logging-set:' + (v === 'yes' ? 'true' : 'false'), 'enhanced application logging')]]));
                for (const k of ['fd-name', 'fd-desc', 'fd-eal']) parts.push(err(k));
                parts.push(el('h4', { text: 'match list' }));
                const yn = ['yes', 'no'];
                const rows = Object.entries(F.matchList || {}).map(([n, m]) => {
                    const set = f => 'match-set:' + arg(n) + ',' + f + ',';
                    const servers = el('div', {}, ...F.sendKinds.flatMap(k => (m[k] || []).map(sv => el('div', { class: 'row' }, el('span', { text: k + ': ' + sv }), delBtn('fd-ml', k + ' ' + sv, 'match-send-remove:' + arg(n) + ',' + k + ',' + arg(sv))))));
                    const sk = sel('kind of server profile for ' + n, F.sendKinds), sp = inp('server profile for ' + n, 'server profile');
                    return el('tr', {}, el('td', { text: n }),
                        el('td', {}, ctl('fd-ml', m['log-type'], F.logTypes, set('log-type'), n + ' log type')),
                        el('td', {}, ctl('fd-ml', m.filter, null, set('filter'), n + ' filter')),
                        el('td', {}, ctl('fd-ml', m['send-to-panorama'] || 'no', yn, set('send-to-panorama'), n + ' panorama')),
                        el('td', {}, ctl('fd-ml', m.quarantine || 'no', yn, set('quarantine'), n + ' quarantine')),
                        el('td', {}, servers, addRow('fd-ml', 'match-send-add', [sk, sp], 'Add', () => sp.value.trim() ? 'match-send-add:' + arg(n) + ',' + sk.value + ',' + arg(sp.value.trim()) : null)),
                        el('td', {}, delBtn('fd-ml', n, 'match-remove:' + arg(n))));
                });
                parts.push(rows.length ? table(['name', 'log type', 'filter', 'panorama', 'quarantine', 'send to', ''], rows) : el('p', { class: 'muted', text: 'no entries' }));
                const mn = inp('new match list entry', 'name'), mt = sel('log type of the new entry', F.logTypes), mf = inp('filter of the new entry', 'All Logs');
                parts.push(addRow('fd-ml', 'match-add', [mn, mt, mf], 'Add entry', () => mn.value.trim() ? 'match-add:' + arg(mn.value.trim()) + ',' + mt.value + ',' + arg(mf.value.trim() || 'All Logs') : null), err('fd-ml'));
                return section('details', 'Details', el('div', { class: 'spdetails' }, ...parts.filter(x => x)));
            }
            for (const [list, L] of Object.entries(F.lists || {})) {
                const fields = Object.keys(L.fields);
                const names = Object.keys(L.entries || {});
                // a fixed list (decoders): also the entries PAN-OS knows that are not in the XML yet (set: created)
                for (const k of L.known || []) if (!names.includes(k)) names.push(k);
                const key = 'spd-' + list;
                parts.push(el('h4', { text: list }));
                const rows = names.map(n => {
                    const e = (L.entries || {})[n] || {};
                    return el('tr', {}, el('td', { text: n }),
                        ...fields.map(f => el('td', {}, ctl(key, e[f] ?? (L.fields[f].kind === 'list' || L.fields[f].kind === 'entries' ? [] : ''), L.fields[f].choices,
                            'detail-entry-set:' + arg(list) + ',' + arg(n) + ',' + arg(f) + ',', list + ' ' + n + ' ' + f))),
                        el('td', {}, !L.fixed && can('detail-entry-remove') ? el('button', { type: 'button', text: '✕', title: 'detail-entry-remove', 'aria-label': 'remove ' + n,
                            onclick: () => act(key, 'detail-entry-remove:' + arg(list) + ',' + arg(n)) }) : null));
                });
                parts.push(names.length ? table([list === 'decoder' ? 'protocol' : 'name', ...fields, ''], rows) : el('p', { class: 'muted', text: 'no entries' }));
                if (!L.fixed && can('detail-entry-add')) {
                    const ni = el('input', { autocomplete: 'off', spellcheck: false, 'aria-label': 'new ' + list, placeholder: list === 'threat-exception' ? 'threat ID' : list === 'dns-category' ? 'pan-dns-sec-…' : list === 'dns-list' ? 'EDL (domain) / default-paloalto-dns' : list === 'dns-exception' ? 'domain, e.g. *.example.com' : 'name' });
                    parts.push(el('div', { class: 'row' }, ni, el('button', { type: 'button', text: 'Add ' + list, title: 'detail-entry-add (PAN-OS defaults)',
                        onclick: () => { if (ni.value.trim()) act(key, 'detail-entry-add:' + arg(list) + ',' + arg(ni.value.trim())); } })));
                }
                parts.push(err(key));
            }
            if (Object.keys(F.options || {}).length) {
                parts.push(el('h4', { text: 'options' }));
                parts.push(table(['option', 'value'], Object.entries(F.options).map(([o, O]) => el('tr', {}, el('td', { text: o }),
                    el('td', {}, ctl('spd-options', O.value, O.choices, 'detail-option-set:' + arg(o) + ',', o))))));
                parts.push(err('spd-options'));
            }
            if (F.categories) {
                // URL filtering: the action per category (url.action-set) and of the credential detection
                parts.push(el('h4', { text: 'categories' }));
                const cats = [...new Set([...Object.keys(F.categories), ...Object.keys(F.credential || {})])].sort();
                parts.push(table(['category', 'site access', 'user credential submission'], cats.map(c => el('tr', {}, el('td', { text: c }),
                    el('td', {}, ctl('spd-cat', F.categories[c] || '', F.categoryActions, v => 'url.category-action-set:' + arg(c) + ',' + v, c)),
                    el('td', {}, ctl('spd-cat', (F.credential || {})[c] || '', F.credentialActions, 'url.credential-action-set:' + arg(c) + ',', c + ' credential'))))));
                parts.push(err('spd-cat'));
            }
            if (!parts.length) return null;
            return section('details', 'Details', el('div', { class: 'spdetails' }, ...parts.filter(x => x)));
        }
        // NAT rule: the security rules its traffic meets, in their order (pan-os-php display-nat-security) - per
        // direction (bi-directional static NAT: also reverse) and firewall context; read when the section is opened
        function objNatSecurity() {
            if (cur.type !== 'rule' || ruletype.value !== 'nat') return null;
            const body = el('div', { class: 'muted', text: 'reading the security rules ...' });
            const d = section('natsec', 'Security rules', body);
            const COV = { full: 'covers it fully', partial: 'covers a part', missing: 'no allow rule', blocked: 'traffic blocked by a rule', unknown: 'not determined' };
            const PATTERN = { 'post-nat-address': 'post-NAT address', 'pre-nat-zone': 'pre-NAT zone', 'translated-port': 'translated port' };
            const target = t => [t.destination ? 'destination ' + t.destination.join(', ') : null, 'to ' + t.to.join(', '), t.from ? 'from ' + t.from.join(', ') : null, t.service ? 'service ' + t.service : null].filter(x => x).join('; ');
            const fill = () => {
                if (d.dataset.loaded) return;
                d.dataset.loaded = '1';
                const q = new URLSearchParams({ type: 'rule', ruletype: 'nat', location: obj.row.location, name: obj.row.name });
                api('GET', base() + '/natsecurity?' + q.toString()).then(res => {
                    body.className = '';
                    const parts = [el('p', { class: 'muted', text: 'pre-NAT addresses and service, post-NAT zones (destination NAT: zone of the translated address by the route of the ingress router); only the allow rules allowed traffic really reaches, in their order (a rule that blocks it before is named)' })];
                    if (errors.natsec) parts.push(el('p', { class: 'error', text: errors.natsec }));
                    let toAdapt = 0, partial = 0;
                    for (const n of res.notes || []) parts.push(el('p', { class: 'error', text: n }));
                    for (const dir of res.directions || []) {
                        const nc = (dir.contexts || []).length, nf = (dir.contexts || []).filter(c => c.summary === 'full').length;
                        parts.push(el('h4', { text: (dir.direction === 'reverse' ? 'reverse direction (bi-directional)' : 'direction of the NAT rule') + ': '
                            + (nc > 1 && nf > 0 && nf < nc ? 'covered fully for ' + nf + ' of ' + nc + ' firewall contexts' : (COV[dir.summary] || dir.summary)) }));
                        if (dir.hiddenContexts) parts.push(el('p', { class: 'muted', text: dir.hiddenContexts + ' firewall context(s) outside your locations' }));
                        for (const c of dir.contexts || []) {
                            parts.push(el('p', {}, el('b', { text: c.context }), c.devices && c.devices.length ? ' - firewalls ' + c.devices.join(', ') : '', ': ' + (COV[c.summary] || c.summary)));
                            if ((c.postNatZones || []).length) parts.push(el('p', { class: 'muted', text: 'post-NAT zone: ' + c.postNatZones.map(z => z.zone + ' (' + z.router + ' ' + z.network + (z.uncertain ? ', uncertain' : '') + ')').join(', ') }));
                            for (const n of [...(c.notes || []).filter(x => !x.startsWith('traffic blocked by rule')), ...new Set(c.zoneNotes || [])]) parts.push(el('p', { class: 'error', text: n }));
                            const open = (loc, name) => el('a', { href: openLink({ type: 'rule', ruletype: 'security', location: loc, name }), target: '_blank', rel: 'noopener', text: 'Open ↗', title: 'show this security rule in a new window' });
                            if (c.blockedBy) parts.push(el('p', {}, 'blocked by ', el('b', { text: c.blockedBy.rule }), ' (' + c.blockedBy.action + (c.blockedBy.location ? ', ' + c.blockedBy.location : '') + ') ', c.blockedBy.locationName ? open(c.blockedBy.locationName, c.blockedBy.rule) : null));
                            if ((c.matches || []).length)
                                parts.push(table(['#', 'Allow rule', 'Location', 'Result', 'Zones', 'Source', 'Destination', 'Service', ''], c.matches.map(m => el('tr', {},
                                    el('td', { text: String(m.position) }), el('td', { text: m.rule }), el('td', { text: m.location }),
                                    el('td', { text: COV[m.coverage] || m.coverage, title: (m.notes || []).join('\n') }),
                                    ...['zones', 'source', 'destination', 'service'].map(k => el('td', { text: (m.details || {})[k] || '' })),
                                    el('td', {}, open(m.locationName, m.rule))))));
                            else if (!c.blockedBy) parts.push(el('p', { class: 'muted', text: 'no allow rule' + (c.hidden ? ' you can see (' + c.hidden + ' outside your types / locations)' : '') }));
                            if (c.hidden && (c.matches || []).length) parts.push(el('p', { class: 'muted', text: c.hidden + ' more outside your types / locations' }));
                            // allow rules written the way of other vendors (post-NAT address, pre-NAT zone, translated port)
                            if ((c.mismatches || []).length) {
                                parts.push(el('p', {}, el('b', { text: 'Allow rules to adapt (written for the traffic after the NAT)' })));
                                parts.push(table(['#', 'Allow rule', 'Location', 'Written with', 'Scope', 'Change', 'Corrected rule', ''], c.mismatches.map(m => {
                                    if (!m.covered) { toAdapt++; if (m.scope === 'partial') partial++; }
                                    return el('tr', { class: m.covered ? 'muted' : '' },
                                        el('td', { text: String(m.position) }), el('td', { text: m.rule }), el('td', { text: m.location }),
                                        el('td', { text: m.patterns.map(x => PATTERN[x] || x).join(' + ') }),
                                        el('td', { text: m.scope === 'full' ? 'exact' : 'partial - would allow more', title: (m.notes || []).join('\n') }),
                                        el('td', { text: m.covered ? 'not needed: allowed by ' + m.covered : m.fix === 'in-place' ? 'in place' : 'clone before it' }),
                                        el('td', { class: 'wrap', text: target(m.target) }),
                                        el('td', {}, open(m.locationName, m.rule)));
                                })));
                            }
                        }
                    }
                    // adapt: one pan-os-php action on the NAT rule (nat-security-fix) - exact ones in place / as a clone,
                    // partial ones only after the review checkbox
                    if (toAdapt && writable && offered['nat-security-fix']) {
                        const f = { key: 'natsec' };
                        const ok = el('input', { type: 'checkbox', 'aria-label': 'partial ones reviewed' });
                        const pbtn = el('button', { type: 'button', text: 'Clone the partial ones too', disabled: true, title: 'nat-security-fix:clone,true',
                            onclick: () => run(() => listChange(f, 'nat-security-fix:clone,true')) });
                        ok.addEventListener('change', () => { pbtn.disabled = !ok.checked; });
                        if (toAdapt > partial) parts.push(el('div', { class: 'row' },
                            el('button', { type: 'button', text: 'Adapt (in place / clone)', title: 'nat-security-fix:fix - exact ones only', onclick: () => run(() => listChange(f, 'nat-security-fix:fix')) }),
                            el('button', { type: 'button', text: 'Clone only', title: 'nat-security-fix:clone - exact ones only, the rules stay', onclick: () => run(() => listChange(f, 'nat-security-fix:clone')) })));
                        if (partial) parts.push(el('div', { class: 'row' }, el('label', {}, ok, ' reviewed: the ' + partial + ' partial one(s) will allow more traffic than the rule names'), pbtn));
                    }
                    body.replaceChildren(...parts);
                }).catch(e => { body.className = 'error'; body.textContent = e.message; });
            };
            d.addEventListener('toggle', () => { if (d.open) fill(); });
            if (d.open) fill();
            return d;
        }
        // who uses the object (as the References of the list), each with "Open ↗" - read when the section is opened
        function objRefs() {
            if (!(state.meta.types[cur.type] && state.meta.types[cur.type].references)) return null;
            const body = el('div', { class: 'muted', text: 'reading the references ...' });
            const d = section('refs', 'References', body);
            const fill = () => {
                if (d.dataset.loaded) return;
                d.dataset.loaded = '1';
                const q = new URLSearchParams({ type: cur.type, location: obj.row.location, name: obj.row.name });
                if (cur.type === 'rule') q.set('ruletype', ruletype.value);
                if (cur.type === 'securityprofile') q.set('securityprofiletype', spTypeOf(obj.row));
                if (cur.type === 'device') q.set('devicetype', devtype.value);
                for (const k of ['template', 'profile']) if (obj.row[k]) q.set(k, obj.row[k]);
                api('GET', base() + '/references?' + q.toString()).then(res => {
                    const o = (res.objects || [])[0];
                    body.className = '';
                    body.replaceChildren(!o ? el('p', { class: 'muted', text: 'object not found' })
                        : o.references.length ? el('div', {}, el('p', { class: 'muted', text: 'used by ' + o.references.length + (o.hidden ? ' (' + o.hidden + ' more outside your types / locations)' : '') }), refsTable(o.references))
                        : el('p', { class: 'muted', text: 'not used (no references)' }));
                }).catch(e => { body.className = 'error'; body.textContent = e.message; });
            };
            d.addEventListener('toggle', () => { if (d.open) fill(); });
            if (d.open) fill();
            return d;
        }
        // a device (device group, template stack, managed firewall, log collector / group): the devices it is
        // connected with, each with "Open ↗" (a new window with that device)
        function objLinks() {
            const r = obj.row, f = cur.type === 'device' ? DEVICE_LINKS[r.type] : null;
            if (!f) return null;
            const list = v => (Array.isArray(v) ? v : (v === null || v === undefined || v === '' ? [] : (typeof v === 'object' ? Object.values(v) : [v]))).map(String);
            const link = (devicetype, name) => el('a', { href: openLink({ type: 'device', devicetype, location: 'shared', name }), target: '_blank', rel: 'noopener',
                text: 'Open ↗', title: 'show the ' + devicetype + ' ' + name + ' in a new window' });
            const rows = f(r).map(([label, devicetype, names, extra]) => [label, devicetype, list(names), extra]).filter(x => x[2].length);
            const body = rows.length ? el('table', { class: 'objfields' }, el('tbody', {}, rows.map(([label, devicetype, names, extra]) => el('tr', {}, el('th', { text: label }),
                el('td', {}, names.map(n => el('div', {}, n, ' ', link(devicetype, n),
                    ...(extra ? extra(n) : []).map(([t, dt, x]) => el('div', { class: 'muted', style: 'padding-left:1.5em' }, '└ ' + t + ': ' + x + ' ', link(dt, x))))))))))
                : el('p', { class: 'muted', text: 'no connections' });
            return section('links', 'Connections', body);
        }
        // variables (Panorama: template, template stack, firewall - its override in the stack; SCM: folder, snippet,
        // device): the value for this object and where it comes from; set here = on this object (variable-set), an
        // inherited one can be overridden here, an own one removed (then the inherited value applies again)
        function objVariables() {
            const eff = obj.row.effective;
            if (cur.type !== 'device' || !eff || typeof eff !== 'object') return null;
            const can = canWrite && offered['variable-set'] && offered['variable-remove'];
            const TYPES = ['ip-netmask', 'ip-range', 'ip-wildcard', 'fqdn', 'group-id', 'device-priority', 'device-id', 'interface', 'as-number',
                'qos-profile', 'egress-max', 'link-tag', 'zone', 'port', 'percent', 'count', 'rate', 'router-id', 'timer'];
            const f = { key: 'variables' };
            const set = (name, type, value) => run(() => listChange(f, 'variable-set:' + actArg(name) + ',' + actArg(type) + ',' + ruleText(value)));
            const link = (kind, name) => kind && name && !(kind === (DEVICE_KIND[obj.row.type] || '') && name === obj.row.name) ? el('a', { href: openLink({ type: 'device', devicetype: kind, location: 'shared', name }), target: '_blank', rel: 'noopener', text: 'Open ↗' }) : null;
            const rows = Object.entries(eff).map(([name, v]) => {
                let valueCell;
                if (can && v.own) {
                    const i = el('input', { value: v.value, autocomplete: 'off', spellcheck: false, 'aria-label': 'value of ' + name });
                    i.addEventListener('change', () => { if (i.value.trim() !== '') set(name, v.type, i.value.trim()); });
                    i.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); i.blur(); } });
                    valueCell = i;
                } else valueCell = el('span', { text: v.value });
                const over = can && !v.own ? el('button', { type: 'button', class: 'small', text: 'Override here', title: 'set ' + name + ' on this object (the inherited value stays where it is)', onclick: () => {
                    const i = el('input', { value: v.value, autocomplete: 'off', spellcheck: false, 'aria-label': 'new value of ' + name });
                    i.addEventListener('change', () => { if (i.value.trim() !== '') set(name, v.type, i.value.trim()); });
                    i.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); i.blur(); } });
                    valueCell.replaceWith(i); valueCell = i; i.focus(); } }) : null;
                const del = can && v.own ? el('button', { type: 'button', class: 'small', text: '✕', title: 'remove ' + name + ' here' + (v.shadowed && v.shadowed.length ? ' - then: ' + v.shadowed[0] : ''), 'aria-label': 'remove ' + name,
                    onclick: () => run(() => listChange(f, 'variable-remove:' + actArg(name))) }) : null;
                return el('tr', {}, el('td', { text: name }), el('td', { text: v.type }), el('td', {}, valueCell),
                    el('td', {}, v.own ? el('b', { text: 'here' }) : el('span', {}, v.from + ' ', link(v.fromkind, v.fromname)),
                        ...(v.shadowed || []).map(x => el('div', { class: 'muted', text: 'hides ' + x }))),
                    el('td', {}, over, del));
            });
            let add = null;
            if (can) {
                const n = el('input', { placeholder: '$name', autocomplete: 'off', spellcheck: false, 'aria-label': 'name of a new variable' });
                const t = el('select', { 'aria-label': 'type of a new variable' }, TYPES.map(x => el('option', { value: x, text: x })));
                const v = el('input', { placeholder: 'value', autocomplete: 'off', spellcheck: false, 'aria-label': 'value of a new variable' });
                add = el('div', { class: 'row' }, n, t, v, el('button', { type: 'button', class: 'small', text: 'Add', onclick: () => {
                    let name = n.value.trim(); if (name && name[0] !== '$') name = '$' + name;
                    if (!/^\$[A-Za-z0-9_.-]{1,62}$/.test(name)) { errors.variables = 'name: $ and letters, digits, _ . -'; render(); return; }
                    if (v.value.trim() === '') { errors.variables = 'a value is needed'; render(); return; }
                    set(name, t.value, v.value.trim()); } }));
            }
            // a template stack: the overrides of its firewalls
            const dv = obj.row.devicevariables && typeof obj.row.devicevariables === 'object' ? Object.entries(obj.row.devicevariables) : [];
            const perDevice = dv.length ? el('div', {}, el('p', { class: 'muted', text: 'Overrides of the firewalls of this stack' }),
                el('table', { class: 'objfields' }, el('tbody', {}, dv.map(([serial, list]) => el('tr', {}, el('th', {}, serial, ' ', link('manageddevice', serial)),
                    el('td', {}, Object.entries(list).map(([n, x]) => el('div', { text: n + ' [' + x.type + '] = ' + x.value })))))))) : null;
            const note = { ManagedDevice: 'kept in the template stack of the firewall (devices/entry/variable)', TemplateStack: 'the stack; a firewall can override a value (its window)',
                Template: 'the template', DeviceOnPrem: 'the device (SCM)', DeviceCloud: 'the device (SCM)', Container: 'the folder (SCM)', Snippet: 'the snippet (SCM)' }[obj.row.type] || '';
            const body = el('div', {},
                rows.length ? el('table', { class: 'objfields' }, el('thead', {}, el('tr', {}, ['Name', 'Type', 'Value', 'From', ''].map(h => el('th', { text: h })))), el('tbody', {}, rows))
                    : el('p', { class: 'muted', text: 'no variables' }),
                errors.variables ? el('div', { class: 'error', text: errors.variables }) : null,
                add, el('p', { class: 'muted', text: 'Set here: ' + note + '. Values with , / : are passed to pan-os-php as $$comma$$ / $$forwardslash$$ / $$colon$$.' }), perDevice);
            return section('vars', 'Variables (' + Object.keys(eff).length + ')', body);
        }
        // a device group: where it is in the hierarchy (shared → parents → it → its children), as pan-os-php type=device
        // devicetype=devicegroup actions=display shows it
        function objHierarchy() {
            const h = obj.row.hierarchy;
            if (cur.type !== 'device' || !Array.isArray(h) || !h.length) return null;
            const lines = h.map((n, i) => '  '.repeat(i) + (i ? '└ ' : '') + n + (i === h.length - 1 ? '   ◀ this ' + ({ Container: 'container', DeviceCloud: 'cloud device', DeviceOnPrem: 'on-prem device' }[obj.row.type] || 'device group') : ''));
            for (const c of (obj.row.children || [])) lines.push('  '.repeat(h.length) + '└ ' + c);
            return section('hierarchy', 'Hierarchy', el('div', {}, el('pre', { class: 'objxml', text: lines.join('\n') }),
                obj.row.type !== 'DeviceGroup' ? null : el('p', { class: 'muted', text: 'firewalls: ' + (obj.row.firewalls ?? '?') + ' in this device group, ' + (obj.row['firewalls-below'] ?? '?') + ' with the device groups below' })));
        }
        function objXml() {
            // no XML: a predefined object (applications, URL categories, profiles of PAN-OS - they come from the App-ID
            // database, not from the configuration) or an object the read did not give (then: a bug - please report)
            // a device (device group, template, …): its XML would be its whole part of the configuration - not shown
            if (cur.type === 'device' && !obj.xml) return null;
            return obj.xml ? section('xml', 'XML', xmlView(obj.xml))
                : el('p', { class: 'muted', text: 'XML: not available. Predefined objects of PAN-OS (applications, URL categories, predefined profiles) are not part of the configuration; for any other object please report it.' });
        }
        function objHistory() {
            const h = obj.history;
            const isStart = (c) => !!(c.change && c.change.version) && !c.change.type && !c.change.run;
            if (!h) return obj.xml ? el('p', { class: 'muted', text: 'History: none for this object (not in the history of the version - e.g. an object of a template, or no git)' }) : null;
            const shown = { i: null };
            const view = el('pre', { class: 'objxml', hidden: true });
            const items = h.commits.map((c, i) => el('li', {},
                el('button', { type: 'button', class: 'small', text: 'XML', title: 'the object after this commit', onclick: () => {
                    if (shown.i === i && !view.hidden) { view.hidden = true; return; }
                    shown.i = i; view.hidden = false; view.textContent = c.text === null ? '(removed by this commit)' : c.text; } }), ' ',
                el('span', { class: 'muted', text: fmtTime(c.time) + ' ' + c.user + ' - ' }),
                // the first commit of a version: its state when it was first opened (the start of the history) - no change
                isStart(c) ? el('span', { class: 'muted', text: 'start: the object as the version was uploaded / made (' + c.subject + ') - no change' }) : el('code', { text: c.subject }),
                // a run result (object-merger, rule-merger, …): what the run did with this object
                (c.notes || []).length ? el('ul', { class: 'objhistnotes' }, c.notes.map(n => el('li', { class: /^Not-merged:/.test(n) ? 'warn' : '', text: n }))) : null));
            const changes = h.commits.filter(c => !isStart(c)).length;
            return section('history', 'History (' + (changes ? changes + (h.commits.length >= 30 ? '+' : '') + ' change' + (changes === 1 ? '' : 's') : 'no changes') + ')',
                el('div', {}, el('p', { class: 'muted', text: 'entry ' + h.path + ' - newest first; a rename starts a new entry' }), el('ul', { class: 'objhist' }, items), view));
        }
        render();
        document.addEventListener('keydown', onKey);
        document.body.append(overlay);
        const first = box.querySelector('input, select');
        if (first) first.focus();
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
    async function openMultiEdit(c) {
        const name = c.filter.slice(9, -1);
        const q = new URLSearchParams({ type: c.type, location: c.location || '', name });
        if (c.ruletype) q.set('ruletype', c.ruletype);
        if (c.template) q.set('template', c.template);
        // the object as it is now (renamed by the change: not found - then only the generic suggestions)
        const obj = await api('GET', base() + '/object?' + q.toString()).catch(() => ({ row: { name }, model: {} }));
        const sugg = filterSuggestions(c.type, c.ruletype, obj.row, obj.model || {}, name);
        const checks = sugg.map(x => { const i = el('input', { type: 'checkbox', checked: x.on }); i.addEventListener('change', () => recount()); return [x, i]; });
        const without = el('input', { type: 'checkbox', checked: true }); without.addEventListener('change', () => recount());
        const loc = el('select', {}, [...location.options].map(o => el('option', { value: o.value, text: o.text })));
        if (![...loc.options].some(o => o.value === c.location)) loc.append(el('option', { value: c.location, text: c.location }));
        loc.value = c.location; loc.addEventListener('change', () => recount());
        const more = el('input', { placeholder: 'more pan-os-php filter (optional)', maxlength: 1500, autocomplete: 'off', spellcheck: false });
        const moreBox = suggest(more, (text, pos) => filterSuggest((state.meta.types[c.type] || {}).filters || {}, text, pos));
        more.addEventListener('change', () => recount());
        const act = el('input', { value: c.actions, maxlength: 2000, autocomplete: 'off', spellcheck: false });
        const result = el('div', { class: 'muted', text: '…' });
        const applyBtn = el('button', { class: 'primary', type: 'button', text: 'Apply', disabled: true });
        const box = el('div', { class: 'objwin', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'multi-edit' });
        const overlay = el('div', { class: 'objoverlay', onclick: (ev) => { if (ev.target === overlay) close(); } }, box);
        const onKey = (ev) => { if (ev.key === 'Escape') close(); };
        function close() { document.removeEventListener('keydown', onKey); overlay.remove(); }
        function filterText() {
            const parts = checks.filter(([, i]) => i.checked).map(([x]) => x.text);
            if (without.checked) parts.push('!(name eq ' + name + ')');
            if (more.value.trim()) parts.push('(' + more.value.trim() + ')');
            return parts.join(' and ');
        }
        let seq = 0, matched = 0;
        async function recount() {
            const my = ++seq;
            applyBtn.disabled = true; result.textContent = 'counting …';
            const qq = new URLSearchParams({ type: c.type, location: loc.value || 'any', filter: filterText() });
            if (c.ruletype) qq.set('ruletype', c.ruletype);
            if (c.template) qq.set('template', c.template);
            try {
                const r = await api('GET', base() + '/objects?' + qq.toString());
                if (my !== seq) return;
                matched = r.total;
                result.replaceChildren(el('strong', { text: r.total + ' object' + (r.total === 1 ? '' : 's') + ' match' }),
                    r.total ? el('div', { class: 'chips' }, r.rows.slice(0, 60).map(x => el('span', { class: 'chip', text: (loc.value === 'any' ? x.location + ': ' : '') + x.name })),
                        r.total > 60 ? el('span', { class: 'muted', text: '… ' + (r.total - 60) + ' more' }) : null) : null);
                applyBtn.disabled = r.total === 0;
            } catch (e) { if (my === seq) result.textContent = e.message; }
        }
        applyBtn.addEventListener('click', () => run(async () => {
            const a = act.value.trim();
            if (/^name-rename:/i.test(a) && !a.includes('$$')) throw new Error('renaming many objects needs a formula with $$current.name$$ (otherwise all get the same name)');
            const f = filterText();
            if (!confirm('Run "' + a + '" on ' + matched + ' object(s)?' + (f ? '' : '\nNo filter: all objects of this type in the location.'))) return;
            const body = { type: c.type, location: loc.value || 'any', filter: f, actions: a, field: 'multi-edit' };
            if (c.ruletype) body.ruletype = c.ruletype;
            if (c.template) body.template = c.template;
            const r = await api('POST', base() + '/change', body);
            setStatus(Object.assign({ loaded: true }, r.status));
            state.cache.clear(); close();
            message('multi-edit done on ' + r.processed + ' object(s) - not saved yet');
            await load(true);
        }));
        box.append(el('div', { class: 'objhead' }, el('h3', { text: 'Multi-edit: ' + c.type + (c.ruletype ? ' / ' + c.ruletype : '') }),
                el('button', { type: 'button', class: 'objclose', text: '✕', 'aria-label': 'close', onclick: close })),
            el('p', { class: 'muted', text: 'The change on "' + name + '" - the same action on more objects. Choose what they have in common (taken from "' + name + '"), check the list, then apply.' }),
            el('table', { class: 'objfields' }, el('tbody', {},
                el('tr', {}, el('th', { text: 'Action' }), el('td', {}, act, el('div', { class: 'muted', text: 'the same on every object; a rename needs a formula ($$current.name$$-new)' }))),
                el('tr', {}, el('th', { text: 'Location' }), el('td', {}, loc)),
                el('tr', {}, el('th', { text: 'Objects that …' }), el('td', {}, sugg.length ? checks.map(([x, i]) => el('label', { class: 'check' }, i, ' ' + x.label + ' ', el('code', { class: 'muted', text: x.text }))) : el('span', { class: 'muted', text: 'no suggestions - use the filter below' }),
                    el('label', { class: 'check' }, without, ' not "' + name + '" itself (already changed)'))),
                el('tr', {}, el('th', { text: 'Filter' }), el('td', {}, moreBox)),
                el('tr', {}, el('th', { text: 'Matches' }), el('td', {}, result)))),
            el('div', { class: 'row' }, applyBtn, el('button', { type: 'button', text: 'Close', onclick: close })));
        document.addEventListener('keydown', onKey);
        document.body.append(overlay);
        await recount();
    }

    // change box
    // the action: type to find it (actions of the type that may run here, from util_action_filter.json)
    const action = el('input', { placeholder: 'type to find an action', autocomplete: 'off', spellcheck: false, onchange: () => actionChanged(), oninput: () => actionChanged() });
    const actionBox = suggest(action, (text) => {
        const acts = state.meta.types[type.value].actions, w = text.trim().toLowerCase();
        const keys = Object.keys(acts).filter(a => a.toLowerCase().includes(w)).sort((a, b) => (b.toLowerCase().startsWith(w) ? 1 : 0) - (a.toLowerCase().startsWith(w) ? 1 : 0));
        return { from: 0, to: text.length, list: keys.map(a => ({ label: a,
            detail: acts[a].length ? acts[a].map(x => x.name + (x.default && x.default !== '*nodefault*' ? '=' + x.default : '')).join(', ') : '', insert: a })) };
    });
    const actionArg = el('input', { maxlength: 1500 });
    const argHelp = el('span', { class: 'muted' });
    function actionChanged() {
        const args = (state.meta.types[type.value].actions[action.value] || []);
        actionArg.disabled = args.length === 0;
        if (actionArg.dataset.for !== action.value) { actionArg.value = ''; actionArg.dataset.for = action.value; }
        actionArg.placeholder = args.map(a => a.name).join(',');
        argHelp.textContent = args.map(a => a.name + (a.help ? ': ' + a.help : '')).join(' | ');
    }
    const changeBox = canWrite ? el('details', { class: 'card' }, el('summary', { text: 'Run a pan-os-php action on all objects of the list' }),
        el('p', { class: 'muted', text: 'The action runs on all objects that match the menu entry, location and the pan-os-php filter above (not the quick filter). It changes the loaded configuration in memory only - nothing is written until you save.' }),
        el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
            if (!action.value) throw new Error('choose an action');
            if (!state.meta.types[type.value].actions[action.value]) throw new Error('"' + action.value + '" is no action of ' + type.value + ' here - type part of the name to find one');
            const body = Object.fromEntries(query());
            body.actions = action.value + (actionArg.value.trim() !== '' ? ':' + actionArg.value.trim() : '');
            if (!confirm('Run "' + body.actions + '" on ' + view.rows.length + ' object(s) of the current list?')) return;
            const r = await api('POST', base() + '/change', body);
            state.cache.clear();
            log.hidden = false; log.textContent = r.log;
            message('action done on ' + r.processed + ' object(s) - not saved yet');
            await load(true);
        }); } }, field('Action', actionBox), el('label', { class: 'grow' }, 'Arguments (comma separated)', actionArg), el('button', { class: 'primary', type: 'submit', text: 'Run on loaded configuration' })),
        argHelp, log) : null;
    const changesCard = el('div', { class: 'card' }, el('h3', { text: 'Unsaved changes' }), el('p', { class: 'muted', text: 'Every change is one pan-os-php action (filter + action) on the loaded configuration - in the object window one per field.' }), changeList,
        el('div', { class: 'row' }, el('button', { type: 'button', text: 'Export as playbook …', title: 'the unsaved changes as a pan-os-php playbook (type=playbook): to run on another version or configuration',
            onclick: () => run(() => exportPlaybook(pid, state.config.cid, 'unsaved', canWrite)) })));

    const title = el('h2', { text: 'Version of ' + fmtTime(config.created) + ' - ' + config.name });
    main(el('div', { class: 'row' }, el('button', { type: 'button', text: '‹ ' + p.name, onclick: () => run(async () => {
            if (lastStatus && lastStatus.dirty && !confirm('There are unsaved changes. They stay in the loaded configuration on the server (recovery copy), but are not a version yet. Leave?')) return;
            await showProject(pid);
        }) }), title),
        el('div', { class: 'statusbar' }, status, autosaveInfo, el('span', { class: 'spacer' }),
            canWrite ? field('Auto save as version', autosave) : el('span', { class: 'muted', text: 'read only' }), canWrite ? saveBtn : null, canWrite ? discardBtn : null),
        el('div', { class: 'viewer' }, menu, el('div', { class: 'vmain' },
            el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(() => load(false)); } },
                tplField, field('Location', el('div', { class: 'locpick' }, locFilter, location, locCount)), dgScopeField, sameNameField, spField, devField, el('label', { class: 'grow' }, 'pan-os-php filter (runs on the server)', filterBox),
                el('button', { class: 'primary', type: 'submit', text: 'Show' }), el('button', { type: 'button', text: 'Reload', onclick: () => run(() => load(true)) })),
            heading,
            el('div', { class: 'row' }, field('Quick filter (in the browser)', quick), extraBox, info),
            tableWrap, pager, changesCard, changeBox)));
    // a new location / device group scope / same-name choice / profile or device type: the list at once (no "Show")
    for (const sel of [tplSel, location, dgScope, sameName, sptype, devtype]) if (sel) sel.addEventListener('change', () => { view.page = 1; run(() => load(false)); });
    drawMenu();
    typeChanged();
    if (preset) {
        // a link from the references: the entry of the type (and rule type) - without the filter of the entry (an address
        // group is in the list of the addresses then)
        if (preset.type && types.includes(preset.type)) {
            const e = entries.find(x => x.id === preset.entry && x.type === preset.type) || viewerEntryFor(entries, preset.type, preset.ruletype, null);
            if (e) { cur = Object.assign({}, e, { noBase: !!e.filter }); typeChanged(); drawMenu(); }
        }
        if (preset.securityprofiletype) sptype.value = preset.securityprofiletype;
        if (preset.devicetype) devtype.value = preset.devicetype;
        // an object of a template: the list only of that template (until the filter is changed)
        if (preset.template) {
            view.template = preset.template;
            if (!tplField.hidden && ![...tplSel.options].some(o => o.value === preset.template)) tplSel.append(el('option', { value: preset.template, text: preset.template }));
            if (!tplField.hidden) tplSel.value = preset.template;
        }
        // a link "Open ↗": the window of that object opens when the list is there
        if (preset.open) view.openAfterLoad = { name: preset.open, location: preset.at || (preset.location === 'any' ? '' : preset.location), template: preset.template || '', profile: preset.profile || '' };
        // a location with the device groups below (<DG>:includechilddgs / :excludemaindg)
        const pl = /^(.+):(includechilddgs|excludemaindg|effective-predefined|effective)$/i.exec(preset.location || '');
        if (pl) { preset.location = pl[1]; dgScope.value = pl[2].toLowerCase(); }
        if (preset.location) {
            if (![...location.options].some(o => o.value === preset.location)) location.append(el('option', { value: preset.location, text: preset.location }));
            location.value = preset.location;
        }
        if (preset.filter) filter.value = preset.filter;
    }

    // status of the loaded configuration + auto save
    state.timers.push(setInterval(() => { api('GET', base() + '/status').then(setStatus).catch(() => {}); }, 30000));
    let lastAuto = Date.now();
    state.timers.push(setInterval(() => {
        const min = parseInt(autosave.value, 10);
        if (!canWrite || !min || !lastStatus || !lastStatus.dirty || Date.now() - lastAuto < min * 60000) return;
        lastAuto = Date.now();
        run(save);
    }, 15000));
    autosave.addEventListener('change', () => { lastAuto = Date.now(); });

    await load(false);
}

window.addEventListener('beforeunload', (ev) => {
    const b = document.querySelector('.badge.dirty');
    if (b) { ev.preventDefault(); ev.returnValue = ''; }
});

// ---------------------------------------------------------------- start
document.getElementById('nav-projects').addEventListener('click', () => run(showProjects));
document.getElementById('nav-account').addEventListener('click', () => run(showAccount));
document.getElementById('logout').addEventListener('click', () => run(async () => { await api('POST', 'logout'); leave(); showLogin(); }));
// a link "Open" of a reference: #p=<project>&c=<version>&type=…&location=…&filter=… opens that version with this list
async function openFromHash() {
    const h = new URLSearchParams(location.hash.slice(1));
    if (!h.get('p') || !h.get('c')) return false;
    history.replaceState(null, '', location.pathname);
    const p = await api('GET', 'projects/' + encodeURIComponent(h.get('p')));
    const c = (await api('GET', 'projects/' + p.pid + '/configs')).configs.find(x => x.cid === h.get('c'));
    if (!c) throw new Error('this version does not exist any more');
    state.project = p;
    await showViewer(c, Object.fromEntries(['type', 'entry', 'ruletype', 'securityprofiletype', 'devicetype', 'location', 'filter', 'template', 'profile', 'open', 'at'].map(k => [k, h.get(k)])));
    return true;
}
run(async () => {
    let me;
    try { me = await api('GET', 'me'); } catch (e) { showLogin(); return; }
    const deep = location.hash.length > 1;
    await entered(me, deep);
    if (deep) await openFromHash();
});
