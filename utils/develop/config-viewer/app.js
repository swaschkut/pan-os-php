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
// js/account.js, js/projects.js, js/plugin-pages.js, js/editors.js, js/ldap.js, js/scm.js, js/merger.js, js/project-tools.js,
// js/viewer-fields.js (the fields of the object windows of the viewer), js/viewer-object.js (the windows of the viewer),
// js/run-file.js (a result file of a run shown in a tab), js/stats-compare.js (two stats runs compared, in a tab)

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
    // what the windows of the viewer (js/viewer-object.js: openObject, showSystem, openMultiEdit) read of this viewer and
    // the functions of the list they call - read when a window is opened (everything below exists by then)
    const viewerContext = {
        get cur() { return cur; }, get base() { return base; }, get canWrite() { return canWrite; }, get ruletype() { return ruletype; },
        get locationInfo() { return locationInfo; }, get location() { return location; }, get devtype() { return devtype; },
        get spTypeOf() { return spTypeOf; }, get fetchObject() { return fetchObject; }, get openLink() { return openLink; },
        get refsTable() { return refsTable; }, get load() { return load; }, get setStatus() { return setStatus; },
    };
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
                onclick: () => run(() => showSystem(viewerContext)) }))].filter(x => x), ...VIEWER_MENU_SECTIONS.map(sec => {
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
                    title: 'the same action on more objects', onclick: () => run(() => openMultiEdit(viewerContext, c)) }) : null,
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
            if (r) await openObject(viewerContext, r);
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
                const row = el('tr', win ? { class: 'clickable' + (typeof r.effective === 'string' && r.effective !== 'used' ? ' overridden' : ''), title: 'open ' + r.name, onclick: (ev) => { if (ev.target.closest('button, a')) return; run(() => openObject(viewerContext, r)); } } : {}, view.columns.map(c => {
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

    async function fetchObject(name, loc, template, profile, cls) {
        const q = new URLSearchParams({ type: cur.type, location: loc, name });
        if (template) q.set('template', template);
        if (profile) q.set('profile', profile);
        if (cur.type === 'rule') q.set('ruletype', ruletype.value);
        if (cur.type === 'securityprofile') q.set('securityprofiletype', spTypeOf({ type: cls }));
        return api('GET', base() + '/object?' + q.toString());
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
    // a result file of a run in a tab of its own: #p=<project>&run=<run>&file=<name> (js/run-file.js)
    if (h.get('p') && h.get('run') && h.get('file')) { await showRunFile(h.get('p'), h.get('run'), h.get('file')); return true; }
    // the figures of two stats runs compared: #p=<project>&stats=<run>[&other=<run>] (js/stats-compare.js)
    if (h.get('p') && h.get('stats')) { await showStatsCompare(h.get('p'), h.get('stats'), h.get('other')); return true; }
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
