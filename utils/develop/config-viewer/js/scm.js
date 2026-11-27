/*
 * pan-os-php config viewer - browser part, SCM tab of a project (SCM_TAB.md): egress IP, Prisma Access pages.
 * Part of app.js in a file of its own: declarations only (functions, constants) - nothing runs when the file is
 * loaded. index.html loads the parts before app.js, which holds the helpers, the viewer / editor and the start.
 */
'use strict';

// ---------------------------------------------------------------- SCM tab of a project (SCM_TAB.md)
// a menu on the left (Prisma Access, Identity & Access, CIE, configuration, deployment, tenant, monitoring, BPA); built:
// Prisma Access > Egress IP - states from an import (export / 92_egress-ip.json / snapshot) or read live (run egress-ip
// with the egress-IP key of the user), shown and compared (SCMEgressIP, the same as scm_egress_ip.php on the CLI); Prisma Access > Infrastructure - states from the SCM import of the project or read live (run scm-pa, scm_pa_export.php),
// compared with scm_pa_compare.php (SCMPrismaAccessCompare)
const SCM_MENU = [
    ['Prisma Access', [['egress', 'Egress IP'], ['infra', 'Infrastructure'], ['sc', 'Service Connection'], ['rn', 'Remote Networks (RN-SPN)'],
        ['mugw', 'Mobile User Gateway'], ['mugp', 'Mobile User GlobalProtect'], ['mupaa', 'Mobile User PAA'], ['muep', 'Mobile User Explicit Proxy'], ['pb', 'Prisma Browser']]],
    ['Identity & Access', [['sa', 'Service accounts']]],
    ['Cloud Identity Engine', [['cie', 'CIE']]],
    ['Configuration', [['versions', 'Config versions and push status'], ['vars', 'Variables']]],
    ['Deployment', [['locations', 'Locations'], ['bandwidth', 'Bandwidth'], ['bgp', 'BGP'], ['steering', 'Traffic steering']]],
    ['Tenant', [['trusted', 'Trusted tenants'], ['licences', 'Licences and instances']]],
    ['Monitoring', [['insights', 'Insights'], ['audit', 'Audit logs']]],
    ['Best practice', [['bpa', 'BPA']]],
];
async function scmTab(base, pid, canWrite, p) {
    const card = el('div', { class: 'card scmtab' });
    const panel = el('div', { class: 'scmpanel' });
    state.scmPage = state.scmPage || {};
    const menu = el('nav', { class: 'scmmenu', 'aria-label': 'SCM' });
    function drawMenu() {
        const cur = state.scmPage[pid] || 'egress';
        menu.replaceChildren(...SCM_MENU.map(([sec, items]) => el('div', { class: 'vsec' }, el('div', { class: 'vsechead', text: sec }),
            items.map(([id, t]) => { const built = id === 'egress' || SCM_PA_VIEWS[id];
                return el('button', { type: 'button', class: 'ventry' + (id === cur ? ' on' : ''), text: t + (built ? '' : ' ·'),
                    title: built ? '' : 'planned (SCM_TAB.md)', onclick: () => { state.scmPage[pid] = id; drawMenu(); run(page); } }); }))));
    }
    async function page() {
        const cur = state.scmPage[pid] || 'egress';
        if (SCM_PA_VIEWS[cur]) { panel.replaceChildren(await scmPaPage(base, cur, canWrite, page)); return; }
        if (cur !== 'egress') {
            const t = SCM_MENU.flatMap(x => x[1]).find(x => x[0] === cur);
            panel.replaceChildren(el('h3', { text: t ? t[1] : cur }), el('p', { class: 'muted', text: 'Planned - see utils/develop/config-viewer/SCM_TAB.md: data from the imported export, a live refresh with your key, compare of two states; changes only through change files, review and a live compare right before the upload.' }));
            return;
        }
        panel.replaceChildren(await egressPage(base, canWrite, page));
    }
    drawMenu();
    await page().catch(e => panel.replaceChildren(el('div', { class: 'error', text: e.message })));
    // all pages at once: from the SCM imports the project has done, or read live (every area + the egress IPs)
    let all = null;
    if (canWrite) {
        const r = await api('GET', base + '/scm/pa/infra').catch(() => null);
        const fromRuns = el('button', { type: 'button', text: 'From the SCM imports', title: 'fill the Prisma Access pages and Egress IP from the SCM imports of this project (imports before 2.1.63 read only the configuration)',
            onclick: () => run(async () => {
                const x = await api('POST', base + '/scm/pa-from-runs');
                message(x.runs === 0 ? 'no SCM import in this project yet' : x.states + ' page state(s), ' + x.egress + ' egress state(s) from ' + x.runs + ' SCM import(s) / read(s)'
                    + (x.config_only ? '; ' + x.config_only + ' import(s) with the configuration only (before 2.1.63) - use "Read all live"' : '') + (x.gone ? '; ' + x.gone + ' without their export any more' : ''));
                await page();
            }) });
        all = el('div', { class: 'row scmall' }, fromRuns, r ? liveForm(r, { keyLabel: 'SCM key', path: base + '/scm-pa/runs', runs: base + '/runs', redraw: page, done: 'Prisma Access read live',
            body: () => ({ page: 'all' }), noKey: 'Read all live: you have no SCM key ' + (p && p.binding && p.binding.kind === 'scm' ? 'for TSG ' + p.binding.target : '') + ' (Account, My API keys, kind SCM).' }) : null);
        const btn = all.querySelector('button[type=submit]');
        if (btn) btn.textContent = 'Read all live';
    }
    card.append(...[el('h2', { text: 'SCM' + (p && p.binding && p.binding.kind === 'scm' ? ' - TSG ' + p.binding.target : '') }), all, el('div', { class: 'scmlayout' }, menu, panel)].filter(x => x));
    return card;
}

// ---- helpers of the SCM tab pages

/**
 * a table with a filter field under every header (contains, case-insensitive; "!text" = without; the values to pick
 * for columns with few values), sort by a click on a header (IPv4 addresses by number), a search over all columns and
 * "Clear filters"; cols = [[key, label]], rows = objects. Returns { node, rowsOf } (rowsOf: the rows shown, in order).
 */
function colTable(cols, rows, extra = [], what = 'entries', render = {}) {
    const val = (x, k) => { const v = x[k]; return v === null || v === undefined ? '' : (typeof v === 'object' ? JSON.stringify(v) : String(v)); };
    const q = el('input', { type: 'search', placeholder: 'search all columns …', 'aria-label': 'search all columns' });
    const colFilter = {}, sort = { key: null, desc: false };
    const ipKey = (v) => /^\d+\.\d+\.\d+\.\d+/.test(v) ? v.replace(/\d+/g, n => n.padStart(3, '0')) : v;
    const heads = cols.map(([k, label]) => {
        const values = [...new Set(rows.map(x => val(x, k)).filter(v => v !== ''))].sort();
        const listId = 'col-' + k.replace(/[^a-z0-9]/gi, '') + '-' + Math.random().toString(36).slice(2, 8);
        const pick = values.length > 0 && values.length <= 50 && values.length < rows.length;
        colFilter[k] = el('input', { type: 'search', class: 'colfilter', placeholder: 'filter …', 'aria-label': 'filter ' + label, autocomplete: 'off',
            list: pick ? listId : null, title: 'contains (case-insensitive); !text = without' });
        colFilter[k].addEventListener('input', draw);
        const th = el('th', { class: 'sortable', title: 'sort', text: label, onclick: () => { sort.desc = sort.key === k ? !sort.desc : false; sort.key = k; draw(); } });
        return { k, th, fth: el('th', {}, colFilter[k], pick ? el('datalist', { id: listId }, values.map(v => el('option', { value: v }))) : null) };
    });
    const tbody = el('tbody', {});
    const count = el('p', { class: 'muted' });
    const match = (v, f) => { f = f.trim().toLowerCase(); if (!f) return true; v = v.toLowerCase(); return f[0] === '!' ? (f.length === 1 || !v.includes(f.slice(1))) : v.includes(f); };
    const rowsOf = () => {
        const all = q.value.trim().toLowerCase();
        const out = rows.filter(x => cols.every(([k]) => match(val(x, k), colFilter[k].value)) && (!all || cols.map(([k]) => val(x, k)).join(' ').toLowerCase().includes(all)));
        if (sort.key) out.sort((a, b) => ipKey(val(a, sort.key)).localeCompare(ipKey(val(b, sort.key)), undefined, { numeric: true }) * (sort.desc ? -1 : 1));
        return out;
    };
    function draw() {
        const shown = rowsOf();
        count.textContent = shown.length + ' of ' + rows.length + ' ' + what;
        for (const h of heads) { h.th.classList.toggle('sorted', sort.key === h.k); h.th.dataset.dir = sort.key === h.k ? (sort.desc ? '▼' : '▲') : ''; }
        tbody.replaceChildren(...shown.map(x => el('tr', {}, cols.map(([k]) => render[k] ? el('td', {}, render[k](x)) : el('td', { text: val(x, k) })))));
    }
    q.addEventListener('input', draw);
    const clear = el('button', { type: 'button', text: 'Clear filters', onclick: () => { q.value = ''; for (const k in colFilter) colFilter[k].value = ''; draw(); } });
    const node = el('div', {}, el('div', { class: 'row' }, q, clear, ...extra), count,
        el('table', { class: 'plain coltable' }, el('thead', {}, el('tr', {}, heads.map(h => h.th)), el('tr', { class: 'filterrow' }, heads.map(h => h.fth))), tbody));
    draw();
    return { node, rowsOf };
}

/** "Read live" of a page: a run with one of the user's keys, polled until it ends; the error stays next to the button */
// a project with a project type (plug-in): the role of a run that reads from a device / tenant - "auto" takes the
// role bound to the tenant of the key, a free role binds it (the server checks it)
function roleSelect(kind) {
    const roles = (state.projectRoles || []).filter(r => !kind || r.kind === kind);
    if (!roles.length) return null;
    return el('select', { 'aria-label': 'role' }, el('option', { value: '', text: 'auto (the role of this tenant / device)' }),
        roles.map(r => el('option', { value: r.name, text: r.title + ' (' + r.name + ': ' + (r.target ? (r.kind === 'scm' ? 'TSG ' : '') + r.target : 'free') + ')' })));
}

function liveForm(r, opts) {
    if (!r.keys.length) return el('p', { class: 'muted', text: opts.noKey });
    const roleSel = roleSelect('scm');
    const key = el('select', { 'aria-label': opts.keyLabel }, r.keys.map(k => el('option', { value: k.kid, text: 'TSG ' + k.target + (k.label && k.label !== k.target ? ' - ' + k.label : '') + (k.refused ? ' (not allowed: ' + k.refused + ')' : '') })));
    const status = el('span', { class: 'muted' });
    return el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
        const job = await api('POST', opts.path, Object.assign({ kid: key.value }, opts.body ? opts.body() : {}, roleSel && roleSel.value ? { role: roleSel.value } : {}));
        status.className = 'muted'; status.textContent = 'reading live …';
        const t = setInterval(async () => {
            const x = await api('GET', opts.runs + '/' + job.jid).catch(() => null);
            if (!x || (x.state !== 'done' && x.state !== 'failed')) return;
            clearInterval(t);
            if (x.state === 'failed') { status.className = 'error'; status.textContent = 'live read failed: ' + (x.error || 'see Runs'); message('live read failed: ' + (x.error || 'see Runs'), 'error'); return; }
            message(opts.done); await opts.redraw();
        }, 1500);
        state.timers.push(t);
    }); } }, field('Live with your key', key), roleSel ? field('Role', roleSel) : null, ...(opts.fields || []),
        el('button', { class: 'primary', type: 'submit', text: 'Read live', disabled: !r.network, title: r.network ? '' : 'network is off for this project (the owner turns it on)' }), status);
}

/**
 * the states of a page as "View" and "Compare" (button tabs): View = one state (default the newest), Compare = two
 * states (default the one before against the newest); view(id) / compare(oldId, newId) return the content
 */
function viewCompare(states, label, view, compare) {
    const out = el('div', {});
    const opt = (s) => el('option', { value: s.id, text: fmtTime(s.time) + ' - ' + s.source + (s.user ? ', ' + s.user : '') });
    const pick = el('select', { 'aria-label': 'state' }, states.map(opt));
    const oldS = el('select', { 'aria-label': 'older state' }, states.map(opt)), newS = el('select', { 'aria-label': 'newer state' }, states.map(opt));
    if (states[1]) oldS.value = states[1].id;
    const body = el('div', {});
    const bView = el('button', { type: 'button', class: 'tabbtn', text: 'View' }), bCmp = el('button', { type: 'button', class: 'tabbtn', text: 'Compare', disabled: states.length < 2,
        title: states.length < 2 ? 'two states are needed' : 'what changed between two states' });
    const bar = el('div', { class: 'row' });
    async function show(mode) {
        bView.classList.toggle('on', mode === 'view'); bCmp.classList.toggle('on', mode === 'compare');
        bar.replaceChildren(...(mode === 'view' ? [field(label, pick)] : [field('older', oldS), field('newer', newS)]));
        body.replaceChildren(el('p', { class: 'muted', text: 'loading …' }));
        body.replaceChildren(mode === 'view' ? await view(pick.value) : (oldS.value === newS.value ? el('p', { class: 'muted', text: 'choose two different states' }) : await compare(oldS.value, newS.value)));
    }
    let mode = 'view';
    bView.onclick = () => run(() => show(mode = 'view'));
    bCmp.onclick = () => run(() => show(mode = 'compare'));
    for (const s of [pick, oldS, newS]) s.addEventListener('change', () => run(() => show(mode)));
    out.append(el('div', { class: 'row tabbar' }, bView, bCmp), bar, body);
    out.showState = (id) => { pick.value = id; return show(mode = 'view'); };
    out.ready = show('view');
    return out;
}

async function egressPage(base, canWrite, redraw) {
    const r = await api('GET', base + '/scm/egress');
    const box = el('div', {});
    // import: 92_egress-ip.json of an export, a zip of the export, or a snapshot of scm_egress_ip.php save=
    const file = el('input', { type: 'file', accept: '.json,.zip,application/json,application/zip', required: true });
    const imp = canWrite ? el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
        const fd = new FormData(); fd.append('file', file.files[0]);
        const x = await api('POST', base + '/scm/egress', fd);
        message(x.count + ' egress IP(s) imported'); await redraw();
    }); } }, field('Import: its infra/92_egress-ip.json, a snapshot (scm_egress_ip.php save=) or an export (zip)', file), el('button', { type: 'submit', text: 'Import' })) : null;
    // live: run egress-ip with an egress-IP key of the user (Account, My API keys, kind egress IP); default prod8
    // (default), older tenants prod - a login error (HTTP 401) names the other one
    let live = null;
    if (canWrite) {
        const sel = (name, list) => el('select', { 'aria-label': name }, list.map(v => el('option', { value: v, text: v })));
        const st = sel('service type', r.options.servicetype), at = sel('address type', r.options.addrtype), lo = sel('location', r.options.location);
        // the environment: the known ones (prod8 default, prod6, prod older tenants) or another prod<N>
        const envs = (r.options.env || ['prod8', 'prod6', 'prod']);
        const envSel = el('select', { 'aria-label': 'environment', title: 'default prod8, then prod6, older tenants prod' }, envs.map(v => el('option', { value: v, text: v + (v === 'prod' ? ' (older tenants)' : '') })),
            el('option', { value: '', text: 'other …' }));
        const envOther = el('input', { type: 'text', placeholder: 'prod<N>', pattern: 'prod[0-9]{0,2}', size: 8, 'aria-label': 'other environment', hidden: true });
        envSel.addEventListener('change', () => { envOther.hidden = envSel.value !== ''; });
        const env = { get value() { return envSel.value || envOther.value.trim(); } };
        live = liveForm(r, { keyLabel: 'egress-IP key', path: base + '/egress-ip/runs', runs: base + '/runs', redraw, done: 'egress IPs read live',
            noKey: 'Live: you have no egress-IP API key yet (Account, My API keys, kind "egress IP", target = TSG id; Prisma Access > Infrastructure Settings > Egress IP API).',
            body: () => ({ servicetype: st.value, addrtype: at.value, location: lo.value, env: env.value }),
            fields: [field('serviceType', st), field('addrType', at), field('location', lo), field('environment', el('span', {}, envSel, ' ', envOther))] });
    }
    const fmtReq = (q) => q ? [q.serviceType, q.addrType, q.location].filter(x => x).join(' / ') : '';
    let vc = null;
    const list = r.states.length === 0 ? el('p', { class: 'muted', text: 'No egress IPs yet - import them or read them live.' }) :
        table(['When', 'Source', 'By', 'TSG', 'Request', 'Addresses', ''], r.states.map((x) => el('tr', {},
            el('td', { text: fmtTime(x.time) }), el('td', { text: x.source + (x.name ? ' (' + x.name + ')' : '') }), el('td', { text: x.user }), el('td', { text: x.tsg || '' }),
            el('td', { text: fmtReq(x.request) }), el('td', { text: String(x.count) }),
            el('td', {}, el('button', { type: 'button', text: 'Show', onclick: () => run(() => vc.showState(x.id)) }), ' ',
                canWrite ? el('button', { type: 'button', class: 'danger', text: 'Delete', onclick: () => run(async () => {
                    if (!confirm('Delete this state of the egress IPs?')) return;
                    await api('DELETE', base + '/scm/egress/' + x.id); await redraw(); }) }) : null))));
    const dl = (name, text, mime) => { const a = el('a', { href: URL.createObjectURL(new Blob([text], { type: mime })), download: name }); document.body.append(a); a.click(); a.remove(); };
    const csv = (rows) => ['service_type,location,address,address_type,allow_listed'].concat(rows.map(x => [x.service_type, x.location, x.address, x.address_type, x.allow_listed]
        .map(v => { v = String(v ?? ''); if (/^[=+\-@]/.test(v)) v = "'" + v; return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }).join(','))).join('\n') + '\n';
    async function view(id) {
        const s = await api('GET', base + '/scm/egress/' + id);
        let t = null;
        t = colTable([['service_type', 'Service type'], ['location', 'Location'], ['address', 'Address'], ['address_type', 'Address type'], ['allow_listed', 'Allow listed']], s.rows, [
            el('button', { type: 'button', text: 'Address list', title: 'the addresses shown, one per line (e.g. an external dynamic list)', onclick: () => dl('egress-ip.txt', [...new Set(t.rowsOf().map(x => x.address))].join('\n') + '\n', 'text/plain') }),
            el('button', { type: 'button', text: 'CSV', title: 'the rows shown', onclick: () => dl('egress-ip.csv', csv(t.rowsOf()), 'text/csv') })], 'address(es)');
        return el('div', {}, el('h3', { text: 'Egress IPs - ' + fmtTime(s.time) + ' (' + s.source + (s.tsg ? ', TSG ' + s.tsg : '') + ', ' + fmtReq(s.request) + ')' }), t.node);
    }
    async function compare(oldId, newId) {
        const s = await api('GET', base + '/scm/egress/' + newId + '?compare=' + encodeURIComponent(oldId));
        const c = s.compare;
        const line = (sign, x) => el('div', { class: sign === '+' ? 'diffadd' : (sign === '-' ? 'diffdel' : 'diffchg'), text: sign + ' ' + x.service_type + '  ' + x.location + '  ' + x.address + (x.address_type ? '  (' + x.address_type + ')' : '') });
        return el('div', { class: 'card' }, el('h3', { text: c.added.length + ' added, ' + c.removed.length + ' removed, ' + c.changed.length + ' changed' }),
            ...c.added.map(x => line('+', x)), ...c.removed.map(x => line('-', x)),
            ...c.changed.map(x => line('~', Object.assign({}, x.new, { address_type: x.old.address_type + ' -> ' + x.new.address_type }))),
            !c.added.length && !c.removed.length && !c.changed.length ? el('p', { class: 'muted', text: 'no change' }) : null);
    }
    if (r.states.length) vc = viewCompare(r.states, 'state', view, compare);
    box.append(el('h3', { text: 'Prisma Access - Egress IP' }),
        el('p', { class: 'muted', text: 'The public addresses of Prisma Access (getPrismaAccessIP/v2): from an import or read live with your egress-IP key; View one state or Compare two. The same as php utils/develop/sase/scm/scm_egress_ip.php on the CLI. Read only.' }),
        ...[imp, live, list, vc].filter(x => x));
    if (vc) await vc.ready;
    return box;
}

// Prisma Access pages that show endpoints of scm_pa_export.php (SCM_PA_PAGES of ViewerApp: page -> area, endpoints):
// title and text; every endpoint of a state is shown in the order of the export - one object as setting / value, a
// list as a table (filters, sort; wide entries: the main fields as columns, all fields under "details")
const SCM_PA_VIEWS = {
    infra: { title: 'Infrastructure', area: 'infra', text: 'Prisma Access infrastructure settings of the tenant (Prisma Access > Infrastructure Settings): infrastructure subnet, BGP, internal DNS servers, locations.' },
    sc: { title: 'Service Connection', area: 'service-connections', text: 'Service connections (SC-CAN) with their IPSec tunnels, IKE gateways, crypto and QoS profiles, groups and traffic steering rules.' },
    rn: { title: 'Remote Networks (RN-SPN)', area: 'remote-networks', text: 'Remote networks with their IPSec tunnels, IKE gateways, crypto and QoS profiles and the bandwidth allocations (SPN).' },
    mugw: { title: 'Mobile User Gateway', area: 'mobile-users', text: 'Mobile users (GlobalProtect): infrastructure settings (portal / gateway, DNS, IP pools) and the gateway locations.' },
    mugp: { title: 'Mobile User GlobalProtect', area: 'mobile-users', text: 'GlobalProtect of the mobile users: authentication, tunnel / agent profiles, global settings, app versions, portal, clientless VPN, trusted zones and the identity objects of the Mobile Users folder (certificates, server profiles, local users, authentication profiles / sequences).' },
    mupaa: { title: 'Mobile User PAA', area: 'mobile-users', text: 'Prisma Access Agent: app settings, client authentication, global settings, token lifetime, staged rollout, tenant settings (internal UI API).' },
    muep: { title: 'Mobile User Explicit Proxy', area: 'explicit-proxy', text: 'Explicit proxy of the mobile users: settings, authentication, IP access, block settings, users, proxy server profiles, upstream proxy rules and the forwarding profiles (internal UI API).' },
    pb: { title: 'Prisma Browser', area: 'prisma-browser', text: 'Prisma Browser (Strata Enterprise Browser): user / device groups, applications, plugins, the policies (sign-in, access and data, security, customization) and pending changes.' },
    sa: { title: 'Service accounts', area: 'iam', text: 'Identity & Access of the tenant: roles, custom roles, permission sets, service accounts, access policies, permissions.' },
};
const SCM_ACRONYMS = { ike: 'IKE', ipsec: 'IPSec', qos: 'QoS', bgp: 'BGP', dns: 'DNS', gp: 'GP', mfa: 'MFA', tls: 'TLS', saml: 'SAML', ldap: 'LDAP', tacacs: 'TACACS+', ep: 'EP', mu: 'MU', ip: 'IP' };
const scmTitle = (name) => name.replace(/^mobile-agent-/, '').replace(/^pa-agent-/, '').split('-').map(w => SCM_ACRONYMS[w] || w).join(' ').replace(/^./, c => c.toUpperCase());

/** an object as name / value pairs: nested objects with dotted names, a list of plain values as "a, b" */
function flatPairs(o, prefix = '', out = []) {
    if (o === null || o === undefined) return out;
    if (typeof o !== 'object') { out.push([prefix, String(o)]); return out; }
    if (Array.isArray(o)) {
        if (o.every(v => v === null || typeof v !== 'object')) out.push([prefix, o.join(', ')]);
        else o.forEach((v, i) => flatPairs(v, prefix + '[' + i + ']', out));
        return out;
    }
    const keys = Object.keys(o);
    if (keys.length === 0 && prefix) out.push([prefix, '(set)']);
    for (const k of keys) flatPairs(o[k], prefix ? prefix + '.' + k : k, out);
    return out;
}

async function scmPaPage(base, page, canWrite, redraw) {
    const def = SCM_PA_VIEWS[page];
    const r = await api('GET', base + '/scm/pa/' + page);
    const box = el('div', {});
    const live = canWrite ? liveForm(r, { keyLabel: 'SCM key', path: base + '/scm-pa/runs', runs: base + '/runs', redraw, done: def.title + ' read live',
        body: () => ({ page }), noKey: 'Live: you have no SCM key yet (Account, My API keys, kind "SCM": the service account - client id / secret - and the TSG id).' }) : null;
    const epStatus = (s) => { const all = Object.values(s.endpoints), ok = all.filter(e => e.status === 'ok').length, na = all.filter(e => e.status === 'unavailable').length;
        return ok + ' of ' + all.length + ' read' + (na ? ', ' + na + ' not available' : '') + (all.length - ok - na ? ', ' + (all.length - ok - na) + ' error' : ''); };
    let vc = null;
    const list = r.states.length === 0 ? el('p', { class: 'muted', text: 'No state yet - import the SCM configuration of the tenant (Configurations: import with your SCM key - it reads this area as well) or read it live.' }) :
        table(['When', 'Source', 'By', 'TSG', 'Read', ''], r.states.map(x => el('tr', {},
            el('td', { text: fmtTime(x.time) }), el('td', { text: x.source === 'import' ? 'SCM import' : x.source }), el('td', { text: x.user }), el('td', { text: x.tsg || '' }),
            el('td', { text: epStatus(x) }),
            el('td', {}, el('button', { type: 'button', text: 'Show', onclick: () => run(() => vc.showState(x.id)) }), ' ',
                canWrite ? el('button', { type: 'button', class: 'danger', text: 'Delete', onclick: () => run(async () => {
                    if (!confirm('Delete this state?')) return;
                    await api('DELETE', base + '/scm/pa/' + page + '/' + x.id); await redraw(); }) }) : null))));
    // an endpoint = a card, closed: its data is loaded when it is opened (a page can have 75000 entries), a list page by
    // page from the server (filters, search and sort run there)
    const epCard = (title, summary, load) => {
        const body = el('div', {});
        const d = el('details', { class: 'card scmep' }, el('summary', {}, el('strong', { text: title }), summary ? el('span', { class: 'muted', text: '  ' + summary }) : null), body);
        let loaded = false;
        d.addEventListener('toggle', () => { if (!d.open || loaded) return; loaded = true; body.replaceChildren(el('p', { class: 'muted', text: 'loading …' }));
            run(async () => { try { body.replaceChildren(await load()); } catch (e) { loaded = false; body.replaceChildren(el('p', { class: 'error', text: e.message })); } }); });
        return d;
    };
    async function view(id) {
        const s = await api('GET', base + '/scm/pa/' + page + '/' + id);
        const kb = (b) => b > 1048576 ? (b / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(b / 1024)) + ' KB';
        const parts = Object.entries(s.endpoints).map(([name, e]) => {
            if (e.status !== 'ok') return el('div', { class: 'card scmep' }, el('strong', { text: scmTitle(name) }), el('span', { class: e.status === 'unavailable' ? 'muted' : 'error',
                text: '  ' + (e.status === 'unavailable' ? 'not available (not licensed / no permission)' : (e.status || 'error')) + (e.http_code ? ' (HTTP ' + e.http_code + ')' : '') + (e.error ? ': ' + e.error : '') }));
            return epCard(scmTitle(name), (e.count !== null && e.count !== undefined ? e.count + (e.count === 1 ? ' entry' : ' entries') + ', ' : '') + kb(e.bytes || 0), () => endpointData(id, name));
        });
        const all = el('div', { class: 'row' }, el('button', { type: 'button', text: 'Open all', title: 'open every endpoint (loads their data)', onclick: () => box.querySelectorAll('details.scmep').forEach(d => { d.open = true; }) }),
            el('button', { type: 'button', text: 'Close all', onclick: () => box.querySelectorAll('details.scmep').forEach(d => { d.open = false; }) }));
        return el('div', {}, el('p', { class: 'muted', text: 'State of ' + fmtTime(s.time) + ' (' + (s.source === 'import' ? 'SCM import' : s.source) + (s.tsg ? ', TSG ' + s.tsg : '') + (s.fetched_at ? ', read ' + s.fetched_at : '') + ') - open an endpoint to load its data' }), all, ...parts);
    }
    // one endpoint: an object as setting / value; a list as a table that loads page by page from the server
    async function endpointData(id, name) {
        const url = base + '/scm/pa/' + page + '/' + id + '/data/' + encodeURIComponent(name);
        const first = await api('GET', url + '?limit=100');
        if (first.kind === 'object') {
            // api_key of the shared infrastructure settings = the egress-IP API key: in the key store of the user
            const shown = (k, v) => v === '***REDACTED***' ? (name === 'shared-infrastructure-settings' && k === 'api_key'
                ? 'egress-IP API key - stored as the egress-IP key of the user who imported / read it (Account, My API keys)' : 'secret (not in the export)') : v;
            return first.pairs.length ? table(['Setting', 'Value'], first.pairs.map(([k, v]) => el('tr', {}, el('td', { text: k }), el('td', { text: shown(k, v) })))) : el('p', { class: 'muted', text: 'empty' });
        }
        if (first.total === 0) return el('p', { class: 'muted', text: 'none' });
        const cols = first.main ? first.main.concat(['_details']) : first.columns;
        const st = { offset: 0, limit: 100, q: '', f: {}, sort: '', desc: false };
        const q = el('input', { type: 'search', placeholder: 'search all fields …', 'aria-label': 'search all fields' });
        const size = el('select', { 'aria-label': 'rows per page' }, [50, 100, 200, 500, 1000].map(n => el('option', { value: n, text: n + ' per page', selected: n === 100 })));
        const count = el('span', { class: 'muted' }), prev = el('button', { type: 'button', text: '‹ previous' }), next = el('button', { type: 'button', text: 'next ›' });
        const tbody = el('tbody', {});
        let timer = null;
        const later = () => { clearTimeout(timer); timer = setTimeout(() => { st.offset = 0; run(load); }, 300); };
        const heads = cols.map(k => {
            if (k === '_details') return { k, th: el('th', { text: 'details' }), fth: el('th', {}) };
            const listId = 'pa-' + Math.random().toString(36).slice(2, 9);
            const inp = el('input', { type: 'search', class: 'colfilter', placeholder: 'filter …', 'aria-label': 'filter ' + k, autocomplete: 'off', list: first.values[k] ? listId : null, title: 'contains (case-insensitive); !text = without' });
            inp.addEventListener('input', () => { st.f[k] = inp.value; later(); });
            const th = el('th', { class: 'sortable', title: 'sort', text: k, onclick: () => { st.desc = st.sort === k ? !st.desc : false; st.sort = k; st.offset = 0; run(load); } });
            return { k, th, fth: el('th', {}, inp, first.values[k] ? el('datalist', { id: listId }, first.values[k].map(v => el('option', { value: v }))) : null) };
        });
        const draw = (x) => {
            count.textContent = (x.matched ? (x.offset + 1) + '-' + Math.min(x.offset + x.rows.length, x.matched) : '0') + ' of ' + x.matched + (x.matched !== x.total ? ' (of ' + x.total + ')' : '') + ' entries';
            prev.disabled = x.offset === 0; next.disabled = x.offset + x.rows.length >= x.matched;
            for (const h of heads) { h.th.classList.toggle('sorted', st.sort === h.k); h.th.dataset.dir = st.sort === h.k ? (st.desc ? '▼' : '▲') : ''; }
            tbody.replaceChildren(...x.rows.map(r => el('tr', {}, cols.map(k => k === '_details'
                ? el('td', {}, el('details', {}, el('summary', { text: Object.keys(r).length + ' fields' }), el('pre', { class: 'scmdetails', text: Object.entries(r).map(([a, b]) => a + ' = ' + b).join('\n') })))
                : el('td', { text: r[k] ?? '' })))));
        };
        async function load() {
            const ps = new URLSearchParams({ offset: st.offset, limit: st.limit, q: st.q, f: JSON.stringify(st.f), sort: st.sort, desc: st.desc ? '1' : '' });
            draw(await api('GET', url + '?' + ps.toString()));
        }
        q.addEventListener('input', () => { st.q = q.value; later(); });
        size.addEventListener('change', () => { st.limit = +size.value; st.offset = 0; run(load); });
        prev.onclick = () => { st.offset = Math.max(0, st.offset - st.limit); run(load); };
        next.onclick = () => { st.offset += st.limit; run(load); };
        const clear = el('button', { type: 'button', text: 'Clear filters', onclick: () => { q.value = ''; st.q = ''; st.f = {}; heads.forEach(h => { const i = h.fth.querySelector('input'); if (i) i.value = ''; }); st.offset = 0; run(load); } });
        draw(first);
        // a short list: no paging
        if (first.total <= 100) { size.hidden = true; prev.hidden = true; next.hidden = true; }
        return el('div', {}, el('div', { class: 'row' }, q, clear, size, prev, next, count),
            el('div', { class: 'scmscroll' }, el('table', { class: 'plain coltable' }, el('thead', {}, el('tr', {}, heads.map(h => h.th)), el('tr', { class: 'filterrow' }, heads.map(h => h.fth))), tbody)));
    }
    async function compare(oldId, newId) {
        const c = await api('GET', base + '/scm/pa/' + page + '/' + newId + '/compare/' + oldId);
        const fmt = (v) => v === null || v === undefined ? '-' : (typeof v === 'object' ? JSON.stringify(v) : String(v));
        const cards = c.endpoints.map(x => epCard(scmTitle(x.endpoint), x.old === 'ok' && x.new === 'ok' ? (x.old_count ?? '?') + ' -> ' + (x.new_count ?? '?') + ' entries'
            : 'older: ' + (x.old || 'not read') + ', newer: ' + (x.new || 'not read'), async () => {
            const e = await api('GET', base + '/scm/pa/' + page + '/' + newId + '/compare/' + oldId + '?ep=' + encodeURIComponent(x.endpoint));
            if (e.not_comparable) return el('p', { class: 'muted', text: 'not compared - ' + e.not_comparable });
            const n = e.counts;
            const more = (list, total) => total > list.length ? [el('p', { class: 'muted', text: '… ' + (total - list.length) + ' more (the first ' + e.max + ' are shown; scm_pa_compare.php on the CLI lists all)' })] : [];
            const lines = [...e.only_right.map(k => el('div', { class: 'diffadd', text: '+ ' + k })), ...more(e.only_right, n.only_right),
                ...e.only_left.map(k => el('div', { class: 'diffdel', text: '- ' + k })), ...more(e.only_left, n.only_left),
                ...e.changed.flatMap(y => y.changes.map(ch => el('div', { class: 'diffchg', text: '~ ' + (e.singleton ? '' : y.key + ': ') + ch.path + ': '
                    + (ch.type === 'left_only' ? fmt(ch.left) + ' -> (removed)' : ch.type === 'right_only' ? '(new) -> ' + fmt(ch.right) : fmt(ch.left) + ' -> ' + fmt(ch.right)) }))), ...more(e.changed, n.changed)];
            return el('div', {}, e.singleton ? null : el('p', { class: 'muted', text: n.only_right + ' added, ' + n.only_left + ' removed, ' + n.changed + ' changed, ' + n.equal + ' equal' }),
                lines.length ? el('div', {}, ...lines) : el('p', { class: 'muted', text: 'no change' }));
        }));
        return el('div', {}, el('p', { class: 'muted', text: '+ only in the newer state, - only in the older state, ~ changed (the same as scm_pa_compare.php) - open an endpoint to compare it' }), ...cards);
    }
    if (r.states.length) vc = viewCompare(r.states, 'state', view, compare);
    box.append(el('h3', { text: (def.area === 'iam' ? 'Identity & Access - ' : 'Prisma Access - ') + def.title }), el('p', { class: 'muted', text: def.text + ' As the SCM API gives them: from the SCM import of the project (it reads these areas as well) or read live with your SCM key (scm_pa_export.php area=' + def.area + '); View one state or Compare two (scm_pa_compare.php). Read only.' }),
        ...[live, list, vc].filter(x => x));
    if (vc) await vc.ready;
    return box;
}
