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

// ---------------------------------------------------------------- login / account
// ---------------------------------------------------------------- help pages (Markdown, shipped in docs/)
// A small Markdown renderer: headings, paragraphs, lists, code blocks, tables, **bold**, `code`, links.
// Everything becomes DOM nodes with textContent - nothing of a page is taken as HTML.
function mdInline(text) {
    const out = [];
    const re = /(\*\*([^*]+)\*\*|`([^`]+)`|\[([^\]]+)\]\(([^)\s]+)\))/g;
    let last = 0, m;
    while ((m = re.exec(text)) !== null) {
        if (m.index > last) out.push(document.createTextNode(text.slice(last, m.index)));
        if (m[2] !== undefined) out.push(el('strong', { text: m[2] }));
        else if (m[3] !== undefined) out.push(el('code', { text: m[3] }));
        else {
            const href = m[5];
            // other help pages open here, web addresses in a new tab, anything else stays text
            if (/^[a-z0-9-]+\.md$/.test(href)) out.push(el('a', { href: '#', text: m[4], onclick: (ev) => { ev.preventDefault(); run(() => showDoc(href.slice(0, -3))); } }));
            else if (/^https:\/\//.test(href)) out.push(el('a', { href, text: m[4], target: '_blank', rel: 'noopener noreferrer' }));
            else out.push(document.createTextNode(m[4]));
        }
        last = re.lastIndex;
    }
    if (last < text.length) out.push(document.createTextNode(text.slice(last)));
    return out;
}
function markdown(md) {
    const root = el('div', { class: 'md' });
    const lines = md.replace(/\r/g, '').split('\n');
    let i = 0;
    while (i < lines.length) {
        const line = lines[i];
        if (/^```/.test(line)) {
            const code = [];
            for (i++; i < lines.length && !/^```/.test(lines[i]); i++) code.push(lines[i]);
            root.append(el('pre', {}, el('code', { text: code.join('\n') })));
            i++; continue;
        }
        const h = /^(#{1,4})\s+(.*)$/.exec(line);
        if (h) { root.append(el('h' + Math.min(6, h[1].length + 1), {}, mdInline(h[2]))); i++; continue; }
        if (/^\s*\|/.test(line)) {
            const rows = [];
            for (; i < lines.length && /^\s*\|/.test(lines[i]); i++)
                if (!/^\s*\|[\s:|-]+\|\s*$/.test(lines[i])) rows.push(lines[i].trim().replace(/^\||\|$/g, '').split(/(?<!\\)\|/).map(c => c.trim().replace(/\\\|/g, '|')));
            root.append(el('table', { class: 'plain' }, rows.map((r, n) => el('tr', {}, r.map(c => el(n === 0 ? 'th' : 'td', {}, mdInline(c)))))));
            continue;
        }
        if (/^\s*([-*]|\d+\.)\s+/.test(line)) {
            const ordered = /^\s*\d+\./.test(line);
            const list = el(ordered ? 'ol' : 'ul', {});
            for (; i < lines.length && /^\s*([-*]|\d+\.)\s+/.test(lines[i]); i++)
                list.append(el('li', {}, mdInline(lines[i].replace(/^\s*([-*]|\d+\.)\s+/, ''))));
            root.append(list);
            continue;
        }
        if (line.trim() === '') { i++; continue; }
        const para = [];
        for (; i < lines.length && lines[i].trim() !== '' && !/^(#{1,4}\s|```|\s*\||\s*([-*]|\d+\.)\s+)/.test(lines[i]); i++) para.push(lines[i].trim());
        root.append(el('p', {}, mdInline(para.join(' '))));
    }
    return root;
}
async function docsCard(current) {
    const list = (await api('GET', 'docs')).docs;
    const body = el('div', {});
    const card = el('div', { class: 'card docs' }, el('h2', { text: 'Help' }),
        el('div', { class: 'row' }, Object.entries(list).map(([name, title]) => el('button', { class: 'link', type: 'button', text: title, onclick: () => run(() => showDoc(name)) }))), body);
    const name = current || Object.keys(list)[0];
    if (name) body.replaceChildren(markdown((await api('GET', 'docs/' + name)).markdown));
    return card;
}
async function showDoc(name) {
    const card = await docsCard(name);
    const old = document.querySelector('.card.docs');
    if (old) old.replaceWith(card); else main(card);
}

async function showLogin() {
    const setup = await api('GET', 'setup').catch(() => ({ first_admin: false }));
    const user = el('input', { name: 'user', autocomplete: 'username', required: true });
    const pass = el('input', { name: 'password', type: 'password', autocomplete: setup.first_admin ? 'new-password' : 'current-password', required: true, minlength: setup.first_admin ? 10 : 1 });
    let form;
    if (setup.first_admin) {
        // a new installation: the first administrator, with the one-time code from ./panosphp-viewer start
        const code = el('input', { name: 'code', autocomplete: 'off', required: true, placeholder: 'XXXX-XXXX-XXXX-XXXX', spellcheck: false });
        const pass2 = el('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: 10 });
        user.value = 'admin';
        form = el('form', { class: 'card login', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
            if (pass.value !== pass2.value) throw new Error('the two passwords differ');
            const r = await api('POST', 'setup', { code: code.value, user: user.value, password: pass.value });
            pass.value = pass2.value = '';
            message('administrator ' + r.user + ' created');
            await entered(r);
        }); } }, el('h2', { text: 'New installation: create the administrator' }),
            el('p', { class: 'muted', text: 'The one-time code is shown on the computer the viewer runs on by ./panosphp-viewer start (or ./panosphp-viewer status).' }),
            field('One-time code', code), field('User name', user), field('Password (10+ characters)', pass), field('Password again', pass2),
            el('button', { class: 'primary', type: 'submit', text: 'Create administrator' }));
    } else {
        form = el('form', { class: 'card login', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
            const r = await api('POST', 'login', { user: user.value, password: pass.value });
            pass.value = '';
            await entered(r);
        }); } }, el('h2', { text: 'Log in' }), field('User', user), field('Password', pass), el('button', { class: 'primary', type: 'submit', text: 'Log in' }),
            el('p', { class: 'muted', text: 'Forgot the password? An administrator gives you a new one (Account, Users).' }));
    }
    const docs = await docsCard().catch(() => null);
    main(el('div', { class: 'loginpage' }, form, docs));
    (setup.first_admin ? form.querySelector('input[name=code]') : user).focus();
}
async function entered(r, deep) {
    state.user = r.user; state.admin = r.admin; state.csrf = r.csrf;
    document.getElementById('nav').hidden = false;
    document.getElementById('who').textContent = r.user + (r.admin ? ' (admin)' : '');
    if (!state.meta) state.meta = await api('GET', 'meta');
    // a link into a version (reference "Open"): no project list first
    if (deep) return;
    // a link into a version, opened before the login: there after the login
    if (!(window.location.hash.length > 1 && await openFromHash())) await showProjects();
    if (r.notices && r.notices.length) cliNoticeCard(r.notices);
}
// administrators: use of the command line since the last login - a refused try can mean someone tried to get in
function cliNoticeCard(list) {
    const refused = list.some(n => n.refused);
    const what = n => n.what + (n.detail && n.detail.user ? ' ' + n.detail.user : '') + (n.detail && n.detail.admin ? ' (admin)' : '');
    const card = el('div', { class: 'card notice' + (refused ? ' warn' : '') }, el('h2', { text: refused ? 'Refused on the command line since your last login' : 'Done on the command line since your last login' }),
        el('p', { class: 'muted', text: refused ? 'Someone on the computer the viewer runs on tried to change users, passwords or tokens. This is only allowed in the browser. Details: Account, audit log.' : 'Shown once. Details: Account, audit log.' }),
        table(['When', 'Command', 'Result'], list.map(n => el('tr', {}, el('td', { text: fmtTime(n.ts) }), el('td', { text: what(n) }), el('td', { text: n.refused ? 'refused' : 'done' })))),
        el('button', { type: 'button', text: 'OK', onclick: () => card.remove() }));
    const m = document.getElementById('main');
    m.insertBefore(card, m.firstChild);
}
// change an entry of my key store in its row: the label (and port), optionally a new secret (empty = the stored one stays)
function keyEdit(k, tr) {
    const label = el('input', { value: k.label, maxlength: 80, autocomplete: 'off' });
    const port = el('input', { type: 'number', min: 1, max: 65535, value: k.port || '', placeholder: '443', class: 'narrow' });
    const key = el('input', { type: 'password', autocomplete: 'new-password', placeholder: 'empty = keep' });
    const cid = el('input', { autocomplete: 'off', spellcheck: false, placeholder: 'client id (empty = keep)' });
    const sec = el('input', { type: 'password', autocomplete: 'new-password', placeholder: 'client secret' });
    const form = el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
        const body = { label: label.value.trim() };
        if (k.kind === 'panos') body.port = port.value;
        if (k.kind === 'scm') { if (cid.value.trim() || sec.value) { body.client_id = cid.value.trim(); body.client_secret = sec.value; } }
        else if (key.value) body.key = k.kind === 'named' || k.kind === 'other' || k.kind === 'ldap' ? key.value : key.value.trim();
        await api('PUT', 'keys/' + k.kid, body);
        await showAccount(); message('key changed');
    }); } }, field('Label', label), k.kind === 'panos' ? field('Port', port) : null,
        k.kind === 'scm' ? [field('New client id', cid), field('New client secret', sec)] : field('New ' + (k.kind === 'ldap' ? 'password' : k.kind === 'named' || k.kind === 'other' ? 'value' : 'API key') + ' (optional)', key),
        el('button', { class: 'primary', type: 'submit', text: 'Save' }), el('button', { type: 'button', text: 'Cancel', onclick: () => run(showAccount) }));
    tr.replaceChildren(el('td', { text: k.target }), el('td', { colspan: 7 }, form));
    label.focus();
}
/**
 * the connection test (Account): fixed fields instead of a command line - one call to a firewall / Panorama, the
 * result as curl -v would show it (DNS, TCP, TLS, certificate chain, HTTP) and the curl line to do the same elsewhere
 */
function connTestWindow(keys) {
    const box = el('div', { class: 'objwin explainwin', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'connection test' });
    const overlay = el('div', { class: 'objoverlay', onclick: (ev) => { if (ev.target === overlay) close(); } }, box);
    const onKey = (ev) => { if (ev.key === 'Escape') close(); };
    function close() { document.removeEventListener('keydown', onKey); overlay.remove(); }
    const host = el('input', { required: true, autocomplete: 'off', placeholder: '192.0.2.10 / fw1.example.com', size: 24 });
    const port = el('input', { inputmode: 'numeric', size: 5, placeholder: '443' });
    const mode = el('select', {}, el('option', { value: 'reach', text: 'reach the device (HTTPS)' }), keys.length ? el('option', { value: 'api', text: 'XML API with my key (show system info)' }) : null);
    const path = el('select', {}, ['/api/', '/', '/php/login.php'].map(p => el('option', { value: p, text: p })));
    const kid = el('select', {}, keys.map(k => el('option', { value: k.kid, text: k.target + (k.label ? ' (' + k.label + ')' : '') })));
    const verify = el('input', { type: 'checkbox' }), proxy = el('input', { type: 'checkbox', checked: true });
    const tls = el('select', {}, el('option', { value: '', text: 'auto' }), el('option', { value: '1.2', text: 'TLS 1.2 only' }), el('option', { value: '1.3', text: 'TLS 1.3' }));
    const sni = el('input', { autocomplete: 'off', size: 22, placeholder: 'optional: fw1.example.com' });
    const fKid = field('My API key', kid), fPath = field('Path', path);
    const modeChanged = () => { fKid.hidden = mode.value !== 'api'; fPath.hidden = mode.value === 'api'; if (mode.value === 'api' && kid.selectedOptions[0] && !host.value) host.value = kid.selectedOptions[0].text.split(' ')[0]; };
    mode.addEventListener('change', modeChanged);
    const out = el('div', {});
    const form = el('form', { onsubmit: (ev) => { ev.preventDefault(); run(async () => {
        out.replaceChildren(el('p', { class: 'muted', text: 'testing ...' }));
        const body = { target: host.value.trim(), mode: mode.value, path: path.value, verify: verify.checked, proxy: proxy.checked, tls: tls.value, servername: sni.value.trim() };
        if (port.value.trim()) body.port = port.value.trim();
        if (mode.value === 'api') body.kid = kid.value;
        try {
            const r = await api('POST', 'conntest', body);
            out.replaceChildren(el('div', { class: 'card notice' }, el('strong', { class: r.ok ? '' : 'warn', text: r.ok ? 'OK' : 'FAILED' }), ...r.summary.flatMap(l => [el('br'), l])),
                el('p', {}, 'same with curl: ', el('code', { text: r.curl })),
                el('details', { open: !r.ok }, el('summary', { text: 'Debug output' }), el('pre', { class: 'log', text: r.debug })));
        } catch (e) { out.replaceChildren(el('p', { class: 'warn', text: e.message })); throw e; }
    }); } },
        el('div', { class: 'row' }, field('Firewall / Panorama (IP or name)', host), field('Port', port), field('Test', mode), fKid, fPath),
        el('div', { class: 'row' }, field('Check the TLS certificate', verify), field('TLS version', tls), field('Use the proxy of the server', proxy), field('Certificate name (SNI)', sni),
            el('button', { class: 'primary', type: 'submit', text: 'Run test' })));
    box.append(el('div', { class: 'objhead' }, el('h3', { text: 'Connection test' }), el('button', { type: 'button', class: 'objclose', text: '✕', 'aria-label': 'close', onclick: close })),
        el('p', { class: 'muted', text: 'From the server of the viewer to the device, for the hosts you may reach. Only HTTPS / HTTP with these fields - no command line, no files. API keys, cookies and passwords are never shown.' }),
        form, out);
    modeChanged();
    document.addEventListener('keydown', onKey);
    document.body.append(overlay);
    host.focus();
}

// the CSV of an SCM service account: header client_id,client_secret (also ; / quoted / BOM / CRLF) - the rows
function parseServiceAccountCsv(text) {
    const lines = text.replace(/^\uFEFF/, '').split(/\r?\n/).filter(l => l.trim() !== '');
    if (!lines.length) throw new Error('the CSV is empty');
    const sep = lines[0].includes(';') && !lines[0].includes(',') ? ';' : ',';
    const cells = (l) => { const out = []; let cur = '', q = false;
        for (let i = 0; i < l.length; i++) { const c = l[i];
            if (q) { if (c === '"' && l[i + 1] === '"') { cur += '"'; i++; } else if (c === '"') q = false; else cur += c; }
            else if (c === '"') q = true; else if (c === sep) { out.push(cur.trim()); cur = ''; } else cur += c; }
        out.push(cur.trim()); return out; };
    const head = cells(lines[0]).map(h => h.toLowerCase().replace(/[\s-]+/g, '_'));
    const iId = head.indexOf('client_id'), iSec = head.indexOf('client_secret');
    if (iId < 0 || iSec < 0) throw new Error('not the CSV of a service account: the first line must name client_id and client_secret');
    const rows = lines.slice(1).map(cells).filter(c => c[iId] && c[iSec]).map(c => ({ client_id: c[iId], client_secret: c[iSec] }));
    if (!rows.length) throw new Error('the CSV has no service account (client_id / client_secret empty)');
    return rows;
}

async function showAccount() {
    const oldPw = el('input', { type: 'password', autocomplete: 'current-password', required: true });
    const newPw = el('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: 10 });
    const nodes = [el('form', { class: 'card', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
        await api('POST', 'password', { old: oldPw.value, new: newPw.value });
        oldPw.value = newPw.value = '';
        message('password changed');
    }); } }, el('h2', { text: 'Change password' }), el('div', { class: 'row' }, field('Current password', oldPw), field('New password (10+ characters)', newPw),
        el('button', { class: 'primary', type: 'submit', text: 'Change' })))];
    // ---- my API keys: the entries of my pan-os-php key store (personal: only I use them; the secret is never shown again)
    {
        const ks = await api('GET', 'keys');
        const kKind = el('select', {}, Object.entries(ks.kinds).map(([k, t]) => el('option', { value: k, text: t })));
        const kTarget = el('input', { autocomplete: 'off', spellcheck: false });
        const kNamed = el('select', {}, ks.named.map(n => el('option', { value: n, text: n })));
        const kPort = el('input', { type: 'number', min: 1, max: 65535, placeholder: '443', class: 'narrow' });
        const kLabel = el('input', { autocomplete: 'off', maxlength: 80, placeholder: 'optional' });
        const kKey = el('input', { type: 'password', autocomplete: 'new-password' });
        const kId = el('input', { autocomplete: 'off', spellcheck: false }), kSecret = el('input', { type: 'password', autocomplete: 'new-password' });
        const fTarget = field('Host name / IP address', kTarget), fNamed = field('Entry', kNamed), fPort = field('Port', kPort);
        const fKey = field('API key', kKey), fId = field('Client id', kId), fSecret = field('Client secret', kSecret);
        // SCM: the CSV of a service account (download in SCM: client_id,client_secret) - read here in the browser only (the
        // file is not uploaded): client id + secret into the form, the TSG id from the client id
        // (name@<TSG id>.iam.panserviceaccount.com); saved with "Save key" as any key
        const kCsv = el('input', { type: 'file', accept: '.csv,text/csv', 'aria-label': 'CSV of an SCM service account' });
        const fCsv = field('or the CSV of the service account (client_id,client_secret)', kCsv);
        kCsv.addEventListener('change', () => run(async () => {
            const f = kCsv.files[0];
            kCsv.value = '';
            if (!f) return;
            if (f.size > 20000) throw new Error('the CSV of a service account is a few lines - this file is too big');
            const rows = parseServiceAccountCsv(await f.text());
            let row = rows[0];
            if (rows.length > 1) {
                const pick = prompt('The file has ' + rows.length + ' service accounts:\n' + rows.map((r, i) => (i + 1) + ': ' + r.client_id).join('\n') + '\nWhich one (number)?', '1');
                row = rows[(parseInt(pick, 10) || 0) - 1];
                if (!row) return;
            }
            kId.value = row.client_id; kSecret.value = row.client_secret;
            const tsg = /@([0-9]{1,20})\.iam\./.exec(row.client_id);
            if (tsg) kTarget.value = tsg[1];
            message('service account ' + row.client_id + ' taken from the CSV' + (tsg ? ' (TSG ' + tsg[1] + ')' : ' - enter the TSG id') + ' - check and "Save key"');
        }));
        const kindChanged = () => {
            const k = kKind.value;
            fTarget.hidden = k === 'named'; fNamed.hidden = k !== 'named'; fPort.hidden = k !== 'panos';
            fKey.hidden = k === 'scm'; fId.hidden = fSecret.hidden = fCsv.hidden = k !== 'scm';
            fTarget.firstChild.textContent = { panos: 'Host name / IP address', scm: 'TSG id', egressip: 'TSG id', ldap: 'Bind user (UPN or DOMAIN\\user)', other: 'Entry name' }[k] || '';
            fKey.firstChild.textContent = k === 'ldap' ? 'Password' : k === 'named' || k === 'other' ? 'Value (password / key)' : 'API key';
        };
        kKind.addEventListener('change', kindChanged); kindChanged();
        // the key from the device: management address + administrator + password (XML API keygen, as key-manager add=<host>)
        const gHost = el('input', { required: true, autocomplete: 'off', placeholder: '192.0.2.10 / fw1.example.com', size: 24 });
        const gPort = el('input', { inputmode: 'numeric', size: 5, placeholder: '443' });
        const gLabel = el('input', { size: 14 });
        const gUser = el('input', { required: true, autocomplete: 'off', size: 14 });
        const gPw = el('input', { type: 'password', required: true, autocomplete: 'new-password', size: 14 });
        const gVerify = el('input', { type: 'checkbox' });
        // debug output of the last attempt (the call, TLS / certificate, curl, the answer - never the password)
        const gDebug = el('details', { class: 'keygendebug', hidden: true }, el('summary', { text: 'Debug output' }), el('pre', { class: 'log' }));
        const showDebug = (text, failed) => { gDebug.hidden = !text; gDebug.open = !!failed; gDebug.lastChild.textContent = text || ''; };
        const genForm = el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
            const body = { target: gHost.value.trim(), username: gUser.value, password: gPw.value, label: gLabel.value.trim(), verify: gVerify.checked };
            if (gPort.value.trim()) body.port = gPort.value.trim();
            showDebug('', false);
            try {
                const k = await api('POST', 'keys/generate', body);
                gPw.value = '';
                await showAccount();
                message('API key of ' + k.target + ' received and saved (…' + String(k.hint).replace(/^…/, '') + ')');
                // the page is drawn again: the debug output of the success below the new form
                const d = document.querySelector('details.keygendebug');
                if (d && k.debug) { d.hidden = false; d.lastChild.textContent = k.debug; }
            }
            catch (e) { showDebug(e.details || '', true); throw e; }
            finally { gPw.value = ''; }
        }); } }, field('Firewall / Panorama (management IP or name)', gHost), field('Port', gPort), field('Label', gLabel), field('Administrator', gUser), field('Password', gPw),
            field('Check the TLS certificate', gVerify), el('button', { class: 'primary', type: 'submit', text: 'Get API key' }));
        const ksFile = el('input', { type: 'file', required: true });
        const ksResult = el('div', {});
        const kindName = { panos: 'PAN-OS', scm: 'SCM', egressip: 'egress IP', ldap: 'LDAP account', named: 'named', other: 'other' };
        nodes.push(el('div', { class: 'card' }, el('h2', { text: 'My API keys' }),
            el('p', { class: 'muted', text: 'The entries of your pan-os-php key store (.panconfkeystore): keys of firewalls / Panoramas and SCM tenants for imports into your projects, and the other entries pan-os-php uses (LDAP accounts = bind user + password, BPA / licence / MaxMind key, egress-IP key, …). Only you can use them - nobody else, also no administrator. After saving, a key is never shown again (only its last 4 characters); it stays until you delete it.' + (ks.network ? '' : ' Network for runs is off at the moment (administrator).') }),
            el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
                const k = kKind.value, body = { kind: k, label: kLabel.value.trim(), target: k === 'named' ? kNamed.value : kTarget.value.trim() };
                if (k === 'scm') { body.client_id = kId.value.trim(); body.client_secret = kSecret.value; } else body.key = k === 'named' || k === 'other' || k === 'ldap' ? kKey.value : kKey.value.trim();
                if (k === 'panos' && kPort.value) body.port = kPort.value;
                await api('POST', 'keys', body);
                kKey.value = kSecret.value = kId.value = '';
                await showAccount(); message('key saved');
            }); } }, field('Kind', kKind), fTarget, fNamed, fPort, field('Label', kLabel), fKey, fId, fSecret, fCsv, el('button', { class: 'primary', type: 'submit', text: 'Save key' })),
            el('h3', { text: 'Get the API key from a firewall / Panorama' }),
            el('p', { class: 'muted', text: 'As pan-os-php key-manager add=<host>: the viewer asks the firewall / Panorama for the API key of the administrator (XML API keygen) and saves it as your key of kind PAN-OS. The password is only sent to the device - it is not saved and not logged. The host must be allowed by the administrator (Network for runs).' + (ks.network ? '' : ' Network for runs is off at the moment - this does not work now.') }),
            genForm, gDebug,
            el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
                const fd = new FormData(); fd.append('keystore', ksFile.files[0]);
                const r = await api('POST', 'keys/import', fd);
                await showAccount();
                message(r.imported.length + ' entr' + (r.imported.length === 1 ? 'y' : 'ies') + ' taken' + (r.skipped.length ? ', ' + r.skipped.length + ' line(s) skipped: ' + r.skipped.map(x => 'line ' + x.line + ' (' + x.reason + ')').join('; ') : ''), r.skipped.length ? 'error' : undefined);
            }); } }, field('Take over an existing .panconfkeystore (an entry of the same kind and target is replaced)', ksFile), el('button', { type: 'submit', text: 'Import key store' })),
            ksResult,
            ks.keys.length === 0 ? el('p', { class: 'muted', text: 'No keys.' }) :
            table(['Kind', 'Target', 'Label', 'Key', 'Saved', 'Last used', 'Import', ''], ks.keys.map(k => el('tr', {},
                el('td', { text: kindName[k.kind] || k.kind }),
                el('td', { text: (k.kind === 'scm' || k.kind === 'egressip' ? 'TSG ' : '') + k.target + (k.port ? ':' + k.port : '') }), el('td', { text: k.label }),
                el('td', { text: k.hint }), el('td', { text: fmtTime(k.created) }), el('td', { text: fmtTime(k.last_used) }),
                el('td', { class: 'wrap' }, !k.import ? el('span', { class: 'muted', text: 'stored (not for imports)' }) : k.refused ? el('span', { class: 'muted', text: k.refused }) : el('span', { class: 'badge', text: 'yes' })),
                el('td', {}, el('div', { class: 'row' },
                    el('button', { type: 'button', text: 'Edit', onclick: (ev) => keyEdit(k, ev.target.closest('tr')) }),
                    el('button', { class: 'danger', type: 'button', text: 'Delete', onclick: () => run(async () => {
                        if (!confirm('Delete the key ' + k.target + '?')) return;
                        await api('DELETE', 'keys/' + k.kid); await showAccount();
                    }) }))))))));
    }
    // ---- network access and requests (every user): what I may, ask the administrators for more, the connection test
    {
        const ks = await api('GET', 'keys');
        const acc = ks.access || {};
        const mine = (await api('GET', 'requests')).requests || [];
        const rHosts = el('textarea', { rows: 3, spellcheck: false, placeholder: 'one per line: fw1.example.com, 192.168.10.155, 10.1.0.0/16, *.example.com, tsg:1234567890' });
        const rReason = el('input', { size: 50, maxlength: 1000, placeholder: 'why - e.g. import of the customer firewall for the as-is report' });
        const rKind = el('select', {}, el('option', { value: 'network', text: 'Network to these hosts' }), el('option', { value: 'conntest', text: 'Connection test (hosts optional)' }));
        nodes.push(el('div', { class: 'card' }, el('h2', { text: 'Network access and requests' }),
            el('p', {}, 'Network: ', el('strong', { text: !ks.network ? 'off for the installation' : acc.network ? 'allow list of the administrator' : 'only own hosts' }),
                ' - own hosts: ', el('strong', { text: (acc.hosts || []).join(', ') || 'none' }),
                ' - connection test: ', el('strong', { text: acc.conntest ? 'allowed' : 'not allowed' })),
            acc.conntest ? el('div', { class: 'row' }, el('button', { type: 'button', class: 'primary', text: 'Connection test', onclick: () => connTestWindow(ks.keys.filter(k => k.kind === 'panos')) }),
                el('span', { class: 'muted', text: 'one call to a firewall / Panorama with everything curl -v shows (DNS, TLS, certificate, HTTP) - no command line' })) : null,
            el('h3', { text: 'Ask the administrators' }),
            el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
                await api('POST', 'requests', { kind: rKind.value, hosts: rHosts.value, reason: rReason.value });
                await showAccount(); message('request sent to the administrators');
            }); } }, field('Request', rKind), el('label', { class: 'grow' }, 'Hosts / networks', rHosts), field('Reason', rReason), el('button', { class: 'primary', type: 'submit', text: 'Send request' })),
            mine.length ? table(['Sent', 'Request', 'Hosts', 'Reason', 'State', 'Note of the administrator', ''], mine.map(r => el('tr', {},
                el('td', { text: fmtTime(r.created) }), el('td', { text: r.kind === 'conntest' ? 'connection test' : 'network' }), el('td', { class: 'wrap', text: r.hosts.join(', ') }),
                el('td', { class: 'wrap', text: r.reason }), el('td', {}, el('span', { class: 'badge' + (r.state === 'rejected' ? ' dirty' : ''), text: r.state })),
                el('td', { class: 'wrap', text: (r.note || '') + (r.decided_by ? ' (' + r.decided_by + ', ' + fmtTime(r.decided) + ')' : '') }),
                el('td', {}, r.state === 'open' ? el('button', { type: 'button', class: 'small', text: 'Withdraw', onclick: () => run(async () => { await api('DELETE', 'requests/' + r.rid); await showAccount(); }) }) : null))))
                : el('p', { class: 'muted', text: 'No requests.' })));
    }
    if (state.admin) {
        const users = (await api('GET', 'users')).users;
        const name = el('input', { required: true, autocomplete: 'off' });
        const pw = el('input', { type: 'password', required: true, minlength: 10, autocomplete: 'new-password' });
        const adm = el('input', { type: 'checkbox' });
        nodes.push(el('div', { class: 'card' }, el('h2', { text: 'Users (admin)' }),
            el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
                await api('POST', 'users', { user: name.value, password: pw.value, admin: adm.checked });
                await showAccount(); message('user created');
            }); } }, field('User name', name), field('Initial password', pw), field('Admin', adm), el('button', { class: 'primary', type: 'submit', text: 'Create user' })),
            el('table', { class: 'plain' }, el('thead', {}, el('tr', {}, el('th', { text: 'User' }), el('th', { text: 'Admin' }), el('th', { text: 'Created' }),
                    el('th', { text: 'Network', title: 'may use the allow list (when it is for selected users)' }), el('th', { text: 'Conn. test' }), el('th', { text: 'Own hosts' }), el('th', {}))),
                el('tbody', {}, users.map(u => el('tr', {}, el('td', { text: u.name }), el('td', { text: u.admin ? 'yes' : '' }), el('td', { text: fmtTime(u.created) }),
                    el('td', {}, u.admin ? el('span', { class: 'muted', text: 'admin' }) : el('input', { type: 'checkbox', checked: u.network, 'aria-label': 'network for ' + u.name,
                        onchange: (ev) => run(async () => { await api('PUT', 'users/' + encodeURIComponent(u.name), { network: ev.target.checked }); message('saved'); }) })),
                    el('td', {}, u.admin ? el('span', { class: 'muted', text: 'admin' }) : el('input', { type: 'checkbox', checked: u.conntest, 'aria-label': 'connection test for ' + u.name,
                        onchange: (ev) => run(async () => { await api('PUT', 'users/' + encodeURIComponent(u.name), { conntest: ev.target.checked }); message('saved'); }) })),
                    el('td', { class: 'wrap' }, el('span', { text: (u.hosts || []).join(', ') || '-' }), ' ', el('button', { type: 'button', class: 'small', text: 'Edit', onclick: (ev) => {
                        const ta = el('textarea', { rows: 3, spellcheck: false, placeholder: 'one per line' }); ta.value = (u.hosts || []).join('\n');
                        ev.target.parentNode.replaceChildren(ta, el('button', { type: 'button', class: 'small primary', text: 'Save', onclick: () => run(async () => {
                            await api('PUT', 'users/' + encodeURIComponent(u.name), { hosts: ta.value }); await showAccount(); message('own hosts of ' + u.name + ' saved'); }) }));
                    } })),
                    el('td', {}, u.name === state.user ? null : el('div', { class: 'row' },
                        el('button', { type: 'button', text: 'New password', onclick: (ev) => run(async () => {
                            if (!confirm('Give "' + u.name + '" a new password? The old one stops working.')) return;
                            const r = await api('POST', 'users/' + encodeURIComponent(u.name) + '/password');
                            ev.target.replaceWith(el('span', {}, el('span', { class: 'muted', text: 'new password (shown only now): ' }), el('code', { text: r.password })));
                        }) }),
                        el('button', { class: 'danger', type: 'button', text: 'Delete', onclick: () => run(async () => {
                            if (!confirm('Delete user "' + u.name + '" and all projects this user owns?')) return;
                            await api('DELETE', 'users/' + encodeURIComponent(u.name)); await showAccount();
                        }) })))))))));
    }
    // ---- requests of all users (administrator): approve (hosts as asked or changed) / reject with a note
    if (state.admin) {
        const all = (await api('GET', 'requests?all=1')).requests || [];
        const open = all.filter(r => r.state === 'open');
        nodes.push(el('div', { class: 'card' }, el('h2', { text: 'Requests (admin)' + (open.length ? ' - ' + open.length + ' open' : '') }),
            all.length ? table(['Sent', 'User', 'Request', 'Hosts', 'Reason', 'State / decision'], all.slice(0, 100).map(r => {
                const h = el('textarea', { rows: 2, spellcheck: false }); h.value = r.hosts.join('\n');
                const note = el('input', { size: 24, maxlength: 1000, placeholder: 'note for the user' });
                const decide = (decision) => run(async () => { await api('PUT', 'requests/' + r.rid, { decision, note: note.value, hosts: h.value }); await showAccount(); message('request ' + (decision === 'approve' ? 'approved' : 'rejected')); });
                return el('tr', { class: r.state === 'open' ? 'warnrow' : '' }, el('td', { text: fmtTime(r.created) }), el('td', { text: r.user }),
                    el('td', { text: r.kind === 'conntest' ? 'connection test' : 'network' }),
                    el('td', { class: 'wrap' }, r.state === 'open' ? h : el('span', { text: r.hosts.join(', ') })), el('td', { class: 'wrap', text: r.reason }),
                    el('td', {}, r.state === 'open' ? el('div', { class: 'row' }, note, el('button', { type: 'button', class: 'small primary', text: 'Approve', onclick: () => decide('approve') }),
                        el('button', { type: 'button', class: 'small danger', text: 'Reject', onclick: () => decide('reject') }))
                        : el('span', {}, el('span', { class: 'badge' + (r.state === 'rejected' ? ' dirty' : ''), text: r.state }), ' ' + (r.decided_by || '') + ' ' + (r.note || ''))));
            })) : el('p', { class: 'muted', text: 'No requests.' })));
    }
    if (state.admin) {
        const pl = (await api('GET', 'meta')).plugins || { plugins: [], errors: {} };
        const errs = Object.entries(pl.errors || {});
        // licence: what is installed, install a new one (paste the text or choose the file), remove it
        const lic = await api('GET', 'license');
        const licText = el('textarea', { rows: 6, placeholder: 'paste the licence here (the whole text with -----BEGIN PAN-OS-PHP LICENSE-----)' });
        const licFile = el('input', { type: 'file', accept: '.lic,.txt,text/plain' });
        licFile.addEventListener('change', () => { if (licFile.files[0]) licFile.files[0].text().then(t => { licText.value = t; }); });
        const L = lic.licence;
        nodes.push(el('div', { class: 'card' }, el('h2', { text: 'Licence (admin)' }),
            L ? table(['Customer', 'Licence', 'Valid until', 'Features', 'State'], [el('tr', {}, el('td', { text: L.customer }), el('td', { text: L.id }),
                el('td', { text: L.valid_until + (L.grace_days ? ' (+' + L.grace_days + ' days grace)' : '') }), el('td', { class: 'wrap', text: L.features.join(', ') }),
                el('td', {}, el('span', { class: 'badge' + (L.state === 'valid' ? '' : ' dirty'), text: L.state + (L.state === 'warning' || L.state === 'grace' ? ' - ' + L.days_left + ' days left' : '') })))])
              : el('p', { class: 'muted', text: 'No licence installed - basic features only. Licensed plug-ins (packages) stay locked.' }),
            lic.error ? el('p', { class: 'error', text: 'The installed licence is not valid: ' + lic.error }) : null,
            lic.clock === 'set back' ? el('p', { class: 'error', text: 'The clock of this computer was set back - licensed plug-ins are locked until it is right again.' }) : null,
            el('form', { onsubmit: (ev) => { ev.preventDefault(); run(async () => {
                await api('PUT', 'license', { license: licText.value }); message('licence installed'); await showAccount();
            }); } }, field('Licence file', licFile), licText, el('div', { class: 'row' }, el('button', { class: 'primary', type: 'submit', text: 'Install licence' }),
                L ? el('button', { class: 'danger', type: 'button', text: 'Remove licence', onclick: () => run(async () => {
                    if (!confirm('Remove the licence? Licensed plug-ins are locked afterwards.')) return;
                    await api('DELETE', 'license'); await showAccount();
                }) }) : null))));
        // network for runs: only imports use it (download a configuration); off by default; allow / deny lists
        const net = await api('GET', 'network');
        const nOn = el('input', { type: 'checkbox', checked: net.enabled });
        const nAllow = el('textarea', { rows: 4, spellcheck: false, placeholder: 'one per line: fw1.example.com, *.example.com, 10.1.1.1, 10.0.0.0/8, tsg:1234567890, tsg:*, *' });
        const nDeny = el('textarea', { rows: 4, spellcheck: false, placeholder: 'one per line - wins over the allow list' });
        nAllow.value = net.allow.join('\n'); nDeny.value = net.deny.join('\n');
        const nUsers = el('select', {}, el('option', { value: 'all', text: 'all users' }), el('option', { value: 'selected', text: 'selected users (Users: Network) and administrators' }));
        nUsers.value = net.users || 'all';
        const nCt = el('select', {}, el('option', { value: 'selected', text: 'administrators and selected users (Users: Conn. test)' }), el('option', { value: 'all', text: 'all users' }));
        nCt.value = net.conntest || 'selected';
        nodes.push(el('form', { class: 'card', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
            await api('PUT', 'network', { enabled: nOn.checked, allow: nAllow.value, deny: nDeny.value, users: nUsers.value, conntest: nCt.value });
            message('network for runs saved'); await showAccount();
        }); } }, el('h2', { text: 'Network for runs (admin)' }),
            el('p', { class: 'muted', text: 'Runs have no network. With this on, an import may download a configuration (read only) from a firewall / Panorama (XML API) or an SCM tenant - with the API key of the user who starts it, in a project whose owner turned network on. Nothing is written to a device. A target must be on the allow list and not on the deny list; an empty allow list allows nothing.' }),
            el('div', { class: 'row' }, field('Network for runs (imports)', nOn), field('Allow list for', nUsers), field('Connection test for', nCt)),
            el('p', { class: 'muted', text: 'Per user (Users below, or by approving a request): own hosts - a user reaches them also when the allow list is not for this user; the deny list wins always.' }),
            el('div', { class: 'row' }, el('label', { class: 'grow' }, 'Allow list', nAllow), el('label', { class: 'grow' }, 'Deny list', nDeny)),
            el('button', { class: 'primary', type: 'submit', text: 'Save' })));
        // App-ID database and MaxMind data of the installation: download (own key, network rules) or upload (air gap)
        const cen = await api('GET', 'central');
        const myKeys = (await api('GET', 'keys')).keys;
        const fwKeys = myKeys.filter(k => k.kind === 'panos'), mmKey = myKeys.find(k => k.kind === 'named' && k.target === 'maxmind-licensekey');
        const aKey = el('select', {}, fwKeys.map(k => el('option', { value: k.kid, text: k.target })));
        const aFile = el('input', { type: 'file', accept: '.xml', required: true }), gFile = el('input', { type: 'file', accept: '.zip', required: true });
        const runsOf = (type) => cen.runs.filter(r => r.type === type).slice(0, 3);
        const runLine = (r) => el('div', { class: 'muted' }, 'last run ' + fmtTime(r.created) + ': ', el('span', { class: 'badge' + (r.state === 'failed' ? ' oom' : ''), text: r.state }),
            r.error ? ' ' + r.error : '', ' ', r.state === 'done' || r.state === 'failed' ? el('a', { href: API + '/projects/' + cen.pid + '/runs/' + r.jid + '/files/run.log', text: 'run.log' }) : null);
        const meta = (m) => m ? (m.version ? 'version ' + m.version + ' - ' : '') + (m.countries ? m.countries + ' countries - ' : '') + m.source + ', ' + m.user + ', ' + fmtTime(m.time) : null;
        const reload = async (msg) => { await showAccount(); if (msg) message(msg); };
        nodes.push(el('div', { class: 'card' }, el('h2', { text: 'App-ID and MaxMind (admin)' }),
            el('p', { class: 'muted', text: 'Data every run and every opened version uses. Download needs network for runs and the host on the allow list (MaxMind: download.maxmind.com); without internet: upload the file. Opened versions use new data after they are opened again.' }),
            el('h3', { text: 'App-ID database (predefined.xml)' }),
            el('p', { text: cen.appid ? 'installation: ' + meta(cen.appid) : 'the one of the image: version ' + (cen.image.version || '?') }),
            el('div', { class: 'row' },
                fwKeys.length ? el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => { await api('POST', 'central/appid/runs', { kid: aKey.value }); await reload('App-ID download queued'); }); } },
                    field('From a firewall (my API key)', aKey), el('button', { type: 'submit', text: 'Download' })) : el('span', { class: 'muted', text: 'Download: add an API key of a firewall under My API keys.' }),
                el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
                    const fd = new FormData(); fd.append('file', aFile.files[0]); message('uploading ...'); await api('POST', 'central/appid', fd); await reload('App-ID database installed');
                }); } }, field('Upload predefined.xml', aFile), el('button', { type: 'submit', text: 'Upload' })),
                cen.appid ? el('button', { class: 'danger', type: 'button', text: 'Back to the image', onclick: () => run(async () => { await api('DELETE', 'central/appid'); await reload(); }) }) : null),
            runsOf('appid').length ? runLine(runsOf('appid')[0]) : null,
            el('h3', { text: 'MaxMind GeoLite2 (countries of IP addresses)' }),
            el('p', { text: cen.geoip ? 'installation: ' + meta(cen.geoip) : 'the data of the image' }),
            el('div', { class: 'row' },
                mmKey ? el('button', { type: 'button', text: 'Download (my maxmind-licensekey)', onclick: () => run(async () => { await api('POST', 'central/geoip/runs', { kid: mmKey.kid }); await reload('MaxMind download queued'); }) })
                    : el('span', { class: 'muted', text: 'Download: add the entry maxmind-licensekey under My API keys.' }),
                el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
                    const fd = new FormData(); fd.append('file', gFile.files[0]); message('uploading ...'); await api('POST', 'central/geoip', fd); await reload('MaxMind zip queued');
                }); } }, field('Upload GeoLite2-Country-CSV zip', gFile), el('button', { type: 'submit', text: 'Upload' })),
                cen.geoip ? el('button', { class: 'danger', type: 'button', text: 'Back to the image', onclick: () => run(async () => { await api('DELETE', 'central/geoip'); await reload(); }) }) : null),
            runsOf('geoip').length ? runLine(runsOf('geoip')[0]) : null));
        nodes.push(el('div', { class: 'card' }, el('h2', { text: 'Plug-ins (admin)' }),
            pl.plugins.length === 0 && errs.length === 0 ? el('p', { class: 'muted', text: 'No plug-ins installed.' }) :
            table(['Plug-in', 'Version', 'Feature', 'Form', 'State'], [
                ...pl.plugins.map(x => el('tr', {}, el('td', { text: x.title + ' (' + x.name + ')' }), el('td', { text: x.version }), el('td', { text: x.feature || 'basic' }),
                    el('td', { text: x.form === 'package' ? 'package (encrypted)' : 'folder (source)' }),
                    el('td', { class: 'wrap' }, el('span', { class: 'badge' + (x.on ? '' : ' dirty'), text: x.on ? 'on' : 'locked' }), x.why ? el('span', { class: 'muted', text: ' ' + x.why }) : null))),
                ...errs.map(([folder, why]) => el('tr', {}, el('td', { text: folder }), el('td', {}), el('td', {}), el('td', {}), el('td', { class: 'wrap', text: 'not loaded: ' + why })))])));
        // predefined playbooks: which ones the runs offer (default visibility.json); some can not run here at all
        const pbs = (await api('GET', 'playbooks?all=1')).playbooks;
        const boxes = pbs.map(p => el('input', { type: 'checkbox', value: p.name, checked: p.on, disabled: !p.usable }));
        nodes.push(el('form', { class: 'card', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
            await api('PUT', 'playbooks', { enabled: boxes.filter(b => b.checked).map(b => b.value) });
            message('predefined playbooks saved'); await showAccount();
        }); } }, el('h2', { text: 'Predefined playbooks (admin)' }),
            el('p', { class: 'muted', text: 'Playbooks shipped with pan-os-php. Only the ones turned on here are offered for runs, to every user. A playbook that is not usable here has steps the viewer does not allow (e.g. mergers, own input / output files).' }),
            pbs.length === 0 ? el('p', { class: 'muted', text: 'No predefined playbooks found.' }) :
            table(['Offered', 'Playbook', 'Steps', 'State'], pbs.map((p, i) => el('tr', {}, el('td', {}, boxes[i]), el('td', { text: p.name }), el('td', { text: String(p.steps) }),
                el('td', { class: 'wrap', text: p.usable ? (p.on ? 'offered' : '') : 'not usable here: ' + p.why.replace(/^playbook: /, '') })))),
            el('button', { class: 'primary', type: 'submit', text: 'Save' })));
        nodes.push(auditCard('audit', 'Audit log (admin, all projects)'));
    }
    main(nodes);
}

// ---------------------------------------------------------------- projects
async function showProjects() {
    state.project = null; state.config = null; state.cache.clear();
    const list = (await api('GET', 'projects')).projects;
    const name = el('input', { required: true, maxlength: 80 });
    main(el('div', { class: 'card' }, el('h2', { text: 'Projects' }),
        el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => { await api('POST', 'projects', { name: name.value }); await showProjects(); }); } },
            field('New project', name), el('button', { class: 'primary', type: 'submit', text: 'Create' })),
        list.length === 0 ? el('p', { class: 'muted', text: 'No projects yet. A project you create is visible only to you until you add members.' }) :
        el('table', { class: 'plain' }, el('thead', {}, el('tr', {}, el('th', { text: 'Project' }), el('th', { text: 'Owner' }), el('th', { text: 'Your permission' }), el('th', { text: 'Created' }))),
            el('tbody', {}, list.map(p => el('tr', {}, el('td', {}, el('button', { class: 'link', type: 'button', text: p.name, onclick: () => run(() => showProject(p.pid)) })),
                el('td', { text: p.owner }), el('td', {}, el('span', { class: 'badge', text: p.role })), el('td', { text: fmtTime(p.created) })))))));
}

function names(text) { return text.split(',').map(t => t.trim()).filter(t => t !== ''); }
function table(head, rows) {
    return el('table', { class: 'plain' }, el('thead', {}, el('tr', {}, head.map(h => el('th', { text: h })))), el('tbody', {}, rows));
}

// audit log: of one project (owner) or of everything (admin)
function auditCard(path, title) {
    const body = el('div', {});
    const user = el('input', { autocomplete: 'off', placeholder: 'all users' });
    async function load() {
        const q = new URLSearchParams({ limit: '200' });
        if (user.value.trim() !== '') q.set('user', user.value.trim());
        const lines = (await api('GET', path + '?' + q)).audit;
        body.replaceChildren(lines.length === 0 ? el('p', { class: 'muted', text: 'No entries.' }) :
            el('div', { class: 'tablewrap' }, table(['Time', 'User', 'Token', 'Address', 'Request', 'Status', 'Details'], lines.map(l => el('tr', {},
                el('td', { text: fmtTime(l.ts) }), el('td', { text: l.user || '' }), el('td', { text: l.token || '' }), el('td', { text: l.ip || '' }),
                el('td', { class: 'wrap', text: l.method + ' ' + l.route }), el('td', { text: String(l.status) }),
                el('td', { class: 'wrap', text: l.detail ? JSON.stringify(l.detail) : '' }))))));
    }
    return el('div', { class: 'card' }, el('h2', { text: title }),
        el('p', { class: 'muted', text: 'Logins, every request that is not a plain read (also refused ones) and every download. Newest first, 200 entries.' }),
        el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(load); } }, field('User', user), el('button', { type: 'submit', text: 'Show audit log' })), body);
}

async function showProject(pid) {
    const p = await api('GET', 'projects/' + pid);
    state.project = p; state.config = null; state.cache.clear();
    const canWrite = p.role !== 'read', owner = p.role === 'owner';
    // access limited to some types / locations: no whole-configuration operations (download, upload, runs)
    const limited = !!(p.types || p.scope);
    const base = 'projects/' + pid;
    const [members, configs, tokens, files, offered] = await Promise.all([api('GET', base + '/members'), api('GET', base + '/configs'), api('GET', base + '/tokens'), api('GET', base + '/files'),
        api('GET', 'playbooks').catch(() => ({ playbooks: [] }))]);

    // ---- versions
    const file = el('input', { type: 'file', accept: '.xml,text/xml,application/xml', required: true });
    const versions = el('div', { class: 'card' }, el('h2', { text: 'Configuration versions' }),
        canWrite && !limited ? el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
            const fd = new FormData(); fd.append('config', file.files[0]);
            message('uploading ...'); await api('POST', base + '/configs', fd); await showProject(pid);
        }); } }, field('Upload a PAN-OS / Panorama XML configuration', file), el('button', { class: 'primary', type: 'submit', text: 'Upload' })) : null,
        configs.configs.length === 0 ? el('p', { class: 'muted', text: 'No configuration yet.' }) :
        table(['File', 'Created', 'By', 'Size', 'How it was created', ''], configs.configs.map(c => el('tr', {},
            el('td', {}, el('button', { class: 'link', type: 'button', text: c.name, onclick: () => run(() => showViewer(c)) })),
            el('td', { text: fmtTime(c.created) }), el('td', { text: c.created_by || '' }), el('td', { text: fmtSize(c.size) }), el('td', { class: 'wrap', text: c.note }),
            el('td', {}, limited ? null : el('a', { href: API + '/' + base + '/configs/' + c.cid + '/download', text: 'Download' }), ' ',
                // a version saved from changes of the viewer: its changes as a pan-os-php playbook
                c.playbook && !limited ? el('button', { type: 'button', text: 'Playbook', title: 'the changes this version was saved from, as a pan-os-php playbook',
                    onclick: () => run(() => exportPlaybook(pid, c.cid, 'version', canWrite)) }) : null, ' ',
                canWrite && !limited ? el('button', { class: 'danger', type: 'button', text: 'Delete', onclick: () => run(async () => {
                    if (!confirm('Delete this version? Unsaved changes on it are lost.')) return;
                    await api('DELETE', base + '/configs/' + c.cid); await showProject(pid);
                }) }) : null)))));

    // ---- import from a firewall / Panorama / SCM tenant (download only, with my own API key) -> a new version
    let importCard = null;
    if (canWrite && !limited) {
        const my = await api('GET', 'keys').catch(() => ({ keys: [] }));
        // a project bound by its first import: only keys of the same kind (PAN-OS) / of its SCM tenant
        const b = p.binding;
        const usable = my.keys.filter(k => k.import && !k.refused && (!b || (b.kind === 'panos' ? k.kind === 'panos' : k.kind === 'scm' && k.target === b.target)));
        const iKey = el('select', {}, usable.map(k => el('option', { value: k.kid, text: (k.kind === 'scm' ? 'SCM TSG ' : '') + k.target + (k.label && k.label !== k.target ? ' (' + k.label + ')' : '') })));
        const iSource = el('select', {}, el('option', { value: 'candidate', text: 'candidate configuration' }), el('option', { value: 'running', text: 'running configuration' }));
        const sourceField = field('Configuration', iSource);
        // SCM: the scope of the import - chosen at the first import, changed later by the owner
        const sc = p.import_scope || { kind: 'all', areas: p.scm_areas, egress: true, config_scope: [] };
        const scopeLocked = !!p.import_scope && !owner;
        const AREA_LABEL = { infra: 'Infrastructure', 'service-connections': 'Service connections', 'remote-networks': 'Remote networks', 'mobile-users': 'Mobile users',
            'explicit-proxy': 'Explicit proxy', 'prisma-browser': 'Prisma Browser', iam: 'Identity & Access' };
        const sKind = el('select', { 'aria-label': 'scope of the SCM import', disabled: scopeLocked },
            [['config', 'configuration only'], ['areas', 'configuration + selected areas'], ['all', 'all (the areas of today)'], ['future', 'all, also future areas']]
                .map(([v, t]) => el('option', { value: v, text: t, selected: sc.kind === v })));
        const box = (v, label, on) => { const c = el('input', { type: 'checkbox', value: v, checked: on, disabled: scopeLocked }); return [c, el('label', { class: 'chk' }, c, ' ' + label)]; };
        const areaBoxes = (p.scm_areas || []).map(a => box(a, AREA_LABEL[a] || a, (sc.areas || p.scm_areas).includes(a)));
        const egressBox = box('egress', 'egress IPs (needs Infrastructure: its API key)', sc.egress !== false);
        const cfgBoxes = (p.scm_config_groups || []).map(g => box(g, g, !sc.config_scope || sc.config_scope.length === 0 || sc.config_scope.includes(g)));
        const areaRow = el('div', { class: 'row scopeareas' }, ...areaBoxes.map(x => x[1]), egressBox[1]);
        const scopeOf = () => ({ kind: sKind.value, areas: areaBoxes.filter(x => x[0].checked).map(x => x[0].value), egress: egressBox[0].checked,
            config_scope: cfgBoxes.filter(x => x[0].checked).map(x => x[0].value) });
        sKind.addEventListener('change', () => { areaRow.hidden = sKind.value !== 'areas'; });
        // the egress IPs need Infrastructure (the API key comes from its settings)
        const infraBox = areaBoxes.find(x => x[0].value === 'infra');
        if (infraBox) {
            egressBox[0].addEventListener('change', () => { if (egressBox[0].checked) infraBox[0].checked = true; });
            infraBox[0].addEventListener('change', () => { if (!infraBox[0].checked) egressBox[0].checked = false; });
        }
        areaRow.hidden = sc.kind !== 'areas';
        const scopeHint = el('span', { class: 'muted', text: p.import_scope ? '' : 'not chosen yet - saved with the first SCM import (or here)' });
        const scopeField = el('div', { class: 'scmscope' }, el('h3', { text: 'SCM import: scope' }), el('div', { class: 'row' }, field('Scope of the SCM import' + (scopeLocked ? ' (the owner changes it)' : ''), sKind),
            scopeHint,
            scopeLocked ? null : el('button', { type: 'button', text: 'Save scope', onclick: () => run(async () => {
                // saved without drawing the project again: the key chosen above stays
                const x = await api('PUT', base + '/import-scope', scopeOf());
                p.import_scope = x.import_scope; scopeHint.textContent = 'saved'; scopeHint.className = 'ok';
                message('scope of the SCM import saved'); }) })), areaRow,
            el('div', { class: 'row' }, el('span', { class: 'muted', text: 'configuration:' }), ...cfgBoxes.map(x => x[1]), el('span', { class: 'muted', text: '(none ticked = all)' })));
        const importStatus = el('span', { class: 'muted' });
        const importBtn = el('button', { class: 'primary', type: 'submit', text: 'Import' });
        // while an import runs: the button is off and the state next to it (one import of a project at a time)
        const watchImport = (job) => {
            importBtn.disabled = true;
            const t = setInterval(async () => {
                const x = await api('GET', base + '/runs/' + job.jid).catch(() => null);
                if (!x) return;
                if (x.state === 'queued' || x.state === 'running') { importStatus.className = 'muted'; importStatus.textContent = 'import ' + x.state + ' …'; return; }
                clearInterval(t); importBtn.disabled = false;
                if (x.state === 'done') { importStatus.className = 'ok'; importStatus.textContent = 'import done - a new version'; message('import done - a new version'); await showProject(pid); }
                else { importStatus.className = 'error'; importStatus.textContent = 'import ' + x.state + ': ' + (x.error || 'see Runs and project files'); }
            }, 2000);
            state.timers.push(t);
        };
        const keyChanged = () => { const k = usable.find(x => x.kid === iKey.value); sourceField.hidden = !k || k.kind === 'scm'; importStatus.textContent = ''; };
        iKey.addEventListener('change', keyChanged); keyChanged();
        const netOn = el('input', { type: 'checkbox', checked: p.network, disabled: !owner, onchange: (ev) => run(async () => {
            await api('PUT', base + '/network', { enabled: ev.target.checked }); await showProject(pid);
        }) });
        const why = !p.network_global ? 'Network for runs is off (an administrator turns it on under Account).'
            : !p.network ? 'Network is off for this project' + (owner ? ' - turn it on above.' : ' (the owner turns it on).')
            : usable.length === 0 ? (b ? 'You have no API key for ' + (b.kind === 'scm' ? 'the SCM tenant TSG ' + b.target : 'a firewall / Panorama') + ' (this project is bound to it) that may be used now - add one under Account, My API keys.'
                : 'You have no API key that may be used now - add one under Account, My API keys (and check the allow list of the administrator).') : null;
        importCard = el('div', { class: 'card' }, el('h2', { text: 'Import from a device' }),
            el('p', { class: 'muted', text: 'Downloads the configuration of a firewall / Panorama (XML API) or an SCM tenant - read only, nothing is written to the device - with your own API key. The result becomes a new version (see Runs and project files for the run).' }),
            el('div', { class: 'row' }, field('Network for this project' + (owner ? '' : ' (owner)'), netOn)),
            why ? el('p', { class: 'muted', text: why }) :
            el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
                const k = usable.find(x => x.kid === iKey.value);
                importStatus.className = 'muted'; importStatus.textContent = 'starting …';
                let job;
                try {
                    job = await api('POST', base + '/import/runs', k && k.kind === 'panos' ? { kid: iKey.value, source: iSource.value } : Object.assign({ kid: iKey.value }, scopeLocked ? {} : { scope: scopeOf() }));
                } catch (e) { importStatus.className = 'error'; importStatus.textContent = e.message; throw e; }
                if (k && k.kind === 'scm' && !scopeLocked) { p.import_scope = scopeOf(); scopeHint.textContent = ''; }
                importStatus.className = 'ok'; importStatus.textContent = 'import queued - it becomes a new version when it is done (Runs and project files)';
                message('import queued - it becomes a new version when it is done (Runs and project files)');
                watchImport(job);
            }); } }, field('From (my API key)', iKey), sourceField, importBtn, importStatus),
            // the scope also without an import now (network off, no key yet): shown, saved by its own button
            !(p.binding && p.binding.kind === 'panos') ? scopeField : null);
        // an import of this project still queued / running (another page, another member): the button stays off
        if (!why) {
            const active = ((await api('GET', base + '/runs').catch(() => ({ runs: [] }))).runs || []).find(r => r.type === 'import' && (r.state === 'queued' || r.state === 'running'));
            if (active) { importStatus.textContent = 'import ' + active.state + ' …'; watchImport(active); }
        }
    }

    // ---- App-ID database of the project (its own, else the one of the installation)
    let appidCard = null;
    if (!limited) {
        const ai = await api('GET', base + '/appid');
        const pFile = el('input', { type: 'file', accept: '.xml', required: true });
        const my = canWrite ? (await api('GET', 'keys').catch(() => ({ keys: [] }))).keys.filter(k => k.kind === 'panos' && !k.refused) : [];
        const pKey = el('select', {}, my.map(k => el('option', { value: k.kid, text: k.target })));
        appidCard = el('div', { class: 'card' }, el('h2', { text: 'App-ID database' }),
            el('p', { text: (ai.from === 'project' ? 'own of this project' : ai.from === 'installation' ? 'the one of the installation' : 'the one of the image') + ': version ' + ((ai.meta && ai.meta.version) || '?')
                + (ai.meta && ai.meta.source && ai.from === 'project' ? ' (' + ai.meta.source + ', ' + ai.meta.user + ', ' + fmtTime(ai.meta.time) + ')' : '') }),
            canWrite ? el('div', { class: 'row' },
                p.network && my.length ? el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
                    await api('POST', base + '/appid/runs', { kid: pKey.value }); message('App-ID download queued - Runs and project files');
                }); } }, field('From a firewall (my API key)', pKey), el('button', { type: 'submit', text: 'Download' }))
                    : el('span', { class: 'muted', text: !p.network ? 'Download from a firewall: network for this project is off (Import from a device).' : 'Download from a firewall: an own API key of a firewall is needed (Account, My API keys).' }),
                el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
                    const fd = new FormData(); fd.append('file', pFile.files[0]); message('uploading ...'); await api('POST', base + '/appid', fd); await showProject(pid); message('App-ID database of the project installed');
                }); } }, field('Upload predefined.xml', pFile), el('button', { type: 'submit', text: 'Upload' })),
                ai.from === 'project' ? el('button', { class: 'danger', type: 'button', text: 'Use the one of the installation', onclick: () => run(async () => { await api('DELETE', base + '/appid'); await showProject(pid); }) }) : null) : null);
    }

    // ---- members with their grants (types, locations)
    const mUser = el('input', { required: true, autocomplete: 'off' });
    const mRole = el('select', {}, el('option', { value: 'read', text: 'read' }), el('option', { value: 'write', text: 'write (change and save)' }));
    const mTypes = el('input', { autocomplete: 'off', placeholder: 'all types' });
    const mScope = el('input', { autocomplete: 'off', placeholder: 'whole configuration' });
    const memberCard = el('div', { class: 'card' }, el('h2', { text: 'Members' }),
        owner ? el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
            const body = { user: mUser.value, role: mRole.value };
            if (names(mTypes.value).length) body.types = names(mTypes.value);
            if (names(mScope.value).length) body.scope = names(mScope.value);
            await api('PUT', base + '/members', body); await showProject(pid);
        }); } }, field('User name', mUser), field('Permission', mRole),
            el('label', { class: 'grow' }, 'Only these types (comma separated, e.g. address,service,rule)', mTypes),
            el('label', { class: 'grow' }, 'Only these locations (comma separated, e.g. shared,DG-Berlin)', mScope),
            el('button', { class: 'primary', type: 'submit', text: 'Add / change' })) : null,
        owner ? el('p', { class: 'muted', text: 'A member limited to types or locations must name one of its locations for every read and change, and can not download, upload or delete whole versions or start runs.' }) : null,
        table(['User', 'Permission', 'Types', 'Locations', ''], members.members.map(m => el('tr', {}, el('td', { text: m.user }), el('td', {}, el('span', { class: 'badge', text: m.role })),
            el('td', { class: 'wrap', text: m.role === 'owner' ? 'all' : (m.types ? m.types.join(', ') : 'all') }),
            el('td', { class: 'wrap', text: m.role === 'owner' ? 'whole configuration' : (m.scope ? m.scope.join(', ') : 'whole configuration') }),
            el('td', {}, m.role !== 'owner' && (owner || m.user === state.user) ? el('button', { class: 'danger', type: 'button', text: owner ? 'Remove' : 'Leave project', onclick: () => run(async () => {
                await api('DELETE', base + '/members/' + encodeURIComponent(m.user));
                if (owner) await showProject(pid); else await showProjects();
            }) }) : null)))));

    // ---- API tokens (scripts)
    const tLabel = el('input', { required: true, maxlength: 80, autocomplete: 'off' });
    const tRole = el('select', {}, el('option', { value: 'read', text: 'read' }), canWrite ? el('option', { value: 'write', text: 'write' }) : null);
    const tDays = el('input', { type: 'number', min: 1, max: 365, value: 30, required: true });
    const tokenOnce = el('div', {});
    const tokenCard = el('div', { class: 'card' }, el('h2', { text: 'API tokens' }),
        el('p', { class: 'muted', text: 'For scripts: "Authorization: Bearer <token>" instead of a login. A token works for this project only, with at most the chosen permission, and follows your own types and locations.' }),
        el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
            const r = await api('POST', base + '/tokens', { label: tLabel.value, role: tRole.value, days: parseInt(tDays.value, 10) });
            await showProject(pid);
            // shown once: the server keeps only a hash
            document.getElementById('token-once').replaceChildren(el('p', { text: 'New token "' + r.label + '" - copy it now, it is not shown again:' }),
                el('input', { class: 'token', readonly: true, value: r.token, onfocus: (e) => e.target.select() }));
        }); } }, field('Label', tLabel), field('Permission', tRole), field('Valid for (days)', tDays), el('button', { class: 'primary', type: 'submit', text: 'Create token' })),
        Object.assign(tokenOnce, { id: 'token-once' }),
        tokens.tokens.length === 0 ? el('p', { class: 'muted', text: 'No tokens.' }) :
        table(['Label', 'User', 'Permission', 'Created', 'Expires', 'Last used', ''], tokens.tokens.map(t => el('tr', {},
            el('td', { text: t.label }), el('td', { text: t.user }), el('td', {}, el('span', { class: 'badge', text: t.role })), el('td', { text: fmtTime(t.created) }),
            el('td', { text: fmtTime(t.expires) + (t.expires * 1000 < Date.now() ? ' (expired)' : '') }), el('td', { text: fmtTime(t.last_used) }),
            el('td', {}, el('button', { class: 'danger', type: 'button', text: 'Delete', onclick: () => run(async () => {
                if (!confirm('Delete the token "' + t.label + '"? Scripts that use it stop working.')) return;
                await api('DELETE', base + '/tokens/' + t.tid); await showProject(pid);
            }) }))))));

    // ---- project files: playbook JSON, BP JSON
    const plug = state.meta.plugins || { runs: {}, kinds: {}, plugins: [] };
    const fKind = el('select', {}, el('option', { value: 'playbook', text: 'playbook JSON' }), el('option', { value: 'bp', text: 'BP JSON' }),
        Object.entries(plug.kinds).map(([k, title]) => el('option', { value: k, text: title })));
    const fFile = el('input', { type: 'file', required: true });
    const filesCard = el('div', { class: 'card' }, el('h2', { text: 'Project files' }),
        el('p', { class: 'muted', text: 'Playbooks and BP JSON files for runs, for the checks of a read (?bp=) and for alert-only-set / best-practice-set. A playbook is checked when it is uploaded: only steps that work on the configuration and write plain file names.' }),
        canWrite && !limited ? el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
            const fd = new FormData(); fd.append('file', fFile.files[0]);
            await api('POST', base + '/files?kind=' + fKind.value, fd); await showProject(pid);
        }); } }, field('Kind', fKind), field('File', fFile), el('button', { class: 'primary', type: 'submit', text: 'Upload' })) : null,
        canWrite && !limited ? el('div', { class: 'row' },
            el('button', { type: 'button', text: 'New playbook (editor)', onclick: () => openEditor('playbook', pid, null, () => showProject(pid)) }),
            el('button', { type: 'button', text: 'New BP JSON (editor)', onclick: () => openEditor('bp', pid, null, () => showProject(pid)) })) : null,
        files.files.length === 0 ? el('p', { class: 'muted', text: 'No files.' }) :
        table(['File', 'Kind', 'Created', 'By', 'Size', ''], files.files.map(f => el('tr', {},
            el('td', { text: f.name }), el('td', {}, el('span', { class: 'badge', text: f.kind })), el('td', { text: fmtTime(f.created) }), el('td', { text: f.created_by || '' }),
            el('td', { text: fmtSize(f.size) }),
            el('td', {}, el('a', { href: API + '/' + base + '/files/' + f.fid + '/download', text: 'Download' }), ' ',
                canWrite && !limited && (f.kind === 'playbook' || f.kind === 'bp') ? el('button', { type: 'button', text: 'Edit', title: 'open a copy in the editor - saving makes a new file',
                    onclick: () => openEditor(f.kind, pid, f, () => showProject(pid)) }) : null, ' ',
                canWrite && !limited ? el('button', { class: 'danger', type: 'button', text: 'Delete', onclick: () => run(async () => {
                    if (!confirm('Delete the file "' + f.name + '"?')) return;
                    await api('DELETE', base + '/files/' + f.fid); await showProject(pid);
                }) }) : null)))));

    // ---- runs (jobs): stats, playbook
    let runsCard = null;
    if (!limited) {
        const rVersion = el('select', { required: true }, configs.configs.map(c => el('option', { value: c.cid, text: c.name + ' - ' + fmtTime(c.created) })));
        const rType = el('select', {}, el('option', { value: 'stats', text: 'stats (BPA figures)' }), el('option', { value: 'playbook', text: 'playbook' }),
            el('option', { value: 'diff', text: 'diff (compare two versions)' }),
            Object.entries(plug.runs).map(([k, r]) => el('option', { value: k, text: r.title })));
        // predefined playbooks (shipped with pan-os-php, turned on by an administrator) and the playbook files of the project
        const ownPb = files.files.filter(f => f.kind === 'playbook');
        const rPlaybook = el('select', {}, el('option', { value: '', text: '- choose a playbook -' }),
            offered.playbooks.length ? el('optgroup', { label: 'predefined (pan-os-php)' }, offered.playbooks.map(p => el('option', { value: 'predefined:' + p.name, text: p.name + ' (' + p.steps + ' steps)' }))) : null,
            ownPb.length ? el('optgroup', { label: 'project files' }, ownPb.map(f => el('option', { value: f.fid, text: f.name }))) : null);
        if (offered.playbooks.length) rPlaybook.value = 'predefined:' + (offered.playbooks.find(p => p.name === 'visibility.json') || offered.playbooks[0]).name;
        const rBp = el('select', {}, el('option', { value: '', text: 'BP JSON shipped with pan-os-php' }), files.files.filter(f => f.kind === 'bp').map(f => el('option', { value: f.fid, text: f.name })));
        const rLocation = el('input', { value: 'any', maxlength: 63 });
        // playbook options for large configurations (type=playbook: subprocess, memorythreshold, debugmemory, removestagefiles)
        const oSub = el('input', { type: 'checkbox' }), oThr = el('input', { type: 'number', min: 64, max: 1048576, step: 64, placeholder: 'MB', class: 'narrow' });
        const oDbg = el('input', { type: 'checkbox' }), oRm = el('input', { type: 'checkbox' });
        const pbOpts = el('details', { class: 'pbopts' }, el('summary', { text: 'Options for large configurations' }),
            el('div', { class: 'row' }, field('Every step its own process (subprocess)', oSub), field('Own process above (memorythreshold, MB)', oThr),
                field('Memory use in run.log (debugmemory)', oDbg), field('Remove stage files (removestagefiles)', oRm)),
            el('p', { class: 'muted', text: 'subprocess: every step runs as its own PHP process, its memory is free again afterwards - slower, needs least memory. memorythreshold: only steps that start while the run uses more than this many MB run as their own process. The memory a run may use at all is set by the administrator of the computer (VIEWER_RUN_MEMORY).' }));
        // diff: this version (file1, the original) against another one (file2); set commands from file1 to file2
        const dOther = el('select', {}, configs.configs.map(c => el('option', { value: c.cid, text: c.name + ' - ' + fmtTime(c.created) })));
        if (configs.configs.length > 1) dOther.value = configs.configs[0].cid;
        if (configs.configs.length > 1) rVersion.value = configs.configs[1].cid;
        const dSet = el('input', { type: 'checkbox', checked: true }), dOrder = el('input', { type: 'checkbox' });
        const dXpath = el('input', { maxlength: 2000, placeholder: "optional, e.g. /config/devices/entry[@name='localhost.localdomain']/device-group" });
        const diffFields = el('span', { class: 'row' }, field('Compare with (file2, the newer one)', dOther), field('Set commands file1 → file2', dSet),
            field('No rule order check', dOrder), el('label', { class: 'grow' }, 'Only this part (XPath)', dXpath));
        const pbField = field('Playbook', rPlaybook), locField = field('Location', rLocation), bpField = field('BP JSON', rBp), versionField = field('Version', rVersion);
        // run types of plug-ins: the fields the plug-in declares (text, location, a project file of a kind)
        const plugFields = el('span', { class: 'row' });
        let plugInputs = [];
        const typeChanged = () => {
            const pr = plug.runs[rType.value];
            pbField.hidden = pbOpts.hidden = rType.value !== 'playbook'; locField.hidden = rType.value !== 'stats';
            diffFields.hidden = rType.value !== 'diff';
            versionField.firstChild.textContent = rType.value === 'diff' ? 'Version (file1, the original)' : 'Version';
            bpField.hidden = (!!pr && !pr.bp) || rType.value === 'diff';
            // a run type without a version (its input is a project file)
            versionField.hidden = !!pr && pr.input === 'none';
            rVersion.required = !versionField.hidden;
            plugInputs = (pr ? pr.fields : []).map(f => {
                const kind = f.kind.startsWith('file:') ? f.kind.slice(5) : null;
                const opts = Object.entries(f.options || {});
                const input = kind ? el('select', {}, el('option', { value: '', text: '- choose a file -' }), files.files.filter(x => x.kind === kind).map(x => el('option', { value: x.fid, text: x.name })))
                    : f.kind === 'select' ? el('select', {}, el('option', { value: '', text: '- choose -' }), opts.map(([v, label]) => { const o = el('option', { value: v, text: label }); o.selected = v === f.default; return o; }))
                    : f.kind === 'multi' ? Object.assign(el('select', { multiple: true, size: Math.min(6, opts.length) }, opts.map(([v, label]) => el('option', { value: v, text: label }))), { isMulti: true })
                    : el('input', { value: f.default || '', maxlength: 200 });
                return { f, input };
            });
            plugFields.replaceChildren(...plugInputs.map(x => field(x.f.label, x.input)));
        };
        rType.addEventListener('change', typeChanged); typeChanged();
        const runsBody = el('div', {});
        // projects the result of a run can go to
        const writable = (await api('GET', 'projects')).projects.filter(x => x.role !== 'read');
        const openFiles = new Set();
        let refreshRuns = async () => {};
        async function drawRuns() {
            const runs = (await api('GET', base + '/runs')).runs;
            const details = new Map();
            for (const r of runs) if (openFiles.has(r.jid)) details.set(r.jid, (await api('GET', base + '/runs/' + r.jid)).files);
            runsBody.replaceChildren(runs.length === 0 ? el('p', { class: 'muted', text: 'No runs yet.' }) :
                table(['Run', 'Version', 'State', 'By', 'Started', 'Finished', ''], runs.flatMap(r => {
                    const open = r.state === 'queued' || r.state === 'running';
                    const row = el('tr', {}, el('td', { text: r.type }), el('td', { text: r.type === 'appid' ? 'App-ID from ' + ((r.args || []).find(a => a.startsWith('x-appid-target=')) || '').slice(15)
                            : r.type === 'ldap-discover' ? 'LDAP servers of ' + ((r.args || []).find(a => a.startsWith('x-ldap-discover-target=')) || '').slice(23)
                            : r.type === 'ldap' ? 'LDAP ' + ((r.args || []).find(a => a.startsWith('x-ldap-target=')) || '').slice(14).replace(/^auto:/, 'automatic: ')
                            : r.type === 'import' ? 'from ' + ((r.args || []).find(a => a.startsWith('x-import-target=')) || '').slice(16).replace(/^panos:/, '').replace(/^scm:/, 'SCM TSG ')
                            : !r.cid ? '-' : (configs.configs.find(c => c.cid === r.cid) || { name: '(deleted version)' }).name }),
                        el('td', { class: 'wrap' }, el('span', { class: 'badge' + (open ? ' dirty' : '') + (r.reason === 'memory' ? ' oom' : ''), text: r.reason === 'memory' ? 'out of memory' : r.state }),
                            r.error ? el('span', { class: r.reason === 'memory' ? 'error' : 'muted', text: ' ' + (r.reason === 'memory' ? r.error.replace(/^out of memory: /, '') : r.error) }) : null),
                        el('td', { text: r.user || '' }), el('td', { text: fmtTime(r.started) }), el('td', { text: fmtTime(r.finished) }),
                        el('td', {},
                            open ? null : el('button', { type: 'button', text: openFiles.has(r.jid) ? 'Hide files' : 'Result files', onclick: () => run(async () => {
                                if (openFiles.has(r.jid)) openFiles.delete(r.jid); else openFiles.add(r.jid);
                                await drawRuns();
                            }) }), ' ',
                            canWrite && (r.type === 'playbook' || r.type === 'object-merger' || r.type === 'rule-merger' || (r.type === 'ldap-users' && (r.args || []).includes('out=%JOB%/out.xml')) || (plug.runs[r.type] && plug.runs[r.type].result)) && r.state === 'done' ? el('span', {}, el('button', { type: 'button', text: 'Result as new version', onclick: (ev) => run(async () => {
                                const to = ev.target.parentNode.querySelector('select').value;
                                await api('POST', base + '/runs/' + r.jid + '/save', to === pid ? {} : { project: to });
                                await showProject(pid); message(to === pid ? 'the result configuration of the run is a new version' : 'the result configuration of the run is a new version of the other project');
                            }) }), ' in ', el('select', { 'aria-label': 'project for the result' }, writable.map(x => { const o = el('option', { value: x.pid, text: x.pid === pid ? 'this project' : x.name }); o.selected = x.pid === pid; return o; }))) : null, ' ',
                            canWrite && r.type === 'import' && r.state === 'failed' && (r.args || []).some(a => a.startsWith('x-import-target=scm:')) ? el('button', { type: 'button', text: 'Convert again', title: 'only the conversion to XML (scm-export-xml) on the export this run has already downloaded - no download, no network', onclick: () => run(async () => {
                                await api('POST', base + '/runs/' + r.jid + '/convert');
                                message('conversion queued - the configuration becomes a new version when it is done'); await refreshRuns();
                            }) }) : null, ' ',
                            el('button', { class: 'danger', type: 'button', text: open ? 'Cancel' : 'Delete', onclick: () => run(async () => {
                                if (!open && !confirm('Delete this run with its result files' + (r.type === 'import' && r.state === 'failed' ? ' (also a downloaded SCM export: Convert again is then not possible)' : '') + '?')) return;
                                await api('DELETE', base + '/runs/' + r.jid); openFiles.delete(r.jid); await refreshRuns();
                            }) })));
                    if (!details.has(r.jid)) return [row];
                    const fl = details.get(r.jid);
                    return [row, el('tr', {}, el('td', { colspan: 7, class: 'wrap' }, fl.length === 0 ? el('span', { class: 'muted', text: 'no files' }) :
                        fl.map(f => el('span', { class: 'filelink' }, el('a', { href: API + '/' + base + '/runs/' + r.jid + '/files/' + f.name.split('/').map(encodeURIComponent).join('/'), text: f.name }),
                            el('span', { class: 'muted', text: ' ' + fmtSize(f.size) }))))) ];
                })));
            return runs.some(r => r.state === 'queued' || r.state === 'running');
        }
        runsCard = el('div', { class: 'card' }, el('h2', { text: 'Runs' }),
            el('p', { class: 'muted', text: 'A run works on one version in its own folder; exports, set commands and the result configuration are its result files. Nothing changes a version - the result of a playbook run can be taken as a new version. diff compares two versions: the differences are in run.log, the set commands (file1 → file2) in set-commands.txt.' }),
            configs.configs.length === 0 && !Object.values(plug.runs).some(r => r.input === 'none') ? el('p', { class: 'muted', text: 'Upload a configuration first.' }) :
            el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
                const body = {};
                if (rBp.value) body.bp = rBp.value;
                if (rType.value === 'playbook') {
                    if (!rPlaybook.value) throw new Error('choose a playbook (upload one under "Project files")');
                    if (rPlaybook.value.startsWith('predefined:')) body.predefined = rPlaybook.value.slice(11); else body.playbook = rPlaybook.value;
                    if (oSub.checked) body.subprocess = true;
                    if (oThr.value) body.memorythreshold = oThr.value;
                    if (oDbg.checked) body.debugmemory = true;
                    if (oRm.checked) body.removestagefiles = true;
                }
                else if (rType.value === 'diff') {
                    delete body.bp;
                    if (dOther.value === rVersion.value) throw new Error('choose two different versions');
                    body.other = dOther.value; body.setcommands = dSet.checked;
                    if (dOrder.checked) body.noruleordercheck = true;
                    if (dXpath.value.trim()) body.xpath = dXpath.value.trim();
                }
                else if (plug.runs[rType.value]) {
                    if (!plug.runs[rType.value].bp) delete body.bp;
                    for (const x of plugInputs) {
                        const v = x.input.isMulti ? Array.from(x.input.selectedOptions).map(o => o.value) : x.input.value.trim();
                        if (v.length === 0 && x.f.required) throw new Error(x.f.label + ' is needed');
                        if (v.length !== 0) body[x.f.name] = v;
                    }
                }
                else body.location = rLocation.value.trim() || 'any';
                const noVersion = plug.runs[rType.value] && plug.runs[rType.value].input === 'none';
                await api('POST', base + (noVersion ? '' : '/configs/' + rVersion.value) + '/' + rType.value + '/runs', body);
                message('run queued');
                await refreshRuns();
            }); } }, field('Run', rType), versionField, diffFields, pbField, locField, plugFields, bpField, el('button', { class: 'primary', type: 'submit', text: 'Start run' }), pbOpts),
            runsBody);
        // while a run is open: refresh the list
        let openRuns = await drawRuns();
        refreshRuns = async () => { openRuns = await drawRuns(); };
        state.pendingTimers = [setInterval(() => { if (openRuns) refreshRuns().catch(() => {}); }, 4000)];
    }

    // ---- LDAP: my saved queries (personal) against the LDAP / AD of the customer, with my own bind account (key store
    // entry ldap_user<user>); and the check of the users of the security rules of a version (user-check-ldap)
    let ldapCard = null;
    if (canWrite && !limited) ldapCard = await ldapTab(base, pid, p, owner, configs.configs);
    // ---- Merger: object-merger / rule-merger / merger-possible-report as runs, their report as tables
    const mergerCard = !limited && configs.configs.length ? await mergerTab(base, pid, canWrite, configs.configs) : null;
    // the SCM tab: not for a project bound to PAN-OS
    const scmCard = !limited && !(p.binding && p.binding.kind === 'panos') ? await scmTab(base, pid, canWrite, p) : null;
    const supportCardEl = canWrite && !limited && configs.configs.length ? await supportCard(base, configs.configs) : null;

    // pages of plug-ins (interface 2): one card per page, drawn from the description the server gives
    const pageCards = limited ? [] : Object.entries(plug.pages || {}).map(([k, pg]) => pluginPageCard(base, k, pg));

    main(el('div', { class: 'row' }, el('h2', { text: 'Project: ' + p.name }), el('span', { class: 'badge', text: 'your permission: ' + p.role }),
        limited ? el('span', { class: 'badge', text: 'limited to ' + [p.types ? 'types ' + p.types.join(', ') : null, p.scope ? 'locations ' + p.scope.join(', ') : null].filter(x => x).join('; ') }) : null,
        // bound by the first import / read from an API: PAN-OS or one SCM tenant (an administrator can release it)
        p.binding ? el('span', { class: 'badge', title: 'set by the first import from an API; imports and SCM reads of another kind / tenant are refused', text: p.binding.kind === 'scm' ? 'SCM tenant TSG ' + p.binding.target : 'PAN-OS (firewall / Panorama)' }) : null,
        p.binding && state.admin ? el('button', { type: 'button', text: 'Release binding', title: 'administrator: the next import / read binds the project again', onclick: () => run(async () => {
            if (!confirm('Release the binding of this project (' + (p.binding.kind === 'scm' ? 'TSG ' + p.binding.target : 'PAN-OS') + ')?')) return;
            await api('DELETE', base + '/binding'); await showProject(pid); }) }) : null,
        owner ? el('button', { class: 'danger', type: 'button', text: 'Delete project', onclick: () => run(async () => {
            if (!confirm('Delete project "' + p.name + '" with all configurations?')) return;
            await api('DELETE', base); await showProjects();
        }) }) : null), projectTabs(pid, [
            ['versions', 'Configuration versions (' + configs.configs.length + ')', [versions, importCard, appidCard]],
            ['runs', 'Runs and project files', [runsCard, filesCard]],
            mergerCard ? ['merger', 'Config merger', [mergerCard]] : null,
            scmCard ? ['scm', 'SCM', [scmCard]] : null,
            ldapCard ? ['ldap', 'LDAP', [ldapCard]] : null,
            pageCards.length ? ['plugin-pages', 'Plug-ins', pageCards] : null,
            supportCardEl ? ['support', 'Support file', [supportCardEl]] : null,
            ['access', 'Members, API tokens' + (owner ? ', audit log' : ''), [memberCard, tokenCard, owner ? auditCard(base + '/audit', 'Audit log of this project') : null]]]));
    // main() clears the timers of the page before - the ones of this page start now
    if (state.pendingTimers) { state.timers.push(...state.pendingTimers); state.pendingTimers = null; }
}

// ---------------------------------------------------------------- pages of plug-ins (interface 2)
// The plug-in describes its blocks; the viewer draws them - a plug-in brings no script for the page. Form: typed fields,
// value = stored value, else the default of the plug-in; the hint of the plug-in (e.g. "tenant A: …") below the field.
function pluginPageCard(base, key, meta) {
    const body = el('div', {}, el('p', { class: 'muted', text: 'loading…' }));
    const card = el('div', { class: 'card' }, el('h2', { text: meta.title }), body);
    const load = () => run(async () => {
        const pg = await api('GET', base + '/pages/' + key);
        body.replaceChildren(pg.text ? el('p', { class: 'muted', text: pg.text }) : '', ...pg.blocks.map(b => pluginFormBlock(base, key, b, pg.write, load)));
    });
    load();
    return card;
}

function pluginFormBlock(base, key, b, canWrite, reload) {
    const inputs = {}, errs = {};
    const stored = b.saved_at !== null;
    const rows = b.fields.map(f => {
        const d = b.defaults[f.name] || {};
        const v = stored ? b.values[f.name] : d.value;
        let input;
        if (f.type === 'select') {
            input = el('select', {}, f.required ? null : el('option', { value: '', text: '-' }),
                Object.entries(f.options).map(([o, label]) => { const x = el('option', { value: o, text: label }); x.selected = o === v; return x; }));
        } else if (f.type === 'bool') {
            input = el('input', { type: 'checkbox' }); input.checked = v === true;
        } else if (f.type === 'list') {
            input = el('textarea', { rows: 4, placeholder: 'one ' + (f.item === 'text' ? 'entry' : f.item) + ' per line' }); input.value = Array.isArray(v) ? v.join('\n') : '';
        } else {
            input = el('input', { type: f.type === 'int' || f.type === 'asn' ? 'number' : 'text', maxlength: f.max || 300,
                placeholder: { ipv4: 'a.b.c.d', 'ipv4-cidr': 'a.b.c.d/n', 'ipv6-cidr': 'x::/n', asn: 'AS number', hostname: 'host.example.com' }[f.type] || '' });
            input.value = v === null || v === undefined ? '' : String(v);
        }
        input.disabled = !canWrite;
        inputs[f.name] = input;
        errs[f.name] = el('div', { class: 'fielderror' });
        return el('div', { class: 'pfield' }, el('label', {}, f.label + (f.required ? ' *' : ''), input),
            d.hint ? el('div', { class: 'muted', text: d.hint }) : null, f.help ? el('div', { class: 'muted', text: f.help }) : null, errs[f.name]);
    });
    const formErr = el('div', { class: 'fielderror' });
    const valueOf = f => {
        const i = inputs[f.name];
        if (f.type === 'bool') return i.checked;
        if (f.type === 'list') return i.value.split('\n').map(x => x.trim()).filter(x => x !== '');
        return i.value;
    };
    const save = () => run(async () => {
        Object.values(errs).forEach(e => e.textContent = ''); formErr.textContent = '';
        const values = {}; b.fields.forEach(f => { values[f.name] = valueOf(f); });
        try {
            await api('PUT', base + '/pages/' + key + '/blocks/' + b.name, { values });
        } catch (e) {
            if (e.fields) { Object.entries(e.fields).forEach(([k, m]) => { (errs[k] || formErr).textContent = m; }); throw new Error(b.title + ': ' + e.message); }
            throw e;
        }
        message(b.title + ': saved'); reload();
    });
    return el('div', { class: 'pblock' }, el('h3', { text: b.title }), b.text ? el('p', { class: 'muted', text: b.text }) : null,
        b.error ? el('div', { class: 'fielderror', text: b.error }) : null,
        el('div', { class: 'pfields' }, rows), formErr,
        el('div', { class: 'row' }, canWrite ? el('button', { class: 'primary', type: 'button', text: 'Save', onclick: save }) : null,
            el('span', { class: 'muted', text: stored ? 'saved by ' + (b.saved_by || '?') + ', ' + fmtTime(b.saved_at) : 'not saved yet - the values shown are the defaults of the plug-in' })));
}

// ---------------------------------------------------------------- editors of pan-os-php (playbook, BP JSON)
// in a sandboxed frame (editor.php: an origin of its own, no API, no cookies); it gets the file and gives the result back
// with postMessage - Save stores a NEW project file, checked like an upload (a playbook: playbookCheck)
function openEditor(kind, pid, file, done) {
    const base = 'projects/' + pid;
    const frame = el('iframe', { src: 'editor.php?e=' + (kind === 'bp' ? 'bp' : 'playbook'), sandbox: 'allow-scripts', title: (kind === 'bp' ? 'BP JSON' : 'playbook') + ' editor', class: 'editorframe' });
    const close = () => { window.removeEventListener('message', onMsg); overlay.remove(); };
    const overlay = el('div', { class: 'editoroverlay' },
        el('div', { class: 'editorbar' }, el('strong', { text: (kind === 'bp' ? 'BP JSON' : 'Playbook') + ' editor' }),
            el('span', { class: 'muted', text: file ? 'a copy of ' + file.name + ' - ' + (kind === 'bp' ? 'Export JSON' : 'SAVE') + ' stores it as a new project file' : 'new file - ' + (kind === 'bp' ? 'starts with the BP JSON shipped with pan-os-php; Export JSON' : 'SAVE') + ' stores it in the project' }),
            el('span', { class: 'spacer' }), el('button', { type: 'button', text: 'Close', onclick: () => { if (confirm('Close the editor? What is not saved is lost.')) close(); } })),
        frame);
    async function onMsg(e) {
        if (e.source !== frame.contentWindow || !e.data || typeof e.data.type !== 'string') return;
        // a file of the project, or - a new BP JSON - the one shipped with pan-os-php as the start
        if (e.data.type === 'panosphp-editor-ready' && (file || kind === 'bp')) {
            const r = await fetch(API + '/' + (file ? base + '/files/' + file.fid + '/download' : 'bp-default'), { credentials: 'same-origin' });
            if (r.ok) frame.contentWindow.postMessage({ type: 'panosphp-editor-load', json: await r.text() }, '*');
            else message('the file could not be read', 'error');
        }
        if (e.data.type === 'panosphp-editor-save' && typeof e.data.json === 'string') {
            const def = file ? file.name.replace(/\.json$/i, '') + '-edited.json' : (kind === 'bp' ? 'bp.json' : 'playbook.json');
            let name = prompt('Name of the new project file', def);
            if (!name) return;
            name = name.trim().endsWith('.json') ? name.trim() : name.trim() + '.json';
            run(async () => {
                const fd = new FormData(); fd.append('file', new Blob([e.data.json], { type: 'application/json' }), name);
                await api('POST', base + '/files?kind=' + kind, fd);
                close(); await done(); message('saved as the new project file ' + name);
            });
        }
    }
    window.addEventListener('message', onMsg);
    document.body.append(overlay);
}

// ---------------------------------------------------------------- LDAP tab of a project
async function ldapTab(base, pid, p, owner, versions) {
    const card = el('div', { class: 'card' });
    const info = await api('GET', 'ldap');
    const allRuns = (await api('GET', base + '/runs')).runs.filter(r => r.user === state.user);
    const runs = allRuns.filter(r => r.type === 'ldap' || r.type === 'ldap-users' || r.type === 'ldap-discover');
    const out = el('div', {});
    const redraw = async () => { card.replaceWith(await ldapTab(base, pid, p, owner, versions)); };
    // the form: a new query, or a saved one to change
    const f = {
        name: el('input', { required: true, maxlength: 80, autocomplete: 'off' }),
        // empty = automatic: the first domain controller of the domain from DNS that works
        server: el('input', { placeholder: 'empty = automatic (DNS of the domain)', autocomplete: 'off', spellcheck: false }),
        domain: el('input', { placeholder: 'example.local', autocomplete: 'off', spellcheck: false }),
        ldaps: el('input', { type: 'checkbox', checked: true }),
        bind_user: el('input', { required: true, placeholder: 'admin@example.com or EXAMPLE\\admin', autocomplete: 'off', spellcheck: false, list: 'ldap-accounts-' + pid }),
        base_dn: el('input', { required: true, placeholder: 'OU=Users,DC=example,DC=com', autocomplete: 'off', spellcheck: false }),
        attribute: el('input', { value: 'sAMAccountName', autocomplete: 'off', spellcheck: false }),
        mode: el('select', {}, Object.entries(info.modes).map(([k, t]) => el('option', { value: k, text: k + ' - ' + t }))),
        users: el('textarea', { rows: 3, placeholder: 'one user per line (or comma separated)', spellcheck: false }),
        group: el('input', { autocomplete: 'off', spellcheck: false }),
        transitive: el('input', { type: 'checkbox' }),
    };
    let editing = null;
    const fUsers = field('Users', f.users), fGroup = field('Group (CN or sAMAccountName)', f.group), fTrans = field('With nested groups', f.transitive);
    const modeChanged = () => { const m = f.mode.value; fUsers.hidden = m === 'group-members'; fGroup.hidden = m !== 'group-members'; fTrans.hidden = m !== 'common-groups'; };
    f.mode.addEventListener('change', modeChanged); modeChanged();
    const saveBtn = el('button', { class: 'primary', type: 'submit', text: 'Save query' });
    const fill = (q) => {
        editing = q ? q.qid : null;
        for (const k of ['name', 'server', 'domain', 'bind_user', 'base_dn', 'attribute']) f[k].value = q ? q[k] : (k === 'attribute' ? 'sAMAccountName' : '');
        f.ldaps.checked = q ? q.ldaps : true;
        f.mode.value = q ? q.mode : 'validation'; f.users.value = q ? q.users.join('\n') : ''; f.group.value = q ? q.group : ''; f.transitive.checked = q ? q.transitive : false;
        saveBtn.textContent = q ? 'Save changes' : 'Save query'; modeChanged();
    };
    // my LDAP accounts (key store entries ldap_user<user>) as suggestions for the bind user
    const accounts = el('datalist', { id: 'ldap-accounts-' + pid }, info.accounts.map(a => el('option', { value: a })));
    const form = el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
        const body = {};
        for (const k of ['name', 'server', 'domain', 'bind_user', 'base_dn', 'attribute', 'mode', 'users', 'group']) body[k] = f[k].value.trim();
        body.ldaps = f.ldaps.checked;
        body.transitive = f.transitive.checked;
        await api(editing ? 'PUT' : 'POST', 'ldap' + (editing ? '/' + editing : ''), body);
        await redraw(); message('LDAP query saved');
    }); } }, field('Name', f.name), field('Domain', f.domain), field('Server (optional)', f.server), field('LDAPS', f.ldaps), field('Bind user (my account)', f.bind_user), field('Base DN', f.base_dn), field('User attribute', f.attribute),
        field('What', f.mode), fUsers, fGroup, fTrans, saveBtn, el('button', { type: 'button', text: 'New', onclick: () => fill(null) }));

    const why = !p.network_global ? 'Network for runs is off (an administrator turns it on under Account).'
        : !p.network ? 'Network is off for this project' + (owner ? ' (Configuration versions, Import from a device).' : ' (the owner turns it on).')
        : info.accounts.length === 0 ? 'You have no LDAP account yet: add one under Account, My API keys (kind LDAP account: bind user + password; key store entry ldap_user<user>).' : null;
    const verSel = () => el('select', { 'aria-label': 'version' }, versions.map(c => el('option', { value: c.cid, text: c.name })));
    // ---- help for the first query: the domain controllers of an AD domain (DNS SRV) and the base DN (RootDSE)
    const dDomain = el('input', { placeholder: 'example.local', autocomplete: 'off', spellcheck: false, required: true });
    const dLdaps = el('input', { type: 'checkbox', checked: true });
    const dOut = el('div', {});
    const showFound = async (jid) => {
        const d = await api('GET', base + '/runs/' + jid + '/ldap-servers');
        const sg = d.suggestion;
        dOut.replaceChildren(
            table(['Server', 'Priority / weight', 'Answered', 'Network'], d.servers.map(s => el('tr', { class: s.refused ? 'warnrow' : '' },
                el('td', { text: s.uri }), el('td', { text: s.priority + ' / ' + s.weight }), el('td', { text: s.answered ? 'yes (base DN from it)' : '' }),
                el('td', { class: 'wrap', text: s.refused ? s.refused : 'allowed' })))),
            el('p', { class: 'muted', text: 'Base DN: ' + sg.base_dn + (sg.base_from === 'rootdse' ? ' (from the server)' : ' (from the domain name - no server answered)')
                + (sg.server ? '' : ' - no server is allowed by the network rules yet: the administrator puts *.' + d.domain + ' on the allow list.')
                + (sg.bind_user ? '' : ' You have no LDAP account @' + d.domain + ' yet: add it under Account, My API keys (bind user ' + sg.bind_hint + ' and its password).') }),
            el('button', { type: 'button', class: 'primary', text: 'Use for a new query', onclick: () => {
                fill(null);
                // the server stays empty: the run takes the first domain controller of the domain that works
                f.name.value = sg.name; f.domain.value = d.domain; f.server.value = ''; f.base_dn.value = sg.base_dn;
                f.bind_user.value = sg.bind_user || ''; f.bind_user.placeholder = sg.bind_hint; f.attribute.value = sg.attribute;
                (sg.bind_user ? f.users : f.bind_user).focus();
                message('filled in - check it, add the users / group, then Save query');
            } }));
    };
    const waitFound = (jid) => {
        dOut.replaceChildren(el('span', { class: 'muted', text: 'searching …' }));
        const t = setInterval(() => run(async () => {
            const r = await api('GET', base + '/runs/' + jid);
            if (r.state === 'queued' || r.state === 'running') return;
            clearInterval(t);
            if (r.state === 'done') await showFound(jid);
            else dOut.replaceChildren(el('span', { class: 'error', text: 'the search failed: ' + (r.error || r.state) + ' ' }),
                el('a', { href: API + '/' + base + '/runs/' + jid + '/files/run.log', target: '_blank', rel: 'noopener', text: 'run.log' }));
        }), 2000);
        // while the project page is built, its timers start with it (showProject)
        (state.pendingTimers || state.timers).push(t);
    };
    const discover = el('details', { class: 'help', open: info.queries.length === 0 },
        el('summary', { text: 'Not sure about server and base DN? Find them from the domain name' }),
        el('p', { class: 'muted', text: 'Asks the DNS for the domain controllers of the AD domain (SRV records) and the first one that answers for its base DN - without a login. The administrator must allow the hosts of the domain (e.g. *.example.local) in the network rules; for internal names the runs may need the DNS server of the domain (VIEWER_RUN_DNS).' }),
        !p.network_global || !p.network ? null : el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
            const r = await api('POST', base + '/ldap-discover/runs', { domain: dDomain.value.trim(), ldaps: dLdaps.checked });
            waitFound(r.jid);
        }); } }, field('AD domain', dDomain), field('LDAPS (636)', dLdaps), el('button', { type: 'submit', text: 'Find servers' })),
        dOut);
    const lastFound = allRuns.find(r => r.type === 'ldap-discover');
    const logLink = (r, text) => el('a', { href: API + '/' + base + '/runs/' + r.jid + '/files/run.log', target: '_blank', rel: 'noopener', text: text || 'run.log' });
    if (lastFound && lastFound.state === 'done') { dDomain.value = ((lastFound.args || []).find(a => a.startsWith('domain=')) || '').slice(7); showFound(lastFound.jid).catch(() => {}); }
    else if (lastFound && (lastFound.state === 'queued' || lastFound.state === 'running')) waitFound(lastFound.jid);

    const queries = info.queries.length === 0 ? el('p', { class: 'muted', text: 'No saved queries yet.' }) :
        table(['Name', 'What', 'Server', 'Base DN', 'Users / group', ''], info.queries.map(q => {
            const v = verSel();
            const noAccount = !info.accounts.includes(q.bind_user.toLowerCase());
            const act = el('select', { 'aria-label': 'show or remove' }, el('option', { value: 'show', text: 'show missing users' }), el('option', { value: 'remove', text: 'remove missing users (result = new version)' }));
            return el('tr', {}, el('td', { text: q.name }), el('td', { text: q.mode }), el('td', { class: 'wrap', text: q.auto ? 'automatic: ' + q.domain + (q.ldaps ? ' (LDAPS)' : ' (LDAP)') : q.server }), el('td', { class: 'wrap', text: q.base_dn }),
                el('td', { class: 'wrap', text: q.mode === 'group-members' ? q.group : q.users.join(', ') }),
                el('td', {}, el('div', { class: 'row' },
                    !why && noAccount ? el('span', { class: 'error', text: 'no LDAP account ' + q.bind_user + ' (My API keys)' }) : null,
                    why || noAccount ? null : el('button', { type: 'button', class: 'primary', text: 'Run', disabled: q.mode !== 'group-members' && q.users.length === 0, onclick: () => run(async () => {
                        await api('POST', base + '/ldap/runs', { qid: q.qid }); await redraw(); message('LDAP query queued');
                    }) }),
                    why || noAccount || versions.length === 0 ? null : el('span', {}, el('button', { type: 'button', text: 'Check the users of the rules', title: 'type=rule actions=user-check-ldap with the server, bind user, base DN and attribute of this query', onclick: () => run(async () => {
                        if (act.value === 'remove' && !confirm('Remove the users that are not in the LDAP any more from the security rules? The result is a new configuration (Result as new version) - the version itself stays.')) return;
                        await api('POST', base + '/configs/' + v.value + '/ldap-users/runs', { qid: q.qid, action: act.value }); await redraw(); message('check queued');
                    }) }), ' of ', v, ' ', act),
                    el('button', { type: 'button', text: 'Edit', onclick: () => { fill(q); f.name.focus(); } }),
                    el('button', { class: 'danger', type: 'button', text: 'Delete', onclick: () => run(async () => {
                        if (!confirm('Delete the LDAP query ' + q.name + '?')) return;
                        await api('DELETE', 'ldap/' + q.qid); await redraw();
                    }) }))));
        }));
    const show = async (r) => {
        if (r.type === 'ldap-users') { out.replaceChildren(el('h3', { text: 'Result' }), logLink(r, 'run.log (download)'), el('pre', { class: 'log', text: await (await fetch(API + '/' + base + '/runs/' + r.jid + '/files/run.log', { credentials: 'same-origin' })).text() })); return; }
        const res = await (await fetch(API + '/' + base + '/runs/' + r.jid + '/files/ldap.json', { credentials: 'same-origin' })).json();
        const rows = res.rows || [];
        const cols = [...new Set(rows.flatMap(x => Object.keys(x)))];
        const val = v => v === null || v === undefined ? '' : typeof v === 'boolean' ? (v ? 'yes' : 'no') : typeof v === 'object' ? Object.entries(v).map(([a, b]) => a + ': ' + b).join(', ') : String(v);
        out.replaceChildren(el('h3', { text: 'Result: ' + res.mode + (res.group ? ' ' + res.group : '') + (res.user ? ' ' + res.user : '') + ' - ' + rows.length + ' row(s)' + (res.missing ? ', ' + res.missing + ' not found' : '') }),
            res.notFound && res.notFound.length ? el('p', { class: 'error', text: 'not found: ' + res.notFound.join(', ') }) : null,
            el('div', { class: 'row' }, el('a', { href: API + '/' + base + '/runs/' + r.jid + '/files/ldap.csv', text: 'CSV' }), logLink(r)),
            rows.length === 0 ? el('p', { class: 'muted', text: 'nothing found' }) :
            table(cols, rows.map(x => el('tr', { class: x.found === false || x.status === 'disabled' || x.expired ? 'warnrow' : '' }, cols.map(c => el('td', { class: 'wrap', text: val(x[c]) }))))));
    };
    const runList = runs.length === 0 ? null : table(['Run', 'State', 'Started', ''], runs.slice(0, 20).map(r => el('tr', {},
        el('td', { text: r.type === 'ldap' ? 'query ' + ((r.args || []).find(a => a.startsWith('mode=')) || '').slice(5)
            : r.type === 'ldap-discover' ? 'servers of ' + ((r.args || []).find(a => a.startsWith('domain=')) || '').slice(7)
            : 'rule users of ' + ((versions.find(c => c.cid === r.cid) || { name: '-' }).name) }),
        el('td', { class: 'wrap' }, el('span', { class: 'badge' + (r.state === 'queued' || r.state === 'running' ? ' dirty' : ''), text: r.state }), r.error ? el('span', { class: 'muted', text: ' ' + r.error }) : null),
        el('td', { text: fmtTime(r.started) }),
        el('td', {}, el('div', { class: 'row' },
            r.state === 'done' ? el('button', { type: 'button', text: 'Show result', onclick: () => run(() => r.type === 'ldap-discover' ? showFound(r.jid).then(() => { discover.open = true; discover.scrollIntoView(); }) : show(r)) }) : null,
            // the log of every finished run (also a failed one - why it failed)
            r.state === 'done' || r.state === 'failed' || r.state === 'cancelled' ? logLink(r) : null,
            r.state === 'queued' || r.state === 'running' ? el('button', { type: 'button', text: 'Refresh', onclick: () => run(redraw) }) : null)))));
    card.append(el('h2', { text: 'LDAP' }),
        el('p', { class: 'muted', text: 'Ask the LDAP / Active Directory with your own account: do the users still exist (cleanup), which groups does a user have, which groups do several users share, who is in a group. The queries are yours (nobody else sees them); the password of the bind user is your LDAP account under My API keys (key store entry ldap_user<user>). The server must be allowed by the administrator (network allow list). "Check the users of the rules" looks up the users of the security rules of a version (pan-os-php user-check-ldap); the run log shows the missing ones, "remove" also makes a result configuration without them.' }),
        why ? el('p', { class: 'muted', text: why }) : null, discover, accounts, form, queries, runList ? el('h3', { text: 'My LDAP runs' }) : null, runList, out);
    return card;
}

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
function liveForm(r, opts) {
    if (!r.keys.length) return el('p', { class: 'muted', text: opts.noKey });
    const key = el('select', { 'aria-label': opts.keyLabel }, r.keys.map(k => el('option', { value: k.kid, text: 'TSG ' + k.target + (k.label && k.label !== k.target ? ' - ' + k.label : '') + (k.refused ? ' (not allowed: ' + k.refused + ')' : '') })));
    const status = el('span', { class: 'muted' });
    return el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
        const job = await api('POST', opts.path, Object.assign({ kid: key.value }, opts.body ? opts.body() : {}));
        status.className = 'muted'; status.textContent = 'reading live …';
        const t = setInterval(async () => {
            const x = await api('GET', opts.runs + '/' + job.jid).catch(() => null);
            if (!x || (x.state !== 'done' && x.state !== 'failed')) return;
            clearInterval(t);
            if (x.state === 'failed') { status.className = 'error'; status.textContent = 'live read failed: ' + (x.error || 'see Runs'); message('live read failed: ' + (x.error || 'see Runs'), 'error'); return; }
            message(opts.done); await opts.redraw();
        }, 1500);
        state.timers.push(t);
    }); } }, field('Live with your key', key), ...(opts.fields || []),
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

// ---------------------------------------------------------------- Merger tab of a project
// object-merger / rule-merger (result configuration = Result as new version) and merger-possible-report (only a report)
// run like every run on a copy of the version; pan-os-php writes the report as data (exportJSON=merger.json - the same
// data as the HTML of exportCSV, which is offered as download); the tables are made from merger.json
const MERGER_OBJECTTYPES = ['tag', 'address', 'service', 'edl', 'region', 'application-custom', 'application-filter', 'addressgroup', 'servicegroup',
    'application-group', 'custom-url-category', 'schedule', 'log-profile', 'decryption-profile', 'hip-object', 'hip-profile', 'securityprofile', 'securityprofilegroup'];
const MERGER_DUP = ['', 'SameAddress', 'Identical', 'WhereUsed', 'SameDstSrcPorts', 'SamePorts', 'SameMembers', 'SameIP4Mapping', 'SamePortMapping', 'SameColor', 'SameName', 'SameValue'];
const RULEMERGER_METHODS = ['matchFromToSrcDstApp', 'matchFromToSrcDstSvc', 'matchFromToSrcSvcApp', 'matchFromToDstSvcApp', 'matchFromSrcDstSvcApp', 'matchToSrcDstSvcApp', 'matchToDstSvcApp', 'matchFromSrcSvcApp', 'identical'];
const RULEMERGER_ADDITIONAL = ['tag', 'secprof', 'user', 'urlcategory', 'target', 'logsetting', 'schedule'];
const MERGER_TYPES = { 'object-merger': 'object-merger', 'rule-merger': 'rule-merger', 'merger-possible-report': 'merger-possible-report (report only)' };

async function mergerTab(base, pid, canWrite, versions) {
    const card = el('div', { class: 'card' });
    const out = el('div', {});
    const redraw = async () => { card.replaceWith(await mergerTab(base, pid, canWrite, versions)); };
    const types = canWrite ? Object.keys(MERGER_TYPES) : ['merger-possible-report'];
    const mType = el('select', { 'aria-label': 'merger' }, types.map(t => el('option', { value: t, text: MERGER_TYPES[t] })));
    const mVersion = el('select', { 'aria-label': 'version' }, versions.map(c => el('option', { value: c.cid, text: c.name + ' (' + fmtTime(c.created) + ')' })));
    // a choice of several values as checkboxes (a multiple select can not be emptied again without Ctrl): nothing
    // ticked = nothing chosen; "none" clears them
    const multi = (list) => {
        const boxes = list.map(x => el('input', { type: 'checkbox', value: x }));
        const box = el('div', { class: 'checks' }, boxes.map(b => el('label', {}, b, ' ' + b.value)),
            el('button', { type: 'button', class: 'small', text: 'none', onclick: () => boxes.forEach(b => { b.checked = false; }) }));
        box.values = () => boxes.filter(b => b.checked).map(b => b.value);
        return box;
    };
    const f = {
        objecttype: multi(MERGER_OBJECTTYPES), location: el('input', { value: 'any', autocomplete: 'off', spellcheck: false }),
        rlocation: el('input', { value: 'any', autocomplete: 'off', spellcheck: false }),
        dup: el('select', {}, MERGER_DUP.map(x => el('option', { value: x, text: x || 'default of the type' }))),
        pick: el('input', { placeholder: '(name regex /^H-/)', autocomplete: 'off', spellcheck: false }),
        exclude: el('input', { placeholder: '(name regex /^tmp/)', autocomplete: 'off', spellcheck: false }),
        limit: el('input', { type: 'number', min: 0, placeholder: 'no limit' }), upper: el('input', { type: 'checkbox' }),
        method: el('select', {}, RULEMERGER_METHODS.map(x => el('option', { value: x, text: x }))),
        rulebase: el('select', {}, el('option', { value: 'pre', text: 'pre rules (Panorama)' }), el('option', { value: 'post', text: 'post rules (Panorama)' })),
        deny: el('input', { type: 'checkbox' }), stopDeny: el('input', { type: 'checkbox', checked: true }), adjacent: el('input', { type: 'checkbox' }),
        filter: el('input', { placeholder: '(from has trust)', autocomplete: 'off', spellcheck: false }), additional: multi(RULEMERGER_ADDITIONAL),
        reportTypes: el('input', { value: 'any', placeholder: 'any or address,service,…', autocomplete: 'off', spellcheck: false }), mergecheck: el('input', { type: 'checkbox', checked: true }),
    };
    const groups = {
        // first the settings in one row (as rule-merger), then the object types over the whole width, left to right
        'object-merger': el('div', {}, el('div', { class: 'row' }, field('Location', f.location), field('DupAlgorithm', f.dup),
            field('pickFilter', f.pick), field('excludeFilter', f.exclude), field('mergeCountLimit', f.limit), field('allowMergingWithUpperLevel', f.upper)),
            el('div', { class: 'row wide' }, groupField('Object types (none ticked = any)', f.objecttype))),
        'rule-merger': el('div', {}, el('div', { class: 'row' }, field('Location', f.rlocation), field('Method', f.method), field('Rule base', f.rulebase), field('mergeDenyRules', f.deny),
            field('stopMergingIfDenySeen', f.stopDeny), field('mergeAdjacentOnly', f.adjacent), field('filter', f.filter)),
            el('div', { class: 'row wide' }, groupField('additionalMatch (none ticked = none)', f.additional))),
        'merger-possible-report': el('div', { class: 'row' }, field('Object types', f.reportTypes), field('mergecheck (would the merge change what a firewall receives)', f.mergecheck)),
    };
    const opts = el('div', {});
    const typeChanged = () => {
        opts.replaceChildren(groups[mType.value]);
    };
    mType.addEventListener('change', typeChanged); typeChanged();
    const selected = (box) => box.values();
    const form = el('form', { onsubmit: (ev) => { ev.preventDefault(); run(async () => {
        const t = mType.value, body = {};
        if (t === 'object-merger') {
            Object.assign(body, { objecttype: selected(f.objecttype).join(',') || 'any', location: f.location.value.trim() || 'any', allowmergingwithupperlevel: f.upper.checked });
            if (f.dup.value) body.dupalgorithm = f.dup.value;
            if (f.pick.value.trim()) body.pickfilter = f.pick.value.trim();
            if (f.exclude.value.trim()) body.excludefilter = f.exclude.value.trim();
            if (f.limit.value !== '') body.mergecountlimit = f.limit.value;
        } else if (t === 'rule-merger') {
            Object.assign(body, { location: f.rlocation.value.trim() || 'any', method: f.method.value, rulebase: f.rulebase.value, mergedenyrules: f.deny.checked,
                stopmergingifdenyseen: f.stopDeny.checked, mergeadjacentonly: f.adjacent.checked, additionalmatch: selected(f.additional) });
            if (f.filter.value.trim()) body.filter = f.filter.value.trim();
        } else Object.assign(body, { objecttype: f.reportTypes.value.trim() || 'any', mergecheck: f.mergecheck.checked });
        await api('POST', base + '/configs/' + mVersion.value + '/' + t + '/runs', body);
        message(t + ' queued'); await redraw();
    }); } }, el('div', { class: 'row' }, field('Merger', mType), field('Version', mVersion)), opts, el('button', { class: 'primary', type: 'submit', text: 'Start' }));

    const runs = (await api('GET', base + '/runs')).runs.filter(r => MERGER_TYPES[r.type]);
    const fileLink = (r, name, text) => el('a', { href: API + '/' + base + '/runs/' + r.jid + '/files/' + name, target: '_blank', rel: 'noopener', text: text || name });
    const runList = runs.length === 0 ? el('p', { class: 'muted', text: 'No merger runs yet.' }) :
        table(['Merger', 'Version', 'Settings', 'State', 'Started', ''], runs.slice(0, 30).map(r => el('tr', {},
            el('td', { text: r.type }), el('td', { text: (versions.find(c => c.cid === r.cid) || { name: '-' }).name }),
            el('td', { class: 'wrap mergersettings', text: mergerSettings(r).join('\n') }),
            el('td', { class: 'wrap' }, el('span', { class: 'badge' + (r.state === 'queued' || r.state === 'running' ? ' dirty' : ''), text: r.state }), r.error ? el('span', { class: 'muted', text: ' ' + r.error }) : null),
            el('td', { text: fmtTime(r.started) }),
            el('td', {}, el('div', { class: 'row' },
                r.state === 'done' ? el('button', { type: 'button', class: 'primary', text: 'Show report', onclick: () => run(() => showMergerReport(base, r, out)) }) : null,
                r.state === 'done' && canWrite && r.type !== 'merger-possible-report' ? el('button', { type: 'button', text: 'Result as new version', onclick: () => run(async () => {
                    if (!confirm('Save the result configuration of this ' + r.type + ' run as a new version? The version it ran on stays.')) return;
                    await api('POST', base + '/runs/' + r.jid + '/save', {}); await showProject(pid); message('the result of the merger is a new version');
                }) }) : null,
                r.state === 'done' ? fileLink(r, 'merger.html', 'HTML') : null,
                r.state === 'done' && r.type !== 'merger-possible-report' ? fileLink(r, 'skipped-merger.html', 'HTML skipped') : null,
                r.state === 'done' ? fileLink(r, 'merger.json', 'JSON') : null,
                r.state === 'done' || r.state === 'failed' || r.state === 'cancelled' ? fileLink(r, 'run.log') : null,
                r.state === 'queued' || r.state === 'running' ? el('button', { type: 'button', text: 'Refresh', onclick: () => run(redraw) }) : null,
                // a finished run: deleted with its files (report, result configuration, run.log); an open one: cancelled
                canWrite || r.user === state.user ? el('button', { type: 'button', class: 'danger', text: r.state === 'queued' || r.state === 'running' ? 'Cancel' : 'Delete',
                    onclick: () => run(async () => {
                        const open = r.state === 'queued' || r.state === 'running';
                        if (!confirm(open ? 'Cancel this ' + r.type + ' run?' : 'Delete this ' + r.type + ' run with its report and result configuration? A version saved from it stays.')) return;
                        await api('DELETE', base + '/runs/' + r.jid);
                        if (out.dataset.jid === r.jid) out.replaceChildren();
                        message(open ? 'run cancelled' : 'run deleted'); await redraw();
                    }) }) : null)))));
    card.append(el('h2', { text: 'Config merger - objects and rules of a version' }),
        el('p', { class: 'muted', text: 'pan-os-php object-merger (objects) / rule-merger (policies) on a copy of a configuration version of this project: the report shows what can be merged (kept ← removed) and what was not merged, with the reason. The version itself stays - "Result as new version" takes the merged configuration. merger-possible-report only reports duplicates (and with mergecheck whether a merge would change what a firewall receives).' }),
        form, el('h3', { text: 'Merger runs' }), runList, out);
    const open = runs.find(r => r.state === 'queued' || r.state === 'running');
    if (open) state.pendingTimers = (state.pendingTimers || []).concat([setTimeout(() => { if (card.isConnected) redraw().catch(() => {}); }, 4000)]);
    return card;
}

// a cell of a merger report: text, or a node (values with their differences marked)
function cellText(c) { return typeof c === 'string' ? c : c.textContent; }
/** the text b with what differs from a marked: the common start and end plain, the middle as <mark> */
function diffMark(a, b) {
    a = a || ''; b = b || '';
    let pre = 0;
    while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++;
    let suf = 0;
    while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
    const mid = b.slice(pre, b.length - suf);
    return el('span', {}, b.slice(0, pre), mid ? el('mark', { class: 'diff', text: mid }) : (a.length > b.length ? el('mark', { class: 'diff gone', text: '∅', title: 'missing here: ' + a.slice(pre, a.length - suf) }) : null), b.slice(b.length - suf));
}
/** lines "prefix + value" where each value is marked against the value of another line */
function diffLines(items, other) {
    const box = el('span', {});
    items.forEach((it, i) => { if (i) box.append(el('br')); box.append(it.prefix, it.value !== other ? diffMark(other, it.value) : it.value); });
    return box;
}

/**
 * "Explain" of a merge the effective-policy check refused (pan-os-php MergeSafety lastDetail): for the firewalls of one
 * location what the name gives before and after the merge, how the name resolves level by level (device group, parents,
 * shared), the members of a group, and the simulated changes. Links open the objects / the rule in the version the run
 * ran on (new window).
 */
function explainMergeSafety(d, link) {
    const box = el('div', { class: 'objwin explainwin', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'explain' });
    const overlay = el('div', { class: 'objoverlay', onclick: (ev) => { if (ev.target === overlay) close(); } }, box);
    const onKey = (ev) => { if (ev.key === 'Escape') close(); };
    function close() { document.removeEventListener('keydown', onKey); overlay.remove(); }
    // the viewer list of the objects (address / service / security profile group / EDL); other types: text only
    const vtype = { addressStore: 'address', serviceStore: 'service', securityProfileGroupStore: 'securityprofilegroup', EDLStore: 'edl' }[d.store];
    const objLink = (name, loc, text) => vtype && loc && loc !== 'predefined' && name ? el('a', { href: link({ name, location: loc, type: vtype }), target: '_blank', rel: 'noopener', text: text || name, title: 'open ' + loc + ': ' + name + ' (new window)' }) : el('span', { text: text || name });
    const list = (items, other) => {
        const o = new Set(other || []);
        return items.length ? el('span', {}, ...items.flatMap((x, i) => [i ? ', ' : '', o.has(x) ? x : el('mark', { class: 'diff', text: x })])) : el('mark', { class: 'diff gone', text: '∅ empty', title: 'nothing - see the resolution below' });
    };
    const STATE = { found: 'found', removed: 'found - removed by this merge', placed: 'placed here by this merge', none: '-' };
    const levelRow = (t, l) => el('tr', { class: t.result && t.result.location === l.location && (l.state === 'found' || l.state === 'placed') ? 'winrow' : '' },
        el('td', { text: l.location }), el('td', { text: STATE[l.state] || l.state }),
        el('td', { class: 'wrap' }, l.state === 'found' || l.state === 'removed' ? objLink(t.name, l.location, (l.value || []).join(', ') || '(empty)') : el('span', { text: (l.value || []).join(', ') })));
    const memberRow = (m) => el('tr', {},
        el('td', { text: m.name }),
        el('td', {}, m.removed ? 'removed from the group' : m.added ? 'added to the group' : m.renamedTo ? 'renamed to ' + m.renamedTo : '',
            m.loop ? el('span', { class: 'warn', text: ' - the group would contain itself (loop): nothing from this member' }) : null),
        el('td', { class: 'wrap' }, m.removed ? el('span', { class: 'muted', text: '-' })
            : m.result ? el('span', {}, objLink(m.result.name, m.result.location, m.result.location + ': ' + m.result.name), ' = ', (m.result.content || []).join(', ') || '(empty)')
            : el('span', { class: 'warn', text: 'does not resolve' })));
    const resultLine = (t) => t.result === null ? el('p', { class: 'warn', text: 'the name does not resolve for these firewalls' })
        : el('p', {}, '→ ', objLink(t.result.name, t.result.location, t.result.location + ': ' + t.result.name), t.result.group ? ' (group)' : '', ': ',
            (t.result.content || []).join(', ') || el('mark', { class: 'diff gone', text: 'empty' }));
    const trace = (res) => el('div', {}, ...(res || []).map(t => el('div', { class: 'explaintrace' },
        el('p', {}, el('strong', { text: t.name }), el('span', { class: 'muted', text: ' (' + (t.precedence === 'ancestor' ? 'ancestor objects take precedence: the highest level wins' : 'the nearest level wins') + ')' })),
        table(['level', 'state', 'value'], t.levels.map(l => levelRow(t, l))),
        resultLine(t),
        t.result && t.result.members ? table(['member', 'after the merge', 'resolves to'], t.result.members.map(memberRow)) : null)));
    const u = d.usedBy || {};
    const userLink = u.kind === 'rule' ? el('a', { href: link({ name: u.name, location: u.location, type: 'rule', ruletype: u.ruletype }), target: '_blank', rel: 'noopener', text: 'rule ' + u.name })
        : u.name ? objLink(u.name, u.location, (u.kind || 'object') + ' ' + u.name) : el('span', { text: u.text || '-' });
    const ch = d.changes || {};
    const changes = [].concat((ch.removed || []).map(x => 'removed: ' + x), (ch.placed || []).map(x => 'placed: ' + x),
        (ch.memberRenamed || []).map(x => 'group ' + x.group + ': member ' + x.from + ' → ' + x.to),
        (ch.memberAdded || []).map(x => 'group ' + x.group + ': member ' + x.name + ' added'),
        (ch.memberRemoved || []).map(x => 'group ' + x.group + ': member ' + x.name + ' removed'));
    // the likely cause in words, read from the resolution: a copy in a lower level that shadows, a name that does not
    // resolve, a group that would contain itself, a group that becomes empty
    const why = [];
    const traces = (side) => (d[side].resolution || []);
    traces('before').forEach((t, i) => {
        const a = traces('after')[i];
        if (!t.result || !a) return;
        if (!a.result) why.push('after the merge "' + a.name + '" does not exist for the firewalls of ' + d.firewalls + ' (no level has it)');
        else if (t.result.location !== a.result.location) {
            const lv = t.levels.findIndex(l => l.location === t.result.location), la = a.levels.findIndex(l => l.location === a.result.location);
            why.push(lv >= 0 && la > lv ? 'for the firewalls of ' + d.firewalls + ' "' + t.name + '" is found in ' + t.result.location + ' first (it shadows the copy of the other levels); "' + a.name + '" only exists in ' + a.result.location + ' - so the value changes'
                : '"' + t.name + '" resolves in ' + t.result.location + ', after the merge "' + a.name + '" in ' + a.result.location);
        }
        ((a.result || {}).members || []).forEach(m => {
            if (m.loop) why.push('group ' + a.result.name + ': member ' + m.name + (m.renamedTo ? ' would be renamed to ' + m.renamedTo : '') + ' - the group would contain itself (loop), the firewall gets nothing from it');
            else if (!m.removed && !m.result) why.push('group ' + a.result.name + ': member ' + (m.renamedTo || m.name) + ' does not resolve for the firewalls of ' + d.firewalls);
        });
        if (a.result && a.result.group && (a.result.content || []).length === 0 && !((a.result.members || []).some(m => m.loop))) why.push('group ' + a.result.name + ' would be empty for the firewalls of ' + d.firewalls);
    });
    if (u.location && u.location !== d.firewalls && u.kind === 'group') why.push('the group ' + u.name + ' is defined in ' + u.location + ', but its members are resolved by the firewalls of ' + d.firewalls + ' (the levels from there upwards)');
    box.append(el('div', { class: 'objhead' }, el('h3', { text: 'Explain: ' + (d.copy || (d.names || []).join(', ')) + ' not merged' }),
            el('button', { type: 'button', class: 'objclose', text: '✕', 'aria-label': 'close', onclick: close })),
        el('p', { class: 'muted', text: 'The merge would change what the firewalls of ' + d.firewalls + ' receive: the name resolves to other values before and after the merge. Differences are marked.' }),
        why.length ? el('div', { class: 'card notice' }, el('strong', { text: 'Why: ' }), ...why.flatMap((w, i) => [i ? el('br') : '', w])) : null,
        el('table', { class: 'plain' }, el('tbody', {}, [
            el('tr', {}, el('th', { text: 'firewalls of' }), el('td', { text: d.firewalls })),
            el('tr', {}, el('th', { text: 'name' }), el('td', { text: (d.names || []).join(', ') + ((d.afterNames || []).join(',') !== (d.names || []).join(',') ? ' → ' + (d.afterNames || []).join(', ') : '') })),
            el('tr', {}, el('th', { text: 'used by' }), el('td', {}, u.location ? u.location + ': ' : '', userLink, d.via && d.via.name && d.via.name !== u.name ? el('span', { class: 'muted', text: ' via group ' + d.via.location + ': ' + d.via.name }) : null)),
            el('tr', {}, el('th', { text: 'before' }), el('td', { class: 'wrap' }, list(d.before.content, d.after.content))),
            el('tr', {}, el('th', { text: 'after' }), el('td', { class: 'wrap' }, list(d.after.content, d.before.content)))])),
        el('div', { class: 'explaincols' },
            el('div', {}, el('h4', { text: 'Before the merge' }), trace(d.before.resolution)),
            el('div', {}, el('h4', { text: 'After the merge (simulated)' }), trace(d.after.resolution))),
        el('h4', { text: 'Simulated changes of this merge step' }),
        changes.length ? el('pre', { class: 'log', text: changes.join('\n') }) : el('p', { class: 'muted', text: 'none' }),
        el('details', {}, el('summary', { text: 'pan-os-php message' }), el('pre', { class: 'log', text: d.reason || '' })));
    document.addEventListener('keydown', onKey);
    document.body.append(overlay);
}

// merger-possible-report: status of a finding (pan-os-php MERGERPOSSIBLEREPORT) - the problems first
const MERGE_PROBLEM = ['conflict', 'would-change-policy', 'not-checked'];
const MERGE_ORDER = ['conflict', 'would-change-policy', 'not-checked', 'merge-into-parent', 'merge-ok', 'unchecked'];

/** the settings a merger run ran with: its pan-os-php arguments without the files of the run */
function mergerSettings(r) {
    return (r.args || []).filter(a => !/^(out|exportjson|exportcsv)=/i.test(a));
}

/** the report of a merger run (merger.json) as tables, with a text filter */
async function showMergerReport(base, r, out) {
    const res = await fetch(API + '/' + base + '/runs/' + r.jid + '/files/merger.json', { credentials: 'same-origin' });
    if (!res.ok) throw new Error('the run has no report (merger.json) - see run.log');
    const rep = await res.json();
    // "Explain" buttons (cells are copied when drawn: one click handler on the report, the detail by number)
    const explains = [];
    const pid = base.split('/')[1];
    const link = (x) => { const h = new URLSearchParams({ p: pid, c: r.cid, type: x.type, location: x.location, filter: '(name eq ' + x.name + ')' }); if (x.ruletype) h.set('ruletype', x.ruletype); return window.location.pathname + '#' + h.toString(); };
    const explainBtn = (d) => { explains.push(d); return el('button', { type: 'button', class: 'small explainbtn', 'data-explain': String(explains.length - 1), text: 'Explain', title: 'why the merge would change the policy' }); };
    out.onclick = (ev) => { const b = ev.target.closest('[data-explain]'); if (b && explains[+b.dataset.explain]) explainMergeSafety(explains[+b.dataset.explain], link); };
    const ref = (x) => x ? (x.location ? x.location + ': ' : '') + x.name + (x.detail ? ' ' + x.detail : '') : '';
    const val = (v) => Array.isArray(v) ? v.join(', ') : (v === null || v === undefined ? '' : String(v));
    const filterBox = el('input', { placeholder: 'filter the rows (text)', autocomplete: 'off', spellcheck: false, 'aria-label': 'filter' });
    const sections = [];
    // one table: head, rows (array of cell texts); filtered by the text box
    // the object type of the rows (first column 'object type' of a part): one choice for all parts
    const typeSel = el('select', { 'aria-label': 'object type' }, el('option', { value: '', text: 'all object types' }));
    const typesSeen = new Set();
    // merger-possible-report: can the copies be merged (status of the merge check of pan-os-php)
    const statusSel = el('select', { 'aria-label': 'merge status' }, el('option', { value: '', text: 'all findings' }),
        el('option', { value: 'problem', text: 'can NOT be merged (conflict, would change policy, not checked)' }),
        el('option', { value: 'merge-ok', text: 'can be merged (merge ok)' }), el('option', { value: 'conflict', text: 'conflict: same name, other value' }),
        el('option', { value: 'would-change-policy', text: 'would change the policy' }), el('option', { value: 'not-checked', text: 'not checked: kept copy not visible there' }),
        el('option', { value: 'merge-into-parent', text: 'merge into the common parent (allowMergingWithUpperLevel)' }),
        el('option', { value: 'unchecked', text: 'no merge check (type without / mergecheck off)' }));
    const section = (title, head, rows) => {
        const body = el('tbody', {});
        const count = el('span', { class: 'muted' });
        const typeCol = head[0] === 'object type' ? 0 : -1;
        // the choice offers only the types that have rows outside the summary (findings, merged, not merged)
        if (typeCol === 0 && title !== 'Summary') rows.forEach(cells => { if (cells[0]) typesSeen.add(cells[0]); });
        // a column 'merge' (merger-possible-report): filtered by the choice "can / can not be merged"
        const statusCol = head.indexOf('merge');
        let limit = 500;
        const more = el('button', { type: 'button', class: 'small', onclick: () => { limit = Infinity; draw(); } });
        const draw = () => {
            const q = filterBox.value.trim().toLowerCase(), t = typeSel.value, st = statusSel.value;
            const shown = rows.filter(cells => (!t || typeCol < 0 || cells[typeCol] === t)
                && (!st || statusCol < 0 || (st === 'problem' ? MERGE_PROBLEM.includes(cells[statusCol]) : cells[statusCol] === st))
                && (!q || cells.map(cellText).join(' ').toLowerCase().includes(q)));
            count.textContent = ' (' + shown.length + (shown.length !== rows.length ? ' of ' + rows.length : '') + ')';
            // a long list: the first 500 rows, the rest on request (no row is left out without saying so)
            body.replaceChildren(...shown.slice(0, limit).map(cells => el('tr', { class: statusCol >= 0 && MERGE_PROBLEM.includes(cells[statusCol]) ? 'warnrow' : '' },
                cells.map(c => typeof c === 'string' ? el('td', { class: 'wrap', text: c }) : el('td', { class: 'wrap' }, c.cloneNode(true))))));
            more.hidden = shown.length <= limit;
            more.textContent = 'show all ' + shown.length + ' rows (' + (shown.length - limit) + ' more)';
        };
        sections.push(draw);
        // every part can be folded: only its title (with the number of rows) stays
        const d = el('details', { class: 'mergersection', open: true }, el('summary', {}, el('h4', {}, title, count)),
            rows.length === 0 ? el('p', { class: 'muted', text: 'none' }) : el('table', { class: 'plain mergertable' }, el('thead', {}, el('tr', {}, head.map(h => el('th', { text: h })))), body), more);
        folds.push(d);
        return d;
    };
    const folds = [];
    let parts = [];
    if (rep.type === 'merger-possible-report') {
        parts.push(section('Summary', ['object type', 'objects', 'same name + value', 'same name, other value', 'overlapping', 'same value, other names', 'merge ok', 'merge into parent', 'would change policy'],
            Object.entries(rep.summary || {}).map(([t, s]) => [t, s.objects, s['same-name-same-value'], s['same-name-different-value'], s['overlapping-conflicts'], s['same-value-different-names'], rep.mergecheck ? s['merge-ok'] : '', rep.mergecheck ? (s['merge-into-parent'] || 0) : '', rep.mergecheck ? s['merge-blocked'] : ''].map(val))));
        // copies "location:name=value": the values marked against the first copy (what differs in a conflict)
        const copiesCell = (copies) => {
            const items = copies.map(c => { const i = c.indexOf('='); return i < 0 ? { prefix: c, value: '' } : { prefix: c.slice(0, i + 1), value: c.slice(i + 1) }; });
            return items.length > 1 && items.some(it => it.value !== items[0].value) ? diffLines(items, items[0].value) : copies.join('\n');
        };
        // the ones that can NOT be merged first (conflict, would change the policy, not checked), then by type
        const rank = (x) => { const i = MERGE_ORDER.indexOf(x.status || 'unchecked'); return i < 0 ? MERGE_ORDER.length : i; };
        const findings = (rep.findings || []).slice().sort((a, b) => rank(a) - rank(b) || String(a.type).localeCompare(String(b.type)));
        parts.push(section('Findings', ['object type', 'merge', 'finding', 'name(s)', 'overlapping', 'kept copy', 'can not be merged (copy: reason)', 'copies (location:name=value)'],
            findings.map(x => [x.type, x.status || 'unchecked', x.kind, x.key, x.overlap,
                (x.keep || '') + (x.parent ? '\n→ copy in the common parent ' + x.parent + ' (object-merger allowMergingWithUpperLevel): ' + (x.intoParent || []).join(', ') : ''),
                (x.blocked || []).some(b => b.detail) ? el('span', {}, ...(x.blocked || []).flatMap((b, i) => [i ? el('br') : '', b.copy + ': ' + b.reason, b.detail ? ' ' : '', b.detail ? explainBtn(Object.assign({ copy: b.copy }, b.detail)) : '']),
                    ...(x.notChecked || []).flatMap(n => [el('br'), n + ': not checked - kept copy not visible there']))
                    : (x.blocked || []).map(b => b.copy + ': ' + b.reason).concat((x.notChecked || []).map(n => n + ': not checked - kept copy not visible there')).join('\n'),
                copiesCell(x.copies || [])].map(c => c !== null && typeof c === 'object' && c.nodeType ? c : val(c)))));
    } else if (rep.type === 'rule-merger') {
        const s = rep.summary || {};
        parts.push(el('p', { text: (s.merged || 0) + ' rule(s) kept with ' + (s.removed || 0) + ' merged into them; ' + (s.skipped || 0) + ' not merged (with the reason)' }));
        const main = (f) => ['from', 'to', 'source', 'destination', 'service', 'application', 'action'].map(k => k + ': ' + val((f || {})[k])).join('\n');
        parts.push(section('Merged', ['rule (kept)', 'location', 'rule base', 'merged into it', 'after the merge'],
            (rep.merged || []).map(m => [m.rule, m.location, m.rulebase, m.removed.map(x => x.name).join('\n'), main(m.after)])));
        parts.push(section('Not merged', ['rule', 'location', 'rule base', 'not merged with', 'reason', 'deny rule'],
            (rep.skipped || []).flatMap(x => (x.notMergedWith.length ? x.notMergedWith : [{ name: '', reason: '' }]).map(n => [x.rule, x.location, x.rulebase, n.name, n.reason, x.denyRules.map(d => d.name).join(', ')]))));
    } else {
        const sum = Object.entries(rep.summary || {});
        parts.push(section('Summary', ['object type', 'kept (merged)', 'removed', 'not merged'], sum.map(([t, x]) => [t, x.merged, x.removed, x.skipped].map(val))));
        parts.push(section('Merged', ['object type', 'value / key', 'kept', 'removed (replaced by the kept one)'],
            (rep.merged || []).map(m => [m.objecttype, m.key, ref(m.kept), m.removed.map(ref).join('\n')])));
        // the values (detail: {value:…}, {prot:…}{dport:…}) of kept and not merged copies: the differences marked
        const head = (x) => x ? (x.location ? x.location + ': ' : '') + x.name + ' ' : '';
        parts.push(section('Not merged', ['object type', 'value / key', 'kept', 'not merged with', 'reason'],
            (rep.skipped || []).map(m => {
                const kd = m.kept ? m.kept.detail || '' : '', od = (m.notMergedWith[0] || {}).detail || '';
                const reason = (m.reason || []).map(x => x.trim()).join('\n');
                return [m.objecttype, m.key, m.kept ? diffLines([{ prefix: head(m.kept), value: kd }], od) : '',
                    diffLines(m.notMergedWith.map(x => ({ prefix: head(x), value: x.detail || '' })), kd),
                    m.safety && m.safety.length ? el('span', {}, reason, ...m.safety.map(d => el('span', {}, el('br'), explainBtn(d), m.safety.length > 1 ? ' ' + d.copy : ''))) : reason];
            })));
    }
    filterBox.addEventListener('input', () => sections.forEach(d => d()));
    statusSel.addEventListener('change', () => sections.forEach(d => d()));
    typeSel.addEventListener('change', () => sections.forEach(d => d()));
    [...typesSeen].sort().forEach(t => typeSel.append(el('option', { value: t, text: t })));
    out.dataset.jid = r.jid;
    out.replaceChildren(el('h3', { text: 'Report: ' + r.type + ' - ' + fmtTime(r.started) }),
        state.project && state.project.role !== 'read' ? el('p', {}, el('button', { type: 'button', class: 'small', text: 'Support file for this run',
            title: 'a support file for the support of pan-os-php with this run, its report and the objects of the report', onclick: () => run(async () => {
                state.supportPreset = { cid: r.cid, run: r.jid }; state.projectTab = state.projectTab || {}; state.projectTab[pid] = 'support'; await showProject(pid); }) })) : null,
        el('p', {}, el('span', { class: 'muted', text: 'Settings: ' }), el('code', { text: ['type=' + r.type].concat(mergerSettings(r)).join(' ') })),
        el('div', { class: 'row' }, typesSeen.size > 0 ? field('Object type', typeSel) : null,
            rep.type === 'merger-possible-report' ? field('Merge', statusSel) : null, field('Filter', filterBox),
            el('button', { type: 'button', class: 'small', text: 'Fold all', onclick: () => folds.forEach(d => { d.open = false; }) }),
            el('button', { type: 'button', class: 'small', text: 'Unfold all', onclick: () => folds.forEach(d => { d.open = true; }) })), ...parts);
    sections.forEach(d => d());
    out.scrollIntoView();
}

// ---------------------------------------------------------------- the change list as a pan-os-php playbook
// source 'unsaved': the unsaved changes of the loaded version; 'version': the changes a saved version was made of.
// One step per change (type, location, filter, actions, comment). Save it as a playbook file of the project (runs,
// playbook editor) or download it.
async function exportPlaybook(pid, cid, source, canWrite) {
    const pb = await api('GET', 'projects/' + pid + '/configs/' + cid + '/playbook?source=' + source);
    const json = JSON.stringify(pb, null, 2);
    const d = new Date(), pad = n => String(n).padStart(2, '0');
    const fileName = el('input', { value: 'changes-' + d.getFullYear() + pad(d.getMonth() + 1) + pad(d.getDate()) + '-' + pad(d.getHours()) + pad(d.getMinutes()) + '.json', maxlength: 120 });
    const box = el('div', { class: 'objwin', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'playbook' });
    const overlay = el('div', { class: 'objoverlay', onclick: (ev) => { if (ev.target === overlay) close(); } }, box);
    const onKey = (ev) => { if (ev.key === 'Escape') close(); };
    function close() { document.removeEventListener('keydown', onKey); overlay.remove(); }
    const blobUrl = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
    box.append(el('div', { class: 'objhead' }, el('h3', { text: 'Playbook: ' + pb.command.length + ' step' + (pb.command.length === 1 ? '' : 's') }),
            el('button', { type: 'button', class: 'objclose', text: '✕', 'aria-label': 'close', onclick: close })),
        el('p', { class: 'muted', text: 'pan-os-php type=playbook runs the steps one after the other - on another version, another configuration or the command line (pan-os-php type=playbook in=… out=… json=<file>). A step with (name eq …) changes that one object; a multi-edit step its filter.' }),
        el('pre', { class: 'log', text: json }),
        el('div', { class: 'row' },
            canWrite ? field('Name of the project file', fileName) : null,
            canWrite ? el('button', { class: 'primary', type: 'button', text: 'Save as playbook file of the project', onclick: () => run(async () => {
                let name = fileName.value.trim(); if (!name) throw new Error('a name is needed');
                if (!/\.json$/i.test(name)) name += '.json';
                const fd = new FormData(); fd.append('file', new Blob([json], { type: 'application/json' }), name);
                await api('POST', 'projects/' + pid + '/files?kind=playbook', fd);
                close(); message('saved as the playbook file ' + name + ' (Runs and project files)');
            }) }) : null,
            el('a', { href: blobUrl, download: fileName.value, text: 'Download', onclick: (ev) => { ev.currentTarget.download = fileName.value.trim() || 'changes.json'; } }),
            el('button', { type: 'button', text: 'Close', onclick: close })));
    document.addEventListener('keydown', onKey);
    document.body.append(overlay);
}

// ---------------------------------------------------------------- support file of a project (todo/support-file.md)
// a run of pan-os-php type=support-file: encrypted for the support of pan-os-php - environment, the case (a run: its
// settings, report, result), an excerpt of the configuration for the names (every copy in every location, groups,
// members, rules - before / after), project data, logs, the errors of this page; options: the whole configuration,
// anonymised (the mapping stays here: a file of the run, never in the support file)
async function supportCard(base, configs, preset) {
    preset = preset || state.supportPreset || {};
    state.supportPreset = null;
    const runs = (await api('GET', base + '/runs')).runs;
    const ver = el('select', {}, configs.map(c => el('option', { value: c.cid, text: c.name + ' (' + fmtTime(c.created) + ')' })));
    if (preset.cid) ver.value = preset.cid;
    const caseRun = el('select', {});
    const fillRuns = () => {
        const list = runs.filter(r => r.cid === ver.value && r.type !== 'support-file' && (r.state === 'done' || r.state === 'failed'));
        caseRun.replaceChildren(el('option', { value: '', text: '- no run (general problem) -' }), ...list.map(r => el('option', { value: r.jid, text: r.type + ' ' + r.jid.slice(0, 8) + ' - ' + r.state + ', ' + fmtTime(r.created) })));
        if (preset.run && list.some(r => r.jid === preset.run)) caseRun.value = preset.run;
    };
    ver.addEventListener('change', fillRuns); fillRuns();
    const names = el('textarea', { rows: 2, spellcheck: false, placeholder: 'optional: object names, comma separated (the names of the report are taken anyway: not merged / blocked ones, merged ones up to 200)' });
    if (preset.names) names.value = preset.names;
    const note = el('textarea', { rows: 3, maxlength: 4000, placeholder: 'what is wrong - e.g. "web1 was merged into web2, but DG-B uses its own web1"' });
    const rules = el('input', { type: 'checkbox', checked: true }), full = el('input', { type: 'checkbox' }), anon = el('input', { type: 'checkbox' }), keepPriv = el('input', { type: 'checkbox' });
    const list = el('div', {});
    const drawList = () => {
        const mine = runs.filter(r => r.type === 'support-file');
        list.replaceChildren(mine.length ? table(['Made', 'By', 'State', 'Files'], mine.map(r => el('tr', {}, el('td', { text: fmtTime(r.created) }), el('td', { text: r.user || '' }),
            el('td', {}, el('span', { class: 'badge' + (r.state === 'failed' ? ' dirty' : ''), text: r.state }), r.error ? ' ' + r.error : ''),
            el('td', {}, r.state === 'done' || r.state === 'failed' ? el('span', {},
                r.state === 'done' ? el('a', { href: API + '/' + base + '/runs/' + r.jid + '/files/support.tsf', text: 'support.tsf' }) : null, ' ',
                el('a', { href: API + '/' + base + '/runs/' + r.jid + '/files/run.log', text: 'run.log' }), ' ',
                (r.args || []).some(a => /^mapping=/.test(a)) && r.state === 'done' ? el('a', { href: API + '/' + base + '/runs/' + r.jid + '/files/mapping-SENSITIVE.json', class: 'warn', text: 'mapping (keep it - never send it)' }) : null)
                : el('span', { class: 'muted', text: 'running ...' })))))
            : el('p', { class: 'muted', text: 'No support file yet.' }));
    };
    drawList();
    return el('div', { class: 'card' }, el('h2', { text: 'Support file' }),
        el('p', { class: 'muted', text: 'For a problem you want the support of pan-os-php to look at: a file you send them (mail, upload). It is encrypted - only the support of pan-os-php can open it. It never contains API keys, the key store, passwords or keys of the configuration (always replaced), sessions or licence keys.' }),
        el('form', { onsubmit: (ev) => { ev.preventDefault(); run(async () => {
            const body = { run: caseRun.value, names: names.value.trim(), note: note.value.trim(), rules: rules.checked, full: full.checked, anonymize: anon.checked,
                ip: keepPriv.checked ? 'keep-private' : 'remap', browser: browserErrors.slice(-100) };
            if (full.checked && !anon.checked && !confirm('The whole configuration goes into the support file - not anonymised (secrets are replaced). Go on?')) return;
            const r = await api('POST', base + '/configs/' + ver.value + '/support-file/runs', body);
            message('support file is being made - it appears below'); runs.unshift(r); drawList();
            const t = setInterval(async () => { const x = await api('GET', base + '/runs/' + r.jid).catch(() => null);
                if (x && (x.state === 'done' || x.state === 'failed')) { clearInterval(t); const i = runs.findIndex(y => y.jid === r.jid); if (i >= 0) runs[i] = x; drawList(); } }, 1500);
            state.timers.push(t);
        }); } },
            el('div', { class: 'row' }, field('Version', ver), field('The run with the problem', caseRun)),
            el('div', { class: 'row' }, el('label', { class: 'grow' }, 'Objects (names)', names)),
            el('div', { class: 'row' }, el('label', { class: 'grow' }, 'What is the problem', note)),
            el('div', { class: 'row' }, field('Rules that use the objects', rules), field('The whole configuration (before / after)', full),
                field('Anonymise everything', anon), field('… keep private IP addresses', keepPriv)),
            el('p', { class: 'muted', text: 'Always in it: versions of pan-os-php / PHP, the settings of the run, its report and log, the hierarchy (device groups / templates), every copy of the objects in every location with the groups that hold them and their members - before and after the run -, project data (versions, last runs, audit of the project) and the last errors of this page. Anonymised: names, addresses and texts become pseudonyms everywhere; the mapping stays here (a file of the run) - keep it, never send it.' }),
            el('button', { class: 'primary', type: 'submit', text: 'Make the support file' })),
        el('h3', { text: 'Support files of this project' }), list);
}

// ---------------------------------------------------------------- tabs of a project (the chosen one is kept per project)
function projectTabs(pid, tabs) {
    tabs = tabs.filter(t => t);
    state.projectTab = state.projectTab || {};
    const panel = el('div', { class: 'tabpanel', role: 'tabpanel' });
    const bar = el('div', { class: 'tabs', role: 'tablist' }, tabs.map(([id, title]) => el('button', { type: 'button', role: 'tab', 'data-tab': id, text: title, onclick: () => show(id) })));
    function show(id) {
        const t = tabs.find(x => x[0] === id) || tabs[0];
        state.projectTab[pid] = t[0];
        for (const b of bar.children) { b.classList.toggle('on', b.dataset.tab === t[0]); b.setAttribute('aria-selected', b.dataset.tab === t[0] ? 'true' : 'false'); }
        panel.replaceChildren(...t[2].filter(x => x));
    }
    show(state.projectTab[pid] || tabs[0][0]);
    return el('div', { class: 'projecttabs' }, bar, panel);
}

// ---------------------------------------------------------------- suggestions while typing (filter, action)
// items(text, cursor) -> { from, to, list: [{ label, detail, insert }] } or null; a chosen item replaces text[from, to)
function suggest(input, items) {
    const box = el('ul', { class: 'suggest', hidden: true });
    let cur = null, sel = -1;
    const close = () => { box.hidden = true; sel = -1; };
    function pick(i) {
        const it = cur && cur.list[i];
        if (!it) return;
        const v = input.value;
        input.value = v.slice(0, cur.from) + it.insert + v.slice(cur.to);
        const at = cur.from + it.insert.length;
        input.focus(); input.setSelectionRange(at, at);
        input.dispatchEvent(new Event('input'));
        input.dispatchEvent(new Event('change'));
    }
    function update() {
        cur = document.activeElement === input ? items(input.value, input.selectionStart === null ? input.value.length : input.selectionStart) : null;
        if (!cur || cur.list.length === 0) return close();
        sel = -1;
        box.replaceChildren(...cur.list.slice(0, 60).map((it, i) => el('li', { title: it.label + (it.detail ? '  ' + it.detail : ''), onmousedown: (ev) => { ev.preventDefault(); pick(i); } },
            el('span', { text: it.label }), it.detail ? el('small', { class: 'muted', text: '  ' + it.detail }) : null)));
        box.hidden = false;
    }
    for (const ev of ['input', 'focus', 'click']) input.addEventListener(ev, update);
    // a click into the list does not take the focus (mousedown: preventDefault), so leaving the field closes it
    input.addEventListener('blur', close);
    input.addEventListener('keydown', (ev) => {
        if (box.hidden) return;
        const n = box.children.length;
        if (ev.key === 'ArrowDown') sel = (sel + 1) % n;
        else if (ev.key === 'ArrowUp') sel = (sel - 1 + n) % n;
        else if ((ev.key === 'Enter' || ev.key === 'Tab') && sel >= 0) { ev.preventDefault(); pick(sel); return; }
        else if (ev.key === 'Escape') { close(); return; }
        else return;
        ev.preventDefault();
        [...box.children].forEach((li, i) => li.classList.toggle('on', i === sel));
        if (box.children[sel]) box.children[sel].scrollIntoView({ block: 'nearest' });
    });
    return el('span', { class: 'suggestwrap' }, input, box);
}

// the pan-os-php filter of a type: "(field operator value) and (...)" - fields and operators from util_action_filter.json
function filterSuggest(filters, text, pos) {
    const before = text.slice(0, pos);
    const open = before.lastIndexOf('('), shut = before.lastIndexOf(')');
    const has = (a, b) => a.toLowerCase().includes(b.toLowerCase());
    // what starts with the typed text first, then what contains it
    const rank = (list, w, key) => list.filter(x => has(key(x), w)).sort((a, b) => (key(b).toLowerCase().startsWith(w.toLowerCase()) ? 1 : 0) - (key(a).toLowerCase().startsWith(w.toLowerCase()) ? 1 : 0));
    if (open > shut) {
        const seg = before.slice(open + 1), parts = seg.split(' ');
        if (parts.length === 1)
            return { from: open + 1, to: pos, list: rank(Object.keys(filters), parts[0], f => f).map(f => ({ label: f, detail: Object.keys(filters[f]).length + ' operators', insert: f + ' ' })) };
        const ops = filters[parts[0]];
        if (!ops) return null;
        if (parts.length === 2)
            return { from: open + 1 + parts[0].length + 1, to: pos, list: rank(Object.entries(ops), parts[1], ([o]) => o).map(([o, d]) => ({
                label: o, detail: (d.arg ? 'value' + (d.example ? ', e.g. ' + d.example : '') : 'no value') + (d.help ? ' - ' + d.help : ''), insert: o + (d.arg ? ' ' : ')') })) };
        return null;
    }
    // outside a term: after a term "and (" / "or (", else a new term with a field
    const word = (before.match(/[^\s()!]*$/) || [''])[0], from = pos - word.length;
    if (/\)\s*$/.test(before.slice(0, from)))
        return { from, to: pos, list: ['and (', 'or (', 'and !('].filter(x => x.startsWith(word.toLowerCase())).map(x => ({ label: x, insert: x })) };
    return { from, to: pos, list: rank(Object.keys(filters), word, f => f).map(f => ({ label: '(' + f, detail: Object.keys(filters[f]).length + ' operators', insert: '(' + f + ' ' })) };
}

// ---------------------------------------------------------------- viewer / editor
// preset (a link "Open" of a reference, in a new window): type, ruletype, securityprofiletype, location, filter
// ---------------------------------------------------------------- the menu of the viewer (as in PAN-OS)
// an entry: a pan-os-php type (+ rule type, + a filter of its own); 'window': the object opens in the object window
const VIEWER_MENU_SECTIONS = ['Objects', 'Policies', 'Network', 'Device', 'Other'];
const VIEWER_MENU = [
    ['Objects', 'addresses', 'Addresses', 'address', { filter: '!(object is.group)', window: 'address', one: 'Address' }],
    ['Objects', 'address-groups', 'Address Groups', 'address', { filter: '(object is.group)', window: 'addressgroup', one: 'Address Group' }],
    ['Objects', 'services', 'Services', 'service', { filter: '!(object is.group)', window: 'service', one: 'Service' }],
    ['Objects', 'service-groups', 'Service Groups', 'service', { filter: '(object is.group)', window: 'servicegroup', one: 'Service Group' }],
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
    ['Network', 'interfaces', 'Interfaces', 'interface'],
    ['Network', 'virtual-wires', 'Virtual Wires', 'virtualwire'],
    ['Network', 'routing', 'Virtual Routers / Routing', 'routing'],
    ['Network', 'static-routes', 'Static Routes', 'static-route'],
    ['Network', 'ike-gateways', 'IKE Gateways', 'ike-gateway'],
    ['Network', 'ipsec-tunnels', 'IPSec Tunnels', 'ipsec-tunnel'],
    ['Network', 'gre-tunnels', 'GRE Tunnels', 'gre-tunnel'],
    ['Network', 'dhcp', 'DHCP', 'dhcp'],
    ['Network', 'gp-portals', 'GlobalProtect Portals', 'gp-portal'],
    ['Network', 'gp-gateways', 'GlobalProtect Gateways', 'gp-gateway'],
    ['Network', 'gp-gateway-tunnels', 'GlobalProtect Gateway Tunnels', 'gpgateway-tunnel'],
    ['Network', 'ike-profiles', 'IKE Crypto Profiles', 'ike-profile'],
    ['Network', 'ipsec-profiles', 'IPSec Crypto Profiles', 'ipsec-profile'],
    ['Network', 'interface-mgmt-profiles', 'Interface Management Profiles', 'interface-management-profile'],
    ['Network', 'zone-protection-profiles', 'Zone Protection Profiles', 'zone-protection-profile'],
    ['Device', 'devices', 'Devices', 'device'],
    ['Device', 'certificates', 'Certificates', 'certificate'],
    ['Device', 'certificate-profiles', 'Certificate Profiles', 'certificate-profile'],
    ['Device', 'ssl-tls-profiles', 'SSL/TLS Service Profiles', 'ssl-tls-service-profile'],
    // DNS rules are comparable to the threat rules (no policies): both under Other
    ['Other', 'threat-rules', 'Threat Rules', 'threat-rule'],
    ['Other', 'dns-rules', 'DNS Rules', 'dns-rule'],
];
/** the entries the user can open: types of the meta (and of a limited access); every other type of the meta under "Other" */
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
    function drawMenu() {
        const limitedHere = !!(p.types || p.scope);
        menu.replaceChildren(...[limitedHere ? null : el('div', { class: 'vsec' }, el('div', { class: 'vsechead', text: 'System' }),
            el('button', { type: 'button', class: 'ventry', text: 'System settings', title: 'management, system, administrators, authentication, logging, updates (type=config-section)',
                onclick: () => run(showSystem) }))].filter(x => x), ...VIEWER_MENU_SECTIONS.map(sec => {
            const list = entries.filter(e => e.section === sec);
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
    const locationInfo = { config: null, ancestor: false };
    async function loadLocations() {
        if (locationsLoaded) return;
        locationsLoaded = true;
        const r = await api('GET', base() + '/locations').catch(() => null);
        if (r) Object.assign(locationInfo, { config: r.config, ancestor: !!r.ancestor });
        if (r) drawSpTypes(r.config);
        if (!r || !r.locations.length) return;
        const was = location.value, kinds = { 'shared': 'shared', 'device-group': 'device groups', 'vsys': 'vsys', 'shared-gateway': 'shared gateways', 'container': 'containers (folders)', 'snippet': 'snippets' };
        const groups = [...new Set(r.locations.map(l => l.kind))].map(k => el('optgroup', { label: kinds[k] || k },
            r.locations.filter(l => l.kind === k).map(l => el('option', { value: l.name, text: l.name }))));
        location.replaceChildren(...(r.any ? [el('option', { value: 'any', text: 'any (all locations)' })] : []), ...groups);
        if ([...location.options].some(o => o.value === was)) location.value = was;
        drawDgScope();
        filterLocations();
    }
    // Panorama: a device group with its child device groups (pan-os-php location=<DG>:includechilddgs) or only its
    // child device groups (location=<DG>:excludemaindg) - offered when a device group is chosen as location; not with
    // access limited to locations (a child device group may be outside the scope)
    const dgScope = el('select', {}, el('option', { value: '', text: 'only this device group' }),
        el('option', { value: 'includechilddgs', text: '+ all child device groups (includechilddgs)' }),
        el('option', { value: 'excludemaindg', text: 'only the child device groups (excludemaindg)' }),
        // the effective view (viewer): the location and all levels above it, the copy that wins per name marked
        el('option', { value: 'effective', text: '+ parents (effective view)' }));
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
    // the kind of a location for the choice: a device group, shared of Panorama (all device groups are below it) or an
    // SCM container (folder: containers, cloud / on-prem devices below it); null: no choice (vsys, snippet, any)
    function scopeKind(name) {
        const o = [...location.options].find(x => x.value === name);
        const group = o && o.parentElement && o.parentElement.tagName === 'OPTGROUP' ? o.parentElement.label : '';
        if (group === 'device groups') return 'dg';
        if (group === 'containers (folders)') return 'container';
        if (name === 'shared' && [...location.querySelectorAll('optgroup')].some(g => g.label === 'device groups')) return 'shared';
        if (group === 'vsys' || group === 'shared gateways') return 'vsys';
        return null;
    }
    function drawDgScope() {
        const kind = scopeKind(location.value);
        dgScopeField.hidden = !!p.scope || kind === null;
        if (dgScopeField.hidden) { dgScope.value = ''; return; }
        const t = { dg: ['only this device group', '+ all child device groups', 'only the child device groups', '+ parents up to shared (effective view)'],
            shared: ['only shared', '+ all device groups', 'only the device groups', null],
            container: ['only this container', '+ all child containers / devices', 'only the child containers / devices', '+ snippets and parents up to All (effective view)'],
            vsys: ['only this vsys', null, null, '+ shared (effective view)'] }[kind];
        [...dgScope.options].forEach((o, i) => { o.hidden = t[i] === null; if (t[i] !== null) o.text = t[i] + (o.value && o.value !== 'effective' ? ' (' + o.value + ')' : ''); });
        if (dgScope.selectedOptions[0] && dgScope.selectedOptions[0].hidden) dgScope.value = '';
        dgScopeField.firstChild.textContent = kind === 'container' ? 'Containers' : (kind === 'vsys' ? 'Scope' : 'Device groups');
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

    function typeChanged() {
        view.template = null;
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
        const eff = dgScope.value === 'effective' && !dgScopeField.hidden && location.value && location.value !== 'any';
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
            + (dgScope.value === 'effective' && !dgScopeField.hidden ? ' - effective view: ' + (locationInfo.config === 'panorama'
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
        if (ref.template && ref.location) h.set('at', ref.location);
        for (const k of ['ruletype', 'securityprofiletype', 'devicetype', 'template', 'profile']) if (ref[k]) h.set(k, ref[k]);
        return window.location.pathname + '#' + h.toString();
    }
    // the references of one object as a box (list rows and the object window): who uses it, each with "Open ↗"
    function refsTable(refs) {
        return table(['Used by', 'Location', 'Name', 'Where', ''], refs.map(ref => el('tr', {},
            el('td', { text: ref.type ? ref.type + (ref.ruletype ? ' (' + ref.ruletype + ')' : '') + (ref.securityprofiletype ? ' (' + ref.securityprofiletype + ')' : '') + (ref.devicetype ? ' (' + ref.devicetype + ')' : '') : ref.class }),
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
    function cell(v) { return Array.isArray(v) ? v.join(', ') : (v === null || v === undefined ? '' : String(v)); }
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
        const desc = { key: 'description', label: 'Description', kind: 'text', value: row.description || '', needs: ['description-delete', 'description-append'],
            act: (o, n) => n === '' ? 'description-delete' : (o === '' ? '' : 'description-delete/') + 'description-append:' + ruleText(n) };
        const tags = { key: 'tag', label: 'Tags', kind: 'list', value: Array.isArray(m.tag) ? m.tag : [], needs: ['tag-add'], needsRemove: ['tag-remove'],
            add: t => 'tag-add:' + actArg(t), remove: t => 'tag-remove:' + actArg(t) };
        const loc = { key: 'location', label: 'Location', kind: 'ro', value: row.location };
        if (kind === 'address')
            return [name, { key: 'type', label: 'Type', kind: 'ro', value: row.type },
                row.type === 'ip-netmask' ? { key: 'value', label: 'Value', kind: 'text', value: row.value || '', needs: ['value-replace'],
                    act: (o, n) => { if (n === '') throw new Error('a value is needed'); return 'value-replace:' + actArg(o) + ',' + actArg(n); } }
                    : { key: 'value', label: 'Value', kind: 'ro', value: row.value || '', note: 'only an ip-netmask value can be changed (pan-os-php value-replace)' },
                desc, tags, loc];
        if (kind === 'addressgroup')
            return [name, { key: 'type', label: 'Type', kind: 'ro', value: row.type },
                Array.isArray(m.static) ? { key: 'members', label: 'Members', kind: 'list', value: m.static, needs: ['add-member'], add: x => 'add-member:' + actArg(x),
                    note: 'removing a member: no pan-os-php action yet' }
                    : { key: 'filter', label: 'Dynamic filter', kind: 'ro', value: row.filter || '', note: 'no pan-os-php action to change it yet' },
                desc, tags, loc];
        if (kind === 'service') {
            const timeout = (key, label, action, def) => ({ key, label, kind: 'text', value: row[key] || '', needs: [action], placeholder: 'default ' + def + ' (= inherit)',
                act: (o, n) => { if (n === '') throw new Error('empty: use "Inherit all timeouts"'); if (!/^[0-9]+$/.test(n)) throw new Error('seconds (digits)'); return action + ':' + n; } });
            return [name, { key: 'value', label: 'Protocol / port', kind: 'ro', value: row.value || '', note: 'no pan-os-php action to change it yet' },
                desc, tags,
                { key: 'sourceport', label: 'Source port', kind: 'text', value: row.sourceport || '', needs: ['sourceport-set', 'sourceport-delete'],
                    act: (o, n) => n === '' ? 'sourceport-delete' : 'sourceport-set:' + actArg(n) },
                timeout('timeout', 'Timeout', 'timeout-set', 3600), timeout('halfclosetimeout', 'Half-close timeout', 'timeout-halfclose-set', 120),
                timeout('timewaittimeout', 'Time-wait timeout', 'timeout-timewait-set', 15),
                { key: 'timeouts', label: '', kind: 'button', text: 'Inherit all timeouts', needs: ['timeout-inherit'], act: () => 'timeout-inherit' }, loc];
        }
        if (kind === 'servicegroup')
            return [name, { key: 'members', label: 'Members', kind: 'ro', value: (Array.isArray(m.members) ? m.members : []).join(', '), note: 'no pan-os-php action to change members of a service group yet' },
                tags, loc];
        if (kind === 'rule') return ruleFields(row, m, name, loc);
        if (kind === 'zone') {
            const bool = (key, label, action) => ({ key, label, kind: 'select', value: '', choices: ['', 'yes', 'no'], needs: [action],
                note: 'the current value is not in the list of pan-os-php - choose to set it', act: (o, n) => n === '' ? '' : action + ':' + (n === 'yes' ? 'true' : 'false') });
            return [name, { key: 'type', label: 'Type', kind: 'ro', value: m.network ? Object.keys(m.network).join(', ') : (row.type || '') },
                { key: 'interfaces', label: 'Interfaces', kind: 'ro', value: fmtTree(m.network) || fmtTree(row.interfaces) || '-' },
                { key: 'zpp', label: 'Zone protection profile', kind: 'text', value: row.zpp || '', needs: ['zpp-set'],
                    act: (o, n) => { if (n === '') throw new Error('removing it: no pan-os-php action yet'); return 'zpp-set:' + actArg(n); } },
                { key: 'log', label: 'Log setting', kind: 'text', value: row.log || '', placeholder: 'empty = PAN-OS default', needs: ['logsetting-set'], act: (o, n) => 'logsetting-set:' + (n === '' ? 'none' : actArg(n)) },
                bool('userid', 'User identification', 'userid-enable'), bool('pbp', 'Packet buffer protection', 'packetbufferprotection-set'),
                row.template ? { key: 'template', label: 'Template', kind: 'ro', value: row.template } : null, loc].filter(f => f);
        }
        if (kind === 'generic') {
            // every other type: all its fields, read only - the list row and what the structured model adds
            const skip = ['name', 'location', 'template', 'refcount', 'store', 'model'];
            const edit = deviceFields(row);
            // a device: its connections (device group, template stack, templates, firewalls, log collectors) are in
            // the section "Connections" of the window, with a link each
            if (DEVICE_LINKS[row.type]) skip.push('templates', 'devices', 'dg', 'templatestack', 'device-template', 'collectors', 'collectorgroups', 'devicegroups', 'logforwarding', 'children', 'hierarchy', 'templatestacks', 'stacktemplates', 'parent', 'clouds', 'onprem', 'snippets', 'containers', 'manageddevice', 'on-prem', 'vsyscontainer', 'variables', 'effective', 'devicevariables');
            const fields = [{ key: 'name', label: 'Name', kind: 'ro', value: row.name }];
            for (const [k, v] of Object.entries(row)) if (!skip.includes(k)) fields.push({ key: k, label: k, kind: 'ro', value: typeof v === 'object' && v !== null && !Array.isArray(v) ? fmtTree(v) : (Array.isArray(v) ? v.join(', ') : (v === null ? '' : String(v))) });
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
            { key: 'description', label: 'Description', kind: 'text', value: row.description || '', needs: ['description-append', 'description-replace-character'],
                act: (o, n) => o === '' ? (n === '' ? '' : 'description-append:' + ruleText(n)) : 'description-replace-character:' + ruleText(o) + ',' + ruleText(n) },
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
            m.category !== undefined || row.urlcategory !== undefined ? { key: 'category', label: 'URL category', kind: 'ro', value: listOf(m.category !== undefined ? m.category : row.urlcategory).join(', ').replace('**ANY**', 'any') || 'any', note: 'no pan-os-php action to change it yet' } : null,
            m.action !== undefined && sec ? { key: 'action', label: 'Action', kind: 'select', value: m.action, choices: ['allow', 'deny', 'drop', 'reset-client', 'reset-server', 'reset-both'], needs: ['action-set'], act: (o, n) => 'action-set:' + n }
                : ( m.action !== undefined ? { key: 'action', label: 'Action', kind: 'ro', value: m.action } : null),
            sec ? { key: 'profilegroup', label: 'Profile group', kind: 'text', value: row.securityprofilegroup && row.securityprofilegroup !== 'null' ? row.securityprofilegroup : '', needs: ['securityprofile-group-set', 'securityprofile-remove'],
                act: (o, n) => n === '' ? 'securityprofile-remove:any' : 'securityprofile-group-set:' + actArg(n) } : null,
            sec && row.securityprofile && row.securityprofile !== 'null' ? { key: 'profiles', label: 'Profiles', kind: 'ro', value: typeof row.securityprofile === 'string' ? row.securityprofile : fmtTree(row.securityprofile) } : null,
            sec ? { key: 'logsetting', label: 'Log forwarding', kind: 'text', value: m.log_setting || '', needs: ['logsetting-set'], act: (o, n) => n === '' ? (() => { throw new Error('removing the log forwarding: no pan-os-php action yet'); })() : 'logsetting-set:' + actArg(n) } : null,
            sec ? { key: 'logstart', label: 'Log at session start', kind: 'select', value: yesno(log.start), choices: ['no', 'yes'], needs: ['logstart-enable', 'logstart-disable'], act: (o, n) => n === 'yes' ? 'logstart-enable' : 'logstart-disable' } : null,
            sec ? { key: 'logend', label: 'Log at session end', kind: 'select', value: yesno(log.end), choices: ['no', 'yes'], needs: ['logend-enable', 'logend-disable'], act: (o, n) => n === 'yes' ? 'logend-enable' : 'logend-disable' } : null,
            sec ? { key: 'schedule', label: 'Schedule', kind: 'text', value: m.schedule || '', needs: ['schedule-set', 'schedule-remove'], act: (o, n) => n === '' ? 'schedule-remove' : 'schedule-set:' + actArg(n) } : null,
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
        async function listChange(f, actions) {
            delete errors[f.key];
            try { await apply(f, actions); obj = await fetchObject(obj.row.name, obj.row.location, obj.row.template, obj.row.profile, obj.row.type); } catch (e) { errors[f.key] = e.message; }
            render();
        }
        function control(f) {
            if (f.kind === 'buttons') {
                const bs = f.buttons.filter(b => canWrite && offered[b[0]]);
                return bs.length ? el('div', { class: 'row' }, bs.map(b => el('button', { type: 'button', text: b[1], onclick: () => run(() => listChange(f, b[0])) })))
                    : el('span', { class: 'muted', text: 'read only' });
            }
            const can = canWrite && f.kind !== 'ro' && (f.needs || []).every(a => offered[a]);
            if (f.kind === 'ro' || !can)
                return el('span', { class: 'objro', text: Array.isArray(f.value) ? f.value.join(', ') : String(f.value === undefined ? '' : f.value) });
            if (f.kind === 'text') {
                const i = el('input', { value: f.value, autocomplete: 'off', spellcheck: false, 'aria-label': f.label, placeholder: f.placeholder || null });
                // applied when the field is left after a change (or Enter) - one action, no common OK
                i.addEventListener('change', () => run(() => change(f, i.value.trim())));
                i.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); i.blur(); } });
                return i;
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
            return el('div', { class: 'chips' }, f.any ? el('span', { class: 'chip any', text: 'any' }) : null, f.value.map(v => el('span', { class: 'chip' }, v,
                canRemove ? el('button', { type: 'button', class: 'chipx', text: '✕', title: 'remove ' + v, 'aria-label': 'remove ' + v, onclick: () => run(async () => {
                    try { await listChange(f, f.remove(v)); } catch (e) { errors[f.key] = e.message; render(); } }) }) : null)), add, extra);
        }
        function render() {
            const fields = windowFields(cur.window, obj.row, obj.model);
            box.replaceChildren(
                el('div', { class: 'objhead' }, el('h3', { text: (cur.one || cur.label) + ': ' + obj.row.name }), obj.row.template ? el('span', { class: 'badge', text: 'template ' + obj.row.template }) : null, el('span', { class: 'badge', text: obj.row.location }),
                    el('button', { type: 'button', class: 'objclose', text: '✕', 'aria-label': 'close', onclick: close })),
                el('table', { class: 'objfields' }, el('tbody', {}, fields.map(f => {
                    const can = f.kind === 'buttons' || (canWrite && f.kind !== 'ro' && (f.needs || []).every(a => offered[a]));
                    return el('tr', {}, el('th', { text: f.label }), el('td', {}, control(f),
                        errors[f.key] ? el('div', { class: 'error', text: errors[f.key] }) : null,
                        done[f.key] ? el('div', { class: 'muted objact' }, '✓ ', el('code', { text: done[f.key] })) : null,
                        f.note && (f.kind === 'ro' || f.kind === 'list' || !can) ? el('div', { class: 'muted', text: f.note }) : null,
                        !canWrite || f.kind === 'ro' || can ? null : el('div', { class: 'muted', text: 'read only: no pan-os-php action for it here (' + (f.needs || []).filter(a => !offered[a]).join(', ') + ')' })));
                }))),
                el('p', { class: 'muted', text: canWrite ? 'A field is applied when you leave it after a change (or press Enter) - as one pan-os-php action on this object; nothing is written until "Save as new version".' : 'read only' }),
                // replaceChildren() writes null as the text "null" - only the sections there are
                ...[objHierarchy(), objLinks(), objVariables(), objRefs(), objXml(), objHistory()].filter(x => x),
                el('div', { class: 'row' }, el('button', { type: 'button', text: 'Close', onclick: close })));
        }
        // the XML of the object (as it is in memory) and its history (git: every commit that changed its entry)
        const opened = {};
        function section(key, title, body) {
            const d = el('details', { class: 'objsection' }, el('summary', { text: title }), body);
            // the hierarchy of a device group is open unless closed (XML / history: closed unless opened)
            d.open = key === 'hierarchy' || key === 'refs' || key === 'links' || key === 'vars' ? opened[key] !== false : !!opened[key];
            d.addEventListener('toggle', () => { opened[key] = d.open; });
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
            return obj.xml ? section('xml', 'XML', el('pre', { class: 'objxml', text: obj.xml }))
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
                field('Location', el('div', { class: 'locpick' }, locFilter, location, locCount)), dgScopeField, sameNameField, spField, devField, el('label', { class: 'grow' }, 'pan-os-php filter (runs on the server)', filterBox),
                el('button', { class: 'primary', type: 'submit', text: 'Show' }), el('button', { type: 'button', text: 'Reload', onclick: () => run(() => load(true)) })),
            heading,
            el('div', { class: 'row' }, field('Quick filter (in the browser)', quick), extraBox, info),
            tableWrap, pager, changesCard, changeBox)));
    drawMenu();
    typeChanged();
    if (preset) {
        // a link from the references: the entry of the type (and rule type) - without the filter of the entry (an address
        // group is in the list of the addresses then)
        if (preset.type && types.includes(preset.type)) {
            const e = entries.find(x => x.type === preset.type && (preset.type !== 'rule' || x.ruletype === (preset.ruletype || 'security'))) || entries.find(x => x.type === preset.type);
            if (e) { cur = Object.assign({}, e, { noBase: !!e.filter }); typeChanged(); drawMenu(); }
        }
        if (preset.securityprofiletype) sptype.value = preset.securityprofiletype;
        if (preset.devicetype) devtype.value = preset.devicetype;
        // an object of a template: the list only of that template (until the filter is changed)
        if (preset.template) view.template = preset.template;
        // a link "Open ↗": the window of that object opens when the list is there
        if (preset.open) view.openAfterLoad = { name: preset.open, location: preset.at || (preset.location === 'any' ? '' : preset.location), template: preset.template || '', profile: preset.profile || '' };
        // a location with the device groups below (<DG>:includechilddgs / :excludemaindg)
        const pl = /^(.+):(includechilddgs|excludemaindg|effective)$/i.exec(preset.location || '');
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
    await showViewer(c, Object.fromEntries(['type', 'ruletype', 'securityprofiletype', 'devicetype', 'location', 'filter', 'template', 'profile', 'open', 'at'].map(k => [k, h.get(k)])));
    return true;
}
run(async () => {
    let me;
    try { me = await api('GET', 'me'); } catch (e) { showLogin(); return; }
    const deep = location.hash.length > 1;
    await entered(me, deep);
    if (deep) await openFromHash();
});
