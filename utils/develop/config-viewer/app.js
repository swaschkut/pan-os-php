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
function message(text, kind) {
    const m = document.getElementById('message');
    m.hidden = !text;
    m.textContent = text || '';
    m.className = kind || 'info';
}
function fmtTime(ts) { return ts ? new Date(ts * 1000).toLocaleString() : ''; }
function fmtSize(n) { return n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.ceil(n / 1024) + ' kB'; }

async function api(method, path, body) {
    const opt = { method, credentials: 'same-origin', headers: {} };
    if (method !== 'GET' && state.csrf) opt.headers['X-CSRF-Token'] = state.csrf;
    if (body instanceof FormData) opt.body = body;
    else if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    const res = await fetch(API + '/' + path, opt);
    let data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    if (res.status === 401 && state.user) { leave(); showLogin(); throw new Error('session ended - please log in again'); }
    if (!res.ok) throw new Error(data && data.error ? data.error : 'request failed (' + res.status + ')');
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
        const kindChanged = () => {
            const k = kKind.value;
            fTarget.hidden = k === 'named'; fNamed.hidden = k !== 'named'; fPort.hidden = k !== 'panos';
            fKey.hidden = k === 'scm'; fId.hidden = fSecret.hidden = k !== 'scm';
            fTarget.firstChild.textContent = { panos: 'Host name / IP address', scm: 'TSG id', egressip: 'TSG id', ldap: 'Bind user (UPN or DOMAIN\\user)', other: 'Entry name' }[k] || '';
            fKey.firstChild.textContent = k === 'ldap' ? 'Password' : k === 'named' || k === 'other' ? 'Value (password / key)' : 'API key';
        };
        kKind.addEventListener('change', kindChanged); kindChanged();
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
            }); } }, field('Kind', kKind), fTarget, fNamed, fPort, field('Label', kLabel), fKey, fId, fSecret, el('button', { class: 'primary', type: 'submit', text: 'Save key' })),
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
            el('table', { class: 'plain' }, el('thead', {}, el('tr', {}, el('th', { text: 'User' }), el('th', { text: 'Admin' }), el('th', { text: 'Created' }), el('th', {}))),
                el('tbody', {}, users.map(u => el('tr', {}, el('td', { text: u.name }), el('td', { text: u.admin ? 'yes' : '' }), el('td', { text: fmtTime(u.created) }),
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
        nodes.push(el('form', { class: 'card', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
            await api('PUT', 'network', { enabled: nOn.checked, allow: nAllow.value, deny: nDeny.value });
            message('network for runs saved'); await showAccount();
        }); } }, el('h2', { text: 'Network for runs (admin)' }),
            el('p', { class: 'muted', text: 'Runs have no network. With this on, an import may download a configuration (read only) from a firewall / Panorama (XML API) or an SCM tenant - with the API key of the user who starts it, in a project whose owner turned network on. Nothing is written to a device. A target must be on the allow list and not on the deny list; an empty allow list allows nothing.' }),
            el('div', { class: 'row' }, field('Network for runs (imports)', nOn)),
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
                canWrite && !limited ? el('button', { class: 'danger', type: 'button', text: 'Delete', onclick: () => run(async () => {
                    if (!confirm('Delete this version? Unsaved changes on it are lost.')) return;
                    await api('DELETE', base + '/configs/' + c.cid); await showProject(pid);
                }) }) : null)))));

    // ---- import from a firewall / Panorama / SCM tenant (download only, with my own API key) -> a new version
    let importCard = null;
    if (canWrite && !limited) {
        const my = await api('GET', 'keys').catch(() => ({ keys: [] }));
        const usable = my.keys.filter(k => k.import && !k.refused);
        const iKey = el('select', {}, usable.map(k => el('option', { value: k.kid, text: (k.kind === 'scm' ? 'SCM TSG ' : '') + k.target + (k.label && k.label !== k.target ? ' (' + k.label + ')' : '') })));
        const iSource = el('select', {}, el('option', { value: 'candidate', text: 'candidate configuration' }), el('option', { value: 'running', text: 'running configuration' }));
        const sourceField = field('Configuration', iSource);
        const keyChanged = () => { const k = usable.find(x => x.kid === iKey.value); sourceField.hidden = !k || k.kind === 'scm'; };
        iKey.addEventListener('change', keyChanged); keyChanged();
        const netOn = el('input', { type: 'checkbox', checked: p.network, disabled: !owner, onchange: (ev) => run(async () => {
            await api('PUT', base + '/network', { enabled: ev.target.checked }); await showProject(pid);
        }) });
        const why = !p.network_global ? 'Network for runs is off (an administrator turns it on under Account).'
            : !p.network ? 'Network is off for this project' + (owner ? ' - turn it on above.' : ' (the owner turns it on).')
            : usable.length === 0 ? 'You have no API key that may be used now - add one under Account, My API keys (and check the allow list of the administrator).' : null;
        importCard = el('div', { class: 'card' }, el('h2', { text: 'Import from a device' }),
            el('p', { class: 'muted', text: 'Downloads the configuration of a firewall / Panorama (XML API) or an SCM tenant - read only, nothing is written to the device - with your own API key. The result becomes a new version (see Runs and project files for the run).' }),
            el('div', { class: 'row' }, field('Network for this project' + (owner ? '' : ' (owner)'), netOn)),
            why ? el('p', { class: 'muted', text: why }) :
            el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
                const k = usable.find(x => x.kid === iKey.value);
                await api('POST', base + '/import/runs', k && k.kind === 'panos' ? { kid: iKey.value, source: iSource.value } : { kid: iKey.value });
                message('import queued - it becomes a new version when it is done (Runs and project files)');
            }); } }, field('From (my API key)', iKey), sourceField, el('button', { class: 'primary', type: 'submit', text: 'Import' })));
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
                            canWrite && (r.type === 'playbook' || (r.type === 'ldap-users' && (r.args || []).includes('out=%JOB%/out.xml')) || (plug.runs[r.type] && plug.runs[r.type].result)) && r.state === 'done' ? el('span', {}, el('button', { type: 'button', text: 'Result as new version', onclick: (ev) => run(async () => {
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

    main(el('div', { class: 'row' }, el('h2', { text: 'Project: ' + p.name }), el('span', { class: 'badge', text: 'your permission: ' + p.role }),
        limited ? el('span', { class: 'badge', text: 'limited to ' + [p.types ? 'types ' + p.types.join(', ') : null, p.scope ? 'locations ' + p.scope.join(', ') : null].filter(x => x).join('; ') }) : null,
        owner ? el('button', { class: 'danger', type: 'button', text: 'Delete project', onclick: () => run(async () => {
            if (!confirm('Delete project "' + p.name + '" with all configurations?')) return;
            await api('DELETE', base); await showProjects();
        }) }) : null), projectTabs(pid, [
            ['versions', 'Configuration versions (' + configs.configs.length + ')', [versions, importCard, appidCard]],
            ['runs', 'Runs and project files', [runsCard, filesCard]],
            ldapCard ? ['ldap', 'LDAP', [ldapCard]] : null,
            ['access', 'Members, API tokens' + (owner ? ', audit log' : ''), [memberCard, tokenCard, owner ? auditCard(base + '/audit', 'Audit log of this project') : null]]]));
    // main() clears the timers of the page before - the ones of this page start now
    if (state.pendingTimers) { state.timers.push(...state.pendingTimers); state.pendingTimers = null; }
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
async function showViewer(config, preset) {
    const p = state.project, pid = p.pid, canWrite = p.role !== 'read';
    state.config = config; state.cache.clear();
    const view = { rows: [], columns: [], sort: null, desc: false, page: 1, size: 50, quick: '', refs: new Map() };
    const base = () => 'projects/' + pid + '/configs/' + state.config.cid;

    // access limited to some types: only these; limited to locations: start with the first one
    const types = (p.types || Object.keys(state.meta.types)).filter(t => state.meta.types[t]);
    const type = el('select', {}, types.map(t => el('option', { value: t, text: t })));
    const ruletype = el('select', {}, state.meta.ruletypes.map(t => el('option', { value: t, text: t })));
    ruletype.value = 'security';
    const sptype = el('select', {}, state.meta.securityprofiletypes.map(t => el('option', { value: t, text: t })));
    // locations: 'any' and those of the version (Panorama: shared + device groups, firewall: shared + vsys, SCM: containers +
    // snippets), known once the version is loaded; a member limited to locations gets only those
    const location = el('select', {}, (p.scope || ['any']).map(l => el('option', { value: l, text: l })));
    let locationsLoaded = false;
    async function loadLocations() {
        if (locationsLoaded) return;
        locationsLoaded = true;
        const r = await api('GET', base() + '/locations').catch(() => null);
        if (!r || !r.locations.length) return;
        const was = location.value, kinds = { 'shared': 'shared', 'device-group': 'device groups', 'vsys': 'vsys', 'shared-gateway': 'shared gateways', 'container': 'containers (folders)', 'snippet': 'snippets' };
        const groups = [...new Set(r.locations.map(l => l.kind))].map(k => el('optgroup', { label: kinds[k] || k },
            r.locations.filter(l => l.kind === k).map(l => el('option', { value: l.name, text: l.name }))));
        location.replaceChildren(...(r.any ? [el('option', { value: 'any', text: 'any (all locations)' })] : []), ...groups);
        if ([...location.options].some(o => o.value === was)) location.value = was;
    }
    const filter = el('input', { placeholder: '(name contains web) and (object is.unused) - type for fields and operators', maxlength: 2000, autocomplete: 'off', spellcheck: false });
    const filterBox = suggest(filter, (text, pos) => filterSuggest(state.meta.types[type.value].filters || {}, text, pos));
    const quick = el('input', { placeholder: 'text in any column', oninput: () => { view.quick = quick.value.toLowerCase(); view.page = 1; draw(); } });
    const rtField = field('Rule type', ruletype), spField = field('Profile type', sptype);
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
        rtField.hidden = type.value !== 'rule'; spField.hidden = type.value !== 'securityprofile';
        action.value = '';
        actionChanged();
    }
    function query() {
        const q = new URLSearchParams({ type: type.value, location: location.value || 'any', filter: filter.value.trim() });
        if (type.value === 'rule') q.set('ruletype', ruletype.value);
        if (type.value === 'securityprofile') q.set('securityprofiletype', sptype.value);
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
        changeList.replaceChildren(...(s.changes || []).map(c => el('li', { text: c })));
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
        view.rows = data.rows; view.columns = data.columns; view.page = 1;
        view.query = key; view.type = type.value; view.refs.clear();
        if (!view.columns.includes(view.sort)) view.sort = null;
        loadLocations();
        info.textContent = data.total + ' objects' + (data.truncated ? ' (first ' + data.rows.length + ' shown)' : '') + (fromCache ? ' - from browser cache' : ' - ' + data.ms + ' ms');
        draw();
    }
    // ---- references of one object (actions=displayreferences): below its row; "Open" shows the user in a new window
    async function toggleRefs(r, key) {
        if (view.refs.has(key)) { view.refs.delete(key); draw(); return; }
        view.refs.set(key, null); draw();
        const q = new URLSearchParams(view.query);
        q.set('name', r.name);
        if (r.location) q.set('location', r.location);
        q.delete('filter');
        try { view.refs.set(key, await api('GET', base() + '/references?' + q.toString())); }
        catch (e) { view.refs.set(key, { error: e.message }); }
        if (view.refs.has(key)) draw();
    }
    function openLink(ref) {
        const h = new URLSearchParams({ p: pid, c: state.config.cid, type: ref.type, location: ref.location, filter: '(name eq ' + ref.name + ')' });
        if (ref.ruletype) h.set('ruletype', ref.ruletype);
        if (ref.securityprofiletype) h.set('securityprofiletype', ref.securityprofiletype);
        return window.location.pathname + '#' + h.toString();
    }
    function refsBox(d) {
        if (d === null) return el('div', { class: 'refs muted', text: 'reading the references ...' });
        if (d.error) return el('div', { class: 'refs error', text: d.error });
        if (!d.objects.length) return el('div', { class: 'refs muted', text: 'object not found' });
        return el('div', { class: 'refs' }, d.objects.map(o => el('div', {},
            el('div', { class: 'muted', text: (d.objects.length > 1 ? o.location + ': ' : '') + (o.references.length ? 'used by ' + o.references.length + ':' : 'not used (no references)')
                + (o.hidden ? ' - ' + o.hidden + ' more outside your types / locations' : '') }),
            o.references.length ? table(['Used by', 'Location', 'Name', 'Where', ''], o.references.map(ref => el('tr', {},
                el('td', { text: ref.type ? ref.type + (ref.ruletype ? ' (' + ref.ruletype + ')' : '') + (ref.securityprofiletype ? ' (' + ref.securityprofiletype + ')' : '') : ref.class }),
                el('td', { text: ref.location || '' }), el('td', { text: ref.name }),
                el('td', { text: [ref.rulebase ? ref.rulebase + ' rule' : null, ...(ref.fields || [])].filter(x => x).join(', ') }),
                el('td', {}, ref.open ? el('a', { href: openLink(ref), target: '_blank', rel: 'noopener', text: 'Open ↗', title: 'show this ' + ref.type + ' in a new window' }) : null)))) : null)));
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
                if (view.sort === c) view.desc = !view.desc; else { view.sort = c; view.desc = false; }
                draw();
            } })), state.meta.types[view.type] && state.meta.types[view.type].references && !view.columns.includes('refcount') ? el('th', { text: 'references' }) : null)),
            el('tbody', {}, slice.flatMap(r => {
                // refcount (types with references): the number is the button that shows the users below the row;
                // 0 - nothing to show; no number (not counted) - the button still works
                const refs = state.meta.types[view.type] && state.meta.types[view.type].references && typeof r.name === 'string' && r.name !== '';
                const key = (r.location || '') + '|' + r.name;
                const refButton = () => r.refcount === 0 ? el('span', { class: 'muted', text: '0', title: 'not used' })
                    : el('button', { type: 'button', class: 'small refbtn' + (view.refs.has(key) ? ' on' : ''), text: (typeof r.refcount === 'number' ? r.refcount : '?') + (view.refs.has(key) ? ' ▾' : ' ▸'),
                        title: (view.refs.has(key) ? 'hide' : 'show') + ' where this object is used (pan-os-php displayreferences)', onclick: () => run(() => toggleRefs(r, key)) });
                const row = el('tr', {}, view.columns.map(c => {
                    if (c === 'refcount' && refs) return el('td', { class: 'refcell' }, refButton());
                    const t = cell(r[c]); return el('td', { text: t, title: t.length > 40 ? t : null });
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
    const changeBox = canWrite ? el('div', { class: 'card' }, el('h3', { text: 'Change the objects of the current list' }),
        el('p', { class: 'muted', text: 'The action runs on all objects that match type, location and the pan-os-php filter above (not the quick filter). It changes the loaded configuration in memory only - nothing is written until you save.' }),
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
        argHelp, el('h3', { text: 'Unsaved changes' }), changeList, log) : null;

    const title = el('h2', { text: 'Version of ' + fmtTime(config.created) + ' - ' + config.name });
    type.addEventListener('change', () => { typeChanged(); filter.value = ''; });
    main(el('div', { class: 'row' }, el('button', { type: 'button', text: '‹ ' + p.name, onclick: () => run(async () => {
            if (lastStatus && lastStatus.dirty && !confirm('There are unsaved changes. They stay in the loaded configuration on the server (recovery copy), but are not a version yet. Leave?')) return;
            await showProject(pid);
        }) }), title),
        el('div', { class: 'statusbar' }, status, autosaveInfo, el('span', { class: 'spacer' }),
            canWrite ? field('Auto save as version', autosave) : el('span', { class: 'muted', text: 'read only' }), canWrite ? saveBtn : null, canWrite ? discardBtn : null),
        el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(() => load(false)); } },
            field('Type', type), rtField, spField, field('Location', location), el('label', { class: 'grow' }, 'pan-os-php filter (runs on the server)', filterBox),
            el('button', { class: 'primary', type: 'submit', text: 'Show' }), el('button', { type: 'button', text: 'Reload', onclick: () => run(() => load(true)) })),
        el('div', { class: 'row' }, field('Quick filter (in the browser)', quick), info),
        tableWrap, pager, changeBox);
    typeChanged();
    if (preset) {
        if (preset.type && state.meta.types[preset.type] && types.includes(preset.type)) { type.value = preset.type; typeChanged(); }
        if (preset.ruletype) ruletype.value = preset.ruletype;
        if (preset.securityprofiletype) sptype.value = preset.securityprofiletype;
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
    await showViewer(c, Object.fromEntries(['type', 'ruletype', 'securityprofiletype', 'location', 'filter'].map(k => [k, h.get(k)])));
    return true;
}
run(async () => {
    let me;
    try { me = await api('GET', 'me'); } catch (e) { showLogin(); return; }
    const deep = location.hash.length > 1;
    await entered(me, deep);
    if (deep) await openFromHash();
});
