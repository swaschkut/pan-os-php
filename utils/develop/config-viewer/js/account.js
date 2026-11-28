/*
 * pan-os-php config viewer - browser part, login, account of the user, help pages (Markdown, shipped in docs/).
 * Part of app.js in a file of its own: declarations only (functions, constants) - nothing runs when the file is
 * loaded. index.html loads the parts before app.js, which holds the helpers, the viewer / editor and the start.
 */
'use strict';

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
    setPlace({ page: 'account' });
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
