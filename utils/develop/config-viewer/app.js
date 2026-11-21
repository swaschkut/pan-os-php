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
async function entered(r) {
    state.user = r.user; state.admin = r.admin; state.csrf = r.csrf;
    document.getElementById('nav').hidden = false;
    document.getElementById('who').textContent = r.user + (r.admin ? ' (admin)' : '');
    if (!state.meta) state.meta = await api('GET', 'meta');
    await showProjects();
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
async function showAccount() {
    const oldPw = el('input', { type: 'password', autocomplete: 'current-password', required: true });
    const newPw = el('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: 10 });
    const nodes = [el('form', { class: 'card', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
        await api('POST', 'password', { old: oldPw.value, new: newPw.value });
        oldPw.value = newPw.value = '';
        message('password changed');
    }); } }, el('h2', { text: 'Change password' }), el('div', { class: 'row' }, field('Current password', oldPw), field('New password (10+ characters)', newPw),
        el('button', { class: 'primary', type: 'submit', text: 'Change' })))];
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
        nodes.push(el('div', { class: 'card' }, el('h2', { text: 'Plug-ins (admin)' }),
            pl.plugins.length === 0 && errs.length === 0 ? el('p', { class: 'muted', text: 'No plug-ins installed.' }) :
            table(['Plug-in', 'Version', 'Feature', 'Form', 'State'], [
                ...pl.plugins.map(x => el('tr', {}, el('td', { text: x.title + ' (' + x.name + ')' }), el('td', { text: x.version }), el('td', { text: x.feature || 'basic' }),
                    el('td', { text: x.form === 'package' ? 'package (encrypted)' : 'folder (source)' }),
                    el('td', { class: 'wrap' }, el('span', { class: 'badge' + (x.on ? '' : ' dirty'), text: x.on ? 'on' : 'locked' }), x.why ? el('span', { class: 'muted', text: ' ' + x.why }) : null))),
                ...errs.map(([folder, why]) => el('tr', {}, el('td', { text: folder }), el('td', {}), el('td', {}), el('td', {}), el('td', { class: 'wrap', text: 'not loaded: ' + why })))])));
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
    const [members, configs, tokens, files] = await Promise.all([api('GET', base + '/members'), api('GET', base + '/configs'), api('GET', base + '/tokens'), api('GET', base + '/files')]);

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
        files.files.length === 0 ? el('p', { class: 'muted', text: 'No files.' }) :
        table(['File', 'Kind', 'Created', 'By', 'Size', ''], files.files.map(f => el('tr', {},
            el('td', { text: f.name }), el('td', {}, el('span', { class: 'badge', text: f.kind })), el('td', { text: fmtTime(f.created) }), el('td', { text: f.created_by || '' }),
            el('td', { text: fmtSize(f.size) }),
            el('td', {}, el('a', { href: API + '/' + base + '/files/' + f.fid + '/download', text: 'Download' }), ' ',
                canWrite && !limited ? el('button', { class: 'danger', type: 'button', text: 'Delete', onclick: () => run(async () => {
                    if (!confirm('Delete the file "' + f.name + '"?')) return;
                    await api('DELETE', base + '/files/' + f.fid); await showProject(pid);
                }) }) : null)))));

    // ---- runs (jobs): stats, playbook
    let runsCard = null;
    if (!limited) {
        const rVersion = el('select', { required: true }, configs.configs.map(c => el('option', { value: c.cid, text: c.name + ' - ' + fmtTime(c.created) })));
        const rType = el('select', {}, el('option', { value: 'stats', text: 'stats (BPA figures)' }), el('option', { value: 'playbook', text: 'playbook' }),
            Object.entries(plug.runs).map(([k, r]) => el('option', { value: k, text: r.title })));
        const rPlaybook = el('select', {}, el('option', { value: '', text: '- choose a playbook -' }), files.files.filter(f => f.kind === 'playbook').map(f => el('option', { value: f.fid, text: f.name })));
        const rBp = el('select', {}, el('option', { value: '', text: 'BP JSON shipped with pan-os-php' }), files.files.filter(f => f.kind === 'bp').map(f => el('option', { value: f.fid, text: f.name })));
        const rLocation = el('input', { value: 'any', maxlength: 63 });
        const pbField = field('Playbook', rPlaybook), locField = field('Location', rLocation), bpField = field('BP JSON', rBp), versionField = field('Version', rVersion);
        // run types of plug-ins: the fields the plug-in declares (text, location, a project file of a kind)
        const plugFields = el('span', { class: 'row' });
        let plugInputs = [];
        const typeChanged = () => {
            const pr = plug.runs[rType.value];
            pbField.hidden = rType.value !== 'playbook'; locField.hidden = rType.value !== 'stats';
            bpField.hidden = !!pr && !pr.bp;
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
                    const row = el('tr', {}, el('td', { text: r.type }), el('td', { text: (configs.configs.find(c => c.cid === r.cid) || { name: '(deleted version)' }).name }),
                        el('td', {}, el('span', { class: 'badge' + (open ? ' dirty' : ''), text: r.state }), r.error ? el('span', { class: 'muted', text: ' ' + r.error }) : null),
                        el('td', { text: r.user || '' }), el('td', { text: fmtTime(r.started) }), el('td', { text: fmtTime(r.finished) }),
                        el('td', {},
                            open ? null : el('button', { type: 'button', text: openFiles.has(r.jid) ? 'Hide files' : 'Result files', onclick: () => run(async () => {
                                if (openFiles.has(r.jid)) openFiles.delete(r.jid); else openFiles.add(r.jid);
                                await drawRuns();
                            }) }), ' ',
                            canWrite && (r.type === 'playbook' || (plug.runs[r.type] && plug.runs[r.type].result)) && r.state === 'done' ? el('span', {}, el('button', { type: 'button', text: 'Result as new version', onclick: (ev) => run(async () => {
                                const to = ev.target.parentNode.querySelector('select').value;
                                await api('POST', base + '/runs/' + r.jid + '/save', to === pid ? {} : { project: to });
                                await showProject(pid); message(to === pid ? 'the result configuration of the run is a new version' : 'the result configuration of the run is a new version of the other project');
                            }) }), ' in ', el('select', { 'aria-label': 'project for the result' }, writable.map(x => { const o = el('option', { value: x.pid, text: x.pid === pid ? 'this project' : x.name }); o.selected = x.pid === pid; return o; }))) : null, ' ',
                            el('button', { class: 'danger', type: 'button', text: open ? 'Cancel' : 'Delete', onclick: () => run(async () => {
                                if (!open && !confirm('Delete this run with its result files?')) return;
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
            el('p', { class: 'muted', text: 'A run works on one version in its own folder; exports, set commands and the result configuration are its result files. Nothing changes a version - the result of a playbook run can be taken as a new version.' }),
            configs.configs.length === 0 && !Object.values(plug.runs).some(r => r.input === 'none') ? el('p', { class: 'muted', text: 'Upload a configuration first.' }) :
            el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
                const body = {};
                if (rBp.value) body.bp = rBp.value;
                if (rType.value === 'playbook') { if (!rPlaybook.value) throw new Error('choose a playbook (upload one under "Project files")'); body.playbook = rPlaybook.value; }
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
            }); } }, field('Run', rType), versionField, pbField, locField, plugFields, bpField, el('button', { class: 'primary', type: 'submit', text: 'Start run' })),
            runsBody);
        // while a run is open: refresh the list
        let openRuns = await drawRuns();
        refreshRuns = async () => { openRuns = await drawRuns(); };
        state.pendingTimers = [setInterval(() => { if (openRuns) refreshRuns().catch(() => {}); }, 4000)];
    }

    main(el('div', { class: 'row' }, el('h2', { text: 'Project: ' + p.name }), el('span', { class: 'badge', text: 'your permission: ' + p.role }),
        limited ? el('span', { class: 'badge', text: 'limited to ' + [p.types ? 'types ' + p.types.join(', ') : null, p.scope ? 'locations ' + p.scope.join(', ') : null].filter(x => x).join('; ') }) : null,
        owner ? el('button', { class: 'danger', type: 'button', text: 'Delete project', onclick: () => run(async () => {
            if (!confirm('Delete project "' + p.name + '" with all configurations?')) return;
            await api('DELETE', base); await showProjects();
        }) }) : null), versions, runsCard, filesCard, memberCard, tokenCard, owner ? auditCard(base + '/audit', 'Audit log of this project') : null);
    // main() clears the timers of the page before - the ones of this page start now
    if (state.pendingTimers) { state.timers.push(...state.pendingTimers); state.pendingTimers = null; }
}

// ---------------------------------------------------------------- viewer / editor
async function showViewer(config) {
    const p = state.project, pid = p.pid, canWrite = p.role !== 'read';
    state.config = config; state.cache.clear();
    const view = { rows: [], columns: [], sort: null, desc: false, page: 1, size: 50, quick: '' };
    const base = () => 'projects/' + pid + '/configs/' + state.config.cid;

    // access limited to some types: only these; limited to locations: start with the first one
    const types = (p.types || Object.keys(state.meta.types)).filter(t => state.meta.types[t]);
    const type = el('select', {}, types.map(t => el('option', { value: t, text: t })));
    const ruletype = el('select', {}, state.meta.ruletypes.map(t => el('option', { value: t, text: t })));
    ruletype.value = 'security';
    const sptype = el('select', {}, state.meta.securityprofiletypes.map(t => el('option', { value: t, text: t })));
    const location = el('input', { value: p.scope ? p.scope[0] : 'any', maxlength: 200 });
    const filter = el('input', { placeholder: '(name contains web) and (object is.unused)', maxlength: 2000 });
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
        const acts = state.meta.types[type.value].actions;
        action.replaceChildren(el('option', { value: '', text: '- choose an action -' }), ...Object.keys(acts).map(a => el('option', { value: a, text: a })));
        actionChanged();
    }
    function query() {
        const q = new URLSearchParams({ type: type.value, location: location.value.trim() || 'any', filter: filter.value.trim() });
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
        if (!view.columns.includes(view.sort)) view.sort = null;
        info.textContent = data.total + ' objects' + (data.truncated ? ' (first ' + data.rows.length + ' shown)' : '') + (fromCache ? ' - from browser cache' : ' - ' + data.ms + ' ms');
        draw();
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
            } })))),
            el('tbody', {}, slice.map(r => el('tr', {}, view.columns.map(c => { const t = cell(r[c]); return el('td', { text: t, title: t.length > 40 ? t : null }); }))))));
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
    const action = el('select', { onchange: () => actionChanged() });
    const actionArg = el('input', { maxlength: 1500 });
    const argHelp = el('span', { class: 'muted' });
    function actionChanged() {
        const args = (state.meta.types[type.value].actions[action.value] || []);
        actionArg.disabled = args.length === 0;
        actionArg.value = '';
        actionArg.placeholder = args.map(a => a.name).join(',');
        argHelp.textContent = args.map(a => a.name + (a.help ? ': ' + a.help : '')).join(' | ');
    }
    const changeBox = canWrite ? el('div', { class: 'card' }, el('h3', { text: 'Change the objects of the current list' }),
        el('p', { class: 'muted', text: 'The action runs on all objects that match type, location and the pan-os-php filter above (not the quick filter). It changes the loaded configuration in memory only - nothing is written until you save.' }),
        el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
            if (!action.value) throw new Error('choose an action');
            const body = Object.fromEntries(query());
            body.actions = action.value + (actionArg.value.trim() !== '' ? ':' + actionArg.value.trim() : '');
            if (!confirm('Run "' + body.actions + '" on ' + view.rows.length + ' object(s) of the current list?')) return;
            const r = await api('POST', base() + '/change', body);
            state.cache.clear();
            log.hidden = false; log.textContent = r.log;
            message('action done on ' + r.processed + ' object(s) - not saved yet');
            await load(true);
        }); } }, field('Action', action), el('label', { class: 'grow' }, 'Arguments (comma separated)', actionArg), el('button', { class: 'primary', type: 'submit', text: 'Run on loaded configuration' })),
        argHelp, el('h3', { text: 'Unsaved changes' }), changeList, log) : null;

    const title = el('h2', { text: 'Version of ' + fmtTime(config.created) + ' - ' + config.name });
    type.addEventListener('change', typeChanged);
    main(el('div', { class: 'row' }, el('button', { type: 'button', text: '‹ ' + p.name, onclick: () => run(async () => {
            if (lastStatus && lastStatus.dirty && !confirm('There are unsaved changes. They stay in the loaded configuration on the server (recovery copy), but are not a version yet. Leave?')) return;
            await showProject(pid);
        }) }), title),
        el('div', { class: 'statusbar' }, status, autosaveInfo, el('span', { class: 'spacer' }),
            canWrite ? field('Auto save as version', autosave) : el('span', { class: 'muted', text: 'read only' }), canWrite ? saveBtn : null, canWrite ? discardBtn : null),
        el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(() => load(false)); } },
            field('Type', type), rtField, spField, field('Location', location), el('label', { class: 'grow' }, 'pan-os-php filter (runs on the server)', filter),
            el('button', { class: 'primary', type: 'submit', text: 'Show' }), el('button', { type: 'button', text: 'Reload', onclick: () => run(() => load(true)) })),
        el('div', { class: 'row' }, field('Quick filter (in the browser)', quick), info),
        tableWrap, pager, changeBox);
    typeChanged();

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
run(async () => {
    try { await entered(await api('GET', 'me')); } catch (e) { showLogin(); }
});
