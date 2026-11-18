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
function showLogin() {
    const user = el('input', { name: 'user', autocomplete: 'username', required: true });
    const pass = el('input', { name: 'password', type: 'password', autocomplete: 'current-password', required: true });
    const form = el('form', { class: 'card login', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
        const r = await api('POST', 'login', { user: user.value, password: pass.value });
        pass.value = '';
        await entered(r);
    }); } }, el('h2', { text: 'Log in' }), field('User', user), field('Password', pass), el('button', { class: 'primary', type: 'submit', text: 'Log in' }));
    main(form);
    user.focus();
}
async function entered(r) {
    state.user = r.user; state.admin = r.admin; state.csrf = r.csrf;
    document.getElementById('nav').hidden = false;
    document.getElementById('who').textContent = r.user + (r.admin ? ' (admin)' : '');
    if (!state.meta) state.meta = await api('GET', 'meta');
    await showProjects();
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
                    el('td', {}, u.name === state.user ? null : el('button', { class: 'danger', type: 'button', text: 'Delete', onclick: () => run(async () => {
                        if (!confirm('Delete user "' + u.name + '" and all projects this user owns?')) return;
                        await api('DELETE', 'users/' + encodeURIComponent(u.name)); await showAccount();
                    }) }))))))));
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

async function showProject(pid) {
    const p = await api('GET', 'projects/' + pid);
    state.project = p; state.config = null; state.cache.clear();
    const [members, configs] = await Promise.all([api('GET', 'projects/' + pid + '/members'), api('GET', 'projects/' + pid + '/configs')]);
    const canWrite = p.role !== 'read', owner = p.role === 'owner';

    const file = el('input', { type: 'file', accept: '.xml,text/xml,application/xml', required: true });
    const versions = el('div', { class: 'card' }, el('h2', { text: 'Configuration versions' }),
        canWrite ? el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
            const fd = new FormData(); fd.append('config', file.files[0]);
            message('uploading ...'); await api('POST', 'projects/' + pid + '/configs', fd); await showProject(pid);
        }); } }, field('Upload a PAN-OS / Panorama XML configuration', file), el('button', { class: 'primary', type: 'submit', text: 'Upload' })) : null,
        configs.configs.length === 0 ? el('p', { class: 'muted', text: 'No configuration yet.' }) :
        el('table', { class: 'plain' }, el('thead', {}, el('tr', {}, el('th', { text: 'File' }), el('th', { text: 'Created' }), el('th', { text: 'By' }), el('th', { text: 'Size' }), el('th', { text: 'How it was created' }), el('th', {}))),
            el('tbody', {}, configs.configs.map(c => el('tr', {},
                el('td', {}, el('button', { class: 'link', type: 'button', text: c.name, onclick: () => run(() => showViewer(c)) })),
                el('td', { text: fmtTime(c.created) }), el('td', { text: c.created_by || '' }), el('td', { text: fmtSize(c.size) }), el('td', { class: 'wrap', text: c.note }),
                el('td', {}, el('a', { href: API + '/projects/' + pid + '/configs/' + c.cid + '/download', text: 'Download' }), ' ',
                    canWrite ? el('button', { class: 'danger', type: 'button', text: 'Delete', onclick: () => run(async () => {
                        if (!confirm('Delete this version? Unsaved changes on it are lost.')) return;
                        await api('DELETE', 'projects/' + pid + '/configs/' + c.cid); await showProject(pid);
                    }) }) : null))))));

    const mUser = el('input', { required: true, autocomplete: 'off' });
    const mRole = el('select', {}, el('option', { value: 'read', text: 'read' }), el('option', { value: 'write', text: 'write (change and save)' }));
    const memberCard = el('div', { class: 'card' }, el('h2', { text: 'Members' }),
        owner ? el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
            await api('PUT', 'projects/' + pid + '/members', { user: mUser.value, role: mRole.value }); await showProject(pid);
        }); } }, field('User name', mUser), field('Permission', mRole), el('button', { class: 'primary', type: 'submit', text: 'Add / change' })) : null,
        el('table', { class: 'plain' }, el('thead', {}, el('tr', {}, el('th', { text: 'User' }), el('th', { text: 'Permission' }), el('th', {}))),
            el('tbody', {}, members.members.map(m => el('tr', {}, el('td', { text: m.user }), el('td', {}, el('span', { class: 'badge', text: m.role })),
                el('td', {}, m.role !== 'owner' && (owner || m.user === state.user) ? el('button', { class: 'danger', type: 'button', text: owner ? 'Remove' : 'Leave project', onclick: () => run(async () => {
                    await api('DELETE', 'projects/' + pid + '/members/' + encodeURIComponent(m.user));
                    if (owner) await showProject(pid); else await showProjects();
                }) }) : null))))));

    main(el('div', { class: 'row' }, el('h2', { text: 'Project: ' + p.name }), el('span', { class: 'badge', text: 'your permission: ' + p.role }),
        owner ? el('button', { class: 'danger', type: 'button', text: 'Delete project', onclick: () => run(async () => {
            if (!confirm('Delete project "' + p.name + '" with all configurations?')) return;
            await api('DELETE', 'projects/' + pid); await showProjects();
        }) }) : null), versions, memberCard);
}

// ---------------------------------------------------------------- viewer / editor
async function showViewer(config) {
    const p = state.project, pid = p.pid, canWrite = p.role !== 'read';
    state.config = config; state.cache.clear();
    const view = { rows: [], columns: [], sort: null, desc: false, page: 1, size: 50, quick: '' };
    const base = () => 'projects/' + pid + '/configs/' + state.config.cid;

    const types = Object.keys(state.meta.types);
    const type = el('select', {}, types.map(t => el('option', { value: t, text: t })));
    const ruletype = el('select', {}, state.meta.ruletypes.map(t => el('option', { value: t, text: t })));
    ruletype.value = 'security';
    const sptype = el('select', {}, state.meta.securityprofiletypes.map(t => el('option', { value: t, text: t })));
    const location = el('input', { value: 'any', maxlength: 200 });
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
