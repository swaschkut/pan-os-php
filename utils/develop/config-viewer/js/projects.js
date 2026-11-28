/*
 * pan-os-php config viewer - browser part, list of projects, the page of a project (members, versions, runs, project files).
 * Part of app.js in a file of its own: declarations only (functions, constants) - nothing runs when the file is
 * loaded. index.html loads the parts before app.js, which holds the helpers, the viewer / editor and the start.
 */
'use strict';

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
    // project type of a plug-in: its roles (each bound to a device / tenant) for the forms of runs that read from one
    state.projectRoles = p.type ? p.type.roles : null;
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
        const iRole = roleSelect(null);
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
                    job = await api('POST', base + '/import/runs', Object.assign(k && k.kind === 'panos' ? { kid: iKey.value, source: iSource.value } : Object.assign({ kid: iKey.value }, scopeLocked ? {} : { scope: scopeOf() }),
                        iRole && iRole.value ? { role: iRole.value } : {}));
                } catch (e) { importStatus.className = 'error'; importStatus.textContent = e.message; throw e; }
                if (k && k.kind === 'scm' && !scopeLocked) { p.import_scope = scopeOf(); scopeHint.textContent = ''; }
                importStatus.className = 'ok'; importStatus.textContent = 'import queued - it becomes a new version when it is done (Runs and project files)';
                message('import queued - it becomes a new version when it is done (Runs and project files)');
                watchImport(job);
            }); } }, field('From (my API key)', iKey), iRole ? field('Role', iRole) : null, sourceField, importBtn, importStatus),
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
            canWrite ? el('option', { value: 'psk-list', text: 'IKE gateways / PSK list' }) : null,
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
        // PSK list: this version and / or - with an SCM key of mine - the firewalls managed by SCM (newest local
        // configuration), both compared by the SHA-1 of the pre-shared key; the PSK lists are sensitive (download once)
        // only SCM keys the project may use: bound to a tenant - only that one; bound to a firewall / Panorama - none; a
        // project type with roles - the tenants of its SCM roles (a free SCM role: any)
        const pskRoles = (state.projectRoles || []).filter(r => r.kind === 'scm');
        const pskFits = k => p.binding && !pskRoles.length ? p.binding.kind === 'scm' && (!p.binding.target || p.binding.target === k.target)
            : !pskRoles.length || pskRoles.some(r => !r.target || r.target === k.target);
        const pskKeys = canWrite ? (await api('GET', 'keys').catch(() => ({ keys: [] }))).keys.filter(k => k.kind === 'scm' && !k.refused && pskFits(k)) : [];
        const pskNoVersion = el('option', { value: '', text: '- no version (only the firewalls of SCM) -' });
        const pskKey = el('select', {}, el('option', { value: '', text: '- none (only the version) -' }),
            pskKeys.map(k => el('option', { value: k.kid, text: 'SCM TSG ' + k.target + (k.label && k.label !== k.target ? ' (' + k.label + ')' : '') })));
        const pskRole = roleSelect('scm');
        const pskFields = el('span', { class: 'row' }, field('Firewalls managed by SCM (my SCM key)', pskKey), pskRole ? field('Role', pskRole) : null,
            el('span', { class: 'muted', text: 'PSK lists (clear text): sensitive, download once. Comparison and SHA-1 lists: result files.' }));
        // run types of plug-ins: the fields the plug-in declares (text, location, a project file of a kind)
        const plugFields = el('span', { class: 'row' });
        let plugInputs = [];
        const typeChanged = () => {
            const pr = plug.runs[rType.value];
            pbField.hidden = pbOpts.hidden = rType.value !== 'playbook'; locField.hidden = rType.value !== 'stats';
            diffFields.hidden = rType.value !== 'diff';
            pskFields.hidden = rType.value !== 'psk-list';
            if (rType.value === 'psk-list') { if (!pskNoVersion.parentNode) rVersion.prepend(pskNoVersion); }
            else if (pskNoVersion.parentNode) { if (rVersion.value === '') rVersion.selectedIndex = 1; pskNoVersion.remove(); }
            versionField.firstChild.textContent = rType.value === 'diff' ? 'Version (file1, the original)' : 'Version';
            bpField.hidden = (!!pr && !pr.bp) || rType.value === 'diff' || rType.value === 'psk-list';
            // a run type without a version (its input is a project file)
            versionField.hidden = !!pr && pr.input === 'none';
            rVersion.required = !versionField.hidden && rType.value !== 'psk-list';
            plugInputs = (pr ? pr.fields : []).map(f => {
                const kind = f.kind.startsWith('file:') ? f.kind.slice(5) : null;
                const opts = Object.entries(f.options || {});
                // a field 'secret': a file uploaded only for this run (never a project file) - sent when the run starts
                const input = f.kind === 'secret' ? Object.assign(el('input', { type: 'file', title: 'sensitive: only for this run - never a project file, removed when the run ends' }), { isSecret: true })
                    : kind ? el('select', {}, el('option', { value: '', text: '- choose a file -' }), files.files.filter(x => x.kind === kind).map(x => el('option', { value: x.fid, text: x.name })))
                    : f.kind === 'select' ? el('select', {}, el('option', { value: '', text: '- choose -' }), opts.map(([v, label]) => { const o = el('option', { value: v, text: label }); o.selected = v === f.default; return o; }))
                    // another pan-os-php image for this run: the names the installation allows
                    : f.kind === 'image' ? el('select', {}, el('option', { value: '', text: 'the image of the viewer' }), ((state.meta.plugins || {}).images || []).map(v => { const o = el('option', { value: v, text: v }); o.selected = v === f.default; return o; }))
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
            const sensitive = new Map();
            for (const r of runs) if (openFiles.has(r.jid)) { const x = await api('GET', base + '/runs/' + r.jid); details.set(r.jid, x.files); sensitive.set(r.jid, x.sensitive || []); }
            runsBody.replaceChildren(runs.length === 0 ? el('p', { class: 'muted', text: 'No runs yet.' }) :
                table(['Run', 'Version', 'State', 'By', 'Started', 'Finished', ''], runs.flatMap(r => {
                    const open = r.state === 'queued' || r.state === 'running';
                    const row = el('tr', {}, el('td', { text: r.type + (r.image ? ' (image ' + r.image + ')' : ''), title: r.image ? 'run with the pan-os-php image "' + r.image + '" of this installation' : null }), el('td', { text: r.type === 'appid' ? 'App-ID from ' + ((r.args || []).find(a => a.startsWith('x-appid-target=')) || '').slice(15)
                            : r.type === 'ldap-discover' ? 'LDAP servers of ' + ((r.args || []).find(a => a.startsWith('x-ldap-discover-target=')) || '').slice(23)
                            : r.type === 'ldap' ? 'LDAP ' + ((r.args || []).find(a => a.startsWith('x-ldap-target=')) || '').slice(14).replace(/^auto:/, 'automatic: ')
                            : r.type === 'import' ? 'from ' + ((r.args || []).find(a => a.startsWith('x-import-target=')) || '').slice(16).replace(/^panos:/, '').replace(/^scm:/, 'SCM TSG ')
                            : r.type === 'psk-list' ? [r.cid ? (configs.configs.find(c => c.cid === r.cid) || { name: '(deleted version)' }).name : null,
                                (r.args || []).some(a => a.startsWith('x-psk-target=')) ? 'firewalls of SCM TSG ' + ((r.args || []).find(a => a.startsWith('x-psk-target=')) || '').slice(17) : null].filter(Boolean).join(' + ')
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
                            canWrite && r.type === 'import' && (r.state === 'failed' || r.state === 'done') && (r.args || []).some(a => a.startsWith('x-import-target=scm:')) ? el('button', { type: 'button', text: 'Convert again', title: 'only the conversion to XML (scm-export-xml) on the export this run has already downloaded - no download, no network; a new version (e.g. after an update of pan-os-php that converts more)', onclick: () => run(async () => {
                                if (r.state === 'done' && !confirm('Convert the export of this import again? The result becomes a new version (no download, no network).')) return;
                                await api('POST', base + '/runs/' + r.jid + '/convert');
                                message('conversion queued - the configuration becomes a new version when it is done'); await refreshRuns();
                            }) }) : null, ' ',
                            el('button', { class: 'danger', type: 'button', text: open ? 'Cancel' : 'Delete', onclick: () => run(async () => {
                                if (!open && !confirm('Delete this run with its result files' + (r.type === 'import' && r.state === 'failed' ? ' (also a downloaded SCM export: Convert again is then not possible)' : '') + '?')) return;
                                await api('DELETE', base + '/runs/' + r.jid); openFiles.delete(r.jid); await refreshRuns();
                            }) })));
                    if (!details.has(r.jid)) return [row];
                    const fl = details.get(r.jid);
                    // sensitive results (e.g. the PSK list for the customer): downloadable once, then removed
                    const sl = sensitive.get(r.jid) || [];
                    const sens = sl.length ? el('div', { class: 'sensitive' }, el('strong', { text: 'Sensitive - download once: ' }),
                        sl.map(f => el('span', { class: 'filelink' }, el('a', { href: API + '/' + base + '/runs/' + r.jid + '/sensitive/' + encodeURIComponent(f.name), text: f.name,
                            onclick: (ev) => { if (!confirm(f.name + ' can be downloaded ONCE - it is removed afterwards. Keep it safe. Download now?')) { ev.preventDefault(); return; } setTimeout(() => refreshRuns(), 1500); } }),
                            el('span', { class: 'muted', text: ' ' + fmtSize(f.size) + ', until ' + fmtTime(f.expires) })))) : null;
                    return [row, el('tr', {}, el('td', { colspan: 7, class: 'wrap' }, sens, fl.length === 0 ? el('span', { class: 'muted', text: 'no files' }) :
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
                else if (rType.value === 'psk-list') {
                    delete body.bp;
                    if (!rVersion.value && !pskKey.value) throw new Error('choose a version and / or an SCM key');
                    if (pskKey.value) body.kid = pskKey.value;
                    if (pskKey.value && pskRole && pskRole.value) body.role = pskRole.value;
                }
                else if (plug.runs[rType.value]) {
                    if (!plug.runs[rType.value].bp) delete body.bp;
                    for (const x of plugInputs) {
                        if (x.input.isSecret) {
                            if (!x.input.files.length) { if (x.f.required) throw new Error(x.f.label + ' is needed'); continue; }
                            const fd = new FormData(); fd.append('file', x.input.files[0]);
                            body[x.f.name] = (await api('POST', base + '/secret-uploads', fd)).token;
                            continue;
                        }
                        const v = x.input.isMulti ? Array.from(x.input.selectedOptions).map(o => o.value) : x.input.value.trim();
                        if (v.length === 0 && x.f.required) throw new Error(x.f.label + ' is needed');
                        if (v.length !== 0) body[x.f.name] = v;
                    }
                }
                else body.location = rLocation.value.trim() || 'any';
                const noVersion = (plug.runs[rType.value] && plug.runs[rType.value].input === 'none') || (rType.value === 'psk-list' && !rVersion.value);
                await api('POST', base + (noVersion ? '' : '/configs/' + rVersion.value) + '/' + rType.value + '/runs', body);
                message('run queued');
                await refreshRuns();
            }); } }, field('Run', rType), versionField, diffFields, pskFields, pbField, locField, plugFields, bpField, el('button', { class: 'primary', type: 'submit', text: 'Start run' }), pbOpts),
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
    const pageCards = limited ? [] : Object.entries(plug.pages || {})
        .filter(([k, pg]) => !pg.types || pg.types.length === 0 || (p.type && pg.types.includes(p.type.key)))
        .map(([k, pg]) => pluginPageCard(base, k, pg));
    // approvals of plug-in pages: the owner decides whether the person who made a plan may approve it (four eyes)
    if (pageCards.length && owner) {
        const fe = el('input', { type: 'checkbox' }); fe.checked = !!p.four_eyes;
        fe.addEventListener('change', () => run(async () => { await api('PUT', base + '/approvals', { four_eyes: fe.checked }); await showProject(pid); }));
        pageCards.unshift(el('div', { class: 'card' }, el('label', { class: 'chk' }, fe, ' Approvals: four eyes - an area of a plan is approved by another person than the one who made the plan')));
    }

    main(el('div', { class: 'row' }, el('h2', { text: 'Project: ' + p.name }), el('span', { class: 'badge', text: 'your permission: ' + p.role }),
        limited ? el('span', { class: 'badge', text: 'limited to ' + [p.types ? 'types ' + p.types.join(', ') : null, p.scope ? 'locations ' + p.scope.join(', ') : null].filter(x => x).join('; ') }) : null,
        // bound by the first import / read from an API: PAN-OS or one SCM tenant (an administrator can release it)
        p.binding ? el('span', { class: 'badge', title: 'set by the first import from an API; imports and SCM reads of another kind / tenant are refused', text: p.binding.kind === 'scm' ? 'SCM tenant TSG ' + p.binding.target : 'PAN-OS (firewall / Panorama)' }) : null,
        // project type of a plug-in: its roles, each bound by its first import / read; the owner sets the type before that
        p.type ? el('span', { class: 'badge', title: 'project type of a plug-in', text: ((plug.projectTypes || {})[p.type.key] || {}).title || p.type.key }) : null,
        ...(p.type ? p.type.roles.map(r => el('span', { class: 'badge' + (r.write ? ' ok' : ''), title: r.write ? 'written to by the runs of the plug-in' : 'read only',
            text: r.title + ': ' + (r.target ? (r.kind === 'scm' ? 'TSG ' : '') + r.target : 'not bound yet') + (r.write ? ' (write)' : '') })) : []),
        owner && !p.binding && Object.keys(plug.projectTypes || {}).length && !(p.type && p.type.roles.some(r => r.target)) ? (() => {
            const sel = el('select', { 'aria-label': 'project type' }, el('option', { value: '', text: 'standard project' }),
                Object.entries(plug.projectTypes).map(([k, t]) => { const o = el('option', { value: k, text: t.title }); o.selected = p.type && p.type.key === k; return o; }));
            return el('span', { class: 'row' }, field('Project type', sel), el('button', { type: 'button', text: 'Set', onclick: () => run(async () => {
                await api('PUT', base + '/type', { type: sel.value || null }); await showProject(pid); }) }));
        })() : null,
        (p.binding || (p.type && p.type.roles.some(r => r.target))) && state.admin ? el('button', { type: 'button', text: 'Release binding', title: 'administrator: the next import / read binds the project again', onclick: () => run(async () => {
            if (!confirm('Release the binding of this project (' + (p.binding ? (p.binding.kind === 'scm' ? 'TSG ' + p.binding.target : 'PAN-OS') : 'all roles') + ')?')) return;
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
