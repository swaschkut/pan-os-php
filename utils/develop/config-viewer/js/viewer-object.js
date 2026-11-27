/*
 * pan-os-php config viewer - browser part, the windows of the viewer: the object window (openObject), the system
 * settings (showSystem) and the same action on more objects (openMultiEdit).
 * Part of app.js (showViewer) in a file of its own: declarations only - nothing runs when the file is loaded.
 * v: the viewer these windows belong to (viewerContext in showViewer) - what they read of it and the functions of the
 * list they call (load, setStatus, …); v.cur is the menu entry shown now.
 */
'use strict';

// System: the settings of the firewall / Panorama (or a template of it) / SCM folder, snippet or device - every
// config section of pan-os-php (type=config-section, utils/common/config_sections.json) that applies; read only,
// secrets never shown
async function showSystem(v) {
    const { base, canWrite, setStatus } = v;
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

async function openObject(v, r) {
    const { base, canWrite, devtype, fetchObject, load, locationInfo, openLink, refsTable, ruletype, setStatus, spTypeOf } = v;
    // the generic window shows the list row when the object can not be read on its own (e.g. a type without a name filter)
    let obj = v.cur.window === 'generic' ? await fetchObject(r.name, r.location, r.template, r.profile, r.type).catch(() => ({ row: r, model: null }))
        : await fetchObject(r.name, r.location, r.template, r.profile, r.type);
    // a read-only object (temporary, predefined, GlobalProtect gateway tunnel - pan-os-php CallContext::readOnlyReason):
    // every field read only, also for a member with write
    const writable = canWrite && !obj.row.readonly;
    const offered = state.meta.types[v.cur.type].actions || {};
    const done = {}, errors = {}, pending = {}, hints = {};
    const box = el('div', { class: 'objwin', role: 'dialog', 'aria-modal': 'true', 'aria-label': v.cur.label + ' ' + r.name });
    const overlay = el('div', { class: 'objoverlay', onclick: (ev) => { if (ev.target === overlay) close(); } }, box);
    const onKey = (ev) => { if (ev.key === 'Escape') close(); };
    let changed = false;
    function close() { document.removeEventListener('keydown', onKey); overlay.remove(); if (changed) run(() => load(true)); }
    async function apply(f, actions) {
        const body = { type: v.cur.type, location: obj.row.location, filter: '(name eq ' + obj.row.name + ')', actions, field: f.key };
        if (obj.row.template) {
            // an object of a template: pan-os-php takes location=any with the template - only when the name is unique in it
            body.template = obj.row.template; body.location = 'any';
            const n = await api('GET', base() + '/objects?' + new URLSearchParams({ type: v.cur.type, location: 'any', template: obj.row.template, filter: body.filter }).toString());
            if (n.total !== 1) throw new Error('"' + obj.row.name + '" is ' + n.total + ' times in template ' + obj.row.template + ' (several vsys) - change it with a filter instead');
        }
        if (v.cur.type === 'rule') body.ruletype = ruletype.value;
        // a security profile: only this one (else "any": every profile of this name in the location - an URL profile too)
        if (v.cur.type === 'securityprofile') body.securityprofiletype = spTypeOf(obj.row);
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
            const q = new URLSearchParams({ type: v.cur.type, location: obj.row.location, name: obj.row.name, kind });
            if (v.cur.type === 'rule') q.set('ruletype', ruletype.value);
            if (v.cur.type === 'securityprofile') q.set('securityprofiletype', spTypeOf(obj.row));
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
        const picks = FIELD_PICKS[v.cur.window] || {};
        const fields = windowFields(v.cur.window, obj.row, obj.model, { ruletype, locationInfo }).map(f => f && !f.pick && picks[f.key] ? Object.assign(f, { pick: picks[f.key] }) : f);
        box.replaceChildren(
            el('div', { class: 'objhead' }, el('h3', { text: (v.cur.one || v.cur.label) + ': ' + obj.row.name }), obj.row.template ? el('span', { class: 'badge', text: 'template ' + obj.row.template }) : null, el('span', { class: 'badge', text: obj.row.location }),
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
        if (v.cur.type !== 'rule' || ruletype.value !== 'nat') return null;
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
        if (!(state.meta.types[v.cur.type] && state.meta.types[v.cur.type].references)) return null;
        const body = el('div', { class: 'muted', text: 'reading the references ...' });
        const d = section('refs', 'References', body);
        const fill = () => {
            if (d.dataset.loaded) return;
            d.dataset.loaded = '1';
            const q = new URLSearchParams({ type: v.cur.type, location: obj.row.location, name: obj.row.name });
            if (v.cur.type === 'rule') q.set('ruletype', ruletype.value);
            if (v.cur.type === 'securityprofile') q.set('securityprofiletype', spTypeOf(obj.row));
            if (v.cur.type === 'device') q.set('devicetype', devtype.value);
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
        const r = obj.row, f = v.cur.type === 'device' ? DEVICE_LINKS[r.type] : null;
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
        if (v.cur.type !== 'device' || !eff || typeof eff !== 'object') return null;
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
        if (v.cur.type !== 'device' || !Array.isArray(h) || !h.length) return null;
        const lines = h.map((n, i) => '  '.repeat(i) + (i ? '└ ' : '') + n + (i === h.length - 1 ? '   ◀ this ' + ({ Container: 'container', DeviceCloud: 'cloud device', DeviceOnPrem: 'on-prem device' }[obj.row.type] || 'device group') : ''));
        for (const c of (obj.row.children || [])) lines.push('  '.repeat(h.length) + '└ ' + c);
        return section('hierarchy', 'Hierarchy', el('div', {}, el('pre', { class: 'objxml', text: lines.join('\n') }),
            obj.row.type !== 'DeviceGroup' ? null : el('p', { class: 'muted', text: 'firewalls: ' + (obj.row.firewalls ?? '?') + ' in this device group, ' + (obj.row['firewalls-below'] ?? '?') + ' with the device groups below' })));
    }
    function objXml() {
        // no XML: a predefined object (applications, URL categories, profiles of PAN-OS - they come from the App-ID
        // database, not from the configuration) or an object the read did not give (then: a bug - please report)
        // a device (device group, template, …): its XML would be its whole part of the configuration - not shown
        if (v.cur.type === 'device' && !obj.xml) return null;
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

async function openMultiEdit(v, c) {
    const { base, load, location, setStatus } = v;
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
