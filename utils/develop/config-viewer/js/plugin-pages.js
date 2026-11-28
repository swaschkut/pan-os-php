/*
 * pan-os-php config viewer - browser part, pages of plug-ins (interface 2): forms, tables, approval steps, matrices.
 * Part of app.js in a file of its own: declarations only (functions, constants) - nothing runs when the file is
 * loaded. index.html loads the parts before app.js, which holds the helpers, the viewer / editor and the start.
 */
'use strict';

// ---------------------------------------------------------------- pages of plug-ins (interface 2)
// The plug-in describes its blocks; the viewer draws them - a plug-in brings no script for the page. Form: typed fields,
// value = stored value, else the default of the plug-in; the hint of the plug-in (e.g. "tenant A: …") below the field.
function pluginPageCard(base, key, meta) {
    const body = el('div', {}, el('p', { class: 'muted', text: 'loading…' }));
    const card = el('div', { class: 'card' }, el('h2', { text: meta.title }), body);
    const load = () => run(async () => {
        const pg = await api('GET', base + '/pages/' + key);
        body.replaceChildren(pg.text ? el('p', { class: 'muted', text: pg.text }) : '',
            ...pg.blocks.map(b => b.kind === 'table' ? pluginTableBlock(base, key, b, pg.write, load)
                : b.kind === 'matrix' ? pluginMatrixBlock(base, key, b, load)
                : b.kind === 'approval' ? pluginApprovalBlock(base, key, b, pg.write, load) : pluginFormBlock(base, key, b, pg.write, load)));
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
        const input = pluginInput(f, v, false);
        input.disabled = !canWrite;
        inputs[f.name] = input;
        errs[f.name] = el('div', { class: 'fielderror' });
        return el('div', { class: 'pfield' }, el('label', {}, f.label + (f.required ? ' *' : ''), input),
            d.hint ? el('div', { class: 'muted', text: d.hint }) : null, f.help ? el('div', { class: 'muted', text: f.help }) : null, errs[f.name]);
    });
    const formErr = el('div', { class: 'fielderror' });
    const valueOf = f => inputs[f.name].valueOf2();
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

// an input for a value of a field (form) or a cell (table); list: one entry per line (form) / separated by , (table)
function pluginInput(f, v, inTable) {
    let input;
    if (f.type === 'select' || f.type === 'file') {
        // file: a project file of a kind (the options are the files of the project) - upload one under "Project files"
        input = el('select', {}, f.required && f.type === 'select' ? null : el('option', { value: '', text: f.type === 'file' ? '- choose a file -' : '-' }),
            Object.entries(f.options || {}).map(([o, label]) => { const x = el('option', { value: o, text: label }); x.selected = o === v; return x; }));
    } else if (f.type === 'images') {
        // pan-os-php images of the installation (VIEWER_RUN_IMAGES) and the one of the viewer: one or more - a check box
        // each (a list with several selected entries is easily read as "one chosen"). The field sits in a <label>: a
        // click on the text of an entry toggles that entry, not the first box of the label
        const boxes = Object.entries(f.options || {}).map(([o, label]) => {
            const box = el('input', { type: 'checkbox', value: o }); box.checked = Array.isArray(v) && v.includes(o);
            return el('span', { class: 'imagecheck', onclick: e => { if (e.target !== box) { e.preventDefault(); if (!box.disabled) box.checked = !box.checked; } } }, box, ' ', label);
        });
        input = el('div', { class: 'imagechecks' }, boxes);
        Object.defineProperty(input, 'disabled', { set: x => boxes.forEach(b => { b.firstChild.disabled = x; }) });
    } else if (f.type === 'bool') {
        input = el('input', { type: 'checkbox' }); input.checked = v === true;
    } else if (f.type === 'list' && !inTable) {
        input = el('textarea', { rows: 4, placeholder: 'one ' + (f.item === 'text' ? 'entry' : f.item) + ' per line' }); input.value = Array.isArray(v) ? v.join('\n') : '';
    } else {
        input = el('input', { type: f.type === 'int' || f.type === 'asn' ? 'number' : 'text', maxlength: f.type === 'list' ? 20000 : (f.max || 300),
            placeholder: f.type === 'list' ? 'a, b, …' : ({ ipv4: 'a.b.c.d', 'ipv4-cidr': 'a.b.c.d/n', 'ipv6-cidr': 'x::/n', asn: 'AS number', hostname: 'host.example.com' }[f.type] || '') });
        input.value = v === null || v === undefined ? '' : Array.isArray(v) ? v.join(', ') : String(v);
    }
    input.valueOf2 = () => f.type === 'bool' ? input.checked
        : f.type === 'images' ? [...input.querySelectorAll('input:checked')].map(x => x.value)
        : f.type === 'list' ? input.value.split(inTable ? ',' : '\n').map(x => x.trim()).filter(x => x !== '') : input.value;
    return input;
}
const pluginShow = v => v === null || v === undefined ? '' : Array.isArray(v) ? v.join(', ') : v === true ? 'yes' : v === false ? 'no' : String(v);

// approval of a plan of a plug-in: the areas of the newest plan (the result of a run), approved / rejected one by one;
// bound to that plan - a new plan starts without decisions. The run that needs it starts only when all are approved.
function pluginApprovalBlock(base, key, b, canWrite, reload) {
    const errs = {}, notes = {};
    const decide = (id, decision) => run(async () => {
        Object.values(errs).forEach(e => e.textContent = '');
        try {
            await api('PUT', base + '/pages/' + key + '/blocks/' + b.name, { decisions: { [id]: { decision, note: notes[id] ? notes[id].value : '' } } });
        } catch (e) {
            if (e.fields) { Object.entries(e.fields).forEach(([k, m]) => { if (errs[k]) errs[k].textContent = m; }); throw new Error(b.title + ': ' + e.message); }
            throw e;
        }
        reload();
    });
    const badge = a => a.decision === 'approve' ? el('span', { class: 'badge ok', text: 'approved' }) : a.decision === 'reject' ? el('span', { class: 'badge warn', text: 'rejected' })
        : el('span', { class: 'badge', text: 'open' });
    const rows = b.areas.map(a => {
        errs[a.id] = el('div', { class: 'fielderror' });
        notes[a.id] = el('input', { maxlength: 300, placeholder: 'note', value: a.note || '' }); notes[a.id].disabled = !canWrite;
        return el('tr', {}, el('td', {}, el('strong', { text: a.title }), a.summary ? el('div', { class: 'muted', text: a.summary }) : null),
            el('td', { text: a.count === null ? '' : String(a.count) }),
            el('td', {}, badge(a), a.by ? el('div', { class: 'muted', text: a.by + ', ' + fmtTime(a.at) }) : null),
            el('td', {}, notes[a.id], errs[a.id]),
            el('td', {}, canWrite ? [el('button', { type: 'button', text: 'Approve', onclick: () => decide(a.id, 'approve') }), ' ',
                el('button', { type: 'button', class: 'danger', text: 'Reject', onclick: () => decide(a.id, 'reject') }), ' ',
                a.decision ? el('button', { type: 'button', text: 'Clear', onclick: () => decide(a.id, 'clear') }) : null] : null));
    });
    const done = b.areas.filter(a => a.decision === 'approve').length;
    return el('div', { class: 'pblock' }, el('h3', { text: b.title }), b.text ? el('p', { class: 'muted', text: b.text }) : null,
        b.error ? el('div', { class: 'fielderror', text: b.error }) : null,
        b.plan === null ? el('p', { class: 'muted', text: 'No plan yet - start the run "' + b.run_title + '" (Runs).' })
            : el('p', { class: 'muted', text: 'Plan: run ' + b.plan.jid.slice(0, 8) + ' by ' + (b.plan.by || '?') + ', ' + fmtTime(b.plan.finished) + ' (content ' + b.plan.hash + ')'
                + (b.four_eyes ? ' - four eyes: approved by another person than ' + (b.plan.by || '?') : '') }),
        b.areas.length ? el('div', { class: 'scmscroll' }, table(['Area', 'Entries', 'Decision', 'Note', ''], rows)) : null,
        b.plan !== null ? el('p', { class: b.complete ? 'notice' : 'muted', text: b.complete ? 'All ' + b.areas.length + ' areas approved - the run that needs this approval can start.'
            : done + ' of ' + b.areas.length + ' areas approved - the run that needs this approval starts only when all are.' }) : null);
}

// a table of a plug-in: its rows, editable columns; stored are the changes per row - the value of the plug-in below a
// changed cell; a filter for long tables (every MU IP pool, every tunnel)
function pluginTableBlock(base, key, b, canWrite, reload) {
    const cells = {}, errs = {}, trs = [];
    const formErr = el('div', { class: 'fielderror' });
    const head = el('tr', {}, b.fields.map(f => el('th', { text: f.label + (f.edit ? ' ✎' : ''), title: f.help || '' })), el('th', {}));
    const body = el('tbody', {}, b.rows.map(r => {
        const rowErr = el('div', { class: 'fielderror' });
        errs[r.key] = rowErr;
        const tr = el('tr', {}, b.fields.map(f => {
            if (!f.edit) return el('td', { text: pluginShow(r.value[f.name]) });
            const input = pluginInput(f, r.value[f.name], true);
            input.disabled = !canWrite;
            cells[r.key + '/' + f.name] = { f, input };
            errs[r.key + '/' + f.name] = el('div', { class: 'fielderror' });
            const changed = r.changed.includes(f.name);
            return el('td', { class: changed ? 'pchanged' : '' }, input,
                changed ? el('div', { class: 'muted', text: 'source: ' + (pluginShow(r.source[f.name]) || '-') }) : null, errs[r.key + '/' + f.name]);
        }), el('td', {}, rowErr));
        tr.searchText = (r.key + ' ' + b.fields.map(f => pluginShow(r.value[f.name])).join(' ')).toLowerCase();
        trs.push(tr);
        return tr;
    }));
    const filter = el('input', { placeholder: 'filter', class: 'narrow' });
    const count = el('span', { class: 'muted', text: b.rows.length + ' rows' });
    filter.addEventListener('input', () => {
        const q = filter.value.trim().toLowerCase(); let n = 0;
        trs.forEach(tr => { tr.hidden = q !== '' && !tr.searchText.includes(q); if (!tr.hidden) n++; });
        count.textContent = (q === '' ? '' : n + ' of ') + b.rows.length + ' rows';
    });
    const save = () => run(async () => {
        Object.values(errs).forEach(e => e.textContent = ''); formErr.textContent = '';
        const rows = {};
        Object.entries(cells).forEach(([id, c]) => { const [k] = [id.slice(0, id.lastIndexOf('/'))]; (rows[k] = rows[k] || {})[c.f.name] = c.input.valueOf2(); });
        try {
            await api('PUT', base + '/pages/' + key + '/blocks/' + b.name, { rows });
        } catch (e) {
            if (e.fields) { Object.entries(e.fields).forEach(([k, m]) => { (errs[k] || formErr).textContent = m; }); throw new Error(b.title + ': ' + e.message); }
            throw e;
        }
        message(b.title + ': saved'); reload();
    });
    return el('div', { class: 'pblock' }, el('h3', { text: b.title }), b.text ? el('p', { class: 'muted', text: b.text }) : null,
        b.error ? el('div', { class: 'fielderror', text: b.error }) : null,
        el('div', { class: 'row' }, filter, count),
        el('div', { class: 'scmscroll' }, el('table', { class: 'ptable' }, el('thead', {}, head), body)), formErr,
        el('div', { class: 'row' }, canWrite && b.rows.length ? el('button', { class: 'primary', type: 'button', text: 'Save', onclick: save }) : null,
            el('span', { class: 'muted', text: b.saved_at ? 'changes saved by ' + (b.saved_by || '?') + ', ' + fmtTime(b.saved_at) : 'no changes yet - the values are the ones of the plug-in' })));
}

// a matrix of a plug-in (read only): rows x columns, a state per cell - e.g. configurations x pan-os-php images. A cell can
// name a run of the project: its files open in a tab (js/run-file.js)
const PLUGIN_MATRIX_BADGE = { ok: 'badge ok', fail: 'badge warn', warn: 'badge dirty', old: 'badge dirty', running: 'badge', none: '' };
// a time of a matrix (cell / row): short, in the time of the browser
function pluginMatrixTime(ts) {
    return ts ? new Date(ts * 1000).toLocaleString([], { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) : '';
}

// what the last start from a matrix did, shown once after the page is drawn again: block => text
const pluginMatrixNotes = {};

function pluginMatrixBlock(base, key, b, reload) {
    const pid = decodeURIComponent(base.split('/')[1]);
    const id = base + '/' + key + '/' + b.name;
    // a run of a cell / the runs of an action: the server computes the matrix again and starts what it offers now
    const start = (body, what) => run(async () => {
        const r = await api('POST', base + '/pages/' + key + '/blocks/' + b.name + '/run', body);
        pluginMatrixNotes[id] = { ok: r.errors.length === 0, text: what + ': ' + r.started.length + ' run(s) started'
            + (r.waiting ? ' (' + r.waiting + ' wait for room in the queue - they start by themselves)' : '')
            + (r.not_started ? ', ' + r.not_started + ' not started' : '') + (r.errors.length ? ' - ' + r.errors.join('; ') : '') };
        reload();
    });
    const text = c => (c.text || c.state) + (c.at ? ' ' + pluginMatrixTime(c.at) : '');
    const links = c => {
        const a = (c.run ? c.files : []).map(f => el('a', { href: runFileLink(pid, c.run, f), target: '_blank', rel: 'noopener', title: 'open ' + f + ' in a new tab', text: f.split('/').pop() }));
        // a finished diff run: its differences by object (in a new tab)
        if (c.diff) a.unshift(el('a', { href: diffViewLink(pid, c.run), target: '_blank', rel: 'noopener', title: 'the differences by object, in a new tab', text: 'diff view' }));
        // the figures of the two runs of the cell compared (the compare of the list of runs, in a new tab)
        if (c.compare) a.push(el('a', { href: location.pathname + '#' + new URLSearchParams({ p: pid, stats: c.compare[0], other: c.compare[1] }).toString(),
            target: '_blank', rel: 'noopener', title: 'compare the figures of the two runs in a new tab', text: 'stats' }));
        return a.length ? el('div', { class: 'matrixfiles' }, a) : null;
    };
    const cell = (r, col, c) => el('td', { title: (c.title || '') + (c.at ? (c.title ? ' - ' : '') + fmtTime(c.at) : '') || null },
        c.state === 'none' && !c.text ? el('span', { class: 'muted', text: '-' }) : el('span', { class: PLUGIN_MATRIX_BADGE[c.state] || 'badge', text: text(c) }),
        c.action ? [' ', el('button', { type: 'button', class: 'small', text: c.action, title: 'start the run of this cell',
            onclick: () => start({ row: r.key, column: col.key }, r.label + ' / ' + col.label) })] : null,
        links(c));
    const sub = r => [r.sub, r.at ? pluginMatrixTime(r.at) : ''].filter(x => x).join(' - ');
    const actions = (b.actions || []).map(a => el('button', { type: 'button', text: a.label + ' (' + a.count + ')', title: a.title || null, disabled: a.count === 0,
        onclick: () => { if (a.count > 1 && !confirm(a.label + ': start ' + a.count + ' runs?')) return; start({ action: a.name }, a.label); } }));
    const note = pluginMatrixNotes[id];
    delete pluginMatrixNotes[id];
    const node = el('div', { class: 'pblock' }, el('h3', { text: b.title }), b.text ? el('p', { class: 'muted', text: b.text }) : null,
        b.error ? el('div', { class: 'fielderror', text: b.error }) : null,
        note ? el('p', { class: note.ok ? 'notice' : 'fielderror', text: note.text }) : null,
        actions.length ? el('div', { class: 'row' }, actions) : null,
        b.rows.length === 0 ? (b.error ? null : el('p', { class: 'muted', text: 'nothing to show yet' })) :
        el('div', { class: 'tablewrap' }, el('table', { class: 'plain matrix' },
            el('thead', {}, el('tr', {}, el('th', { text: '' }), b.columns.map(c => el('th', { text: c.label, title: c.title || null })))),
            el('tbody', {}, b.rows.map(r => el('tr', {}, el('td', { class: 'wrap' }, el('b', { text: r.label }), sub(r) ? el('div', { class: 'muted', text: sub(r) }) : null),
                r.cells.map((c, i) => cell(r, b.columns[i], c))))))));
    // while a run of the matrix runs: drawn again every 10 seconds, as long as the page is shown
    if (b.rows.some(r => r.cells.some(c => c.state === 'running')))
        setTimeout(() => { if (node.isConnected) reload(); }, 10000);
    return node;
}
