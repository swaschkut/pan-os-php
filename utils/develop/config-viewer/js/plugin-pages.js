/*
 * pan-os-php config viewer - browser part, pages of plug-ins (interface 2): forms, tables, approval steps.
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
    if (f.type === 'select') {
        input = el('select', {}, f.required ? null : el('option', { value: '', text: '-' }),
            Object.entries(f.options).map(([o, label]) => { const x = el('option', { value: o, text: label }); x.selected = o === v; return x; }));
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
