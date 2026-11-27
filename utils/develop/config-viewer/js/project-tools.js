/*
 * pan-os-php config viewer - browser part, change list as playbook, support file, tabs of a project, suggestions while typing.
 * Part of app.js in a file of its own: declarations only (functions, constants) - nothing runs when the file is
 * loaded. index.html loads the parts before app.js, which holds the helpers, the viewer / editor and the start.
 */
'use strict';

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
