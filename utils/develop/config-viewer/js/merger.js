/*
 * pan-os-php config viewer - browser part, Merger tab of a project.
 * Part of app.js in a file of its own: declarations only (functions, constants) - nothing runs when the file is
 * loaded. index.html loads the parts before app.js, which holds the helpers, the viewer / editor and the start.
 */
'use strict';

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
