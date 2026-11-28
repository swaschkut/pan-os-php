/*
 * pan-os-php config viewer - browser part, the differences of a diff run by object (a tab of its own, opened from the
 * list of runs or a matrix of a plug-in: #p=<project>&diff=<run>): where (shared, device group, template, …), what
 * (address, rules, …), which object, and the lines only file2 has (+) / only file1 has (-). The server reads run.log
 * of the run (DiffLog of pan-os-php). Part of app.js in a file of its own: declarations only - nothing runs when the
 * file is loaded.
 */
'use strict';

// the address that opens the diff view of a run
function diffViewLink(pid, jid) {
    return location.pathname + '#' + new URLSearchParams({ p: pid, diff: jid }).toString();
}

async function showDiffView(pid, jid) {
    const base = 'projects/' + encodeURIComponent(pid);
    const p = await api('GET', base);
    const d = await api('GET', base + '/runs/' + encodeURIComponent(jid) + '/diff-view');
    document.title = 'Diff view - ' + p.name;
    const main = document.getElementById('main');
    const file = name => el('a', { href: runFileLink(pid, d.run.jid, name), target: '_blank', rel: 'noopener', text: name });
    const added = d.entries.reduce((n, e) => n + (e.added && !e.removed ? 1 : 0), 0);
    const removed = d.entries.reduce((n, e) => n + (e.removed && !e.added ? 1 : 0), 0);
    const filter = el('input', { type: 'search', placeholder: 'filter: name, type, location, XPath or a line', 'aria-label': 'filter' });
    const out = el('div', {});
    main.replaceChildren(el('div', { class: 'card' }, el('h2', { text: 'Diff view' }),
        el('p', { class: 'muted', text: 'Project ' + p.name + ' - diff run ' + d.run.jid.slice(0, 8) + ' of ' + fmtTime(d.run.finished || d.run.created) }),
        el('p', { class: 'wrap' }, el('b', { text: 'file1 (-): ' }), d.file1.label),
        el('p', { class: 'wrap' }, el('b', { text: 'file2 (+): ' }), d.file2.label),
        el('p', {}, el('span', { class: 'badge ' + (d.final === 'PASS' ? 'ok' : d.final === 'FAIL' ? 'warn' : ''), text: d.final ? 'FinalResult ' + d.final : 'no FinalResult (the run failed?)' }), ' ',
            el('span', { class: 'muted', text: d.count + ' XPath(s) differ - ' + added + ' with added lines only (+), ' + removed + ' with removed lines only (-), ' + (d.entries.length - added - removed) + ' with both'
                + (d.truncated ? ' - the first ' + d.entries.length + ' are shown' : '') })),
        el('p', { class: 'matrixfiles' }, file('run.log'), d.setcommands ? file('set-commands.txt') : null),
        el('div', { class: 'row' }, field('Filter', filter))), out);

    // a line of the diff: + green, - red; the filter text marked
    const mark = (text, q) => {
        if (!q) return [text];
        const parts = [], low = text.toLowerCase();
        let i = 0, k;
        while ((k = low.indexOf(q, i)) >= 0) { parts.push(text.slice(i, k), el('mark', { text: text.slice(k, k + q.length) })); i = k + q.length; }
        parts.push(text.slice(i));
        return parts;
    };
    const lines = (e, q) => el('pre', { class: 'difflines' }, e.lines.map(l => el('span', { class: l[0] === '+' ? 'diffadd' : 'diffdel' }, ...mark(l, q), '\n')),
        e.lines_cut ? el('span', { class: 'muted', text: '… ' + e.lines_cut + ' more line(s) - run.log has all' }) : null);
    // + only: lines (an object, a setting) file2 has more; - only: file1 has more; both: a value changed
    const what = e => e.added && !e.removed ? el('span', { class: 'badge ok', text: 'added' }) : e.removed && !e.added ? el('span', { class: 'badge warn', text: 'removed' })
        : el('span', { class: 'badge dirty', text: 'changed' });
    // location -> kind -> entries; a group is drawn when it is opened (a large diff has thousands of entries)
    function draw() {
        const q = filter.value.trim().toLowerCase();
        const hit = e => !q || [e.location, e.kind, e.name, e.xpath].some(x => x.toLowerCase().includes(q)) || e.lines.some(l => l.toLowerCase().includes(q));
        const shown = d.entries.filter(hit);
        const byLoc = new Map();
        for (const e of shown) {
            if (!byLoc.has(e.location)) byLoc.set(e.location, new Map());
            const k = byLoc.get(e.location);
            if (!k.has(e.kind)) k.set(e.kind, []);
            k.get(e.kind).push(e);
        }
        if (shown.length === 0) { out.replaceChildren(el('div', { class: 'card' }, el('p', { class: 'muted', text: d.count ? 'nothing matches the filter' : 'no differences' }))); return; }
        out.replaceChildren(...[...byLoc].map(([loc, kinds]) => {
            const n = [...kinds.values()].reduce((a, x) => a + x.length, 0);
            const body = el('div', {});
            const fill = () => body.replaceChildren(...[...kinds].map(([kind, es]) => el('div', { class: 'diffkind' }, el('h3', { text: (kind || '(the location itself)') + ' (' + es.length + ')' }),
                es.map(e => el('details', { class: 'diffentry', open: q !== '' && es.length <= 20 },
                    el('summary', {}, what(e), ' ', el('b', {}, ...mark(e.name || '(no name)', q)), ' ', el('span', { class: 'muted', text: '+' + e.added + ' / -' + e.removed })),
                    el('div', { class: 'muted wrap', text: e.xpath }), lines(e, q))))));
            const det = el('details', { class: 'card diffloc', open: byLoc.size === 1 || q !== '' },
                el('summary', {}, el('b', { text: loc }), ' ', el('span', { class: 'muted', text: n + ' object(s)' })), body);
            if (det.open) fill(); else det.addEventListener('toggle', () => { if (det.open && !body.firstChild) fill(); });
            return det;
        }));
    }
    let timer = null;
    filter.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(draw, 250); });
    draw();
}
