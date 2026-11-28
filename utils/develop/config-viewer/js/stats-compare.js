/*
 * pan-os-php config viewer - browser part, the figures of two stats runs of a project compared (a tab of its own,
 * opened from the list of runs: #p=<project>&stats=<run>[&other=<run>]) - e.g. the result of the same playbook with
 * two pan-os-php images. The compare itself is done by the server (StatsCompare of pan-os-php).
 * Part of app.js in a file of its own: declarations only - nothing runs when the file is loaded.
 */
'use strict';

// the address that opens the compare with this run as the first one
function statsCompareLink(pid, jid) {
    return location.pathname + '#' + new URLSearchParams({ p: pid, stats: jid }).toString();
}

async function showStatsCompare(pid, jidA, jidB) {
    const base = 'projects/' + encodeURIComponent(pid);
    const p = await api('GET', base);
    const [runs, configs] = await Promise.all([api('GET', base + '/runs'), api('GET', base + '/configs')]);
    const stats = (runs.runs || []).filter(r => r.type === 'stats' && r.state === 'done');
    document.title = 'Stats compare - ' + p.name;
    const main = document.getElementById('main');
    const head = el('div', { class: 'card' }, el('h2', { text: 'Stats compare' }),
        el('p', { class: 'muted', text: 'Project ' + p.name + ' - the figures of two finished stats runs: what differs, and what exists in one of them only.' }));
    if (stats.length < 2) {
        head.append(el('p', { text: 'Two finished stats runs are needed (Runs: stats).' }));
        main.replaceChildren(head);
        return;
    }
    // a run in the lists: its version with the note (which run / image made that version), the image and the time of the stats run
    const label = r => {
        const c = configs.configs.find(x => x.cid === r.cid);
        return (c ? c.name + (c.note ? ' - ' + c.note : '') : '(deleted version)') + '  |  stats' + (r.image ? ' with image ' + r.image : '') + ' ' + fmtTime(r.finished || r.created);
    };
    const options = sel => stats.map(r => { const o = el('option', { value: r.jid, text: label(r) }); o.selected = r.jid === sel; return o; });
    if (!stats.some(r => r.jid === jidA)) jidA = stats[0].jid;
    if (!stats.some(r => r.jid === jidB) || jidB === jidA) jidB = (stats.find(r => r.jid !== jidA) || {}).jid;
    const a = el('select', {}, options(jidA)), b = el('select', {}, options(jidB));
    const out = el('div', {});
    head.append(el('div', { class: 'row' }, field('A (from)', a), field('B (to)', b),
        el('button', { type: 'button', text: 'A ⇄ B', title: 'swap the two runs', onclick: () => { const x = a.value; a.value = b.value; b.value = x; run(load); } })));
    const value = v => v === null || v === undefined ? '' : typeof v === 'boolean' ? (v ? 'true' : 'false') : String(v);
    const delta = (x, y) => typeof x === 'number' && typeof y === 'number' ? (y - x > 0 ? '+' : '') + String(Math.round((y - x) * 1000) / 1000) : '';
    const onlyList = (title, obj) => {
        const names = Object.keys(obj);
        return names.length === 0 ? null : el('details', { class: 'statsonly' }, el('summary', { text: title + ' (' + names.length + ')' }),
            table(['Figure', 'Value'], names.map(n => el('tr', {}, el('td', { class: 'wrap', text: n }), el('td', { text: value(obj[n]) })))));
    };
    async function load() {
        history.replaceState(null, '', location.pathname + '#' + new URLSearchParams({ p: pid, stats: a.value, other: b.value }).toString());
        if (a.value === b.value) { out.replaceChildren(el('div', { class: 'card' }, el('p', { text: 'Choose two different runs.' }))); return; }
        out.replaceChildren(el('div', { class: 'card' }, el('p', { class: 'muted', text: 'comparing ...' })));
        const r = await api('GET', base + '/runs/' + a.value + '/stats-compare?other=' + b.value);
        const blocks = Object.keys(r.blocks);
        const summary = el('div', { class: 'card' },
            el('p', {}, el('span', { class: 'badge ' + (r.equal ? 'ok' : 'warn'), text: r.equal ? 'no figure differs' : r.changed + (r.changed === 1 ? ' figure differs' : ' figures differ') }), ' ',
                r.only_a ? el('span', { class: 'badge', text: r.only_a + ' only in A' }) : null, ' ', r.only_b ? el('span', { class: 'badge', text: r.only_b + ' only in B' }) : null, ' ',
                el('span', { class: 'muted', text: r.blocks_a + ' / ' + r.blocks_b + ' statistics blocks (A / B)' })),
            r.blocks_only_a.length ? el('p', { class: 'wrap' }, el('b', { text: 'Statistics blocks only in A: ' }), r.blocks_only_a.join('; ')) : null,
            r.blocks_only_b.length ? el('p', { class: 'wrap' }, el('b', { text: 'Statistics blocks only in B: ' }), r.blocks_only_b.join('; ')) : null,
            r.same ? el('p', { text: 'Both runs have the same figures with the same values.' }) : null);
        // visibility not 100 %: every component that is not 100 in A or in B, with the value of both; the first statistics
        // block is the whole configuration (what compare-stats-not-100 of type=playbook-validation checks), the other
        // blocks are folded
        const nf = r.not_full || [], first = nf.length ? nf[0].block : null;
        const pct = v => v === null || v === undefined ? '-' : typeof v === 'number' ? v + ' %' : String(v);
        const nfTable = rows => table(['Component', 'Group', 'A', 'B'], rows.map(x => el('tr', {}, el('td', { text: x.name }), el('td', { class: 'muted', text: x.group || '' }),
            el('td', {}, el('span', { class: x.a === 100 ? 'badge ok' : x.a === null || x.a === 'N/A' ? 'badge' : 'badge warn', text: pct(x.a) })),
            el('td', {}, el('span', { class: x.b === 100 ? 'badge ok' : x.b === null || x.b === 'N/A' ? 'badge' : 'badge warn', text: pct(x.b) })))));
        const rest = [...new Set(nf.filter(x => x.block !== first).map(x => x.block))];
        const notFull = el('div', { class: 'card' }, el('h3', { text: 'Visibility not 100 %' }),
            el('p', { class: 'muted', text: 'Components whose visibility is not 100 % in A or in B. Left out: "N/A" (nothing to check) and ' + (r.not_full_excluded || []).join(', ') + '.' }),
            nf.length === 0 ? el('p', {}, el('span', { class: 'badge ok', text: 'everything is 100 % in A and B' })) :
            [el('p', {}, el('b', { text: first })), nfTable(nf.filter(x => x.block === first)),
                rest.length ? el('details', { class: 'statsonly' }, el('summary', { text: 'the other statistics blocks (' + rest.length + ')' }),
                    rest.map(h => [el('p', {}, el('b', { text: h })), nfTable(nf.filter(x => x.block === h))])) : null]);
        out.replaceChildren(summary, notFull, ...blocks.map(h => {
            const d = r.blocks[h], changed = Object.keys(d.changed);
            return el('div', { class: 'card' }, el('h3', { text: h }),
                changed.length ? table(['Figure', 'A', 'B', 'B - A'], changed.map(n => el('tr', {}, el('td', { class: 'wrap', text: n }),
                    el('td', { text: value(d.changed[n].from) }), el('td', { text: value(d.changed[n].to) }), el('td', { text: delta(d.changed[n].from, d.changed[n].to) })))) : null,
                onlyList('Only in A', d.only_a), onlyList('Only in B', d.only_b));
        }));
    }
    a.addEventListener('change', () => run(load)); b.addEventListener('change', () => run(load));
    main.replaceChildren(head, out);
    await load();
}
