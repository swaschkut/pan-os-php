/*
 * pan-os-php config viewer - browser part, a result file of a run shown in the page (a tab of its own, opened from
 * the list of runs: #p=<project>&run=<run>&file=<name>) instead of download + text editor.
 * Part of app.js in a file of its own: declarations only - nothing runs when the file is loaded.
 */
'use strict';

// result files that are text: shown in the page. Everything else (HTML exports, archives, …) stays a download - an
// HTML file of a run is never opened as a page of the viewer.
const RUN_FILE_TEXT = /(^|\/)[^/.]+$|\.(log|txt|xml|json|csv|set|md|ya?ml|conf|cfg)$/i;
// more than this is not put into the page (the browser gets slow) - download it
const RUN_FILE_VIEW_MAX = 30 * 1048576;

function runFileIsText(name) { return RUN_FILE_TEXT.test(name); }

// the address that opens a result file in a tab of its own
function runFileLink(pid, jid, name) {
    return location.pathname + '#' + new URLSearchParams({ p: pid, run: jid, file: name }).toString();
}

async function showRunFile(pid, jid, name) {
    const base = 'projects/' + encodeURIComponent(pid);
    const p = await api('GET', base);
    const r = await api('GET', base + '/runs/' + encodeURIComponent(jid));
    const f = (r.files || []).find(x => x.name === name);
    if (!f) throw new Error('the run has no file "' + name + '" (any more)');
    const url = API + '/' + base + '/runs/' + r.jid + '/files/' + f.name.split('/').map(encodeURIComponent).join('/');
    document.title = f.name + ' - ' + p.name;
    const head = el('div', { class: 'card' },
        el('h2', { text: f.name }),
        el('p', { class: 'muted', text: 'Project ' + p.name + ' - run ' + r.type + (r.image ? ' (image ' + r.image + ')' : '') + ' of ' + fmtTime(r.created) + ' - ' + fmtSize(f.size) }));
    const main = document.getElementById('main');
    if (!runFileIsText(f.name) || f.size > RUN_FILE_VIEW_MAX) {
        head.append(el('p', { text: !runFileIsText(f.name) ? 'This kind of file is not shown in the page.' : 'The file is too large to show it in the page.' }),
            el('p', {}, el('a', { href: url, text: 'Download ' + f.name })));
        main.replaceChildren(head);
        return;
    }
    const res = await fetch(url, { credentials: 'same-origin' });
    if (!res.ok) throw new Error('the file could not be read (' + res.status + ')');
    const text = (await res.text()).replace(/\r\n?/g, '\n');
    const lines = text === '' ? 0 : text.split('\n').length - (text.endsWith('\n') ? 1 : 0);
    // line numbers and text: two columns of one scrolling area (as text - nothing of the file becomes markup)
    const numbers = el('pre', { class: 'filenumbers', 'aria-hidden': 'true', text: Array.from({ length: lines }, (x, i) => i + 1).join('\n') });
    const body = el('pre', { class: 'filetext', text: text });
    const view = el('div', { class: 'fileview' }, numbers, body);
    const wrap = el('input', { type: 'checkbox' });
    wrap.addEventListener('change', () => { view.classList.toggle('wrap', wrap.checked); numbers.hidden = wrap.checked; });
    head.append(el('div', { class: 'row' },
        el('span', { class: 'muted', text: lines + (lines === 1 ? ' line' : ' lines') }),
        el('label', { class: 'check', title: 'long lines are wrapped; the line numbers are hidden then' }, wrap, ' wrap long lines'),
        el('a', { href: url, text: 'Download' })));
    main.replaceChildren(head, view);
}
