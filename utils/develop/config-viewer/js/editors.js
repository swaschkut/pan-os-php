/*
 * pan-os-php config viewer - browser part, editors of pan-os-php in a window (playbook, BP JSON).
 * Part of app.js in a file of its own: declarations only (functions, constants) - nothing runs when the file is
 * loaded. index.html loads the parts before app.js, which holds the helpers, the viewer / editor and the start.
 */
'use strict';

// ---------------------------------------------------------------- editors of pan-os-php (playbook, BP JSON)
// in a sandboxed frame (editor.php: an origin of its own, no API, no cookies); it gets the file and gives the result back
// with postMessage - Save stores a NEW project file, checked like an upload (a playbook: playbookCheck)
function openEditor(kind, pid, file, done) {
    const base = 'projects/' + pid;
    const frame = el('iframe', { src: 'editor.php?e=' + (kind === 'bp' ? 'bp' : 'playbook'), sandbox: 'allow-scripts', title: (kind === 'bp' ? 'BP JSON' : 'playbook') + ' editor', class: 'editorframe' });
    const close = () => { window.removeEventListener('message', onMsg); overlay.remove(); };
    const overlay = el('div', { class: 'editoroverlay' },
        el('div', { class: 'editorbar' }, el('strong', { text: (kind === 'bp' ? 'BP JSON' : 'Playbook') + ' editor' }),
            el('span', { class: 'muted', text: file ? 'a copy of ' + file.name + ' - ' + (kind === 'bp' ? 'Export JSON' : 'SAVE') + ' stores it as a new project file' : 'new file - ' + (kind === 'bp' ? 'starts with the BP JSON shipped with pan-os-php; Export JSON' : 'SAVE') + ' stores it in the project' }),
            el('span', { class: 'spacer' }), el('button', { type: 'button', text: 'Close', onclick: () => { if (confirm('Close the editor? What is not saved is lost.')) close(); } })),
        frame);
    async function onMsg(e) {
        if (e.source !== frame.contentWindow || !e.data || typeof e.data.type !== 'string') return;
        // a file of the project, or - a new BP JSON - the one shipped with pan-os-php as the start
        if (e.data.type === 'panosphp-editor-ready' && (file || kind === 'bp')) {
            const r = await fetch(API + '/' + (file ? base + '/files/' + file.fid + '/download' : 'bp-default'), { credentials: 'same-origin' });
            if (r.ok) frame.contentWindow.postMessage({ type: 'panosphp-editor-load', json: await r.text() }, '*');
            else message('the file could not be read', 'error');
        }
        if (e.data.type === 'panosphp-editor-save' && typeof e.data.json === 'string') {
            const def = file ? file.name.replace(/\.json$/i, '') + '-edited.json' : (kind === 'bp' ? 'bp.json' : 'playbook.json');
            let name = prompt('Name of the new project file', def);
            if (!name) return;
            name = name.trim().endsWith('.json') ? name.trim() : name.trim() + '.json';
            run(async () => {
                const fd = new FormData(); fd.append('file', new Blob([e.data.json], { type: 'application/json' }), name);
                await api('POST', base + '/files?kind=' + kind, fd);
                close(); await done(); message('saved as the new project file ' + name);
            });
        }
    }
    window.addEventListener('message', onMsg);
    document.body.append(overlay);
}
