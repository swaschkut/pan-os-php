/*
 * pan-os-php config viewer - browser part, LDAP tab of a project.
 * Part of app.js in a file of its own: declarations only (functions, constants) - nothing runs when the file is
 * loaded. index.html loads the parts before app.js, which holds the helpers, the viewer / editor and the start.
 */
'use strict';

// ---------------------------------------------------------------- LDAP tab of a project
async function ldapTab(base, pid, p, owner, versions) {
    const card = el('div', { class: 'card' });
    const info = await api('GET', 'ldap');
    const allRuns = (await api('GET', base + '/runs')).runs.filter(r => r.user === state.user);
    const runs = allRuns.filter(r => r.type === 'ldap' || r.type === 'ldap-users' || r.type === 'ldap-discover');
    const out = el('div', {});
    const redraw = async () => { card.replaceWith(await ldapTab(base, pid, p, owner, versions)); };
    // the form: a new query, or a saved one to change
    const f = {
        name: el('input', { required: true, maxlength: 80, autocomplete: 'off' }),
        // empty = automatic: the first domain controller of the domain from DNS that works
        server: el('input', { placeholder: 'empty = automatic (DNS of the domain)', autocomplete: 'off', spellcheck: false }),
        domain: el('input', { placeholder: 'example.local', autocomplete: 'off', spellcheck: false }),
        ldaps: el('input', { type: 'checkbox', checked: true }),
        bind_user: el('input', { required: true, placeholder: 'admin@example.com or EXAMPLE\\admin', autocomplete: 'off', spellcheck: false, list: 'ldap-accounts-' + pid }),
        base_dn: el('input', { required: true, placeholder: 'OU=Users,DC=example,DC=com', autocomplete: 'off', spellcheck: false }),
        attribute: el('input', { value: 'sAMAccountName', autocomplete: 'off', spellcheck: false }),
        mode: el('select', {}, Object.entries(info.modes).map(([k, t]) => el('option', { value: k, text: k + ' - ' + t }))),
        users: el('textarea', { rows: 3, placeholder: 'one user per line (or comma separated)', spellcheck: false }),
        group: el('input', { autocomplete: 'off', spellcheck: false }),
        transitive: el('input', { type: 'checkbox' }),
    };
    let editing = null;
    const fUsers = field('Users', f.users), fGroup = field('Group (CN or sAMAccountName)', f.group), fTrans = field('With nested groups', f.transitive);
    const modeChanged = () => { const m = f.mode.value; fUsers.hidden = m === 'group-members'; fGroup.hidden = m !== 'group-members'; fTrans.hidden = m !== 'common-groups'; };
    f.mode.addEventListener('change', modeChanged); modeChanged();
    const saveBtn = el('button', { class: 'primary', type: 'submit', text: 'Save query' });
    const fill = (q) => {
        editing = q ? q.qid : null;
        for (const k of ['name', 'server', 'domain', 'bind_user', 'base_dn', 'attribute']) f[k].value = q ? q[k] : (k === 'attribute' ? 'sAMAccountName' : '');
        f.ldaps.checked = q ? q.ldaps : true;
        f.mode.value = q ? q.mode : 'validation'; f.users.value = q ? q.users.join('\n') : ''; f.group.value = q ? q.group : ''; f.transitive.checked = q ? q.transitive : false;
        saveBtn.textContent = q ? 'Save changes' : 'Save query'; modeChanged();
    };
    // my LDAP accounts (key store entries ldap_user<user>) as suggestions for the bind user
    const accounts = el('datalist', { id: 'ldap-accounts-' + pid }, info.accounts.map(a => el('option', { value: a })));
    const form = el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
        const body = {};
        for (const k of ['name', 'server', 'domain', 'bind_user', 'base_dn', 'attribute', 'mode', 'users', 'group']) body[k] = f[k].value.trim();
        body.ldaps = f.ldaps.checked;
        body.transitive = f.transitive.checked;
        await api(editing ? 'PUT' : 'POST', 'ldap' + (editing ? '/' + editing : ''), body);
        await redraw(); message('LDAP query saved');
    }); } }, field('Name', f.name), field('Domain', f.domain), field('Server (optional)', f.server), field('LDAPS', f.ldaps), field('Bind user (my account)', f.bind_user), field('Base DN', f.base_dn), field('User attribute', f.attribute),
        field('What', f.mode), fUsers, fGroup, fTrans, saveBtn, el('button', { type: 'button', text: 'New', onclick: () => fill(null) }));

    const why = !p.network_global ? 'Network for runs is off (an administrator turns it on under Account).'
        : !p.network ? 'Network is off for this project' + (owner ? ' (Configuration versions, Import from a device).' : ' (the owner turns it on).')
        : info.accounts.length === 0 ? 'You have no LDAP account yet: add one under Account, My API keys (kind LDAP account: bind user + password; key store entry ldap_user<user>).' : null;
    const verSel = () => el('select', { 'aria-label': 'version' }, versions.map(c => el('option', { value: c.cid, text: c.name })));
    // ---- help for the first query: the domain controllers of an AD domain (DNS SRV) and the base DN (RootDSE)
    const dDomain = el('input', { placeholder: 'example.local', autocomplete: 'off', spellcheck: false, required: true });
    const dLdaps = el('input', { type: 'checkbox', checked: true });
    const dOut = el('div', {});
    const showFound = async (jid) => {
        const d = await api('GET', base + '/runs/' + jid + '/ldap-servers');
        const sg = d.suggestion;
        dOut.replaceChildren(
            table(['Server', 'Priority / weight', 'Answered', 'Network'], d.servers.map(s => el('tr', { class: s.refused ? 'warnrow' : '' },
                el('td', { text: s.uri }), el('td', { text: s.priority + ' / ' + s.weight }), el('td', { text: s.answered ? 'yes (base DN from it)' : '' }),
                el('td', { class: 'wrap', text: s.refused ? s.refused : 'allowed' })))),
            el('p', { class: 'muted', text: 'Base DN: ' + sg.base_dn + (sg.base_from === 'rootdse' ? ' (from the server)' : ' (from the domain name - no server answered)')
                + (sg.server ? '' : ' - no server is allowed by the network rules yet: the administrator puts *.' + d.domain + ' on the allow list.')
                + (sg.bind_user ? '' : ' You have no LDAP account @' + d.domain + ' yet: add it under Account, My API keys (bind user ' + sg.bind_hint + ' and its password).') }),
            el('button', { type: 'button', class: 'primary', text: 'Use for a new query', onclick: () => {
                fill(null);
                // the server stays empty: the run takes the first domain controller of the domain that works
                f.name.value = sg.name; f.domain.value = d.domain; f.server.value = ''; f.base_dn.value = sg.base_dn;
                f.bind_user.value = sg.bind_user || ''; f.bind_user.placeholder = sg.bind_hint; f.attribute.value = sg.attribute;
                (sg.bind_user ? f.users : f.bind_user).focus();
                message('filled in - check it, add the users / group, then Save query');
            } }));
    };
    const waitFound = (jid) => {
        dOut.replaceChildren(el('span', { class: 'muted', text: 'searching …' }));
        const t = setInterval(() => run(async () => {
            const r = await api('GET', base + '/runs/' + jid);
            if (r.state === 'queued' || r.state === 'running') return;
            clearInterval(t);
            if (r.state === 'done') await showFound(jid);
            else dOut.replaceChildren(el('span', { class: 'error', text: 'the search failed: ' + (r.error || r.state) + ' ' }),
                el('a', { href: API + '/' + base + '/runs/' + jid + '/files/run.log', target: '_blank', rel: 'noopener', text: 'run.log' }));
        }), 2000);
        // while the project page is built, its timers start with it (showProject)
        (state.pendingTimers || state.timers).push(t);
    };
    const discover = el('details', { class: 'help', open: info.queries.length === 0 },
        el('summary', { text: 'Not sure about server and base DN? Find them from the domain name' }),
        el('p', { class: 'muted', text: 'Asks the DNS for the domain controllers of the AD domain (SRV records) and the first one that answers for its base DN - without a login. The administrator must allow the hosts of the domain (e.g. *.example.local) in the network rules; for internal names the runs may need the DNS server of the domain (VIEWER_RUN_DNS).' }),
        !p.network_global || !p.network ? null : el('form', { class: 'row', onsubmit: (ev) => { ev.preventDefault(); run(async () => {
            const r = await api('POST', base + '/ldap-discover/runs', { domain: dDomain.value.trim(), ldaps: dLdaps.checked });
            waitFound(r.jid);
        }); } }, field('AD domain', dDomain), field('LDAPS (636)', dLdaps), el('button', { type: 'submit', text: 'Find servers' })),
        dOut);
    const lastFound = allRuns.find(r => r.type === 'ldap-discover');
    const logLink = (r, text) => el('a', { href: API + '/' + base + '/runs/' + r.jid + '/files/run.log', target: '_blank', rel: 'noopener', text: text || 'run.log' });
    if (lastFound && lastFound.state === 'done') { dDomain.value = ((lastFound.args || []).find(a => a.startsWith('domain=')) || '').slice(7); showFound(lastFound.jid).catch(() => {}); }
    else if (lastFound && (lastFound.state === 'queued' || lastFound.state === 'running')) waitFound(lastFound.jid);

    const queries = info.queries.length === 0 ? el('p', { class: 'muted', text: 'No saved queries yet.' }) :
        table(['Name', 'What', 'Server', 'Base DN', 'Users / group', ''], info.queries.map(q => {
            const v = verSel();
            const noAccount = !info.accounts.includes(q.bind_user.toLowerCase());
            const act = el('select', { 'aria-label': 'show or remove' }, el('option', { value: 'show', text: 'show missing users' }), el('option', { value: 'remove', text: 'remove missing users (result = new version)' }));
            return el('tr', {}, el('td', { text: q.name }), el('td', { text: q.mode }), el('td', { class: 'wrap', text: q.auto ? 'automatic: ' + q.domain + (q.ldaps ? ' (LDAPS)' : ' (LDAP)') : q.server }), el('td', { class: 'wrap', text: q.base_dn }),
                el('td', { class: 'wrap', text: q.mode === 'group-members' ? q.group : q.users.join(', ') }),
                el('td', {}, el('div', { class: 'row' },
                    !why && noAccount ? el('span', { class: 'error', text: 'no LDAP account ' + q.bind_user + ' (My API keys)' }) : null,
                    why || noAccount ? null : el('button', { type: 'button', class: 'primary', text: 'Run', disabled: q.mode !== 'group-members' && q.users.length === 0, onclick: () => run(async () => {
                        await api('POST', base + '/ldap/runs', { qid: q.qid }); await redraw(); message('LDAP query queued');
                    }) }),
                    why || noAccount || versions.length === 0 ? null : el('span', {}, el('button', { type: 'button', text: 'Check the users of the rules', title: 'type=rule actions=user-check-ldap with the server, bind user, base DN and attribute of this query', onclick: () => run(async () => {
                        if (act.value === 'remove' && !confirm('Remove the users that are not in the LDAP any more from the security rules? The result is a new configuration (Result as new version) - the version itself stays.')) return;
                        await api('POST', base + '/configs/' + v.value + '/ldap-users/runs', { qid: q.qid, action: act.value }); await redraw(); message('check queued');
                    }) }), ' of ', v, ' ', act),
                    el('button', { type: 'button', text: 'Edit', onclick: () => { fill(q); f.name.focus(); } }),
                    el('button', { class: 'danger', type: 'button', text: 'Delete', onclick: () => run(async () => {
                        if (!confirm('Delete the LDAP query ' + q.name + '?')) return;
                        await api('DELETE', 'ldap/' + q.qid); await redraw();
                    }) }))));
        }));
    const show = async (r) => {
        if (r.type === 'ldap-users') { out.replaceChildren(el('h3', { text: 'Result' }), logLink(r, 'run.log (download)'), el('pre', { class: 'log', text: await (await fetch(API + '/' + base + '/runs/' + r.jid + '/files/run.log', { credentials: 'same-origin' })).text() })); return; }
        const res = await (await fetch(API + '/' + base + '/runs/' + r.jid + '/files/ldap.json', { credentials: 'same-origin' })).json();
        const rows = res.rows || [];
        const cols = [...new Set(rows.flatMap(x => Object.keys(x)))];
        const val = v => v === null || v === undefined ? '' : typeof v === 'boolean' ? (v ? 'yes' : 'no') : typeof v === 'object' ? Object.entries(v).map(([a, b]) => a + ': ' + b).join(', ') : String(v);
        out.replaceChildren(el('h3', { text: 'Result: ' + res.mode + (res.group ? ' ' + res.group : '') + (res.user ? ' ' + res.user : '') + ' - ' + rows.length + ' row(s)' + (res.missing ? ', ' + res.missing + ' not found' : '') }),
            res.notFound && res.notFound.length ? el('p', { class: 'error', text: 'not found: ' + res.notFound.join(', ') }) : null,
            el('div', { class: 'row' }, el('a', { href: API + '/' + base + '/runs/' + r.jid + '/files/ldap.csv', text: 'CSV' }), logLink(r)),
            rows.length === 0 ? el('p', { class: 'muted', text: 'nothing found' }) :
            table(cols, rows.map(x => el('tr', { class: x.found === false || x.status === 'disabled' || x.expired ? 'warnrow' : '' }, cols.map(c => el('td', { class: 'wrap', text: val(x[c]) }))))));
    };
    const runList = runs.length === 0 ? null : table(['Run', 'State', 'Started', ''], runs.slice(0, 20).map(r => el('tr', {},
        el('td', { text: r.type === 'ldap' ? 'query ' + ((r.args || []).find(a => a.startsWith('mode=')) || '').slice(5)
            : r.type === 'ldap-discover' ? 'servers of ' + ((r.args || []).find(a => a.startsWith('domain=')) || '').slice(7)
            : 'rule users of ' + ((versions.find(c => c.cid === r.cid) || { name: '-' }).name) }),
        el('td', { class: 'wrap' }, el('span', { class: 'badge' + (r.state === 'queued' || r.state === 'running' ? ' dirty' : ''), text: r.state }), r.error ? el('span', { class: 'muted', text: ' ' + r.error }) : null),
        el('td', { text: fmtTime(r.started) }),
        el('td', {}, el('div', { class: 'row' },
            r.state === 'done' ? el('button', { type: 'button', text: 'Show result', onclick: () => run(() => r.type === 'ldap-discover' ? showFound(r.jid).then(() => { discover.open = true; discover.scrollIntoView(); }) : show(r)) }) : null,
            // the log of every finished run (also a failed one - why it failed)
            r.state === 'done' || r.state === 'failed' || r.state === 'cancelled' ? logLink(r) : null,
            r.state === 'queued' || r.state === 'running' ? el('button', { type: 'button', text: 'Refresh', onclick: () => run(redraw) }) : null)))));
    card.append(el('h2', { text: 'LDAP' }),
        el('p', { class: 'muted', text: 'Ask the LDAP / Active Directory with your own account: do the users still exist (cleanup), which groups does a user have, which groups do several users share, who is in a group. The queries are yours (nobody else sees them); the password of the bind user is your LDAP account under My API keys (key store entry ldap_user<user>). The server must be allowed by the administrator (network allow list). "Check the users of the rules" looks up the users of the security rules of a version (pan-os-php user-check-ldap); the run log shows the missing ones, "remove" also makes a result configuration without them.' }),
        why ? el('p', { class: 'muted', text: why }) : null, discover, accounts, form, queries, runList ? el('h3', { text: 'My LDAP runs' }) : null, runList, out);
    return card;
}
