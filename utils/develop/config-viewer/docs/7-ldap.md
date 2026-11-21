# LDAP

The tab **LDAP** of a project asks the LDAP / Active Directory of the customer **with your own account** - for the
firewall administrator who needs to know which groups a user is in, and for the cleanup of the rules: do the users of
the security rules still exist?

## What is needed

1. **Network** - as for an import from a device (see *Import from devices*): network for runs (administrator), network
   for the project (owner), and the **LDAP server on the allow list** of the administrator (e.g. `dc1.example.com`,
   `*.example.com` or its network). The server is always named explicitly - there is no automatic discovery (DNS SRV).
2. **Your LDAP account** - under **Account → My API keys**: kind *LDAP account*, the bind user (`alice@example.com`
   or `EXAMPLE\alice`) and its password. In the pan-os-php key store this is the entry `ldap_user<bind user>`, e.g.
   `ldap_useralice@example.com:<password>` (as `tsg_id<TSG>` for SCM) - *Import key store* takes such lines over from
   an existing `.panconfkeystore`. The bind user of a query must be one of your LDAP accounts. The password is
   personal, never shown again, and is given to the run only in its key store (removed when the run ends, never in
   `run.log`). The old entry `ldap-password` (password only) is not used for LDAP any more.
3. **Write permission** in the project.

## Not sure about server and base DN?

In the tab **LDAP**, *Not sure about server and base DN? Find them from the domain name*: enter the AD domain (e.g.
`example.local`) → **Find servers**. The run asks

1. the DNS for the domain controllers (SRV records `_ldap._tcp.dc._msdcs.<domain>`, else `_ldap._tcp.<domain>`;
   none: the domain name itself), ordered by priority / weight - with LDAPS port 636 (or LDAP when *LDAPS* is off),
2. the first one that answers for its RootDSE - anonymous, no password: the **base DN** (`defaultNamingContext`).
   Only servers in the domain (`<host>.<domain>`) are asked.

The result lists the servers with what the network rules allow now. **Use for a new query** fills in the form: the
allowed server that answered, its base DN, your LDAP account of the domain as bind user (`<you>@<domain>` - add it
under *My API keys* first) and `sAMAccountName`; you add the users or the group and save it.

Needed: network for runs and for the project, and the hosts of the domain on the allow list (`*.example.local`).
Internal names: the runs use the DNS of the computer the viewer runs on. If it does not know the AD domain (e.g. the
viewer machine is not in it, or Docker falls back to public DNS servers), set the DNS servers of the domain in `.env`
next to `panosphp-viewer`: `VIEWER_RUN_DNS=10.0.0.10,10.0.0.11`, then `./panosphp-viewer restart`.

Command line: `pan-os-php type=ldap-query mode=discover domain=example.local [ldaps=no] [out=servers.json]`.

## Saved queries

A query is **yours** - nobody else sees it, also no administrator. It holds:

| Field | |
|---|---|
| Server | `ldaps://dc1.example.com:636` (or `ldap://…`) |
| Bind user | one of your LDAP accounts: `alice@example.com` (UPN) or `EXAMPLE\alice` |
| Base DN | where to search: `OU=Users,DC=example,DC=com` |
| User attribute | the attribute the user names are in (default `sAMAccountName`) |
| What | see below |

What a query asks (pan-os-php `type=ldap-query mode=…`, the scripts of `utils/develop/ldap` without questions):

| What | | Result |
|---|---|---|
| `validation` | do the accounts still exist? (users: one per line) | per user: found, active / disabled, expired, password last set, expiry |
| `user-groups` | the groups of a user | direct and nested groups |
| `common-groups` | the groups **all** given users are in | fewest members first, *with nested groups* optional; per user direct / nested |
| `group-members` | the members of a group (CN or sAMAccountName) | status and expiry, soonest expiry first |

**Run** starts it; the result is shown in the tab (*Show result*: a table, rows of missing / disabled / expired
accounts marked) and is kept as `ldap.json` / `ldap.csv` with the run (**Runs and project files**). Every finished run
- also a failed one - has its `run.log` linked under *My LDAP runs*.

## Check the users of the rules of a version

**Check the users of the rules** runs `type=rule location=any actions=user-check-ldap:…` on a version with the
server, bind user, base DN and attribute of the query:

- **show missing users** - the run log names the security rules with users that are not in the LDAP any more
- **remove missing users** - also removes them from the rules (a rule without users left is disabled); the result is
  a configuration of the run: **Result as new version** under **Runs and project files**. The version itself stays.

## On the command line (pan-os-php)

```
pan-os-php type=ldap-query mode=validation ldapServer=ldaps://dc1.example.com:636 ldapUser=alice@example.com \
    dn="OU=Users,DC=example,DC=com" users=bob,carol out=ldap.json csv=ldap.csv
pan-os-php type=ldap-query mode=common-groups ... users=bob,carol transitive=yes
pan-os-php type=ldap-query mode=group-members ... group=VPN-Users
```

The password: key store entry `ldap_user<ldapUser>`, e.g. `ldap_useralice@example.com` (asked for and stored when it is
missing; `pan-os-php type=key-manager add=ldap_useralice@example.com apikey=<password>`). The same for the rule
actions `user-check-ldap` and the scripts of `utils/develop/ldap`. Entry names are read in lower case; a bind user can
not contain spaces, `:`, `%` or `/`. `dn` may use `;` instead of `,`. In `user-check-ldap` the server can be given as `ldaps%dc1.example.com%636` (`:` and `/` can not be used in the
arguments of an action).
