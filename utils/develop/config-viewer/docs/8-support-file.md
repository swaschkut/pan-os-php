# Support file

For a problem the support of pan-os-php should look at - a merge that should not have happened, a run that fails, the
viewer itself - a project makes a **support file**: one file you send to the support (mail, upload). It is
**encrypted**: only the support of pan-os-php can open it.

## Make one

Project → tab **Support file** (write permission), or in a merger report the button **Support file for this run**:

- **Version** and **the run with the problem** (optional - without a run: a general problem)
- **Objects (names)** (optional): object names for the excerpt; the names of the report of the run are taken anyway
  (not merged / blocked ones always, merged ones up to 200)
- **What is the problem**: a short description
- **Rules that use the objects** (default on), **the whole configuration** (before / after the run),
  **anonymise everything** (and *keep private IP addresses*)

**Make the support file** starts a run; the file appears below (`support.tsf`) - download it and send it.

## What is in it

- the versions of pan-os-php, PHP, the operating system; the viewer (version, settings - without the host lists)
- the run: type, settings, state, error, `run.log`, its report (`merger.json`) and its result
- the **hierarchy**: device groups with their parents, templates / template stacks, number of firewalls
- an **excerpt of the configuration** for the objects - before and after the run: every copy of a name in every
  location (shared, device groups, vsys), the groups that hold them up to the top, the members of these groups down
  to the leaves, the rules that use them. The excerpt is a small configuration - the support runs the same merger
  on it and sees the same result.
- with *the whole configuration*: the version and the result
- project data: versions (name, size, how they were made), the last 50 runs, the audit log of the project
- the last errors of this page (script errors, refused requests)

**Never in it:** API keys, the key store, passwords / phash / keys / pre-shared keys / SNMP communities of the
configuration (always replaced, also without anonymisation), sessions, licence keys, other projects.

## Anonymised

Every name, address, host name and text becomes a pseudonym - the same one in every file of the support file
(`pan-os-php type=config-anonymize`), so the problem stays visible. The project and version names are left out. The
**mapping** (original → pseudonym) is a file of the run: `mapping-SENSITIVE.json` - keep it, **never send it**; when
the support asks about `addr-7f3a01`, you look it up. A file that still holds an original value after the
anonymisation is left out of the support file (named in its notes).

## Command line

```bash
pan-os-php type=support-file in=config.xml out=support.tsf [result=out.xml] [report=merger.json] [names=a,b] [rules=no] \
    [full] [anonymize [ip=keep-private] mapping=map.json] [extra=<folder>] [note="..."]
```

The support opens it with `pan-os-php type=support-file-read in=support.tsf key=<support key> out=<folder>`
(the key stays with the support).
