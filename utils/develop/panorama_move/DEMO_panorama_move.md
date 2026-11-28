# panorama-move – demo: one device group into an empty Panorama

A complete run with files of this repository: one device group of a demo Panorama (file1) is moved into an empty
Panorama configuration (file2). Nothing is sent to a device - two XML files in, two XML files and a report out.
Reference of all arguments: [README_panorama_move.md](README_panorama_move.md).

`pan-os-php` below is the alias; without it: `php <pan-os-php>/utils/pan-os-php.php`. `<pan-os-php>` is the folder of
this repository. The numbers are the ones of this demo (alpha, 2026-11-28).

## 1. Prepare the three files

```bash
mkdir panorama-move-demo && cd panorama-move-demo

# file1: the demo Panorama (PAN-OS 11.0, nine device groups)
cp <pan-os-php>/tests/input/panorama-move/panorama-move-A.xml A.xml

# file2: the empty Panorama of pan-os-php - it is PAN-OS 10.2, the target must have the same or a newer version
sed 's/version="10.2.0"/version="11.0.0"/' <pan-os-php>/lib/resources/baseconfig/panorama_baseconfig.xml > B.xml

# the device groups to move, one per line
echo "Hamburg Office" > dgs.txt
```

With your own files: file2 is an export of the target Panorama. An older target version is a blocking finding
(`version`), execute then writes nothing.

Which device groups file1 has: `pan-os-php type=device in=A.xml actions=display location=any`

## 2. Check run - nothing is written but the report

```bash
pan-os-php type=panorama-move file1=A.xml file2=B.xml dg-list=dgs.txt
```

```
 * device groups: 2, firewalls: 1, template stacks: 1, templates: 3, shared objects: 7
 * encrypted values (master key): 0 - master-key=same
 * findings: blocking 0, warning 4, info 1
 * report: panorama-move-report/REPORT.md, panorama-move-report/plan.json, follow-up: panorama-move-report/MIGRATION_FOLLOWUP.md
```

Two device groups: `Hamburg Office` and its parent `Perimeter-FWs`, which is copied because other device groups of
file1 still use it. Exit code 0: no blocking finding; 2: blocking findings - solve them first.

Read `panorama-move-report/REPORT.md`, section *Findings*. In this demo:

| finding | what it means | what to do |
|---|---|---|
| template `Internet Perimeter Master`: panorama-server 192.0.2.1 | after a push the firewalls would connect to Panorama A again | `panorama-ip=<address of Panorama B>` |
| template stack `DE_Berlin_Office_Stack`: panorama-server `$panorama_primary` | a template variable - never changed by the tool | set the value of the variable in Panorama B |
| shared rules of file1 without equivalent in file2 | the empty Panorama has no shared rules: the shared rules of A no longer apply to the moved firewall | accept (`shared-rules=skip`, default) or `shared-rules=to-top-dg` |
| effective rule base: `Perimeter-FWs/post/security/no traffic out of dc` resolves differently | a transferred rule matches other values after the move | REPORT.md, section *Effective rule base per moved firewall* |
| info: shared setting `profiles` set in file2 only | applies to the moved firewall after the move | - |

## 3. Decide the options, check again

```bash
pan-os-php type=panorama-move file1=A.xml file2=B.xml dg-list=dgs.txt panorama-ip=192.0.2.50 shared-rules=to-top-dg
```

`findings: blocking 0, warning 3, info 2` - the Panorama server finding became an info (`set to 192.0.2.50`), the
shared rules are now *copied into the top moved device group(s)*. A check run can be repeated as often as needed.

## 4. Execute

```bash
pan-os-php type=panorama-move file1=A.xml file2=B.xml dg-list=dgs.txt panorama-ip=192.0.2.50 shared-rules=to-top-dg \
    mode=execute out1=A_new.xml out2=B_new.xml
```

```
 * written: A_new.xml (device groups 8, unresolved 0)
 * written: B_new.xml (device groups 2, unresolved 0)
 * device groups: 2, firewalls: 1, template stacks: 1, templates: 3, shared objects: 9
 * findings: blocking 0, warning 3, info 2
 * panorama-ip=192.0.2.50 - Panorama server settings in transferred templates / stacks: 2
```

`A_new.xml`: Panorama A without the moved device group and its firewall. `B_new.xml`: the empty Panorama with the two
device groups, the firewall, the template stack, three templates and the shared objects they use. `A.xml` and `B.xml`
are not changed.

## 5. Look at the result

```bash
pan-os-php type=device in=B_new.xml actions=display location=any          # device groups, templates, firewalls
pan-os-php type=rule in=B_new.xml actions=display location=any            # the transferred rules

# set commands that bring a Panorama from the old to the new file
pan-os-php type=diff file1=B.xml file2=B_new.xml outputformatset=set_B.txt    # 153 lines
pan-os-php type=diff file1=A.xml file2=A_new.xml outputformatset=set_A.txt    # 10 lines
```

## 6. What is left to do by hand: MIGRATION_FOLLOWUP.md

`panorama-move-report/MIGRATION_FOLLOWUP.md` is the checklist of the migration, written on every run. What the tool did
is ticked (`[x]`), everything else is open (`[ ]`). In this demo: 2 done, 8 open, plus the steps per firewall.

| section | open in this demo |
|---|---|
| 1. before loading into Panorama B | configuration snapshots on both Panoramas; one transferred rule resolves differently |
| 2. Panorama B | load `B_new.xml` (or the set commands) and commit; value of `$panorama_primary`; log forwarding of the moved firewall |
| 3. per firewall | device registration auth key on Panorama B, `request sc3 reset` / `request authkey set` on the firewall, Panorama server → Panorama B, push; table with serial, device group and template stack to tick off |
| 4. Panorama A afterwards | load `A_new.xml` and commit; auth keys / certificates of the moved firewall; WildFire appliances and Log Collectors |

Done by the tool: device groups, templates, template stacks, managed devices and shared objects transferred; Panorama
server of the template set to 192.0.2.50.

The checklist names numbers of rules only - the rules themselves are in `REPORT.md` (*Shared rules – impact per moved
firewall*, *Effective rule base per moved firewall*). With encrypted values in the transferred configuration and
`master-key=different` there is a fourth file, `SECRETS_CHECKLIST.md`: the fields to set again in Panorama B.

## Files of the demo

| file | |
|---|---|
| `A.xml`, `B.xml`, `dgs.txt` | input |
| `A_new.xml`, `B_new.xml` | output of execute |
| `panorama-move-report/REPORT.md` | findings and every table of the plan |
| `panorama-move-report/plan.json` | the same as data |
| `panorama-move-report/MIGRATION_FOLLOWUP.md` | checklist of the manual steps |
| `set_A.txt`, `set_B.txt` | set commands (`type=diff`) |
