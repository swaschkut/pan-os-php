# Migration follow-up – Panorama A → Panorama B

Generated 2026-11-17 12:45 by pan-os-php type=panorama-move (execute) – file1 `input/panorama-move/panorama-move-A.xml`, file2 `input/panorama-move/panorama-move-B-clean.xml`.
Moved firewalls: 1, device groups move / copy: 1 / 0. Items marked [x] were done by panorama-move; tick off the others.

## 1. Before loading the configuration into Panorama B

- [ ] Save a named configuration snapshot on Panorama A and on Panorama B
- [ ] Master key: confirm Panorama B uses the same master key as Panorama A – 2 encrypted value(s) are copied unchanged (SECRETS_CHECKLIST.md lists them)

## 2. Panorama B – configuration

- [ ] Load the configuration: import `/tmp/ex/B_new.xml` as named snapshot and load it, or apply the set commands of `pan-os-php type=diff file1=input/panorama-move/panorama-move-B-clean.xml file2=/tmp/ex/B_new.xml outputformatset=set_B.txt`; commit to Panorama
- [x] Device groups, templates, template stacks, managed devices (serials) and shared objects transferred *(done by panorama-move)*
- [x] Panorama server in template Paris Datacenter: panorama-server 192.0.2.1 → 203.0.113.50 *(done by panorama-move, panorama-ip)*
- [x] Panorama server in template Paris Datacenter: panorama-server-2 192.0.2.2 → 203.0.113.51 *(done by panorama-move, panorama-ip)*
- [ ] Access domain `ad-paris`: create / extend it in Panorama B with testDG, Paris_Datacenter_Stack, firewall 007100000290 and assign it to the administrator(s) paris-admin – administrators mapped by RADIUS / TACACS+ / SAML attributes: update the mapping
- [ ] Log collection: add 007100000290 to a collector group of Panorama B (Panorama A: `lcg-paris`)
- [ ] Plugin `sd_wan` references firewall 007100000290 – configure it in Panorama B
- [ ] Device group `testDG`: master device 000000000101 is not moved – choose a moved firewall (User-ID)

## 3. Per firewall – connect to Panorama B

Steps for each firewall (device registration auth key: Panorama B PAN-OS 10.1 or later):

1. Panorama B: create a device registration auth key for the serial – `request authkey add name <key-name> lifetime <minutes> count 1 serial <serial> devtype fw` (or Panorama > Device Registration Auth Key)
2. Firewall, only when it was onboarded to Panorama A with an auth key (PAN-OS 10.1 or later): `request sc3 reset` and `debug software restart process management-server` – irreversible, ends the trust to Panorama A
3. Firewall: `request authkey set <auth-key>`
4. Firewall: Panorama server → Panorama B: `set deviceconfig system panorama local-panorama panorama-server 203.0.113.50` and `... panorama-server-2 203.0.113.51`, commit (PAN-OS before 9.1: `set deviceconfig system panorama-server 203.0.113.50`)
5. Panorama B: Panorama > Managed Devices > Summary – connected; push device group and template stack, check *In Sync*
6. HA pairs: both peers must be moved (HA is not visible in the Panorama configuration)

| done | serial | vsys | device group in Panorama B | template stack(s) in Panorama B |
|---|---|---|---|---|
| [ ] | 007100000290 | vsys1 | testDG | Paris_Datacenter_Stack |

## 4. Panorama A – after the firewalls are connected to Panorama B

- [ ] Load the cleaned configuration `/tmp/ex/A_new.xml` (or the set commands of `pan-os-php type=diff file1=input/panorama-move/panorama-move-A.xml file2=/tmp/ex/A_new.xml outputformatset=set_A.txt`) and commit – moved device groups, templates / stacks, firewalls and unused shared objects are removed *(file written by panorama-move)*
- [x] Access domain members of moved device groups / templates / firewalls removed in `/tmp/ex/A_new.xml`: ad-paris: testDG; ad-paris: Paris_Datacenter_Stack; ad-paris: firewall 007100000290 *(done by panorama-move)*
- [ ] Plugin `sd_wan` of Panorama A still references firewall 007100000290 – remove the moved entries (not changed by panorama-move)
- [ ] Logs of 007100000290 stay in collector group `lcg-paris` of Panorama A – keep Panorama A / the collectors for the retention period
- [ ] Device registration auth keys / device certificates of the moved firewalls on Panorama A are no longer needed – remove them
- [ ] WildFire appliances and Log Collectors managed by Panorama A are not moved – re-home them if the moved firewalls should use other ones
