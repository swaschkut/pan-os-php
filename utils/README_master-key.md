# pan-os-php type=master-key

Master-key encrypted values of a firewall / Panorama configuration.

* **display** – the XPath of every encrypted value and which master key decrypts it
* **rekey** – re-encrypt all values: master key of the input → target master key (default: the PAN-OS default master
  key), offline into `out=`; keeps the real secrets, needs the master key of the input
* **scrub** – lab copy: every encrypted value is **replaced** (placeholder / new certificate with the same name), so the
  configuration loads and commits on a lab device with the default master key; needs no master key, decrypts nothing

Open: AES-256-GCM – see [todo/master-key-rekey.md](../todo/master-key-rekey.md).

Code: `utils/lib/MASTER_KEY__.php` (type), `utils/common/ConfigSecrets.php` (scan, shared class),
`lib/helper-classes/PanosCrypto.php` (AES-256-CBC). Tests: `tests/test_master_key.php`.

**Values are never displayed** – neither encrypted nor decrypted, not in text, JSON or HTML.

## What PAN-OS provides: master key and encryption level

PAN-OS (firewall and Panorama) stores secrets of the configuration – private keys, pre-shared keys, passwords of server
profiles, … – encrypted with the **master key**. Two settings decide how a value looks in the XML:

| setting | values |
|---|---|
| master key | the **default master key** of PAN-OS (the same on every device, publicly known) until a **custom master key** (16 characters) is configured: *Device > Master Key and Diagnostics* (Panorama: *Panorama > Master Key and Diagnostics*) |
| encryption level | the algorithm the master key is used with, see below |

| level | algorithm | value in the XML | pan-os-php |
|---|---|---|---|
| 0 | default algorithm = AES-256-CBC | `-AQ==…` | display, cleartext, rekey, scrub |
| 1 | AES-256-CBC | `-AQ==…` | display, cleartext, rekey, scrub |
| 2 | AES-256-GCM (PAN-OS 10.0 and later) | `-#…` | detected and listed; replaced by scrub; not decrypted / not re-keyed |

AES-256-CBC and AES-256-GCM use the same cipher (AES with a 256 bit key) in two modes:

* **CBC** only keeps a value secret. PAN-OS adds a SHA-1 of the clear text to the value to notice a wrong key or a
  changed value. The same clear text always gives the same encrypted value.
* **GCM** is authenticated encryption: secrecy and a built-in integrity check (authentication tag) in one step; the
  same clear text gives a different value each time.

CBC is the default because Panorama and its managed firewalls (and both peers of an HA pair) have to use the same
level, and older PAN-OS releases do not support GCM.

### CLI: check and change the level

Operational mode of the device CLI (not available in the web interface):

```
> show system masterkey-properties
Master key expires at: unspecified
Reminders will begin at: unspecified
Master key on hsm: no
Automatically renew master key lifetime: 0
Encryption Level: 1
```

```
> request encryption-level level 2                        # level 1 -> 2, existing values are re-encrypted
> request encryption-level re-encrypt yes level 2         # the same, explicit
> request encryption-level re-encrypt no level 2          # only new values use level 2, existing values stay
> request encryption-level re-encrypt yes level 1         # back to AES-256-CBC
```

* `re-encrypt no` leaves a configuration with both formats (`-AQ==…` and `-#…`); `type=master-key` shows which value
  uses which
* use level 2 only when Panorama and all managed devices, or both HA peers, support it and are all set to it –
  devices on different levels can get out of sync
* a downgrade to a PAN-OS release without GCM converts the values back to AES-256-CBC automatically
* PAN-OS 12.2.2 and later enforce a custom master key: after a grace period (default 60 days) with the default master
  key, commits are blocked – relevant for a lab device that is kept on the default master key (`scrub` / `rekey` can
  target a custom key with `new-master-key-file=`)
* check the result offline: `pan-os-php type=master-key in=<exported configuration>`

Palo Alto Networks documentation:

* [Master Key Encryption](https://docs.paloaltonetworks.com/ngfw/administration/certificate-management/master-key-encryption) – concept, AES-256-CBC and AES-256-GCM
* [Configure Master Key Encryption Level](https://docs.paloaltonetworks.com/ngfw/administration/certificate-management/master-key-encryption/configure-master-key-encryption-level) – the CLI commands above
* [Configure a Master Key](https://docs.paloaltonetworks.com/ngfw/administration/certificate-management/master-key-encryption/configure-master-key) – set a custom master key
  ([Panorama and PAN-OS](https://docs.paloaltonetworks.com/ngfw/administration/certificate-management/master-key-encryption/configure-master-key/configure-the-master-key-panorama-and-pan-os))

## Usage

```bash
pan-os-php type=master-key in=config.xml                                   # all encrypted values
pan-os-php type=master-key in=config.xml master-key-file=key.txt           # also test a custom master key
pan-os-php type=master-key in=config.xml master-key-file=key.txt key=unknown   # only what no key decrypts
pan-os-php type=master-key in=config.xml actions=exportToHtml:secrets.html
pan-os-php type=master-key in=config.xml cleartext                         # lab: show the values the default key can read
pan-os-php type=master-key in=config.xml cleartext master-key-file=key.txt  # also the values of a custom master key
pan-os-php type=master-key in=config.xml shadow-json
pan-os-php type=master-key in=api://192.168.1.1                            # candidate configuration of a device

# scrub: customer configuration (any master key, encryption level 1 or 2) -> lab copy for the default master key
pan-os-php type=master-key in=customer.xml out=lab.xml actions=scrub
pan-os-php type=master-key in=customer.xml out=lab.xml actions=scrub placeholder=dummy

# rekey: custom master key -> default master key
pan-os-php type=master-key in=config.xml out=config-default-key.xml master-key-file=key.txt actions=rekey
# rekey: custom -> another custom key / default -> custom key
pan-os-php type=master-key in=config.xml out=new.xml master-key-file=key.txt new-master-key-file=newkey.txt actions=rekey
pan-os-php type=master-key in=config.xml out=new.xml new-master-key-file=newkey.txt actions=rekey
```

| argument | |
|---|---|
| `in=` | firewall or Panorama configuration (file or `api://`); never changed |
| `out=` | `rekey`: output file (required) |
| `master-key-file=` | file with a custom master key (first line) – tested on the values the default master key does not decrypt |
| `master-key=` | the same on the command line (visible in the shell history / process list – prefer the file) |
| `new-master-key-file=` / `new-master-key=` | `rekey`: target master key; default: the PAN-OS default master key |
| `placeholder=` | `scrub`: clear text that replaces every secret (default `Dummy-1234567890`) |
| `allow-partial` | `rekey` / `scrub`: write `out=` although some values could not be re-encrypted / replaced |
| `hashes` | display / exportToHtml: also list the password hashes (`phash`) – XPath and algorithm, never the hash |
| `cleartext` | display / exportToHtml: show the decrypted value of every secret the default (public) master key – or the given master key – can read (for a lab) |
| `key=` | `all` (default) \| `default` \| `given` \| `unknown` – show only values of that key state |
| `actions=` | `display` (default) \| `exportToHtml:FILE` (a `/` in the file name as `//`) \| `rekey` (alone) \| `scrub` (alone) |
| `shadow-json` | JSON: `encrypted_values` (xpath, location, field, version, format, length, key), `summary`; rekey: `rekey` (xpath, location, field, status, from), `summary` |

## What is found

The whole XML as stored is scanned (every leaf element, also what pan-os-php does not model; the object model is not
loaded): values in the format `-` + base64(version byte) + payload.

| format | meaning |
|---|---|
| `aes-256-cbc` | version 1 (`-AQ==` + SHA-1 of the clear text + ciphertext) – the SHA-1 shows whether a key is the right one; `display` and `rekey` support it |
| `aes-256-gcm` | encryption level 2 (PAN-OS 10.0+), prefix `-#…` – **detected and listed, not decrypted or re-keyed** |
| `unknown` | another version byte in the `-XX==` framing – listed, not checked |
| `malformed` | prefix of version 1 but no valid value (hash / block length) – listed, not checked |

| key | meaning |
|---|---|
| `default` | decrypts with the PAN-OS default master key |
| `given` | decrypts with the key of `master-key-file=` / `master-key=` |
| `unknown` | neither – another (custom) master key, or a format that is not checked |

Per value: XPath, location (`shared`, `device-group NAME`, `template NAME`, `template-stack NAME`, `vsys NAME`,
`mgt-config`, `panorama`, `device`), field (element path without names – same kind of secret = same field), length.
The summary counts by key, format, field and location; `other_master_key` = well-formed values that no tested key
decrypts.

## cleartext (lab)

`cleartext` adds the decrypted value to `display` and `exportToHtml`, like `type=ike-gateway … psk-cleartext` does for
pre-shared keys. It is shown only for values that **decrypt with the default master key** (which is public, so these
values are not a secret) or with a master key given by `master-key-file=` / `master-key=`. Values of another, unknown
master key, and AES-256-GCM / unknown / malformed values, show no cleartext. Multi-line values (private keys) are
printed as a block; in JSON the field is `cleartext`. For a lab / analysis of the own configuration – not shown without
the flag.

## Values that do not depend on the master key

| value | what it is | handling |
|---|---|---|
| `phash` (administrators in `mgt-config/users`, users of a local user database) | one-way password hash in crypt format: `$1$` MD5-crypt, `$5$` SHA-256-crypt, `$6$` SHA-512-crypt, 13 characters DES-crypt, `*` no password | counted in the summary; flag `hashes` lists XPath + algorithm (MD5 / DES marked as weak). Never changed by `rekey`; works on any device whatever its master key |
| `public-key` of certificates | PEM text (`-----BEGIN …`), public | not listed |
| `subject-hash`, `issuer-hash` of certificates | identifiers, no secrets | not listed |

Everything else that is sensitive is stored master-key encrypted (`-AQ==…`: private keys, pre-shared keys, passwords
and secrets of server profiles, SNMPv3, routing authentication, …) and is found by the scan – by its format, whatever
the element is called. A secret stored as clear text would not be recognised.

## Example

```
 * template Paris Datacenter (1)
   - /config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Paris Datacenter']/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway/entry[@name='gw1']/authentication/pre-shared-key/key
       AES-256-CBC (version 1) | key: UNKNOWN (other master key) | 57 characters

summary: 8 encrypted value(s) in the configuration
        1 decrypt with the default master key
        3 do NOT decrypt with the default master key -> custom master key (test it with master-key-file=)
        1 in a format version that is not supported (e.g. AES-256-GCM / encryption level 2) - not checked
```

## rekey

Every encrypted value (AES-256-CBC) is decrypted with the master key of the input (`master-key-file=`) **or** the default
master key – whichever fits (a configuration can hold both) – and encrypted with the target key. The SHA-1 inside the
value proves that the right key was used; after re-encryption the value is checked again with the target key.

| status | |
|---|---|
| `rekeyed` | re-encrypted (`from`: `given` / `default`) |
| `already-target-key` | already decrypts with the target key – unchanged |
| `failed` | no key decrypts it (another master key) – unchanged |
| `unsupported` | other format version / malformed – unchanged |

* `failed` / `unsupported` values: `out=` is **not** written and the exit code is ≠ 0 – unless `allow-partial` (then the
  file is written with these values unchanged and a warning)
* nothing but the encrypted values changes; hashes (`phash`) stay
* the result goes to `out=` only – nothing is sent to a device (also with `in=api://`); `rekey` can not be combined
  with other actions – run `display` on the output afterwards
* **a file encrypted with the default master key is as good as clear text** (the default key is public): protect it
  like a file with clear text passwords
* loading the output: the device / Panorama must use the target master key

## scrub – lab copy of a configuration

Use case: a configuration from another device (custom master key, encryption level 1 or 2) has to be loaded and
committed on a **lab** Panorama / firewall with the default master key, to validate other changes. The commit fails
while the lab device can not read the encrypted values. `scrub` replaces all of them – the real secrets are not needed
and are gone afterwards.

| what | replaced by |
|---|---|
| every encrypted value (pre-shared keys, passwords, secrets, …) – AES-256-CBC of any master key, AES-256-GCM, unknown version, malformed | the placeholder (`placeholder=`, default `Dummy-1234567890` – 16 characters, to satisfy minimum lengths such as 8 for SNMPv3), encrypted with the target master key as AES-256-CBC |
| certificate entry with a private key | new certificate: **same entry name, same subject**, key type / size, CA flag and subject alternative names of the old one, new key pair (RSA key as `BEGIN RSA PRIVATE KEY` like PAN-OS stores it); `public-key`, `private-key`, `not-valid-before`, `not-valid-after`, `expiry-epoch` are updated; valid as long as the old one, at least one year |
| issuer of such a certificate | replaced issuer in the same configuration (same subject DN) → the new certificate is signed by it, the chain stays intact; issuer not in the configuration / without private key → self-signed, `issuer` / `issuer-hash` follow the subject |
| certificate without private key that was issued by a replaced certificate | re-issued by the new issuer (the key is thrown away) |
| other certificates without private key, `phash`, everything else | unchanged |

* nothing is decrypted, `master-key=` is refused; the target key is the default master key or `new-master-key-file=`
* copies of the same certificate (e.g. one CA in several templates) get the same new certificate
* `out=` only; values that can not be replaced (certificate whose `public-key` is unreadable) → nothing is written and
  exit code ≠ 0, unless `allow-partial`
* **lab only**: VPNs, authentication against servers and certificate trust do not work with the result
* the password hashes stay: after loading, the administrators of the input apply – make sure you keep an administrator
  you can log in with
* target device: encryption level 1 (the placeholders are AES-256-CBC). Whether a device on level 2 accepts AES-256-CBC
  values when loading is not verified
* not verified on a device yet: `subject-hash` / `issuer-hash` are kept from the old certificate (same subject) – if
  PAN-OS rejects a certificate for it, re-import that certificate in the lab

## Limits

* AES-256-GCM (encryption level 2, PAN-OS 10.0+, prefix `-#…`): detected and reported, but **not decrypted or
  re-keyed** – the key derivation of the GCM format is not implemented. A configuration that still holds GCM values is
  refused by `rekey` (unless `allow-partial`, which leaves them unchanged). Set the device to encryption level 1
  (`request encryption-level re-encrypt yes level 1`) before a rekey, or re-enter the affected secrets afterwards
* a master key protected by an HSM cannot be tested offline
* `in=api://` loads the candidate configuration; nothing is written
