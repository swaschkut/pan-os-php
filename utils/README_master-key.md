# pan-os-php type=master-key

Master-key encrypted values of a firewall / Panorama configuration.

* **display** – the XPath of every encrypted value and which master key decrypts it
* **rekey** – re-encrypt all values: master key of the input → target master key (default: the PAN-OS default master
  key), offline into `out=`

Open: AES-256-GCM – see [todo/master-key-rekey.md](../todo/master-key-rekey.md).

Code: `utils/lib/MASTER_KEY__.php` (type), `utils/common/ConfigSecrets.php` (scan, shared class),
`lib/helper-classes/PanosCrypto.php` (AES-256-CBC). Tests: `tests/test_master_key.php`.

**Values are never displayed** – neither encrypted nor decrypted, not in text, JSON or HTML.

## Usage

```bash
pan-os-php type=master-key in=config.xml                                   # all encrypted values
pan-os-php type=master-key in=config.xml master-key-file=key.txt           # also test a custom master key
pan-os-php type=master-key in=config.xml master-key-file=key.txt key=unknown   # only what no key decrypts
pan-os-php type=master-key in=config.xml actions=exportToHtml:secrets.html
pan-os-php type=master-key in=config.xml shadow-json
pan-os-php type=master-key in=api://192.168.1.1                            # candidate configuration of a device

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
| `allow-partial` | `rekey`: write `out=` although some values could not be re-encrypted |
| `hashes` | display / exportToHtml: also list the password hashes (`phash`) – XPath and algorithm, never the hash |
| `key=` | `all` (default) \| `default` \| `given` \| `unknown` – show only values of that key state |
| `actions=` | `display` (default) \| `exportToHtml:FILE` (a `/` in the file name as `//`) \| `rekey` (alone) |
| `shadow-json` | JSON: `encrypted_values` (xpath, location, field, version, format, length, key), `summary`; rekey: `rekey` (xpath, location, field, status, from), `summary` |

## What is found

The whole XML as stored is scanned (every leaf element, also what pan-os-php does not model; the object model is not
loaded): values in the format `-` + base64(version byte) + payload.

| format | meaning |
|---|---|
| `aes-256-cbc` | version 1 (`-AQ==` + SHA-1 of the clear text + ciphertext) – the SHA-1 shows whether a key is the right one |
| `unknown` | another version byte (e.g. AES-256-GCM, encryption level 2) – listed, not checked |
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

## Limits

* AES-256-GCM (encryption level 2, PAN-OS 10.0+): format and key derivation are not implemented – such values appear as
  `unknown` (an example value with known clear text and master key is needed)
* a master key protected by an HSM cannot be tested offline
* `in=api://` loads the candidate configuration; nothing is written
