# pan-os-php type=master-key

Master-key encrypted values of a firewall / Panorama configuration.

**Step 1 (implemented): display** – the XPath of every encrypted value and which master key decrypts it.
Planned: `rekey` (old master key → new master key), AES-256-GCM – see
[todo/master-key-rekey.md](../todo/master-key-rekey.md).

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
```

| argument | |
|---|---|
| `in=` | firewall or Panorama configuration (file or `api://`); read only |
| `master-key-file=` | file with a custom master key (first line) – tested on the values the default master key does not decrypt |
| `master-key=` | the same on the command line (visible in the shell history / process list – prefer the file) |
| `key=` | `all` (default) \| `default` \| `given` \| `unknown` – show only values of that key state |
| `actions=` | `display` (default) \| `exportToHtml:FILE` (a `/` in the file name as `//`) |
| `shadow-json` | JSON: `encrypted_values` (xpath, location, field, version, format, length, key), `summary` |

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

Not listed as encrypted: hashes (`phash` of local administrators) – they do not depend on the master key; the summary
shows their number.

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

## Limits

* AES-256-GCM (encryption level 2, PAN-OS 10.0+): format and key derivation are not implemented – such values appear as
  `unknown` (an example value with known clear text and master key is needed)
* a master key protected by an HSM cannot be tested offline
* `in=api://` loads the candidate configuration; nothing is written
