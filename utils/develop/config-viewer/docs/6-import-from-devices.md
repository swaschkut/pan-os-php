# Import from devices

A project can get its configuration directly from a **firewall / Panorama** (XML API) or an **SCM tenant** - read only,
nothing is written to the device. The result becomes a new version of the project.

## What is needed

1. **Network for runs** - an administrator turns it on under **Account → Network for runs (admin)** and keeps the
   **allow list** and the **deny list** (one entry per line):
   - `fw1.example.com`, `*.example.com`, `10.1.1.1`, `10.0.0.0/8` - firewalls / Panoramas
   - `tsg:1234567890`, `tsg:*` - SCM tenants
   - `*` - everything

   A target must be on the allow list and not on the deny list (the deny list wins; an empty allow list allows
   nothing). Off by default.
2. **Network for the project** - the owner turns it on in the project (tab **Configuration versions**, **Import from a
   device**). It works only while the administrator allows network.
3. **Your own API key** - under **Account → My API keys**:
   - PAN-OS: host name / IP address and the XML API key - or **Get the API key from a firewall / Panorama**: management
     IP / name (port), administrator and password; the viewer asks the device for the key (XML API `type=keygen` by
     POST, as `type=key-manager add=<host>`) and saves it as your PAN-OS key. The password is only sent to the device:
     not saved, not logged, not in the audit log. The host must be on the allow list (step 1). TLS: the certificate is
     checked only with *Check the TLS certificate* (firewalls mostly have their own certificate; pan-os-php does not
     check it either). A wrong password gives the message of the device (e.g. "Invalid Credentials.").
     **Debug output** (below the form, open after an error): the call as pan-os-php shows it with `debugapi`
     (`API call through POST`, `RAW HTTP POST Content: user=…&password=********`), the TLS check, the connection,
     the certificate of the device (subject, issuer, validity, verify result), the curl log (TLS version / cipher,
     HTTP status), the answer of the device (the key shortened as pan-os-php prints it) and a hint for the usual errors
     (name does not resolve, connection refused, timeout, TLS handshake, certificate not trusted / name does not match).
     It contains no password and no complete key - it can be passed on for support.
   - SCM: TSG id, client id and client secret of a service account

   - LDAP accounts: bind user + password (`ldap_user<bind user>`, see *LDAP*)
   - other entries of the pan-os-php key store: egress-IP key (`egressip_tsg_id<TSG>`), `ldap-password` (old), `bpa-apikey`,
     `license-apikey`, `maxmind-licensekey`, `gcp-mysql-password`, and any other entry name - stored for the runs
     that need them
   - **an existing `.panconfkeystore`**: *Import key store* takes over all its entries (an entry of the same kind and
     target is replaced; lines that do not fit are named with their line number, never their content)

   A key is **personal**: only you use it, in your projects - nobody else, also no administrator. After saving it is
   never shown again (only its last 4 characters). **Edit** in its row changes the label (e.g. after a key store
   import) and, for PAN-OS, the port; a new secret can be given there too - left empty, the stored one stays. It stays until you delete it - for the next import and, later,
   for other work with the same device.
4. **Write permission** in the project.

## Import

Project → **Configuration versions** → **Import from a device**: choose your key and, for PAN-OS, candidate or running
configuration → **Import**. The run is listed under **Runs and project files**; when it is done the configuration is a
new version (`fw1.example.com.xml`, `scm-<TSG>.xml`).

What runs:

- PAN-OS: `type=upload in=api://<host>[/running-config] out=out.xml`
- SCM: `type=scm-export in=scm-api://<TSG> area=config` (read only), then offline `type=scm-export-xml` → `out.xml`

**Convert again** - when an SCM import fails in the conversion (`scm-export-xml`), the downloaded export stays with
the run. *Convert again* in the list of runs runs only the conversion once more on it: no download, no network, no
key; the log of the attempt before stays as `run-1.log`. When it works the configuration becomes a new version. (So
keep the failed run until then - deleting it removes the export.)

Only the download step gets a network; every other run (and the conversion step) has none. The run gets a key store
with only this one key; it is removed when the run ends, and the key is taken out of `run.log`.

## App-ID database and MaxMind data

Every run and every opened version uses the **App-ID database** (`predefined.xml`: applications, threats, regions) and
the **MaxMind GeoLite2** data (countries of IP addresses). By default the ones shipped in the image.

- **Installation** (administrator, **Account → App-ID and MaxMind**):
  - App-ID: **Download** from a firewall with an own API key (`type=download-predefined`, read only), or **Upload** a
    `predefined.xml` (air gap); **Back to the image**.
  - MaxMind: **Download** with the own `maxmind-licensekey` entry (needs `download.maxmind.com` on the allow list), or
    **Upload** the `GeoLite2-Country-CSV` zip of MaxMind (air gap - converted without network).
- **Project** (write permission, tab **Configuration versions → App-ID database**): an own App-ID database, e.g. the
  one of the firewall the project is about - download (network of the project, own key) or upload. It wins over the
  one of the installation.

Opened versions use new data after they are opened again.
