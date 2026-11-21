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
   - PAN-OS: host name / IP address and the XML API key
   - SCM: TSG id, client id and client secret of a service account

   - other entries of the pan-os-php key store: egress-IP key (`egressip_tsg_id<TSG>`), `ldap-password`, `bpa-apikey`,
     `license-apikey`, `maxmind-licensekey`, `gcp-mysql-password`, and any other entry name - stored for the runs
     that need them
   - **an existing `.panconfkeystore`**: *Import key store* takes over all its entries (an entry of the same kind and
     target is replaced; lines that do not fit are named with their line number, never their content)

   A key is **personal**: only you use it, in your projects - nobody else, also no administrator. After saving it is
   never shown again (only its last 4 characters). It stays until you delete it - for the next import and, later,
   for other work with the same device.
4. **Write permission** in the project.

## Import

Project → **Configuration versions** → **Import from a device**: choose your key and, for PAN-OS, candidate or running
configuration → **Import**. The run is listed under **Runs and project files**; when it is done the configuration is a
new version (`fw1.example.com.xml`, `scm-<TSG>.xml`).

What runs:

- PAN-OS: `type=upload in=api://<host>[/running-config] out=out.xml`
- SCM: `type=scm-export in=scm-api://<TSG> area=config` (read only), then offline `type=scm-export-xml` → `out.xml`

Only the download step gets a network; every other run (and the conversion step) has none. The run gets a key store
with only this one key; it is removed when the run ends, and the key is taken out of `run.log`.
