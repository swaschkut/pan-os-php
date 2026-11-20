# iron-skillet / best practice: URL HTTP header logging (PAN-OS 12.2)

**Status:** open – XML element names unknown (2026-11-20)
**Code:** `URLProfile::ironSkilletXml()` (`lib/object-classes/URLProfile.php`, today `log-http-hdr-user-agent`,
`log-http-hdr-referer`, `log-http-hdr-xff` from 9.1), `PH::IRONSKILLET_VERSIONS` (12.2 has its own snippets since
2026-11-20), BP JSON `utils/api/v1/bp/*bp_sp_panw.json` (`url` section)

## What is new in 12.2

PANW: New Features PAN-OS 12.2 – *HTTP Request and Response Header Logging* (URL Filtering logs):

- configured in the **URL Filtering profile**
- options: individual request or response headers, *Log all HTTP headers*, *Enable logging of response code in HTTP
  response*, *Max Header Length* (1 – 4,092 bytes; default not stated), truncation of headers above the limit
- new URL log fields: *URL Index* and *Direction*; logging request and response headers gives two log entries per
  resource
- a privacy notice is shown the first time request header logging is enabled

Source: https://docs.paloaltonetworks.com/ngfw/new-features/by-version/panos/12-2

## Open

1. **XML of a 12.2 URL profile with these options set** (`show config running xpath ... profiles/url-filtering`):
   element names, structure (single headers as members?), default of *Max Header Length*, how the existing
   `log-http-hdr-*` elements relate to the new options.
2. **Decide what belongs to the 12.2 snippet / best practice:**
   - keep only the three existing headers (user agent, referer, XFF) as today, or
   - add the response code (*Enable logging of response code in HTTP response*), or
   - *Log all HTTP headers* – more log volume, request headers can hold personal data (privacy notice): rather not as
     default
3. Implement in `URLProfile::ironSkilletXml()` for `version_compare( $version, '12.2', '>=' )`, with a test in
   `tests/test_ironskillet_version.php` (12.2 URL snippet = 12.1 + the new elements); BP JSON / visibility check only
   if the decision in 2 makes it a best-practice setting.

## Context

- 12.2 snippets today = 12.1 snippets + VP local deep learning (SQL Injection / Command Injection); this is the only
  other security profile change PANW lists for 12.2.
- PAN-OS 12.1 has no security profile changes (PANW: New Features PAN-OS 12.1).
