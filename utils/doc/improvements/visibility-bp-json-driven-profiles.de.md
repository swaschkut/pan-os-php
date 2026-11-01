# Alert-Only- und Best-Practice-Profile aus der BP-JSON-Datei

**Status:** Vorschlag, nicht umgesetzt
**Datum:** 2026-11-01
**Code-Stand:** `beta` `cb9c2dc9` plus Patch `av-msoffice-shell-10.0` (Zeilennummern können sich verschieben)
**Englische Fassung:** `visibility-bp-json-driven-profiles.md`

## 1. Ziel

Die BP-JSON-Datei (`utils/api/v1/bp/scm_bp_sp_panw.json` oder eine angepasste Kopie) soll die eine Stelle sein, die
festlegt, was „sichtbar“ (Alert-Only) und „Best Practice“ für Security-Profile bedeuten. Daraus sollen drei Dinge folgen:

1. **Erzeugen:** die `Alert-Only-*`-Profile (später auch `Outbound-*` / `Inbound-*` / `Internal-*`), z. B.
   `type=device actions=sp_spg-create-alert-only-bp`.
2. **Setzen:** bestehende Profile sichtbar machen, z. B. `type=securityprofile actions=spyware.alert-only-set`.
3. **Prüfen:** Filter wie `(object is.visibility)` und der Export (`exportToExcel`).

Heute liest nur Schritt 3 die JSON-Datei. Wer die JSON-Datei ändert, ändert damit das Prüfergebnis, aber nicht, was
pan-os-php erzeugt oder setzt.

Die JSON-Datei darf keinen Wert erzwingen können, den PAN-OS in einer bestimmten Version, mit oder ohne Lizenz oder auf
einer bestimmten Plattform nicht annimmt. pan-os-php bildet viele solcher Fälle bereits bewusst ab (Abschnitt 4). Sie
müssen erhalten bleiben, und zwar an einer Stelle.

## 2. Stand

- **iron-skillet-Dateien entfernt** (`33239cc2`, `c7c0c3b5`): Jede Object-Class baut ihre Basisprofile mit
  `ironSkilletXml( $version )`. Die Versionsunterschiede stehen als Bedingungen im Code.
- **URL-Kategorien** (`cb9c2dc9`): `URLProfile::ironSkilletCategories()` liest `predefined.xml`
  (`<pan-url-categories>`), dieselbe Quelle, die auch die Prüfung nutzt. Kategorien kommen mit den Dynamic Updates,
  nicht mit PAN-OS. Die Liste ist daher für alle Versionen gleich. Eigene Kategorien heißen für alle Versionen
  `Block` / `Allow`.
- **Antivirus-ML-Modelle** (Patch `av-msoffice-shell-10.0`): `AntiVirusProfile::ironSkilletContentXml()` legt
  MSOffice und Shell ab 10.0 an (vorher ab 10.2, siehe G3). Die Versionen bleiben in der Class sichtbar; sie stimmen mit
  `predefined.xml` überein.
- **Versionsvergleich:** `URLProfile::ironSkilletCategories()` vergleicht eine iron-skillet-Version wie `"11.1"` als
  `"11.1.0"` mit `minver` / `maxver`, denn `version_compare()` stuft `"11.1"` niedriger ein als `"11.1.0"`.
- **Prüfwerkzeug:** `utils/develop/ironskillet/url_categories_check.php` (nur lesend) meldet je iron-skillet-Version
  die vordefinierten URL-Kategorien, die in den URL-Profilen fehlen.

## 3. Problem: Die Regeln liegen an vier Stellen

| Schritt | Code | Liest die BP-JSON-Datei? |
|---|---|---|
| Erzeugen | `lib/object-classes/*Profile.php` `ironSkilletXml()`, aufgerufen von `utils/common/actions-device.php` | nein |
| Laden | `lib/object-classes/trait/sp_action_{spyware,virus,wildfire}.php` `load_from_domxml_*()`, `URLProfile::load_from_domxml()` | nein |
| Setzen | `utils/common/actions-securityprofile.php` `*.alert-only-set`, `*.best-practice-set` | nur `virus.decoder.alert-only-set` (4159), `virus.inline-ml.alert-only-set` (4196), `url.best-practice-set` (6146) |
| Prüfen | `lib/object-classes/SecurityProfile2.php`, die `*_visibility()` / `*_best_practice()` der Traits, `is_visibility()`; außerdem `exportToExcel` | ja |

**Hinweis zu „Laden“:** Die Loader schreiben PAN-OS-Standardwerte ins XML, wenn ein Element fehlt. Zum Beispiel fügen
sie ab 11.2 `advanced-dns-security-categories` hinzu, oder ab 11.1 `cloud-inline-analysis` mit `no`. Ein Profil kann
sich also schon beim Laden ändern, bevor überhaupt eine Action läuft.

### Was die `visibility`-Abschnitte der JSON-Datei fordern

Die meisten Einträge sind Bedingungen (`!wert` = alles außer diesem Wert), keine Werte. Das genügt zum Prüfen, aber
nicht zum Erzeugen oder Setzen.

| Typ / Abschnitt | `visibility` |
|---|---|
| virus / rule | `action`, `wildfire-action`, `mlav-action`: `!allow` |
| virus / cloud-inline | `inline-policy-action` (type `any`): `!disable` |
| spyware / rule | Severities `any, critical, high, medium, low, informational`; `action`: `!allow` |
| spyware / dns | `log-level`: `!none` für `pan-dns-sec-` `adtracking, ddns, grayware, malware, phishing, proxy, recent, parked, cc` |
| spyware / advanced-dns | `log-level`: `!none` für `pan-adns-sec-dnsmisconfig, pan-adns-sec-hijacking` |
| spyware / lists | `default-paloalto-dns` `action`: `!allow` |
| spyware / cloud-inline | type `any`: `!allow`; `HTTP` und `HTTP2 Command and Control detector`: `local-deep-learning` `enable` |
| vulnerability / rule | Severities wie bei spyware; `action`: `!allow` |
| vulnerability / cloud-inline | type `any`: `!allow` |
| url / site_access | `!allow` |
| url / user_credential_submission | Kategorie `!allow`; Mode `!disabled` |
| url / mica-engine | `local-inline-cat` `yes`, `cloud-inline-cat` `yes` |
| file-blocking / rule | `alert`: Application `any`, Filetype `any`, Direction `both`, Action `alert` |
| wildfire / rule | Application `any`, Filetype `any`, Direction `both`, Analysis `public-cloud` oder `private-cloud` |
| wildfire / cloud-inline | Application `any`, type `any`, Direction `both`, Action `!allow` |

## 4. PAN-OS-Verhalten, das pan-os-php bereits abbildet (bleibt erhalten)

Diese Unterschiede sind gewollt: PAN-OS verhält sich in diesen Versionen, mit oder ohne Lizenz oder auf SCM anders.
Heute ist jeder Fall an mehreren der oben genannten Stellen einzeln umgesetzt, und nicht überall gleich.

Die Spalte **`predefined.xml`** zeigt, was die Datei selbst über die Version sagt (`minver`). Wo sie etwas sagt, kann
sie die Quelle sein (Abschnitt 6.1).

| # | PAN-OS-Verhalten | Erzeugen (`ironSkilletXml`) | Laden | Setzen | Prüfen | `predefined.xml` | Beleg |
|---|---|---|---|---|---|---|---|
| 1 | **WildFire Inline ML:** vor 11.1 nicht vorhanden; **11.1: Regel-Action kann nicht `alert` sein, nur `allow`**; `alert` ab 11.2 | 11.1 `wf_inline_allow` / `allow`; ab 11.2 `wf_inline_alert` / `alert`; Inbound/Internal `wf_inline_block` nur in 11.1 und 11.2 | ergänzt `cloud-inline-analysis` `no` ab 11.1 (`sp_action_wildfire.php:57`) | `wildfire.inline-ml.alert-only-set` nur ab 11.2, 11.1 auskommentiert (5721–5783); `wildfire.inline-ml.best-practice-set` ab 11.1 (5904, 5914) | vor 11.1 `null`, **11.1 immer TRUE** (`SecurityProfile2.php:238–240, 281–299`); `is_visibility` ab 11.2 (`sp_action_wildfire.php:278`) | nicht enthalten | CHANGELOG 2.1.57 „PAN-OS 11.1 - bugfix as wf mica-engine can not set for alerting“; 2.1.58 |
| 2 | **Anti-Spyware Inline ML** (C2-Detektoren) | alle 5 Detektoren ab 10.2 | ergänzt fehlende Unknown-TCP/UDP-Detektoren ab 10.2 (`sp_action_spyware.php:111, 123`) | `spyware.inline-ml.alert-only-set` / `.best-practice-set` ab 10.2 (4680 / 4300) | vor 10.2 `null` (`SecurityProfile2.php:230`) | `mica-engine-anti-spyware minver="10.2.0"`; **HTTP, HTTP2, SSL `minver="11.1.0"`, Unknown-TCP/UDP `minver="11.0.0"`** (G8) | CHANGELOG 2.1.57 „add <cloud-inline-analysis> starting with PAN-OS 10.2“ |
| 3 | **`local-deep-learning`** an den Spyware-Detektoren: ab 11.2 | `enable` ab 11.2 | ergänzt `disable` ab 11.2 (`sp_action_spyware.php:86, 113–132`) | nicht behandelt | **nicht geprüft** (`SecurityProfile2.php:218, 269` „todo: speciall now for LDL“), obwohl die JSON `enable` fordert | nicht enthalten | CHANGELOG 2.1.42 |
| 4 | **DNS-Security-Kategorien:** keine Action `alert`, Sichtbarkeit nur über `log-level` | Alert-Only-AS: `allow` + `log-level default`; 10.0: 4 Kategorien, ab 10.1: 8 (ohne `pan-dns-sec-adtracking`) | ergänzt ab 10.0 die 9 Kategorien, inklusive `adtracking`, mit `default` (`sp_action_spyware.php:380–441`) | `spyware.dns.alert-only-set` (4761) | ab 10.2 (`spyware_dns_security_visibility`, `sp_action_spyware.php:906`) | `pan-dns-security-categories minver="10.0.0"`, alle Kategorien inklusive `adtracking` `minver="10.0.0"` | — |
| 5 | **Advanced DNS Security** (`pan-adns-sec-*`): ab 11.2 | nicht in den Profilen | ergänzt beide mit `log-level default` ab 11.2 (`sp_action_spyware.php:500–519`) | — | ab 11.2 (`sp_action_spyware.php:948`) | nicht enthalten | CHANGELOG 2.1.28, 2.1.43, 2.1.57 |
| 6 | **DNS-Security-Lizenz** | — | — | Argument `has-DNS-license`: ohne Lizenz `allow`, `packet-capture disable`, **`log-level none`** (4778–4880) | kennt die Lizenz nicht | — | — |
| 7 | **SCM (Buckbeak):** Anti-Spyware ohne `botnet-domains` | `AntiSpywareProfile::ironSkilletXmlScm()` (11.1) | — | `spyware.dns.*-set`, `spyware.botnet.*-set` übersprungen (4375, 4473, 4775, 4919) | keine Sonderbehandlung | — | — |
| 8 | **Vulnerability Inline ML:** ab 11.0 | ab 11.0 | — | `vulnerability.inline-ml.*-set` ab 11.0 (5071/5081, 5195/5206) | vor 11.0 `null` (`SecurityProfile2.php:200`) | `mica-engine-vulnerability minver="11.0.0"` | CHANGELOG 2.1.28 „only on PANOS version >=11.0“ |
| 9 | **Antivirus-ML-Modelle** (`mlav-engine-filebased-enabled`): ab 10.0; `MachO`, `OOXML` ab 11.1 | in der Class (Patch `av-msoffice-shell-10.0`): ab 10.0 6 Modelle inklusive MSOffice, Shell; `MachO`, `OOXML` ab 11.1 | ergänzt `MSOffice`, `Shell` (`disable`) ab 10.0, `MachO`, `OOXML` ab 11.1 (`sp_action_virus.php:191–212`) | `virus.inline-ml.alert-only-set` liest die JSON, ohne Versionsprüfung (4179) | **vor 10.2 `null`** (`SecurityProfile2.php:335`), sollte ab 10.0 prüfen | `mlav-engine-filebased-enabled minver="9.2.0"` (= 10.0); MSOffice, Shell ohne `minver`; `OOXML`, `MachO` `minver="11.1.0"` | Palo Alto: MSOffice ab Content 8434, Shell ab Content 8543, PAN-OS 10.x und neuer |
| 10 | **Antivirus-Decoder und `mlav-action`** | in der Class: `http2` ab 9.1, `mlav-action` ab 10.0 | ergänzt `mlav-action` `allow` ab 11.1, wenn fehlend (`sp_action_virus.php:73`) | `virus.decoder.alert-only-set` liest die JSON (4159) | — | `http2 minver="9.0.0"`, `mlav-action minver="9.2.0"` | CHANGELOG 2.1.57 „virus.decoder.alert-only-set - bugfix for older PAN-OS version“ |
| 11 | **URL Inline-Kategorisierung** (`local-inline-cat`, `cloud-inline-cat`): ab 10.2 | ab 10.2 | ergänzt `no` ab 10.2 (`URLProfile.php:363, 373`) | ab 10.2 (`URLProfile.php:884, 1145`) | — | `local-inline-cat minver="10.2.0"` | — |
| 12 | **URL-ML-Engines** (`mlav-engine-urlbased-enabled`) | in 10.0 und 10.1: `Phishing Detection`, `Javascript Exploit Detection` | — | — | — | `Phishing Detection minver="10.2.0"` (G9) | — |
| 13 | **URL-Kategorien:** kommen mit den Dynamic Updates, nicht mit PAN-OS | aus `predefined.xml`, alle Versionen (`cb9c2dc9`) | jede vordefinierte Kategorie startet als `allow` (`URLProfile.php:150–161`) | `url.*.alert-only-set` | gegen `predefined.xml` | `<pan-url-categories>` | Palo Alto: Kategorien sind auf allen PAN-OS-Versionen sichtbar und funktionieren ab 9.1 |

## 5. Befunde

| ID | Befund | Auswirkung |
|---|---|---|
| G1 | `local-deep-learning` wird erzeugt und geladen, aber nicht geprüft (#3) | ein Profil mit `local-deep-learning disable` gilt als sichtbar, obwohl die JSON `enable` fordert |
| G2 | Ohne DNS-Lizenz setzt `spyware.dns.alert-only-set` `log-level none` (#6); die Prüfung fordert `!none` und kennt die Lizenz nicht | nach der Action ist das Profil nicht sichtbar; die Prüfung sollte es als nicht anwendbar werten |
| G3 | **Erledigt beim Erzeugen:** Antivirus MSOffice / Shell gibt es ab 10.0 (#9). Die Class legt sie jetzt ab 10.0 an. **Offen:** Die Prüfung liefert vor 10.2 `null` | vorher hatten Alert-Only-AV und die BP-Profile für 10.0 / 10.1 MSOffice und Shell auf `disable` (vom Loader ergänzt); die Prüfung hat das nicht bemerkt |
| G4 | `virus.inline-ml.alert-only-set` vergleicht `$type == $mlav_engine_entry`, also einen String mit einem `DOMElement` (`actions-securityprofile.php:4204`) | JSON-Einträge für einen bestimmten Modellnamen greifen nie; nur type `any` funktioniert |
| G5 | Die meisten Set-Actions lesen die JSON-Datei nicht (Abschnitt 3) | eine angepasste JSON-Datei ändert das Prüfergebnis, aber nicht, was die Actions setzen |
| G6 | Versionswissen steht an bis zu vier Stellen, z. B. WildFire 11.1 beim Erzeugen, Setzen (auskommentiert) und Prüfen (#1) | eine Korrektur an einer Stelle wird an den anderen leicht vergessen |
| G7 | Die Loader verändern das XML (Abschnitt 3) | `out=` enthält Elemente, die in der Eingabe nicht standen, auch wenn keine Action das Profil geändert hat |
| G8 | Spyware-Detektoren: Erzeugen, Laden und Setzen legen alle 5 ab 10.2 an; `predefined.xml` nennt HTTP, HTTP2, SSL ab 11.1.0 und Unknown-TCP/UDP ab 11.0.0 (#2) | entweder hießen die Detektoren in 10.2 anders, oder pan-os-php legt in 10.2 / 11.0 Detektoren an, die PAN-OS nicht kennt; zu klären |
| G9 | URL-ML-Engine `Phishing Detection` wird für 10.0 / 10.1 angelegt; `predefined.xml` nennt sie ab 10.2.0 (#12) | gleiche Frage wie G8 |

## 6. Vorschlag: drei Ebenen

### 6.1 Was PAN-OS kann (Capabilities)

Eine Stelle je Profiltyp beantwortet, was es gibt und was angenommen wird, abhängig von PAN-OS-Version, Lizenz und
Plattform. Das ist die Tabelle aus Abschnitt 4, aus den vier Stellen herausgelöst in Code, den alle aufrufen. Zum
Beispiel als statische Methode je Class:

```php
// Skizze, Namen noch abzustimmen
WildfireProfile::capabilities( '11.1', $options )
// => array( 'inline-ml' => array( 'available' => true, 'actions' => array( 'allow' ) ) )   // 11.1: kein 'alert'
WildfireProfile::capabilities( '11.2', $options )
// => array( 'inline-ml' => array( 'available' => true, 'actions' => array( 'allow', 'alert', 'block' ) ) )
AntiSpywareProfile::capabilities( '11.2', array( 'dns-license' => false, 'scm' => false ) )
// => array( 'dns' => array( 'available' => true, 'licensed' => false, ... ), 'local-deep-learning' => true, ... )
```

Erzeugen, Laden, Setzen und Prüfen fragen diese Methode, statt selbst `$version` zu vergleichen.

**Quelle der Capabilities:** zuerst `predefined.xml`, wo die Datei eine Versionsangabe (`minver` / `maxver`) hat. Das
ist dieselbe Datei, aus der pan-os-php auch beim Laden und Prüfen liest. Sie wird mit den Dynamic Updates aktualisiert.
So ist es bereits umgesetzt für die URL-Kategorien.

Wo die Versionen in der Class sichtbar bleiben sollen, wie für die Antivirus-Decoder und -Modelle entschieden, behält die
Class sie, und `predefined.xml` ist die Referenz, gegen die ein Test sie prüft.

| Aus `predefined.xml` (hat `minver`) | Bleibt im Code (nicht in `predefined.xml`) |
|---|---|
| Antivirus: Decoder (`http2`), `mlav-action`, ML-Modelle (#9, #10) | WildFire Inline ML, inklusive „11.1 nur `allow`“ (#1) |
| URL-Kategorien (#13), `local-inline-cat` (#11), URL-ML-Engines (#12) | `local-deep-learning` (#3) |
| DNS-Security-Kategorien (#4) | Advanced DNS Security (#5) |
| Spyware Inline ML und Detektoren (#2) | DNS-Lizenz (#6), SCM (#7) |
| Vulnerability Inline ML (#8) | |

Versionen werden dreistellig verglichen (`"11.1"` als `"11.1.0"`), wie in `URLProfile::ironSkilletCategories()`.

### 6.2 Was gewünscht ist (Policy)

Die BP-JSON-Datei, im Format unverändert und vom Anwender anpassbar: `visibility` für Alert-Only, `bp` für Best Practice.

### 6.3 Von der Bedingung zum Wert (Resolution)

Eine Funktion je Profiltyp wendet einen JSON-Abschnitt auf ein Profil an, innerhalb der Capabilities:

1. Für jedes Element, das die JSON nennt: Kann die Version es nicht haben, wird nichts gesetzt, und das Element ist
   „nicht anwendbar“. Die Prüfung liefert dafür `null`, wie heute schon, z. B. Spyware Inline vor 10.2.
2. Erfüllt der aktuelle Wert die Bedingung bereits, bleibt er unverändert. Ein vorhandenes `block` wird nie zu `alert`.
3. Sonst wird der erste Wert gesetzt, der die Bedingung erfüllt **und** den die Version annimmt:

| Bedingung | Gesetzter Wert (Standard) |
|---|---|
| `action` `!allow` (Rules, Decoder, URL-Kategorien, `lists`) | `alert` |
| spyware / vulnerability `inline-policy-action` `!allow` | `alert` |
| wildfire inline `action` `!allow` | `alert` ab 11.2; **11.1: es gibt nur `allow` → nicht anwendbar** (heute „11.1 immer TRUE“) |
| virus inline `!disable` | `enable(alert-only)` |
| DNS `log-level` `!none` | `default`; ohne DNS-Lizenz: nicht anwendbar (G2) |
| credential `mode` `!disabled` | `ip-user` |
| ein fester Wert (`yes`, `enable`, `alert`, `any`, `both`, `public-cloud`) | genau dieser Wert |

4. Welche Einträge vorhanden sein müssen, bestimmen die `type`-Listen der JSON, bei URL- und DNS-Kategorien
   `predefined.xml`, bei Antivirus-Modellen die Class. Es bestimmt nicht das Basisprofil.
5. Fehlt ein Abschnitt in der JSON-Datei, wird nichts gesetzt und nichts geprüft. Das entspricht der Entscheidung für
   die Vulnerability- und Anti-Spyware-Rules: Was die Datei nicht fordert, wird nicht geprüft.

**Option (offen):** Ein JSON-Abschnitt kann konkrete Werte zum Setzen mitbringen, z. B. `"alert-only": { ... }` neben
`visibility`. Sie übersteuern die Standardwerte oben. Beim Laden der Datei prüft pan-os-php, dass diese Werte die
`visibility`-Bedingung des Abschnitts und die Capabilities erfüllen.

### 6.4 Die drei Schritte danach

| Schritt | Wie |
|---|---|
| `Alert-Only-*` erzeugen | Basisprofil aus der Class (`ironSkilletXml()`, nur die Struktur), danach die Resolution mit `visibility` |
| `*.alert-only-set` | dieselbe Resolution auf das bestehende Profil; die eigene Logik je Typ in `actions-securityprofile.php` entfällt |
| Prüfen | `visibility`-Bedingungen; die Capabilities entscheiden über „nicht anwendbar“ |
| Selbsttest | nach dem Erzeugen oder Setzen muss `is.visibility` mit derselben JSON-Datei TRUE sein, oder `null`, wo nicht anwendbar |

Best Practice funktioniert genauso, mit den `bp`-Abschnitten und den Profilen `Outbound-*` / `Inbound-*` / `Internal-*`.

## 7. Schritte

1. **Abschnitt 4 prüfen:** jede Zeile bestätigen, vor allem G8 und G9 und welche Versionsgrenzen noch nötig sind.
   Fehlende Zeilen ergänzen (z. B. File Blocking, Data Filtering, Zone Protection, Log Forwarding).
2. **Capabilities im Code** (6.1), zuerst aus `predefined.xml`, mit einem Test je Version, der sie mit dem heutigen
   Verhalten vergleicht.
3. **Prüfung auf Capabilities umstellen:** `SecurityProfile2` und die Traits fragen die Capabilities statt `$version`.
   G1, G2 und den offenen Teil von G3 schließen.
4. **Pilot URL:** Resolution für `url` (site access, credential, mica-engine), genutzt von
   `sp_spg-create-alert-only-bp` und `url.alert-only-set`.
5. **Anti-Spyware:** Rules, DNS, Advanced DNS, Lists, Inline, `local-deep-learning`, Lizenz, SCM.
6. **Vulnerability, Antivirus (G4), WildFire, File Blocking.**
7. **Best Practice** mit den `bp`-Abschnitten.
8. **Entfernen** der Versionsprüfungen, die dann noch in Actions und Loadern stehen. Über G7 entscheiden (Loader
   verändern das XML).

**Tests für jeden Schritt:** jede Version von 8.1 bis 12.1 × die mitgelieferte JSON-Datei und angepasste Varianten,
also ein fehlender Abschnitt, ein strengerer Wert und ein Wert, den die Version nicht annimmt. Erwartete Ergebnisse:

- erzeugen, dann prüfen: sichtbar;
- setzen auf einem nicht sichtbaren Profil: danach sichtbar;
- setzen auf einem Best-Practice-Profil: nichts wird heruntergestuft.

## 8. Offene Fragen

1. Nur Standardwerte (6.3), oder auch konkrete Werte in der JSON-Datei (`"alert-only": {...}`)?
2. Woher kennt pan-os-php Lizenz und Plattform im Offline-Betrieb? Heute sind das Action-Argumente
   (`has-DNS-license`). Im API-Modus könnten sie vom Gerät gelesen werden.
3. G8 / G9: Gelten die `minver` aus `predefined.xml` für die Spyware-Detektoren und `Phishing Detection`, oder hatten
   ältere Versionen dieselben Funktionen unter anderem Namen?
4. G7: Sollen die Loader weiterhin PAN-OS-Standardwerte ins XML schreiben, oder nur in den Speicher?
5. Wird 8.1 für diese Actions noch unterstützt?
