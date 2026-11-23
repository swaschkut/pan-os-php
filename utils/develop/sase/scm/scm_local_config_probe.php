<?php
/**
 * ISC License
 *
 * Copyright (c) 2026, Sven Waschkut - pan-os-php@waschkut.net
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * scm_local_config_probe.php
 *
 * Checks, read-only, what the SCM NGFW operations API gives of the configuration of a firewall managed by Strata
 * Cloud Manager (GET /local-config/versions, GET /local-config/download - "the XML configuration file pushed to a
 * device"), and whether the pre-shared keys of its IKE gateways in it can be decrypted:
 *   - format of each encrypted value (-AQ== = master key encryption level 1, other = not readable by pan-os-php)
 *   - decryptable with the default master key, or with master-key=<key> (the SHA1 in the value proves it)
 *
 * Prints never a secret: only names of IKE gateways and yes / no / counts. The downloaded configuration is written
 * only with save=<file> (chmod 600 - it holds the encrypted secrets of the firewall).
 *
 * php scm_local_config_probe.php file=<config.xml> [master-key=<key>]         offline: a configuration downloaded in SCM
 *                                                                           (Device Management > Local Config Management)
 * php scm_local_config_probe.php in=scm-api://<TSG>                            list the managed firewalls (serials)
 * php scm_local_config_probe.php in=scm-api://<TSG> serial=<serial> [config-version=<id>] [master-key=<key>] [save=<file>]
 *     [base=https://api.strata.paloaltonetworks.com/config/operations/v1] [debugapi]
 *
 * base: the URL of the operations API is not documented on pan.dev (only the paths) - without base= the probable
 * ones are tried one after the other and the HTTP code of each try is printed.
 */
set_include_path(dirname(__FILE__) . '/../../../../' . PATH_SEPARATOR . get_include_path());
require_once("lib/pan_php_framework.php");
require_once("utils/lib/UTIL.php");

PH::print_stdout();
PH::print_stdout("*********** " . basename(__FILE__) . " **************");
PH::print_stdout();

$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'in=scm-api://<TSG>', 'argDesc' => 'scm-api://[TSG]');
$supportedArguments['file'] = array('niceName' => 'file', 'shortHelp' => 'offline: a configuration file (e.g. downloaded in SCM, Local Config Management)', 'argDesc' => '[file]');
$supportedArguments['serial'] = array('niceName' => 'serial', 'shortHelp' => 'serial number of the firewall (without: list the managed firewalls)', 'argDesc' => '[serial]');
$supportedArguments['config-version'] = array('niceName' => 'config-version', 'shortHelp' => 'id of the configuration version to download (default: the newest; not version= - pan-os-php itself answers that)', 'argDesc' => '[id]');
$supportedArguments['master-key'] = array('niceName' => 'master-key', 'shortHelp' => 'master key of the firewall, if not the default one', 'argDesc' => '[key]');
$supportedArguments['save'] = array('niceName' => 'save', 'shortHelp' => 'write the downloaded configuration to this file (chmod 600; not out= - UTIL would load an existing out= file as the SCM base configuration)', 'argDesc' => '[file]');
$supportedArguments['base'] = array('niceName' => 'base', 'shortHelp' => 'URL of the operations API (default: try the probable ones)', 'argDesc' => '[url]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$usage = "php " . basename(__FILE__) . " in=scm-api://<TSG> [serial=<serial> [config-version=<id>] [master-key=<key>] [save=<file>] [base=<url>]]";

// offline: a configuration file (no API)
foreach( array_slice($argv, 1) as $a )
    if( strpos($a, 'file=') === 0 )
    {
        $mk = null;
        foreach( array_slice($argv, 1) as $b )
            if( strpos($b, 'master-key=') === 0 )
                $mk = substr($b, 11);
        $doc = new DOMDocument();
        if( !@$doc->load(substr($a, 5), XML_PARSE_BIG_LINES) )
            derr("file: not a readable XML file", null, FALSE);
        PH::print_stdout(" - file " . basename(substr($a, 5)) . ", root <" . $doc->documentElement->nodeName . ">");
        $stats = probeAnalyse( new DOMXPath($doc), $mk );
        exit( $stats['psk'] > 0 && $stats['default'] + $stats['given'] === $stats['psk'] ? 0 : 1 );
    }

$util = new UTIL("custom", $argv, $argc, __FILE__, $supportedArguments, $usage);
$util->utilInit();

/* @var PanSCMAPIConnector $connector */
$connector = $util->pan->connector;
if( !is_object($connector) || get_class($connector) !== "PanSCMAPIConnector" )
    derr("argument in=scm-api://<TSG> is required", null, FALSE);
if( isset(PH::$args['debugapi']) )
    $connector->setShowApiCalls(TRUE);
$api = rtrim($connector->url_api, "/");

// ---- without serial: the managed firewalls of the tenant
if( !isset(PH::$args['serial']) || PH::$args['serial'] === true )
{
    $r = $connector->sendSCMAPIRequest("GET", $api . "/config/setup/v1/devices?limit=1000", false, FALSE);
    $list = isset($r['json']['data']) ? $r['json']['data'] : ( is_array($r['json']) && isset($r['json'][0]) ? $r['json'] : array() );
    PH::print_stdout(" - GET /config/setup/v1/devices: HTTP " . $r['http_code'] . ", " . count($list) . " device(s)");
    foreach( $list as $d )
        PH::print_stdout("   * serial " . ( $d['id'] ?? $d['serial_number'] ?? '?' ) . "  " . ( $d['name'] ?? $d['hostname'] ?? '' ) . "  [folder " . ( $d['folder'] ?? '-' ) . "]  "
            . ( $d['model'] ?? '' ) . " " . ( $d['software_version'] ?? $d['sw_version'] ?? '' ));
    PH::print_stdout();
    PH::print_stdout(" next: serial=<serial> to probe the configuration of one firewall");
    exit(0);
}
$serial = (string)PH::$args['serial'];
if( !preg_match('/^[0-9A-Za-z]{6,20}$/', $serial) )
    derr("serial: the serial number of the firewall", null, FALSE);

// ---- 1) versions: the probable URLs / parameter names, until one answers 200
$bases = isset(PH::$args['base']) && PH::$args['base'] !== true ? array( rtrim(PH::$args['base'], "/") )
    : array( $api . "/config/operations/v1", $api . "/operations/v1", $api . "/config/ngfw-operations/v1", $api . "/config/device-operations/v1" );
$found = null;
foreach( $bases as $base )
{
    foreach( array('device', 'serial') as $param )
    {
        $url = $base . "/local-config/versions?" . $param . "=" . rawurlencode($serial);
        $r = $connector->sendSCMAPIRequest("GET", $url, false, FALSE);
        PH::print_stdout(" - try GET " . substr($url, strlen($api)) . ": HTTP " . $r['http_code']);
        if( $r['http_code'] == 200 && is_array($r['json']) )
        {
            $found = array( 'base' => $base, 'param' => $param, 'json' => $r['json'] );
            break 2;
        }
    }
}
if( $found === null )
{
    PH::print_stdout();
    PH::print_stdout(" ! no answer 200 - the URL of the operations API (base=) or the parameter name is another one, or the service account");
    PH::print_stdout("   lacks the permission. Look at the request of the SCM page Device Management > Local Config Management");
    PH::print_stdout("   (browser developer tools) and give it with base=.");
    exit(2);
}
$versions = isset($found['json']['data']) ? $found['json']['data'] : $found['json'];
PH::print_stdout();
PH::print_stdout(" - versions: " . count($versions) . "  (base " . substr($found['base'], strlen($api)) . ", parameter " . $found['param'] . ")");
foreach( array_slice($versions, 0, 10) as $v )
    PH::print_stdout("   * id " . ( $v['id'] ?? '?' ) . "  local_version " . ( $v['local_version'] ?? '?' ) . "  xfmed_version " . ( $v['xfmed_version'] ?? '?' )
        . "  " . ( $v['timestamp'] ?? '' ) . "  md5 " . ( $v['md5'] ?? '-' ));
if( count($versions) == 0 )
{
    PH::print_stdout(" ! no version for this firewall");
    exit(2);
}

// ---- 2) download: the given version, else the newest
$version = isset(PH::$args['config-version']) && PH::$args['config-version'] !== true ? (string)PH::$args['config-version'] : null;
if( $version === null )
{
    usort($versions, function( $a, $b ) { return strcmp((string)( $b['timestamp'] ?? '' ), (string)( $a['timestamp'] ?? '' )) ?: ( ( $b['id'] ?? 0 ) <=> ( $a['id'] ?? 0 ) ); });
    $version = (string)( $versions[0]['id'] ?? $versions[0]['local_version'] ?? '' );
}
$url = $found['base'] . "/local-config/download?" . $found['param'] . "=" . rawurlencode($serial) . "&version=" . rawurlencode($version);
$r = $connector->sendSCMAPIRequest("GET", $url, false, FALSE);
$xml = is_string($r['response']) ? $r['response'] : '';
PH::print_stdout(" - download version " . $version . ": HTTP " . $r['http_code'] . ", " . strlen($xml) . " bytes");
if( $r['http_code'] != 200 || $xml === '' )
    exit(2);
if( isset(PH::$args['save']) && PH::$args['save'] !== true )
{
    file_put_contents(PH::$args['save'], $xml);
    chmod(PH::$args['save'], 0600);
    PH::print_stdout("   written to " . PH::$args['save'] . " (chmod 600 - holds the encrypted secrets of the firewall)");
}
$doc = new DOMDocument();
if( !@$doc->loadXML($xml, XML_PARSE_BIG_LINES) )
{
    PH::print_stdout(" ! the answer is not XML");
    exit(2);
}
$xp = new DOMXPath($doc);
PH::print_stdout(" - root <" . $doc->documentElement->nodeName . ">" . ( $doc->documentElement->hasAttribute('version') ? " version " . $doc->documentElement->getAttribute('version') : "" )
    . ", vsys: " . $xp->query("//devices/entry/vsys/entry")->length . ", template / device-group parts: " . $xp->query("//template|//device-group")->length);

probeAnalyse( $xp, isset(PH::$args['master-key']) && PH::$args['master-key'] !== true ? (string)PH::$args['master-key'] : null );

PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************");
PH::print_stdout();

/** the pre-shared keys of the IKE gateways of a configuration: format and whether they can be decrypted - never the value */
function probeAnalyse( DOMXPath $xp, ?string $masterKey ): array
{
    $crypto = new PanosCrypto();
    $stats = array( 'gateways' => 0, 'psk' => 0, 'level1' => 0, 'other' => 0, 'default' => 0, 'given' => 0, 'no' => 0 );
    PH::print_stdout();
    PH::print_stdout(" - IKE gateways with pre-shared key:");
    foreach( $xp->query("//network/ike/gateway/entry") as $gw )
    {
        $stats['gateways']++;
        $key = $xp->query("authentication/pre-shared-key/key", $gw)->item(0);
        if( $key === null )
            continue;
        $stats['psk']++;
        $value = trim($key->textContent);
        $where = $xp->query("ancestor::entry[parent::vsys or parent::template or parent::device-group]", $gw)->item(0);
        $label = $gw->getAttribute('name') . ( $where !== null ? " (" . $where->parentNode->nodeName . " " . $where->getAttribute('name') . ")" : "" );
        if( strpos($value, "-AQ==") !== 0 )
        {
            $stats['other']++;
            PH::print_stdout("   * " . $label . ": other format (" . ( $value === '' ? 'empty' : 'prefix ' . substr($value, 0, 5) ) . ") - not readable by pan-os-php");
            continue;
        }
        $stats['level1']++;
        // PanosCrypto::decrypt(): the clear text, '' / false when the key does not fit (the SHA1 in the value is checked)
        $ok = function( $key ) use ( $crypto, $value ) { $c = $crypto->decrypt($value, $key); return is_string($c) && $c !== ''; };
        $how = $ok(null) ? 'default' : ( $masterKey !== null && $ok($masterKey) ? 'given' : 'no' );
        $stats[$how]++;
        PH::print_stdout("   * " . $label . ": level 1, " . ( $how === 'default' ? "decryptable with the DEFAULT master key"
            : ( $how === 'given' ? "decryptable with the given master key" : "NOT decryptable" . ( $masterKey === null ? " with the default master key (master-key=<key>?)" : "" ) ) ));
    }
    PH::print_stdout();
    PH::print_stdout(" - summary: " . $stats['gateways'] . " IKE gateway(s), " . $stats['psk'] . " with pre-shared key: " . $stats['level1'] . " level 1 ("
        . $stats['default'] . " default master key, " . $stats['given'] . " given master key, " . $stats['no'] . " not decryptable), " . $stats['other'] . " other format");

    return $stats;
}
