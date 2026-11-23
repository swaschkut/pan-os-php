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
 * Read only: every firewall managed by the SCM tenant, the newest version of its configuration (SCM NGFW operations API
 * local-config) and the IKE gateways with pre-shared key.
 *
 * The output names gateways, peers and whether the PSK can be decrypted - never a secret. The clear text goes only into
 * psk-list=<file> (CSV, chmod 600).
 *
 * pan-os-php type=scm-ngfw-psk-list in=scm-api://<TSG> [serial=<s1,s2>] [master-key=<key>] [psk-list=<file>]
 *     [save-dir=<dir>] [base=<url>] [debugapi]
 */
set_include_path(dirname(__FILE__) . '/../../../../' . PATH_SEPARATOR . get_include_path());
require_once("lib/pan_php_framework.php");
require_once("utils/lib/UTIL.php");
require_once(dirname(__FILE__) . "/lib/SCMLocalConfig.php");

PH::print_stdout();
PH::print_stdout("*********** " . basename(__FILE__) . " **************");
PH::print_stdout();

$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'in=scm-api://<TSG>', 'argDesc' => 'scm-api://[TSG]');
$supportedArguments['serial'] = array('niceName' => 'serial', 'shortHelp' => 'comma separated serial numbers (default: every firewall of the tenant)', 'argDesc' => '[serial1,serial2]');
$supportedArguments['master-key'] = array('niceName' => 'master-key', 'shortHelp' => 'master key of the firewalls, if not the default one (the default one is tried first)', 'argDesc' => '[key]');
$supportedArguments['psk-list'] = array('niceName' => 'psk-list', 'shortHelp' => 'write the PSK list with the clear text of the decryptable pre-shared keys to this CSV file (chmod 600)', 'argDesc' => '[file]');
$supportedArguments['save-dir'] = array('niceName' => 'save-dir', 'shortHelp' => 'write the downloaded configurations to this directory: <serial>-<version>.xml (chmod 600 - they hold the encrypted secrets)', 'argDesc' => '[directory]');
$supportedArguments['base'] = array('niceName' => 'base', 'shortHelp' => 'URL of the operations API (default: try the probable ones)', 'argDesc' => '[url]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$usage = "php " . basename(__FILE__) . " in=scm-api://<TSG> [serial=<s1,s2>] [master-key=<key>] [psk-list=<file>] [save-dir=<dir>] [base=<url>]";

$util = new UTIL("custom", $argv, $argc, __FILE__, $supportedArguments, $usage);
$util->utilInit();

/* @var PanSCMAPIConnector $connector */
$connector = $util->pan->connector;
if( !is_object($connector) || get_class($connector) !== "PanSCMAPIConnector" )
    derr("argument in=scm-api://<TSG> is required", null, FALSE);
if( isset(PH::$args['debugapi']) )
    $connector->setShowApiCalls(TRUE);

$arg = function( $name ) { return isset(PH::$args[$name]) && PH::$args[$name] !== true && PH::$args[$name] !== '' ? (string)PH::$args[$name] : null; };
$masterKey = $arg('master-key');
$pskList = $arg('psk-list');
$saveDir = $arg('save-dir');
if( $saveDir !== null && !is_dir($saveDir) && !@mkdir($saveDir, 0700, TRUE) )
    derr("save-dir: not possible to create " . $saveDir, null, FALSE);

$lc = new SCMLocalConfig( $connector, $arg('base') );
$lc->log = function( $line ) { PH::print_stdout("     " . $line); };

// ---- the firewalls
try
{
    $devices = $lc->devices();
}
catch( Exception $e )
{
    derr($e->getMessage(), null, FALSE);
}
if( $arg('serial') !== null )
{
    $wanted = array_values(array_filter(array_map('trim', explode(",", $arg('serial')))));
    $known = array_column($devices, null, 'serial');
    $devices = array();
    foreach( $wanted as $s )
        $devices[] = isset($known[$s]) ? $known[$s] : array( 'serial' => $s, 'name' => '', 'folder' => '', 'model' => '', 'software_version' => '', 'connected' => null );
}
PH::print_stdout(" - " . count($devices) . " firewall(s)");

$firewalls = array();
$stats = array( 'firewalls' => 0, 'without_version' => 0, 'download_failed' => 0, 'gateways' => 0,
    SCMLocalConfig::PSK_DEFAULT => 0, SCMLocalConfig::PSK_GIVEN => 0, SCMLocalConfig::PSK_NOT_DECRYPTABLE => 0,
    SCMLocalConfig::PSK_OTHER_FORMAT => 0, SCMLocalConfig::PSK_NONE => 0 );
foreach( $devices as $d )
{
    $stats['firewalls']++;
    PH::print_stdout();
    PH::print_stdout(" * " . $d['serial'] . ( $d['name'] !== '' ? "  " . $d['name'] : "" ) . ( $d['folder'] !== '' ? "  [folder " . $d['folder'] . "]" : "" )
        . ( $d['model'] !== '' ? "  " . $d['model'] : "" ) . ( $d['software_version'] !== '' ? " " . $d['software_version'] : "" )
        . ( $d['connected'] === false ? "  (not connected)" : "" ));

    $versions = $lc->versions( $d['serial'] );
    if( $versions === null && $lc->found() !== null )
    {
        // the URL is known (another firewall answered): an error of this firewall only
        $stats['download_failed']++;
        PH::print_stdout("   ! no answer 200 for the versions of this firewall");
        continue;
    }
    if( $versions === null )
    {
        PH::print_stdout();
        PH::print_stdout(" ! the operations API did not answer 200 - the URL (base=) or the parameter name is another one, or the service account");
        PH::print_stdout("   lacks the permission. Look at the request of the SCM page Device Management > Local Config Management");
        PH::print_stdout("   (browser developer tools) and give it with base=.");
        exit(2);
    }
    $newest = SCMLocalConfig::newest( $versions );
    if( $newest === null )
    {
        $stats['without_version']++;
        PH::print_stdout("   no configuration version in SCM");
        continue;
    }
    $vid = SCMLocalConfig::versionId( $newest );
    PH::print_stdout("   newest of " . count($versions) . " version(s): id " . $vid . "  local_version " . ( $newest['local_version'] ?? '?' )
        . "  " . ( $newest['timestamp'] ?? '' ));
    $xml = $lc->download( $d['serial'], $vid );
    $doc = new DOMDocument();
    if( $xml === null || !@$doc->loadXML($xml, XML_PARSE_BIG_LINES) )
    {
        $stats['download_failed']++;
        PH::print_stdout("   ! download failed or not XML");
        continue;
    }
    if( $saveDir !== null )
    {
        $file = rtrim($saveDir, "/") . "/" . preg_replace('/[^0-9A-Za-z._-]/', '_', $d['serial'] . "-" . $vid) . ".xml";
        $fh = SCMLocalConfig::openSecretFile( $file );
        fwrite( $fh, $xml );
        fclose( $fh );
        PH::print_stdout("   written to " . $file);
    }

    $gateways = SCMLocalConfig::gateways( new DOMXPath($doc), $masterKey );
    unset( $xml, $doc );
    if( empty($gateways) )
        PH::print_stdout("   no IKE gateway");
    foreach( $gateways as $g )
    {
        $stats['gateways']++;
        $stats[$g['psk_status']]++;
        PH::print_stdout("   - " . SCMLocalConfig::gatewayLine( $g ));
    }
    $firewalls[] = array( 'serial' => $d['serial'], 'firewall' => $d['name'], 'config_version' => $vid,
        'config_timestamp' => (string)( $newest['timestamp'] ?? '' ), 'gateways' => $gateways );
}

PH::print_stdout();
PH::print_stdout(" - summary: " . $stats['firewalls'] . " firewall(s) (" . $stats['without_version'] . " without version, " . $stats['download_failed'] . " download failed), "
    . $stats['gateways'] . " IKE gateway(s): " . $stats[SCMLocalConfig::PSK_DEFAULT] . " default master key, " . $stats[SCMLocalConfig::PSK_GIVEN] . " given master key, "
    . $stats[SCMLocalConfig::PSK_NOT_DECRYPTABLE] . " not decryptable, " . $stats[SCMLocalConfig::PSK_OTHER_FORMAT] . " other format, " . $stats[SCMLocalConfig::PSK_NONE] . " without PSK");

if( $pskList !== null )
{
    try
    {
        $n = SCMLocalConfig::writePSKList( $pskList, $firewalls );
    }
    catch( Exception $e )
    {
        derr($e->getMessage(), null, FALSE);
    }
    PH::print_stdout(" - PSK list: " . $n . " row(s) -> " . $pskList . " (chmod 600 - clear text secrets)");
}
else
    PH::print_stdout(" - no clear text written (psk-list=<file> writes the PSK list)");

PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************");
PH::print_stdout();

// 0: every pre-shared key decryptable, 1: not every one, 2: API / download error
exit( $stats['download_failed'] > 0 ? 2 : ( $stats[SCMLocalConfig::PSK_NOT_DECRYPTABLE] + $stats[SCMLocalConfig::PSK_OTHER_FORMAT] > 0 ? 1 : 0 ) );
