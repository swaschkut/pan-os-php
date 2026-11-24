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
 * Read only: the IKE gateways and their pre-shared keys
 * - in=scm-api://<TSG>: of every firewall managed by the SCM tenant, the newest version of its configuration (SCM NGFW
 *   operations API local-config)
 * - in=<file.xml>: of a configuration file (firewall, Panorama templates, SCM folders / snippets / devices), offline
 *
 * The output names gateways, peers and whether the PSK can be decrypted - never a secret. The clear text goes only into
 * psk-list=<file> (CSV, chmod 600); sha1-list=<file> is the list without clear text; compare=<SHA-1 / PSK list>
 * compares it (side a) with this one (side b) by gateway name and SHA-1 of the pre-shared key (IKEPSKList).
 *
 * pan-os-php type=scm-ngfw-psk-list in=scm-api://<TSG>|<file.xml> [serial=<s1,s2>] [master-key=<key>] [psk-list=<file>]
 *     [sha1-list=<file>] [compare=<file> [compare-out=<file>]] [save-dir=<dir>] [base=<url>] [debugapi]
 */
set_include_path(dirname(__FILE__) . '/../../../../' . PATH_SEPARATOR . get_include_path());
require_once("lib/pan_php_framework.php");
require_once("utils/lib/UTIL.php");
require_once(dirname(__FILE__) . "/lib/SCMLocalConfig.php");

PH::print_stdout();
PH::print_stdout("*********** " . basename(__FILE__) . " **************");
PH::print_stdout();

$pskStats = function() {
    return array( 'firewalls' => 0, 'without_version' => 0, 'download_failed' => 0, 'gateways' => 0,
        IKEPSKList::PSK_DEFAULT => 0, IKEPSKList::PSK_GIVEN => 0, IKEPSKList::PSK_NOT_DECRYPTABLE => 0,
        IKEPSKList::PSK_OTHER_FORMAT => 0, IKEPSKList::PSK_NONE => 0 );
};
$pskGateways = function( array $gateways, array &$stats ) {
    if( empty($gateways) )
        PH::print_stdout("   no IKE gateway");
    foreach( $gateways as $g )
    {
        $stats['gateways']++;
        $stats[$g['psk_status']]++;
        PH::print_stdout("   - " . IKEPSKList::gatewayLine( $g ));
    }
};

/** the end of both modes: summary, PSK list, SHA-1 list, comparison; the exit code */
function pskFinish( array $firewalls, array $stats, array $opt, bool $live )
{
    PH::print_stdout();
    PH::print_stdout(" - summary: " . ( $live ? $stats['firewalls'] . " firewall(s) (" . $stats['without_version'] . " without version, " . $stats['download_failed'] . " download failed), " : "" )
        . $stats['gateways'] . " IKE gateway(s): " . $stats[IKEPSKList::PSK_DEFAULT] . " default master key, " . $stats[IKEPSKList::PSK_GIVEN] . " given master key, "
        . $stats[IKEPSKList::PSK_NOT_DECRYPTABLE] . " not decryptable, " . $stats[IKEPSKList::PSK_OTHER_FORMAT] . " other format, " . $stats[IKEPSKList::PSK_NONE] . " without PSK");
    try
    {
        if( $opt['psk-list'] !== null )
            PH::print_stdout(" - PSK list: " . IKEPSKList::writePSKList( $opt['psk-list'], $firewalls ) . " row(s) -> " . $opt['psk-list'] . " (chmod 600 - clear text secrets)");
        else
            PH::print_stdout(" - no clear text written (psk-list=<file> writes the PSK list)");
        if( $opt['sha1-list'] !== null )
            PH::print_stdout(" - SHA-1 list (no clear text): " . IKEPSKList::writeSHA1List( $opt['sha1-list'], $firewalls ) . " row(s) -> " . $opt['sha1-list']);
        if( $opt['compare'] !== null )
        {
            $a = IKEPSKList::readSHA1List( $opt['compare'] );
            $b = array();
            foreach( $firewalls as $fw )
                foreach( $fw['gateways'] as $g )
                    $b[] = $g + array( 'serial' => $fw['serial'], 'firewall' => $fw['firewall'] );
            $rows = IKEPSKList::compare( $a, $b );
            PH::print_stdout();
            PH::print_stdout(" - comparison by gateway name and SHA-1 of the pre-shared key: a = " . basename( $opt['compare'] ) . ", b = this list");
            foreach( $rows as $r )
                PH::print_stdout("   * " . str_pad( $r['result'], 9 ) . " " . $r['ike_gateway'] . ( $r['a_where'] !== '' ? "  a: " . $r['a_where'] : "" ) . ( $r['b_where'] !== '' ? "  b: " . $r['b_where'] : "" ));
            $sum = IKEPSKList::compareSummary( $rows );
            PH::print_stdout(" - comparison: " . $sum[IKEPSKList::SAME] . " same, " . $sum[IKEPSKList::DIFFERENT] . " different, " . $sum[IKEPSKList::ONLY_A] . " only in a, "
                . $sum[IKEPSKList::ONLY_B] . " only in b, " . $sum[IKEPSKList::UNKNOWN] . " unknown (no PSK / other format)");
            if( $opt['compare-out'] !== null )
            {
                IKEPSKList::writeCompare( $opt['compare-out'], $rows );
                PH::print_stdout(" - comparison -> " . $opt['compare-out']);
            }
        }
    }
    catch( Exception $e )
    {
        derr($e->getMessage(), null, FALSE);
    }
    PH::print_stdout();
    PH::print_stdout("************* END OF SCRIPT scm_ngfw_psk_list.php ************");
    PH::print_stdout();
    // 0: done (also with pre-shared keys that can not be decrypted - see the summary), 2: API / download error
    exit( $stats['download_failed'] > 0 ? 2 : 0 );
}

// ---- in=<file.xml>: offline, before UTIL (it would load the whole configuration)
$pre = array();
foreach( array_slice( $argv, 1 ) as $a )
    if( is_string($a) && ( $i = strpos( $a, '=' ) ) !== FALSE )
        $pre[strtolower( substr( $a, 0, $i ) )] = substr( $a, $i + 1 );
$opt = array();
foreach( array( 'psk-list', 'sha1-list', 'compare', 'compare-out', 'master-key' ) as $k )
    $opt[$k] = isset($pre[$k]) && $pre[$k] !== '' ? $pre[$k] : null;
if( isset($pre['in']) && $pre['in'] !== '' && strpos( $pre['in'], 'scm-api://' ) !== 0 )
{
    $file = $pre['in'];
    PH::print_stdout(" - configuration file " . basename( $file ));
    $doc = new DOMDocument();
    if( !is_file($file) || !@$doc->load($file, XML_PARSE_BIG_LINES) )
        derr("in=: not readable as XML: " . $file, null, FALSE);
    $stats = $pskStats();
    $gateways = IKEPSKList::gateways( new DOMXPath($doc), $opt['master-key'] );
    unset( $doc );
    $pskGateways( $gateways, $stats );
    pskFinish( array( array( 'serial' => '', 'firewall' => '', 'config_version' => '', 'config_timestamp' => '', 'gateways' => $gateways ) ), $stats, $opt, FALSE );
}

$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'in=scm-api://<TSG> (the firewalls managed by SCM) or in=<file.xml> (a configuration, offline)', 'argDesc' => 'scm-api://[TSG]|[file]');
$supportedArguments['serial'] = array('niceName' => 'serial', 'shortHelp' => 'comma separated serial numbers (default: every firewall of the tenant)', 'argDesc' => '[serial1,serial2]');
$supportedArguments['master-key'] = array('niceName' => 'master-key', 'shortHelp' => 'master key of the firewalls, if not the default one (the default one is tried first)', 'argDesc' => '[key]');
$supportedArguments['psk-list'] = array('niceName' => 'psk-list', 'shortHelp' => 'write the PSK list with the clear text of the decryptable pre-shared keys to this CSV file (chmod 600)', 'argDesc' => '[file]');
$supportedArguments['sha1-list'] = array('niceName' => 'sha1-list', 'shortHelp' => 'write the list without clear text (SHA-1 of the pre-shared key) to this CSV file - for compare=', 'argDesc' => '[file]');
$supportedArguments['compare'] = array('niceName' => 'compare', 'shortHelp' => 'compare with this SHA-1 / PSK list (side a; this list: side b) by gateway name and SHA-1 of the pre-shared key', 'argDesc' => '[file]');
$supportedArguments['compare-out'] = array('niceName' => 'compare-out', 'shortHelp' => 'write the comparison to this CSV file (no secret)', 'argDesc' => '[file]');
$supportedArguments['save-dir'] = array('niceName' => 'save-dir', 'shortHelp' => 'write the downloaded configurations to this directory: <serial>-<version>.xml (chmod 600 - they hold the encrypted secrets)', 'argDesc' => '[directory]');
$supportedArguments['base'] = array('niceName' => 'base', 'shortHelp' => 'URL of the operations API (default: try the probable ones)', 'argDesc' => '[url]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$usage = "php " . basename(__FILE__) . " in=scm-api://<TSG>|<file.xml> [serial=<s1,s2>] [master-key=<key>] [psk-list=<file>] [sha1-list=<file>] [compare=<file> [compare-out=<file>]] [save-dir=<dir>] [base=<url>]";

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
$stats = $pskStats();
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
        $stats['download_failed']++;
        pskFinish( $firewalls, $stats, $opt, TRUE );
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
        $fh = IKEPSKList::openSecretFile( $file );
        fwrite( $fh, $xml );
        fclose( $fh );
        PH::print_stdout("   written to " . $file);
    }

    $gateways = IKEPSKList::gateways( new DOMXPath($doc), $masterKey );
    unset( $xml, $doc );
    $pskGateways( $gateways, $stats );
    $firewalls[] = array( 'serial' => $d['serial'], 'firewall' => $d['name'], 'config_version' => $vid,
        'config_timestamp' => (string)( $newest['timestamp'] ?? '' ), 'gateways' => $gateways );
}

pskFinish( $firewalls, $stats, $opt, TRUE );
