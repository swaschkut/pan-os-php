<?php
/**
 * ISC License
 *
 * Copyright (c) 2024, Sven Waschkut - pan-os-php@waschkut.net
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

// Export all Remote Network (RN / RN-SPN) related configuration of one Prisma Access tenant (TSG)
// see utils/develop/sase/scm/README_rn_export.md
//
// php utils/develop/sase/scm/scm_rn_export.php in=scm-api://<TSG_ID> [outdir=export] [egressip] [egressip-env=prod|prod6] [psk-list] [master-key=...] [debugapi]

require_once("lib/pan_php_framework.php");
require_once("utils/lib/UTIL.php");
require_once(dirname(__FILE__) . "/lib/SCMRemoteNetworkExport.php");

PH::print_stdout();
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout();

PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );

$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'SCM tenant. ie: in=scm-api://<TSG_ID>', 'argDesc' => 'scm-api://[TSG_ID]');
$supportedArguments['outdir'] = Array('niceName' => 'outdir', 'shortHelp' => 'base directory for the export; files go to <outdir>/<TSG_ID>/<timestamp>/ (default: export)', 'argDesc' => '[directory]');
$supportedArguments['folder'] = Array('niceName' => 'folder', 'shortHelp' => 'SCM folder for the IKE/IPsec objects (default: "Remote Networks")', 'argDesc' => '[folder]');
$supportedArguments['egressip'] = Array('niceName' => 'egressip', 'shortHelp' => 'also download the egress IPs via the Prisma Access egress-IP API (separate API key, stored in .panconfkeystore as egressip_tsg_id<TSG_ID>)');
$supportedArguments['egressip-env'] = Array('niceName' => 'egressip-env', 'shortHelp' => 'egress-IP API host: prod (api.prod.datapath.prismaaccess.com, default) | prod6 (api.prod6.datapath.prismaaccess.com)', 'argDesc' => 'prod|prod6');
$supportedArguments['psk-list'] = Array('niceName' => 'psk-list', 'shortHelp' => 'write psk-list.csv (chmod 600) with the decrypted current PSK per IKE gateway and an empty psk_new column for the import');
$supportedArguments['master-key'] = Array('niceName' => 'master-key', 'shortHelp' => 'master key to decrypt the PSKs (default: PAN-OS default master key)', 'argDesc' => '[master-key]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');

$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=scm-api://<TSG_ID> [outdir=export] [egressip] [egressip-env=prod|prod6] [psk-list] [master-key=...]\n".
    "php ".basename(__FILE__)." help          : more help messages\n";
##############

$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();

##########################################

/* @var PanSCMAPIConnector $connector */
$connector = $util->pan->connector;
if( !is_object($connector) || get_class($connector) !== "PanSCMAPIConnector" )
    derr( "argument in=scm-api://<TSG_ID> is required", null, FALSE );

if( isset(PH::$args['debugapi']) )
    $connector->setShowApiCalls( TRUE );

$tsg = $connector->apihost;

$outdir = isset(PH::$args['outdir']) ? PH::$args['outdir'] : "export";
$folder = isset(PH::$args['folder']) ? PH::$args['folder'] : "Remote Networks";
$egressEnv = isset(PH::$args['egressip-env']) ? PH::$args['egressip-env'] : "prod";
if( $egressEnv !== "prod" && $egressEnv !== "prod6" )
    derr( "egressip-env must be 'prod' or 'prod6'", null, FALSE );

########################################################################################################################

$export = new SCMRemoteNetworkExport( $connector, $tsg, $outdir, $folder );
$dir = $export->prepareDirectory();

PH::print_stdout();
PH::print_stdout( " * TSG: " . $tsg );
PH::print_stdout( " * export directory: " . $dir );
PH::print_stdout();

$export->exportEndpoints();

$egressKey = null;
if( isset(PH::$args['egressip']) )
    $egressKey = $connector->getEgressIPApiKey( $tsg );
$export->exportEgressIP( $egressKey, $egressEnv );

$ipMapping = $export->buildIPMapping();
$pskStats = null;
if( isset(PH::$args['psk-list']) )
{
    $masterKey = ( isset(PH::$args['master-key']) && PH::$args['master-key'] !== "" ) ? PH::$args['master-key'] : null;
    $pskStats = $export->writePSKList( $masterKey );
    PH::print_stdout( " * psk-list.csv: " . $pskStats['gateways'] . " gateway(s), decrypted: " . $pskStats['decrypted'] . ", failed: " . $pskStats['decrypt_failed'] );
    PH::print_stdout( PH::boldText("   ! psk-list.csv contains cleartext PSKs - keep it out of tickets / git") );
}

$manifest = $export->writeManifest( PH::frameworkVersion(), $ipMapping, $pskStats );

########################################################################################################################

PH::print_stdout();
PH::print_stdout( " * remote networks: " . $manifest['ip_mapping']['remote_networks'] . " | egress IPs matched: " . $manifest['ip_mapping']['egress_matched'] );
foreach( $manifest['import_hints'] as $hint )
    PH::print_stdout( " ! " . $hint['type'] . ": " . count($hint['objects']) . " object(s) - " . $hint['message'] );
if( $manifest['errors'] > 0 )
    PH::print_stdout( PH::boldText(" x " . $manifest['errors'] . " endpoint(s) failed - see manifest.json") );
PH::print_stdout( " * done: " . $dir );

PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
########################################################################################################################
