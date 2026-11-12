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

// Export Prisma Access configuration of one tenant (TSG): infrastructure, Remote Networks (RN / RN-SPN), Service Connections (SC-CAN)
// see utils/develop/sase/scm/README_pa_export.md
//
// php utils/develop/sase/scm/scm_pa_export.php in=scm-api://<TSG_ID> [area=infra,remote-networks,service-connections] [outdir=export] [egressip] [egressip-env=prod|prod6] [psk-list] [master-key=...] [debugapi]

require_once("lib/pan_php_framework.php");
require_once("utils/lib/UTIL.php");
require_once(dirname(__FILE__) . "/lib/SCMPrismaAccessExport.php");

PH::print_stdout();
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout();

PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );

$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'SCM tenant. ie: in=scm-api://<TSG_ID>', 'argDesc' => 'scm-api://[TSG_ID]');
$supportedArguments['area'] = Array('niceName' => 'area', 'shortHelp' => 'comma separated areas to export: ' . implode(",", SCMPrismaAccessExport::AREAS) . ' (default: all)', 'argDesc' => '[area1,area2]');
$supportedArguments['outdir'] = Array('niceName' => 'outdir', 'shortHelp' => 'base directory for the export; files go to <outdir>/<TSG_ID>/<timestamp>/ (default: export)', 'argDesc' => '[directory]');
$supportedArguments['folder'] = Array('niceName' => 'folder', 'shortHelp' => 'SCM folder for the Remote Network IKE/IPsec objects (default: "Remote Networks")', 'argDesc' => '[folder]');
$supportedArguments['sc-folder'] = Array('niceName' => 'sc-folder', 'shortHelp' => 'SCM folder for the Service Connection IKE/IPsec/QoS objects (default: "Service Connections")', 'argDesc' => '[folder]');
$supportedArguments['egressip'] = Array('niceName' => 'egressip', 'shortHelp' => 'also download the egress IPs via the Prisma Access egress-IP API (API key from .panconfkeystore egressip_tsg_id<TSG_ID>, else api_key of shared-infrastructure-settings, else asked for)');
$supportedArguments['egressip-env'] = Array('niceName' => 'egressip-env', 'shortHelp' => 'egress-IP API host: prod (api.prod.datapath.prismaaccess.com, default) | prod6 (api.prod6.datapath.prismaaccess.com)', 'argDesc' => 'prod|prod6');
$supportedArguments['psk-list'] = Array('niceName' => 'psk-list', 'shortHelp' => 'per remote-networks / service-connections area: write psk-list.csv and bgp-secret-list.csv (chmod 600) with the decrypted current value and an empty *_new column for the import');
$supportedArguments['master-key'] = Array('niceName' => 'master-key', 'shortHelp' => 'master key to decrypt PSKs and BGP secrets (default: PAN-OS default master key)', 'argDesc' => '[master-key]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');

$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=scm-api://<TSG_ID> [area=infra,remote-networks,service-connections] [outdir=export] [egressip] [egressip-env=prod|prod6] [psk-list] [master-key=...]\n".
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

//$defaultArea can be set by a wrapper script (scm_rn_export.php)
$areaArg = isset(PH::$args['area']) ? PH::$args['area'] : ( isset($defaultArea) ? $defaultArea : implode(",", SCMPrismaAccessExport::AREAS) );
$areas = array_values( array_filter( array_map('trim', explode(",", $areaArg)) ) );

$outdir = isset(PH::$args['outdir']) ? PH::$args['outdir'] : "export";
$folder = isset(PH::$args['folder']) ? PH::$args['folder'] : "Remote Networks";
$egressEnv = isset(PH::$args['egressip-env']) ? PH::$args['egressip-env'] : "prod";
if( $egressEnv !== "prod" && $egressEnv !== "prod6" )
    derr( "egressip-env must be 'prod' or 'prod6'", null, FALSE );

########################################################################################################################

$export = new SCMPrismaAccessExport( $connector, $tsg, $outdir, $folder, $areas );
if( isset(PH::$args['sc-folder']) && PH::$args['sc-folder'] !== "" )
    $export->folders[SCMPrismaAccessExport::AREA_SC] = PH::$args['sc-folder'];
$dir = $export->prepareDirectory();

PH::print_stdout();
PH::print_stdout( " * TSG: " . $tsg );
PH::print_stdout( " * areas: " . implode(", ", $export->areas) );
PH::print_stdout( " * export directory: " . $dir );
PH::print_stdout();

$export->exportEndpoints();

$egressKey = null;
if( isset(PH::$args['egressip']) )
{
    //1) .panconfkeystore  2) api_key of shared-infrastructure-settings (only if exported)  3) ask + store
    $egressKey = $connector->getEgressIPApiKey( $tsg, FALSE );
    if( $egressKey === null && $export->getSecret('shared-infrastructure-settings.api_key') !== null )
    {
        $egressKey = $export->getSecret('shared-infrastructure-settings.api_key');
        PH::print_stdout( " * egress-IP API key: using api_key of shared-infrastructure-settings (not stored)" );
    }
    if( $egressKey === null )
        $egressKey = $connector->getEgressIPApiKey( $tsg, TRUE );
}
$export->exportEgressIP( $egressKey, $egressEnv );

$mappings = array();
$secretStats = array();
$masterKey = ( isset(PH::$args['master-key']) && PH::$args['master-key'] !== "" ) ? PH::$args['master-key'] : null;
foreach( $export->connectionAreas() as $area )
{
    $mappings[$area] = $export->buildIPMapping( $area );

    if( isset(PH::$args['psk-list']) )
    {
        $psk = $export->writePSKList( $masterKey, $area );
        $bgp = $export->writeBGPSecretList( $masterKey, $area );
        $secretStats[$area] = array( 'psk' => $psk, 'bgp_secret' => $bgp );
        PH::print_stdout( " * " . $area . "/psk-list.csv: " . $psk['gateways'] . " gateway(s), decrypted: " . $psk['decrypted'] . ", failed: " . $psk['decrypt_failed'] );
        PH::print_stdout( " * " . $area . "/bgp-secret-list.csv: " . $bgp['secrets'] . " secret(s), decrypted: " . $bgp['decrypted'] . ", failed: " . $bgp['decrypt_failed'] );
    }
}
if( count($secretStats) > 0 )
    PH::print_stdout( PH::boldText("   ! psk-list.csv / bgp-secret-list.csv contain cleartext secrets - keep them out of tickets / git") );

$manifest = $export->writeManifest( PH::frameworkVersion(), $mappings, $secretStats );

########################################################################################################################

PH::print_stdout();
if( $manifest['infra'] !== null )
    PH::print_stdout( " * infra: subnet " . json_encode($manifest['infra']['infrastructure_subnet']) . " | AS " . json_encode($manifest['infra']['infra_bgp_as']) . " | internal DNS servers: " . count($manifest['infra']['internal_dns_servers']) );
if( isset($manifest['ip_mapping'][SCMPrismaAccessExport::AREA_RN]) )
    PH::print_stdout( " * remote networks: " . $manifest['ip_mapping'][SCMPrismaAccessExport::AREA_RN]['remote_networks'] . " | egress IPs matched: " . $manifest['ip_mapping'][SCMPrismaAccessExport::AREA_RN]['egress_matched'] );
if( isset($manifest['ip_mapping'][SCMPrismaAccessExport::AREA_SC]) )
    PH::print_stdout( " * service connections: " . $manifest['ip_mapping'][SCMPrismaAccessExport::AREA_SC]['service_connections'] );
foreach( $manifest['import_hints'] as $hint )
    PH::print_stdout( " ! [" . $hint['area'] . "] " . $hint['type'] . ": " . count($hint['objects']) . " object(s) - " . $hint['message'] );
if( $manifest['errors'] > 0 )
    PH::print_stdout( PH::boldText(" x " . $manifest['errors'] . " endpoint(s) failed - see manifest.json") );
PH::print_stdout( " * done: " . $dir );

PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
########################################################################################################################
