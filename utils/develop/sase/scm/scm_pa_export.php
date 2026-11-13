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

// Export Prisma Access configuration of one tenant (TSG): infrastructure, Remote Networks (RN / RN-SPN), Service Connections (SC-CAN),
// Mobile Users (GlobalProtect), Prisma Browser, IAM (documentation), config (folders / snippets, objects, security) + migration checklist
// see utils/develop/sase/scm/README_pa_export.md
//
// php utils/develop/sase/scm/scm_pa_export.php in=scm-api://<TSG_ID> [area=infra,config,remote-networks,service-connections,mobile-users,explicit-proxy,prisma-browser,iam] [outdir=export] [egressip] [egressip-env=prod|prod6] [psk-list] [master-key=...] [debugapi]

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
$supportedArguments['mu-folder'] = Array('niceName' => 'mu-folder', 'shortHelp' => 'SCM folder for the Mobile Users identity / mobile-agent objects (default: "Mobile Users")', 'argDesc' => '[folder]');
$supportedArguments['container'] = Array('niceName' => 'container', 'shortHelp' => 'config area: comma separated folder / snippet names to export (default: all containers; the hierarchy is always exported)', 'argDesc' => '[name1,name2]');
$supportedArguments['config-types'] = Array('niceName' => 'config-types', 'shortHelp' => 'config area: comma separated object types, e.g. addresses,security-rules (default: all)', 'argDesc' => '[type1,type2]');
$supportedArguments['config-scope'] = Array('niceName' => 'config-scope', 'shortHelp' => 'config area: comma separated groups ' . implode(",", SCMPrismaAccessExport::CONFIG_GROUPS) . ' (default: all)', 'argDesc' => '[group1,group2]');
$supportedArguments['config-mode'] = Array('niceName' => 'config-mode', 'shortHelp' => 'config area: leaf (default, query only the deepest folders - their answers contain the parent objects) | all (query every container, slower; for verification)', 'argDesc' => 'leaf|all');
$supportedArguments['config-devices'] = Array('niceName' => 'config-devices', 'shortHelp' => 'config area: also export device folders (type cloud / on-prem)');
$supportedArguments['config-parallel'] = Array('niceName' => 'config-parallel', 'shortHelp' => 'config area: concurrent API requests (default 8, 1 = sequential)', 'argDesc' => 'N');
$supportedArguments['config-page-size'] = Array('niceName' => 'config-page-size', 'shortHelp' => 'config area: entries per API page (default 1000; the server may cap it)', 'argDesc' => 'N');
$supportedArguments['config-heavy-types'] = Array('niceName' => 'config-heavy-types', 'shortHelp' => 'config area: also export types whose answers contain the whole predefined catalog per folder (applications) - very slow');
$supportedArguments['config-predefined-snippets'] = Array('niceName' => 'config-predefined-snippets', 'shortHelp' => 'config area: also export predefined snippets (large)');
$supportedArguments['ui-api-host'] = Array('niceName' => 'ui-api-host', 'shortHelp' => 'explicit-proxy area: internal UI API host of the tenant region (default ' . SCMPrismaAccessExport::UI_API_HOST_DEFAULT . ', see browser developer tools: requests to /api/config/v9.2/...)', 'argDesc' => '[host]');
$supportedArguments['egressip'] = Array('niceName' => 'egressip', 'shortHelp' => 'also download the egress IPs via the Prisma Access egress-IP API (API key from .panconfkeystore egressip_tsg_id<TSG_ID>, else api_key of shared-infrastructure-settings, else asked for)');
$supportedArguments['egressip-env'] = Array('niceName' => 'egressip-env', 'shortHelp' => 'egress-IP API host: prod (api.prod.datapath.prismaaccess.com, default) | prod6 (api.prod6.datapath.prismaaccess.com)', 'argDesc' => 'prod|prod6');
$supportedArguments['psk-list'] = Array('niceName' => 'psk-list', 'shortHelp' => 'write the secret lists (chmod 600) with the decrypted current value and an empty *_new column for the import: psk-list.csv + bgp-secret-list.csv (remote-networks, service-connections), secret-list.csv (mobile-users)');
$supportedArguments['master-key'] = Array('niceName' => 'master-key', 'shortHelp' => 'master key to decrypt PSKs and BGP secrets (default: PAN-OS default master key)', 'argDesc' => '[master-key]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');

$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=scm-api://<TSG_ID> [area=infra,config,remote-networks,service-connections,mobile-users,explicit-proxy,prisma-browser,iam] [outdir=export] [egressip] [egressip-env=prod|prod6] [psk-list] [master-key=...]\n".
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
if( isset(PH::$args['mu-folder']) && PH::$args['mu-folder'] !== "" )
    $export->folders[SCMPrismaAccessExport::AREA_MU] = PH::$args['mu-folder'];

$listArg = function( $name ){
    if( !isset(PH::$args[$name]) || PH::$args[$name] === "" )
        return null;
    return array_values( array_filter( array_map('trim', explode(",", PH::$args[$name])) ) );
};
$export->configOptions = array(
    'containers' => $listArg('container'),
    'types' => $listArg('config-types'),
    'scope' => $listArg('config-scope'),
    'mode' => isset(PH::$args['config-mode']) ? PH::$args['config-mode'] : 'leaf',
    'devices' => isset(PH::$args['config-devices']),
    'predefined_snippets' => isset(PH::$args['config-predefined-snippets']),
    'heavy_types' => isset(PH::$args['config-heavy-types']),
    'parallel' => isset(PH::$args['config-parallel']) ? (int)PH::$args['config-parallel'] : 8,
    'page_size' => isset(PH::$args['config-page-size']) ? (int)PH::$args['config-page-size'] : 1000,
);
if( !in_array($export->configOptions['mode'], array('leaf', 'all'), TRUE) )
    derr( "config-mode must be leaf or all", null, FALSE );
if( $export->configOptions['scope'] !== null )
    foreach( $export->configOptions['scope'] as $g )
        if( !in_array($g, SCMPrismaAccessExport::CONFIG_GROUPS, TRUE) )
            derr( "config-scope: unknown group '" . $g . "' - supported: " . implode(",", SCMPrismaAccessExport::CONFIG_GROUPS), null, FALSE );
if( $export->configOptions['types'] !== null )
{
    $known = array_map( function($t){ return $t['name']; }, SCMPrismaAccessExport::getConfigTypes() );
    foreach( $export->configOptions['types'] as $t )
        if( !in_array($t, $known, TRUE) )
            derr( "config-types: unknown type '" . $t . "' - supported: " . implode(",", $known), null, FALSE );
}
if( isset(PH::$args['ui-api-host']) && PH::$args['ui-api-host'] !== "" )
    $export->uiApiHost = preg_replace( '#^https?://#', '', rtrim(PH::$args['ui-api-host'], "/") );
$dir = $export->prepareDirectory();

PH::print_stdout();
PH::print_stdout( " * TSG: " . $tsg );
PH::print_stdout( " * areas: " . implode(", ", $export->areas) );
PH::print_stdout( " * export directory: " . $dir );
PH::print_stdout();

$export->exportEndpoints();
if( $export->hasArea(SCMPrismaAccessExport::AREA_CONFIG) )
    $export->exportConfig();

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
//egress IPs belong to infra: no "skipped" entry for exports without infra unless egressip was requested
if( $export->hasArea(SCMPrismaAccessExport::AREA_INFRA) || isset(PH::$args['egressip']) )
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
if( $export->hasArea(SCMPrismaAccessExport::AREA_MU) )
{
    $mappings[SCMPrismaAccessExport::AREA_MU] = $export->buildMobileUsersMapping();
    if( isset(PH::$args['psk-list']) )
    {
        $sec = $export->writeSecretList( SCMPrismaAccessExport::AREA_MU, $masterKey );
        $secretStats[SCMPrismaAccessExport::AREA_MU] = array( 'secret' => $sec );
        PH::print_stdout( " * " . SCMPrismaAccessExport::AREA_MU . "/secret-list.csv: " . $sec['secrets'] . " secret(s), decrypted: " . $sec['decrypted'] . ", failed: " . $sec['decrypt_failed'] . ", hashed: " . $sec['hashed'] );
    }
}
if( count($secretStats) > 0 )
    PH::print_stdout( PH::boldText("   ! psk-list.csv / bgp-secret-list.csv / secret-list.csv contain cleartext secrets - keep them out of tickets / git") );

$manifest = $export->writeManifest( PH::frameworkVersion(), $mappings, $secretStats );

########################################################################################################################

PH::print_stdout();
if( $manifest['infra'] !== null )
    PH::print_stdout( " * infra: subnet " . json_encode($manifest['infra']['infrastructure_subnet']) . " | AS " . json_encode($manifest['infra']['infra_bgp_as']) . " | internal DNS servers: " . count($manifest['infra']['internal_dns_servers']) );
if( isset($manifest['ip_mapping'][SCMPrismaAccessExport::AREA_RN]) )
    PH::print_stdout( " * remote networks: " . $manifest['ip_mapping'][SCMPrismaAccessExport::AREA_RN]['remote_networks'] . " | egress IPs matched: " . $manifest['ip_mapping'][SCMPrismaAccessExport::AREA_RN]['egress_matched'] );
if( isset($manifest['ip_mapping'][SCMPrismaAccessExport::AREA_SC]) )
    PH::print_stdout( " * service connections: " . $manifest['ip_mapping'][SCMPrismaAccessExport::AREA_SC]['service_connections'] );
if( $manifest['mobile_users'] !== null )
    PH::print_stdout( " * mobile users: portal " . json_encode($manifest['mobile_users']['portal_hostname']) . " | MU locations: " . $manifest['ip_mapping'][SCMPrismaAccessExport::AREA_MU]['locations'] . " | egress IPs matched: " . $manifest['ip_mapping'][SCMPrismaAccessExport::AREA_MU]['egress_matched'] );
foreach( $manifest['import_hints'] as $hint )
    PH::print_stdout( " ! [" . $hint['area'] . "] " . $hint['type'] . ": " . ( isset($hint['total']) ? $hint['total'] . " object(s) of " . count($hint['objects']) . " owner(s) / type(s)" : count($hint['objects']) . " object(s)" ) . " - " . $hint['message'] );
if( $manifest['config'] !== null )
    PH::print_stdout( " * config: " . $manifest['config']['folders'] . " folder(s), " . $manifest['config']['snippets'] . " snippet(s), "
        . count($manifest['config']['containers_exported']) . " container(s) exported, " . array_sum($manifest['config']['owned_objects_by_type']) . " owned object(s) - see config/hierarchy.txt" );
if( $manifest['config'] !== null && $manifest['config']['devices'] !== null )
    PH::print_stdout( " * devices: " . $manifest['config']['devices']['total'] . " (connected " . $manifest['config']['devices']['connected']
        . ", not connected " . count($manifest['config']['devices']['disconnected']) . ", HA pairs " . count($manifest['config']['devices']['ha_pairs']) . ") - see config/devices.csv" );
if( $manifest['prisma_browser'] !== null )
    PH::print_stdout( " * prisma browser: user groups " . $manifest['prisma_browser']['user_groups'] . " | applications " . $manifest['prisma_browser']['applications'] . " | pending changes " . $manifest['prisma_browser']['pending_changes'] );
if( $manifest['iam'] !== null )
    PH::print_stdout( " * iam: access policies " . $manifest['iam']['access_policies'] . " | custom roles " . count($manifest['iam']['custom_roles']) . " | service accounts " . count($manifest['iam']['service_accounts']) );
if( count($manifest['unavailable']) > 0 )
    PH::print_stdout( " - not available (licence / permission): " . implode(", ", $manifest['unavailable']) );
$actions = array_filter( $manifest['migration_checklist'], function($i){ return $i['status'] == 'action_required'; } );
PH::print_stdout( " * MIGRATION_CHECKLIST.md: " . count($actions) . " action(s) required, " . count($manifest['migration_checklist']) . " item(s)" );
if( $manifest['errors'] > 0 )
    PH::print_stdout( PH::boldText(" x " . $manifest['errors'] . " endpoint(s) failed - see manifest.json") );
PH::print_stdout( " * done: " . $dir );

PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
########################################################################################################################
