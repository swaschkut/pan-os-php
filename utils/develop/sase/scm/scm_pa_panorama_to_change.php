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

// Panorama configuration (XML, offline) -> change request JSON for scm_pa_change.php
//   shared -> folder All, device-groups -> folders below ngfw-shared (hierarchy kept), templates / template-stacks ->
//   snippets, attached to the device-group folders (stack, then its templates - from the firewalls of the device-group);
//   firewalls themselves come later. Translation XML -> SCM API fields: SCMImporter + SCMChangeGenerator (type=scm-import).
// see utils/develop/sase/scm/README_pa_panorama_import.md
//
// php utils/develop/sase/scm/scm_pa_panorama_to_change.php in=panorama.xml out=change.json
//     [dg-parent=ngfw-shared] [device-group=DG1,DG2] [shared=all|folder|skip] [no-templates] [no-rules] [no-zones]

set_include_path(dirname(__FILE__) . '/../../../../' . PATH_SEPARATOR . get_include_path());
require_once("lib/pan_php_framework.php");
require_once("utils/lib/UTIL.php");
require_once(dirname(__FILE__) . "/lib/SCMPrismaAccessExport.php");
if( !class_exists("SCMCHANGES") )
    require_once("utils/lib/SCMCHANGES.php");

$usage = "USAGE: php " . basename(__FILE__) . " in=panorama.xml out=change.json [dg-parent=ngfw-shared] [device-group=DG1,DG2] [shared=all|folder|skip] [no-templates] [no-rules] [no-zones] [cloud-appid-api=URL]\n"
    . "  in            Panorama configuration (XML file)\n"
    . "  out           change request for scm_pa_change.php\n"
    . "  dg-parent     folder that holds the device-group tree: ngfw-shared (default, 'All Firewalls')\n"
    . "                or a folder below it (lab); SCM allows max. 4 folder levels below ngfw-shared, as Panorama max. 4\n"
    . "                device-group levels below shared - a dg-parent folder takes levels from the device-group tree\n"
    . "  device-group  only these device-groups (and their parents)\n"
    . "  shared        Panorama shared: 'all' (default, folder All - also visible to the snippets of the templates),\n"
    . "                'folder' (into dg-parent) or 'skip'\n"
    . "  no-templates  device-groups only: no snippets of templates / template-stacks\n"
    . "  no-rules      objects only, no security rules (rules reference custom applications that are not imported)\n"
    . "  cloud-appid-api  cloud App-ID API helper to check SaaS applications (github.com/swaschkut/pan-os_cloud-appid-API-helper):\n"
    . "                'auto' (default): http://localhost:8080 / http://host.docker.internal:8080; not reachable -> the\n"
    . "                container is started with docker (docker start / docker run -d -p 8080:80 --name\n"
    . "                panos_cloud-appid_mock swaschkut/pan-os_cloud-appid_api-helper); URL: this helper; 'off': only the\n"
    . "                list lib/object-classes/cloud-appid/cloud-appid.txt\n"
    . "  no-zones      do not create zones for the rules (default: a zone used by the rules of a device-group that is not\n"
    . "                in an attached snippet / parent folder is created in its folder - definition from the templates)\n"
;

$args = array();
foreach( array_slice($argv, 1) as $a )
{
    $p = strpos($a, "=");
    $args[strtolower($p === false ? $a : substr($a, 0, $p))] = $p === false ? true : substr($a, $p + 1);
}
foreach( array_keys($args) as $a )
    if( !in_array($a, array('in', 'out', 'dg-parent', 'device-group', 'shared', 'no-templates', 'no-rules', 'no-zones', 'cloud-appid-api', 'help'), TRUE) )
    {
        print "unknown argument '" . $a . "'\n\n" . $usage;
        exit(1);
    }
if( isset($args['help']) || !isset($args['in']) || !isset($args['out']) || $args['in'] === true || $args['out'] === true )
{
    print $usage;
    exit( isset($args['help']) ? 0 : 1 );
}
$shared = isset($args['shared']) ? $args['shared'] : 'all';
if( !in_array($shared, array('all', 'folder', 'skip'), TRUE) )
    derr( "shared= must be 'all', 'folder' or 'skip'", null, FALSE );
$dgParent = isset($args['dg-parent']) && $args['dg-parent'] !== true ? $args['dg-parent'] : SCMImporter::FIREWALL_FOLDER;

PH::print_stdout();
PH::print_stdout("*********** " . basename(__FILE__) . " **************");
PH::print_stdout( "PAN-OS-PHP version: " . PH::frameworkVersion() );

if( !is_readable($args['in']) )
    derr( "file '" . $args['in'] . "' not readable", null, FALSE );
$srcDoc = new DOMDocument();
if( !$srcDoc->load($args['in'], XML_PARSE_BIG_LINES) )
    derr( "error while reading xml file '" . $args['in'] . "'", null, FALSE );
if( (new DOMXPath($srcDoc))->query("/config/devices/entry/device-group")->length == 0 )
    derr( "'" . $args['in'] . "' is not a Panorama configuration with device-groups", null, FALSE );

// 1) XML -> SCM XML: device-groups below dg-parent (empty SCM base configuration: everything is "new")
$baseFile = dirname(__FILE__) . "/../../buckbeak_baseconfig.xml";
$scmDoc = new DOMDocument();
$scmDoc->load( $baseFile, XML_PARSE_BIG_LINES );
$scm = new BuckbeakConf();
$scm->load_from_domxml( $scmDoc );
$pano = new PanoramaConf();
$pano->load_from_domxml( $srcDoc );

$importer = new SCMImporter( $scm );
$importer->panoramaScope = isset($args['no-templates']) ? 'device-groups' : 'templates';
$importer->dgParentFolder = $dgParent;
$importer->zonesFromRules = !isset($args['no-rules']) && !isset($args['no-zones']);
// SCM: rules take profile groups only, antivirus + WildFire combined, DNS security separate from spyware
$importer->scmProfiles = TRUE;
$importer->customApplicationsElsewhere = TRUE;
// zones of the templates reference the interface variables created below ($ethernet1_1 …)
$importer->interfaceVariables = !isset($args['no-templates']);
if( isset($args['device-group']) && $args['device-group'] !== true )
    $importer->deviceGroupFilter = array_values( array_filter( array_map('trim', explode(",", $args['device-group'])) ) );
$importer->importPanorama( $pano, $shared == 'all' ? 'global' : $shared );

if( count($importer->depthErrors) > 0 )
{
    PH::print_stdout();
    foreach( $importer->depthErrors as $e )
        PH::print_stdout( " x " . $e );
    derr( "the device-group hierarchy does not fit below '" . $dgParent . "' (SCM: max. " . SCMImporter::MAX_FOLDER_DEPTH
        . " folder levels below " . SCMImporter::FIREWALL_FOLDER . ", as Panorama: max. 4 device-group levels below shared)"
        . ( $dgParent !== SCMImporter::FIREWALL_FOLDER ? " - use dg-parent=" . SCMImporter::FIREWALL_FOLDER : "" ), null, FALSE );
}

$tmp = tempnam( sys_get_temp_dir(), "scm-import-" );
ob_start();
$scm->save_to_file( $tmp );
ob_end_clean();

// 2) SCM XML -> SCM API requests (bodies in SCM field names)
ob_start();
$json = SCMCHANGES::generate( $baseFile, $tmp );
ob_end_clean();
unlink( $tmp );
$gen = json_decode( $json, TRUE );

// 3) requests -> change request for scm_pa_change.php
$known = array();
foreach( SCMPrismaAccessExport::getConfigTypes() as $t )
    $known[$t['name']] = $t;

$change = array(
    'format' => 'pan-os-php-scm-change-request',
    'description' => "Panorama " . basename($args['in']) . ": device-groups below '" . $dgParent . "'"
        . ( $importer->panoramaScope == 'templates' ? ", templates / template-stacks as snippets" : "" ),
    'source' => array( 'file' => basename($args['in']), 'created_at' => date('c'), 'tool' => basename(__FILE__) . " " . PH::frameworkVersion(),
        'dg_parent' => $dgParent, 'shared' => $shared, 'scope' => $importer->panoramaScope, 'summary' => $importer->summary ),
    'snippets' => array(),
    'folders' => array(),
);
$supportedOther = array( 'zones', 'zone-protection-profiles' );
$notImported = array();
$counts = array();
$folderIdx = array();
foreach( $gen['requests'] as $r )
{
    $obj = $r['object'];
    $resource = $obj['resource'];
    $body = is_array($r['body']) ? $r['body'] : array();

    if( $resource == 'snippets' )
    {
        if( $r['method'] == 'POST' )
            $change['snippets'][] = array( 'name' => $body['name'] );
        continue;
    }
    if( $resource == 'folders' )
    {
        $name = $r['method'] == 'POST' ? $body['name'] : $obj['name'];
        if( $r['method'] == 'POST' && $name !== SCMImporter::FIREWALL_FOLDER )
        {
            $folderIdx[$name] = count($change['folders']);
            $change['folders'][] = array( 'name' => $name, 'parent' => $body['parent'] ) + ( isset($body['snippets']) ? array( 'snippets' => $body['snippets'] ) : array() );
        }
        elseif( $r['method'] == 'PUT' && isset($folderIdx[$name]) && isset($body['snippets']) )
            $change['folders'][ $folderIdx[$name] ]['snippets'] = $body['snippets'];
        elseif( $r['method'] == 'PUT' )
            $notImported[] = array( 'type' => 'folders', 'name' => $name, 'reasons' => array( "change of an existing folder: " . json_encode($body) ) );
        continue;
    }
    if( $resource == 'devices' )
        continue;
    if( isset($args['no-rules']) && isset($known[$resource]) && $known[$resource]['group'] == 'policies' )
    {
        $counts['(no-rules) ' . $resource] = ( isset($counts['(no-rules) ' . $resource]) ? $counts['(no-rules) ' . $resource] : 0 ) + 1;
        continue;
    }
    $scopeKey = $obj['scope_type'] == 'snippet' ? 'snippet' : 'folder';
    $entry = array( 'type' => $resource, 'name' => $obj['name'], $scopeKey => $obj['scope'], 'position' => $obj['position'] );
    $supported = isset($known[$resource]) && ( in_array($known[$resource]['group'], array('objects', 'identity', 'policies'), TRUE) || in_array($resource, $supportedOther, TRUE) );
    if( $r['method'] !== 'POST' || $r['review'] || !$supported || !in_array($obj['scope_type'], array('folder', 'snippet'), TRUE) )
    {
        $reasons = $r['review'] ? $r['warnings'] : array( $r['method'] !== 'POST' ? $r['method'] . " request" : ( !$supported ? "type not supported by scm_pa_change.php" : "scope " . $obj['scope_type'] ) );
        $notImported[] = array_filter( $entry, function($v){ return $v !== null; } ) + array( 'reasons' => $reasons );
        continue;
    }
    $item = array( $scopeKey => $obj['scope'], 'name' => $obj['name'] );
    if( !empty($known[$resource]['position']) && $scopeKey == 'folder' )
        $item['position'] = $obj['position'] !== null ? $obj['position'] : 'pre';
    foreach( $body as $k => $v )
        if( !in_array($k, array('folder', 'snippet', 'device', 'name', 'id'), TRUE) )
            $item[$k] = $v;
    $change[$resource][] = $item;
    $counts[$resource] = ( isset($counts[$resource]) ? $counts[$resource] : 0 ) + 1;
}
if( count($change['snippets']) == 0 )
    unset( $change['snippets'] );
$warnings = $importer->warnings;
if( count($importer->groupTags) > 0 )
    $warnings[] = "rule group tags (display grouping, no SCM field) removed: " . implode(", ", array_keys($importer->groupTags));
// custom applications: rules refer to them - created as in Panorama (category … characteristics, default ports /
// IP protocol / ICMP type + code, timeouts, parent app); what is not taken yet (signatures) -> placeholders list
$appScopes = array();
if( $shared !== 'skip' && ($sh = DH::findFirstElement('shared', $pano->xmlroot)) !== FALSE )
    $appScopes[] = array( $shared == 'all' ? 'All' : $dgParent, $sh );
$dgFolderNames = array_map( function($f){ return $f['name']; }, $change['folders'] );
foreach( $pano->deviceGroups as $dg )
    if( in_array($dg->name(), $dgFolderNames, TRUE) )
        $appScopes[] = array( $dg->name(), $dg->xmlroot );
$appFlags = array( 'evasive-behavior' => 'evasive', 'consume-big-bandwidth' => 'excessive_bandwidth_use', 'used-by-malware' => 'used_by_malware',
    'able-to-transfer-file' => 'transfers_files', 'has-known-vulnerability' => 'has_known_vulnerabilities', 'tunnel-other-application' => 'tunnels_other_apps',
    'prone-to-misuse' => 'prone_to_misuse', 'pervasive-use' => 'pervasive' );
$appPlaceholders = array();
$warningsApps = array();
$predefinedApps = AppStore::getPredefinedStore( $pano );
$xpa = new DOMXPath($pano->xmldoc);
foreach( $appScopes as $as )
    foreach( $xpa->query("application/entry", $as[1]) as $app )
    {
        // only applications that are not PAN-OS predefined (they exist in SCM)
        if( $predefinedApps->find($app->getAttribute('name'), null, false) !== null )
        {
            $warningsApps[] = "custom application '" . $app->getAttribute('name') . "' (" . $as[0] . ") has the name of a PAN-OS predefined application - not created, SCM uses the predefined one";
            continue;
        }
        $item = array( 'folder' => $as[0], 'name' => $app->getAttribute('name') );
        $missing = array();
        foreach( $app->childNodes as $c )
        {
            if( $c->nodeType != XML_ELEMENT_NODE )
                continue;
            $t = trim($c->textContent);
            if( in_array($c->tagName, array('category', 'subcategory', 'technology', 'description'), TRUE) )
                $item[$c->tagName] = $t;
            elseif( $c->tagName == 'risk' )
                $item['risk'] = (int)$t;
            elseif( isset($appFlags[$c->tagName]) )
                $item[$appFlags[$c->tagName]] = $t == 'yes';
            elseif( $c->tagName == 'default' )
            {
                // identification without signature: ports, IP protocol, ICMP / ICMPv6 type + code
                $def = array();
                foreach( $c->childNodes as $d )
                {
                    if( $d->nodeType != XML_ELEMENT_NODE )
                        continue;
                    if( $d->tagName == 'port' )
                    {
                        $ports = array();
                        foreach( $d->getElementsByTagName('member') as $m )
                            $ports[] = trim($m->textContent);
                        $def['port'] = $ports;
                    }
                    elseif( $d->tagName == 'ident-by-ip-protocol' )
                        $def['ident_by_ip_protocol'] = trim($d->textContent);
                    elseif( $d->tagName == 'ident-by-icmp-type' || $d->tagName == 'ident-by-icmp6-type' )
                    {
                        $ic = array();
                        foreach( array('type', 'code') as $k )
                            if( ($v = DH::findFirstElement($k, $d)) !== FALSE && trim($v->textContent) !== '' )
                                $ic[$k] = trim($v->textContent);
                        $def[str_replace('-', '_', $d->tagName)] = $ic;
                    }
                    else
                        $missing[] = 'default/' . $d->tagName;
                }
                if( count($def) > 0 )
                    $item['default'] = $def;
            }
            elseif( in_array($c->tagName, array('timeout', 'tcp-timeout', 'udp-timeout', 'tcp-half-closed-timeout', 'tcp-time-wait-timeout'), TRUE) )
                $item[str_replace('-', '_', $c->tagName)] = (int)$t;
            elseif( $c->tagName == 'parent-app' )
                $item['parent_app'] = $t;
            elseif( in_array($c->tagName, array('alg-disable-capability'), TRUE) )
                $item['alg_disable_capability'] = $t;
            elseif( in_array($c->tagName, array('no-appid-caching', 'file-type-ident', 'virus-ident', 'data-ident'), TRUE) )
                $item[str_replace('-', '_', $c->tagName)] = $t == 'yes';
            else
                $missing[] = $c->tagName;
        }
        $change['applications'][] = $item;
        $counts['applications'] = ( isset($counts['applications']) ? $counts['applications'] : 0 ) + 1;
        // what the SCM applications API cannot take yet (e.g. signatures): listed, the application is created anyway
        if( count($missing) > 0 )
            $appPlaceholders[] = array( 'type' => 'applications', 'name' => $item['name'], 'folder' => $as[0],
                'content' => array( "custom application created without: " . implode(", ", $missing) . " (application identification not complete)" ) );
    }

// interfaces of the templates / template-stacks -> SCM interface variables in the snippet ($ethernet1_1, sub interfaces
// $ethernet1_2.1, tunnel $tunnel-1 …), IP addresses included. No default_value: SCM keeps it unique in the tenant
// (live: "'ethernet1/3' is already in use") and the value is set per firewall (DeviceOnPrem, later step) - the
// Panorama interface of each variable is listed in 'interface_variables' of the change file (not sent).
// Interface management profiles of the template as well.
$ifIncomplete = array();
$ifVariables = array();        // [snippet, variable, interface]
$ifCreated = array();          // snippet => [variable => true]
/** text leaves of a node are only "no" / "disable" / empty: PAN-OS defaults, nothing lost */
function onlyDefaults( DOMElement $n )
{
    foreach( $n->getElementsByTagName('*') as $c )
    {
        $hasChild = FALSE;
        foreach( $c->childNodes as $cc )
            if( $cc->nodeType == XML_ELEMENT_NODE )
                $hasChild = TRUE;
        if( !$hasChild && !in_array( trim($c->textContent), array('', 'no', 'disable', 'disabled'), TRUE ) )
            return FALSE;
    }
    return TRUE;
}
/** layer3 settings of an interface / unit node: ip, mtu, management profile; unsupported children -> $missing */
function layer3Body( DOMElement $l3, array &$missing, array $skip = array() )
{
    $b = array();
    foreach( $l3->childNodes as $c )
    {
        if( $c->nodeType != XML_ELEMENT_NODE || in_array($c->tagName, $skip, TRUE) )
            continue;
        if( $c->tagName == 'ip' )
        {
            $ips = array();
            foreach( $c->childNodes as $e )
                if( $e->nodeType == XML_ELEMENT_NODE )
                    $ips[] = array( 'name' => $e->getAttribute('name') );
            if( count($ips) > 0 )
                $b['ip'] = $ips;
        }
        elseif( $c->tagName == 'mtu' )
            $b['mtu'] = (int)trim($c->textContent);
        elseif( $c->tagName == 'interface-management-profile' )
            $b['interface_management_profile'] = trim($c->textContent);
        elseif( $c->tagName == 'dhcp-client' )
            $b['dhcp_client'] = array( 'enable' => TRUE );
        elseif( $c->tagName == 'comment' || $c->tagName == 'tag' )
            continue;
        elseif( !onlyDefaults($c) )
            $missing[] = $c->tagName;
    }
    return $b;
}
$ifScopes = array();
if( $importer->panoramaScope == 'templates' )
{
    foreach( $pano->templates as $t )
        if( ($sn = $importer->snippetNameOf('template', $t->name())) !== null )
            $ifScopes[] = array( $sn, $t->xmlroot );
    foreach( $pano->templatestacks as $t )
        if( ($sn = $importer->snippetNameOf('stack', $t->name())) !== null )
            $ifScopes[] = array( $sn, $t->xmlroot );
}
$xpi = new DOMXPath($pano->xmldoc);
foreach( $ifScopes as $is )
{
    list($sn, $root) = $is;
    $base = "config/devices/entry/network/";
    foreach( $xpi->query($base . "profiles/interface-management-profile/entry", $root) as $p )
    {
        $item = array( 'snippet' => $sn, 'name' => $p->getAttribute('name') );
        foreach( $p->childNodes as $c )
        {
            if( $c->nodeType != XML_ELEMENT_NODE )
                continue;
            if( $c->tagName == 'permitted-ip' )
            {
                $item['permitted_ip'] = array();
                foreach( $c->childNodes as $e )
                    if( $e->nodeType == XML_ELEMENT_NODE )
                        $item['permitted_ip'][] = array( 'name' => $e->getAttribute('name') );
            }
            else
                $item[str_replace('-', '_', $c->tagName)] = trim($c->textContent) == 'yes';
        }
        $change['interface-management-profiles'][] = $item;
        $counts['interface-management-profiles'] = ( isset($counts['interface-management-profiles']) ? $counts['interface-management-profiles'] : 0 ) + 1;
    }
    $add = function( $type, $item, $missing, $panosName ) use( &$change, &$counts, &$ifIncomplete, &$ifCreated, &$ifVariables, $sn ){
        $change[$type][] = $item;
        $ifVariables[] = array( 'snippet' => $sn, 'variable' => $item['name'], 'interface' => $panosName );
        $counts[$type] = ( isset($counts[$type]) ? $counts[$type] : 0 ) + 1;
        $ifCreated[$sn][$item['name']] = TRUE;
        if( count($missing) > 0 )
            $ifIncomplete[] = array( 'type' => $type, 'name' => $item['name'], 'snippet' => $sn, 'missing' => array( "not imported: " . implode(", ", array_unique($missing)) ) );
    };
    foreach( $xpi->query($base . "interface/ethernet/entry", $root) as $eth )
    {
        $name = $eth->getAttribute('name');
        $item = array( 'snippet' => $sn, 'name' => SCMImporter::interfaceVariable($name) );
        $missing = array();
        $units = array();
        foreach( $eth->childNodes as $c )
        {
            if( $c->nodeType != XML_ELEMENT_NODE )
                continue;
            if( $c->tagName == 'comment' )
                $item['comment'] = trim($c->textContent);
            elseif( in_array($c->tagName, array('link-speed', 'link-duplex', 'link-state'), TRUE) )
                $item[str_replace('-', '_', $c->tagName)] = trim($c->textContent);
            elseif( $c->tagName == 'layer3' )
            {
                $item['layer3'] = layer3Body( $c, $missing, array('units') );
                foreach( $xpi->query("units/entry", $c) as $u )
                    $units[] = array( 'layer3', $u );
            }
            elseif( $c->tagName == 'layer2' )
            {
                $item['layer2'] = new stdClass();
                foreach( $xpi->query("units/entry", $c) as $u )
                    $units[] = array( 'layer2', $u );
            }
            elseif( $c->tagName == 'tap' )
                $item['tap'] = new stdClass();
            elseif( !onlyDefaults($c) )
                $missing[] = $c->tagName;
        }
        $add( 'ethernet-interfaces', $item, $missing, $name );
        foreach( $units as $uu )
        {
            list($mode, $u) = $uu;
            $uname = $u->getAttribute('name');
            $umissing = array();
            $tag = $xpi->query("tag", $u)->item(0);
            if( $mode == 'layer3' )
            {
                $sub = array( 'snippet' => $sn, 'name' => SCMImporter::interfaceVariable($uname), 'parent_interface' => $item['name'] )
                    + ( $tag !== null ? array( 'tag' => (int)trim($tag->textContent) ) : array() ) + layer3Body( $u, $umissing );
                if( ($cm = $xpi->query("comment", $u)->item(0)) !== null )
                    $sub['comment'] = trim($cm->textContent);
                $add( 'layer3-subinterfaces', $sub, $umissing, $uname );
            }
            else
            {
                $sub = array( 'snippet' => $sn, 'name' => SCMImporter::interfaceVariable($uname), 'parent_interface' => $item['name'] )
                    + ( $tag !== null ? array( 'vlan_tag' => trim($tag->textContent) ) : array() );
                $add( 'layer2-subinterfaces', $sub, $umissing, $uname );
            }
        }
    }
    foreach( array( 'tunnel' => 'tunnel-interfaces', 'loopback' => 'loopback-interfaces', 'vlan' => 'vlan-interfaces' ) as $tag => $type )
        foreach( $xpi->query($base . "interface/" . $tag . "/units/entry", $root) as $u )
        {
            $missing = array();
            $item = array( 'snippet' => $sn, 'name' => SCMImporter::interfaceVariable($u->getAttribute('name')) )
                + layer3Body( $u, $missing );
            if( ($cm = $xpi->query("comment", $u)->item(0)) !== null )
                $item['comment'] = trim($cm->textContent);
            $add( $type, $item, $missing, $u->getAttribute('name') );
        }
    foreach( array('aggregate-ethernet') as $tag )
        foreach( $xpi->query($base . "interface/" . $tag . "/entry", $root) as $ae )
            $ifIncomplete[] = array( 'type' => 'aggregate-interfaces', 'name' => SCMImporter::interfaceVariable($ae->getAttribute('name')), 'snippet' => $sn,
                'missing' => array( "aggregate interface not imported yet (template '" . $sn . "')" ) );
}
// zones that reference an interface variable not created above: placeholder ethernet interface (the reference stays)
$ifPlaceholders = array();
foreach( isset($change['zones']) ? $change['zones'] : array() as $z )
{
    if( !isset($z['snippet']) || !isset($z['network']) || !is_array($z['network']) )
        continue;
    foreach( $z['network'] as $mode => $members )
        if( is_array($members) && array_keys($members) === range(0, count($members) - 1) )
            foreach( $members as $m )
                if( is_string($m) && $m !== '' && $m[0] == '$' && !isset($ifCreated[$z['snippet']][$m]) )
                {
                    $change['ethernet-interfaces'][] = array( 'snippet' => $z['snippet'], 'name' => $m );
                    $counts['ethernet-interfaces'] = ( isset($counts['ethernet-interfaces']) ? $counts['ethernet-interfaces'] : 0 ) + 1;
                    $ifCreated[$z['snippet']][$m] = TRUE;
                    $ifPlaceholders[] = array( 'type' => 'ethernet-interfaces', 'name' => $m, 'snippet' => $z['snippet'],
                        'content' => array( "placeholder: interface used by zone '" . $z['name'] . "', not in the template - no configuration" ) );
                }
}

// application groups / filters
$filterMap = array( 'subcategory' => 'sub_category' );
foreach( $appScopes as $as )
{
    foreach( $xpa->query("application-group/entry", $as[1]) as $g )
    {
        $members = array();
        foreach( $xpa->query("members/member|member", $g) as $m )
            $members[] = trim($m->textContent);
        $change['application-groups'][] = array( 'folder' => $as[0], 'name' => $g->getAttribute('name'), 'members' => $members );
        $counts['application-groups'] = ( isset($counts['application-groups']) ? $counts['application-groups'] : 0 ) + 1;
    }
    foreach( $xpa->query("application-filter/entry", $as[1]) as $f )
    {
        $item = array( 'folder' => $as[0], 'name' => $f->getAttribute('name') );
        foreach( $f->childNodes as $c )
        {
            if( $c->nodeType != XML_ELEMENT_NODE )
                continue;
            $k = isset($filterMap[$c->tagName]) ? $filterMap[$c->tagName] : str_replace('-', '_', $c->tagName);
            $members = array();
            foreach( $c->childNodes as $m )
                if( $m->nodeType == XML_ELEMENT_NODE )
                    $members[] = trim($m->textContent);
            if( count($members) > 0 )
                $item[$k] = $k == 'risk' ? array_map('intval', $members) : $members;
            else
                $item[$k] = trim($c->textContent) == 'yes';
        }
        $change['application-filters'][] = $item;
        $counts['application-filters'] = ( isset($counts['application-filters']) ? $counts['application-filters'] : 0 ) + 1;
    }
}

// applications referenced by rules / application groups: custom (created above), application group / filter,
// PAN-OS predefined (predefined.xml incl. containers), cloud App-ID (SaaS: API helper or list) - else placeholder
$known = array();
foreach( array('applications', 'application-groups', 'application-filters') as $t )
    foreach( isset($change[$t]) ? $change[$t] : array() as $it )
        $known[$it['name']] = $t;
$refs = array();
foreach( isset($change['security-rules']) ? $change['security-rules'] : array() as $r )
    foreach( isset($r['application']) ? (array)$r['application'] : array() as $a )
        $refs[$a][] = array( $r['folder'], "rule '" . $r['name'] . "'" );
foreach( isset($change['application-groups']) ? $change['application-groups'] : array() as $g )
    foreach( $g['members'] as $a )
        $refs[$a][] = array( $g['folder'], "application group '" . $g['name'] . "'" );

/** GET without PHP warnings (the pan-os-php error handler stops on warnings); false if not reachable */
function httpGetQuiet( $url, $timeout = 5 )
{
    $ch = curl_init( $url );
    curl_setopt_array( $ch, array( CURLOPT_RETURNTRANSFER => TRUE, CURLOPT_CONNECTTIMEOUT => 3, CURLOPT_TIMEOUT => $timeout, CURLOPT_PROXY => '' ) );
    $r = curl_exec( $ch );
    $code = (int)curl_getinfo( $ch, CURLINFO_HTTP_CODE );
    return ( $r === false || $code < 200 || $code >= 300 ) ? false : $r;
}

/**
 * base URL of the cloud App-ID API helper; started with docker when it is not reachable (only when needed)
 * @return string|null
 */
function cloudAppidApi( array $args, array &$messages )
{
    static $base = false;
    if( $base !== false )
        return $base;
    $base = null;
    $mode = isset($args['cloud-appid-api']) && is_string($args['cloud-appid-api']) ? $args['cloud-appid-api'] : 'auto';
    if( $mode === 'off' )
        return null;
    $reachable = function( $url ){
        return httpGetQuiet( rtrim($url, '/') . "/?type=op&cmd=" . rawurlencode("<show><cloud-appid><application>ssl</application></cloud-appid></show>"), 3 ) !== false;
    };
    if( $mode !== 'auto' )
    {
        if( $reachable($mode) )
            return $base = rtrim($mode, '/');
        $messages[] = "cloud App-ID API helper " . $mode . " not reachable - list cloud-appid.txt used";
        return null;
    }
    $candidates = array( 'http://localhost:8080', 'http://host.docker.internal:8080' );
    foreach( $candidates as $c )
        if( $reachable($c) )
            return $base = $c;

    // start the container (docker on this host, or the docker socket mounted into the pan-os-php container)
    exec( "docker version --format '{{.Server.Version}}' 2>/dev/null", $out, $rc );
    if( $rc !== 0 )
    {
        $messages[] = "cloud App-ID API helper not reachable and docker not available here (in the pan-os-php container: mount "
            . "/var/run/docker.sock, or start it on the host: docker run -d -p 8080:80 --name panos_cloud-appid_mock "
            . "swaschkut/pan-os_cloud-appid_api-helper) - list cloud-appid.txt used";
        return null;
    }
    $name = 'panos_cloud-appid_mock';
    exec( "docker ps -a -q -f name=^/" . $name . "$ 2>/dev/null", $ids );
    if( count($ids) > 0 )
        exec( "docker start " . $name . " 2>&1", $o2, $rc2 );
    else
        exec( "docker run -d -p 8080:80 --name " . $name . " swaschkut/pan-os_cloud-appid_api-helper 2>&1", $o2, $rc2 );
    if( $rc2 !== 0 )
    {
        $messages[] = "cloud App-ID API helper: docker could not start " . $name . " (" . implode(" ", array_slice($o2, -2)) . ") - list cloud-appid.txt used";
        return null;
    }
    $messages[] = "cloud App-ID API helper: container " . $name . ( count($ids) > 0 ? " started" : " created and started" );
    for( $i = 0; $i < 30; $i++ )
    {
        foreach( $candidates as $c )
            if( $reachable($c) )
                return $base = $c;
        sleep(2);
    }
    $messages[] = "cloud App-ID API helper: container started, but not reachable on port 8080 within 60 s - list cloud-appid.txt used";
    return null;
}
$appidMessages = array();
$cloudList = null;
$appResolution = array( 'custom / group / filter' => 0, 'predefined' => 0, 'cloud App-ID' => 0, 'placeholder' => 0 );
foreach( $refs as $a => $users )
{
    if( $a === 'any' )
        continue;
    if( isset($known[$a]) )
    {
        $appResolution['custom / group / filter']++;
        continue;
    }
    if( $predefinedApps->find($a, null, false) !== null )
    {
        $appResolution['predefined']++;
        continue;
    }
    $cloud = null;
    if( ($api = cloudAppidApi( $args, $appidMessages )) !== null )
    {
        $url = $api . "/?type=op&cmd=" . rawurlencode("<show><cloud-appid><application>" . htmlspecialchars($a, ENT_XML1) . "</application></cloud-appid></show>");
        $answer = httpGetQuiet($url, 10);
        if( $answer !== false )
            $cloud = strpos($answer, 'status="success"') !== false && preg_match('/<(entry|application)[^>]*>/', $answer) && strpos($answer, $a) !== false;
    }
    if( $cloud === null )
    {
        if( $cloudList === null )
        {
            $cloudList = array();
            foreach( @file(dirname(__FILE__) . "/../../../../lib/object-classes/cloud-appid/cloud-appid.txt") ?: array() as $line )
                if( preg_match('/^\d+\s+(\S+)/', $line, $mm) )
                    $cloudList[$mm[1]] = TRUE;
        }
        $cloud = isset($cloudList[$a]);
        if( !$cloud )
            foreach( array_keys($cloudList) as $n )
                if( strlen($n) == 20 && strpos($a, $n) === 0 )      // the list truncates names to 20 characters
                {
                    $cloud = TRUE;
                    break;
                }
    }
    if( $cloud )
    {
        $appResolution['cloud App-ID']++;
        continue;
    }
    // not known: placeholder custom application in the folder of the first user
    $appResolution['placeholder']++;
    $change['applications'][] = array( 'folder' => $users[0][0], 'name' => $a, 'category' => 'networking', 'subcategory' => 'ip-protocol',
        'technology' => 'network-protocol', 'risk' => 1, 'description' => 'pan-os-php placeholder - application not in the configuration, not predefined, not cloud App-ID' );
    $counts['applications'] = ( isset($counts['applications']) ? $counts['applications'] : 0 ) + 1;
    $appPlaceholders[] = array( 'type' => 'applications', 'name' => $a, 'folder' => $users[0][0],
        'content' => array( "placeholder: application not in the configuration, not in predefined.xml, not a cloud App-ID application - content unknown (used by "
            . implode(", ", array_map( function($u){ return $u[1]; }, $users )) . ")" ) );
}

// profiles completed through the internal UI API by scm_pa_change.php: complete PAN-OS entry as _internal
$internalCount = 0;
foreach( $importer->internal as $in )
{
    $key = $in['scope_type'] == 'snippet' ? 'snippet' : 'folder';
    if( !isset($change[$in['resource']]) )
        continue;
    foreach( $change[$in['resource']] as $idx => $item )
        if( $item['name'] === $in['name'] && isset($item[$key]) && $item[$key] === $in['scope'] )
        {
            $change[$in['resource']][$idx]['_internal'] = array( 'prefix' => $in['prefix'], 'entry' => $in['entry'] );
            $internalCount++;
            break;
        }
}

// objects in the change file that are imported without part of their content / references
$incomplete = array();
foreach( $importer->incomplete as $inc )
{
    $key = $inc['scope_type'] == 'snippet' ? 'snippet' : 'folder';
    if( !isset($change[$inc['resource']]) )
        continue;
    foreach( $change[$inc['resource']] as $item )
        if( $item['name'] === $inc['name'] && isset($item[$key]) && $item[$key] === $inc['scope'] )
        {
            $incomplete[] = array( 'type' => $inc['resource'], 'name' => $inc['name'], $key => $inc['scope'], 'missing' => $inc['missing'] );
            break;
        }
}
$change['incomplete'] = array_merge( $incomplete, $ifIncomplete );

// objects created because something refers to them (references are never removed): PAN-OS predefined copies,
// placeholders with unknown / not writable content
$placeholders = array_merge( $appPlaceholders, $ifPlaceholders );
foreach( $importer->placeholders as $ph )
{
    $key = $ph['scope_type'] == 'snippet' ? 'snippet' : 'folder';
    if( !isset($change[$ph['resource']]) )
        continue;
    foreach( $change[$ph['resource']] as $item )
        if( $item['name'] === $ph['name'] && isset($item[$key]) && $item[$key] === $ph['scope'] )
        {
            $placeholders[] = array( 'type' => $ph['resource'], 'name' => $ph['name'], $key => $ph['scope'], 'content' => $ph['content'] );
            break;
        }
}
$change['placeholders'] = $placeholders;
if( count($ifVariables) > 0 )
    $change['interface_variables'] = $ifVariables;

/** address (ipv4 / ipv6, with or without prefix) - else an address object name */
function isIpValue( $v )
{
    $a = explode('/', $v)[0];
    return filter_var($a, FILTER_VALIDATE_IP) !== FALSE;
}
/** interface address given as address object name. Panorama: a template refers to shared objects only. SCM: the
 *  snippet keeps the name, on the firewall the object of its folder (device-group) wins over the one of All -
 *  value = closest object in the device-group hierarchy, else shared; a different device-group object is reported */
function resolveAddressName( $pano, $name, $dgName, $serial, $var, array &$warnings )
{
    $shared = $pano->addressStore->find($name, null, false);
    $dgObj = null;
    $dgFound = null;
    $dg = $dgName !== null ? $pano->findDeviceGroup($dgName) : null;
    while( $dg !== null && $dgObj === null )
    {
        $o = $dg->addressStore->find($name, null, false);
        if( $o !== null )
        {
            $dgObj = $o;
            $dgFound = $dg->name();
        }
        $dg = $dg->parentDeviceGroup;
    }
    $valueOf = function( $o ){ return $o->isGroup() ? "group " . $o->name() : $o->value(); };
    if( $dgObj !== null )
    {
        if( $shared !== null && $valueOf($shared) !== $valueOf($dgObj) )
            $warnings[] = "firewall " . $serial . " " . $var . ": address object '" . $name . "' - Panorama template uses shared (" . $valueOf($shared)
                . "), SCM uses the object of folder '" . $dgFound . "' (" . $valueOf($dgObj) . ") - the folder object wins over All";
        return array( $valueOf($dgObj), "address object '" . $name . "' (device-group " . $dgFound . ( $shared !== null ? ", overrides shared" : "" ) . ")",
            $shared !== null && $valueOf($shared) !== $valueOf($dgObj) ? $valueOf($shared) : null );
    }
    if( $shared !== null )
        return array( $valueOf($shared), "address object '" . $name . "' (shared)", null );
    $warnings[] = "firewall " . $serial . " " . $var . ": address object '" . $name . "' not found (shared / device-group hierarchy)";
    return array( $name, "address object '" . $name . "' not found", null );
}
$fwWarnings = array();

// managed firewalls: serial -> device-group folder, template-stack -> snippets, interface variables of these snippets
// (for the device step: device in the folder, interface variable values per device) - not sent by scm_pa_change.php
$firewalls = array();
$xpf = new DOMXPath($pano->xmldoc);
$dgOfSerial = array();
foreach( $xpf->query("/config/devices/entry/device-group/entry") as $dgE )
    foreach( $xpf->query("devices/entry", $dgE) as $d )
        $dgOfSerial[$d->getAttribute('name')] = $dgE->getAttribute('name');
$stackOfSerial = array();
foreach( $xpf->query("/config/devices/entry/template-stack/entry") as $stE )
    foreach( $xpf->query("devices/entry", $stE) as $d )
        $stackOfSerial[$d->getAttribute('name')] = $stE->getAttribute('name');
$serials = array();
foreach( $xpf->query("/config/mgt-config/devices/entry") as $d )
    $serials[$d->getAttribute('name')] = TRUE;
$serials += array_fill_keys( array_keys($dgOfSerial), TRUE ) + array_fill_keys( array_keys($stackOfSerial), TRUE );
foreach( array_keys($serials) as $serial )
{
    $fw = array( 'serial' => (string)$serial );
    if( isset($dgOfSerial[$serial]) && in_array($dgOfSerial[$serial], $dgFolderNames, TRUE) )
        $fw['folder'] = $dgOfSerial[$serial];
    elseif( isset($dgOfSerial[$serial]) )
        $fw['device_group'] = $dgOfSerial[$serial] . " (not imported)";
    $snips = array();
    if( isset($stackOfSerial[$serial]) )
    {
        $fw['template_stack'] = $stackOfSerial[$serial];
        if( ($sn = $importer->snippetNameOf('stack', $stackOfSerial[$serial])) !== null )
            $snips[] = $sn;
        foreach( $xpf->query("/config/devices/entry/template-stack/entry[@name='" . $stackOfSerial[$serial] . "']/templates/member") as $m )
            if( ($sn = $importer->snippetNameOf('template', trim($m->textContent))) !== null )
                $snips[] = $sn;
    }
    $fw['snippets'] = $snips;
    // Panorama template variables for this firewall: device value (stack devices/entry) > stack > templates (stack order)
    $tplVars = array();
    $varSources = array();
    if( isset($stackOfSerial[$serial]) )
    {
        $st = "/config/devices/entry/template-stack/entry[@name='" . $stackOfSerial[$serial] . "']";
        $varSources[] = array( $st . "/devices/entry[@name='" . $serial . "']/variable/entry", 'template variable (device)' );
        $varSources[] = array( $st . "/variable/entry", 'template variable (stack)' );
        foreach( $xpf->query($st . "/templates/member") as $m )
            $varSources[] = array( "/config/devices/entry/template/entry[@name='" . trim($m->textContent) . "']/variable/entry", 'template variable (template ' . trim($m->textContent) . ')' );
    }
    foreach( $varSources as $vs )
        foreach( $xpf->query($vs[0]) as $ve )
            if( !isset($tplVars[$ve->getAttribute('name')]) && ($val = $xpf->query("type/*", $ve)->item(0)) !== null )
                $tplVars[$ve->getAttribute('name')] = array( trim($val->textContent), $vs[1] );
    // interface addresses as imported into the snippets (first snippet in stack order wins)
    $ifIps = array();
    foreach( array('ethernet-interfaces', 'layer3-subinterfaces', 'tunnel-interfaces', 'loopback-interfaces', 'vlan-interfaces') as $t )
        foreach( isset($change[$t]) ? $change[$t] : array() as $it )
        {
            $ips = isset($it['layer3']['ip']) ? $it['layer3']['ip'] : ( isset($it['ip']) ? $it['ip'] : array() );
            $ifIps[$it['snippet'] . "|" . $it['name']] = array_map( function($x){ return is_array($x) ? $x['name'] : $x; }, $ips );
        }
    $vars = array();
    foreach( $snips as $sn )
        foreach( $ifVariables as $v )
        {
            if( $v['snippet'] !== $sn || isset($vars[$v['variable']]) )
                continue;
            $entry = array( 'interface' => $v['interface'] );
            $ips = isset($ifIps[$sn . "|" . $v['variable']]) ? $ifIps[$sn . "|" . $v['variable']] : array();
            if( count($ips) > 0 )
            {
                $resolved = array();
                $src = array();
                $objInfo = array();
                foreach( $ips as $ip )
                {
                    if( isset($tplVars[$ip]) )
                    {
                        $val = $tplVars[$ip][0];
                        $s1 = $tplVars[$ip][1] . " " . $ip;
                    }
                    else
                    {
                        $val = $ip;
                        $s1 = 'template ' . $sn;
                    }
                    // address object name instead of an address: the name stays (SCM resolves it on the device -
                    // object of the folder before All); the resolution is only shown, with a Panorama / SCM conflict
                    if( !isIpValue($val) )
                    {
                        list($scmVal, $s2, $panoVal) = resolveAddressName( $pano, $val, isset($dgOfSerial[$serial]) ? $dgOfSerial[$serial] : null, $serial, $v['variable'], $fwWarnings );
                        $s1 .= ", " . $s2;
                        $objInfo[$val] = array( 'scm' => $scmVal ) + ( $panoVal !== null ? array( 'panorama' => $panoVal ) : array() );
                    }
                    $resolved[] = $val;
                    $src[$s1] = TRUE;
                }
                $entry['ip'] = $resolved;
                $entry['ip_source'] = implode(", ", array_keys($src));
                // address object names: value SCM resolves (folder object before All) and, if different, the shared
                // value the firewall got from Panorama
                if( count($objInfo) > 0 )
                    $entry['address_objects'] = $objInfo;
            }
            $vars[$v['variable']] = $entry;
        }
    $fw['interfaces'] = $vars;
    $firewalls[] = $fw;
}
if( count($firewalls) > 0 )
    $change['firewalls'] = $firewalls;
$warnings = array_merge( $warnings, $fwWarnings );
$change['not_imported'] = $notImported;
$warnings = array_merge( $warnings, $warningsApps );
$change['warnings'] = $warnings;

file_put_contents( $args['out'], json_encode( $change, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . "\n" );

PH::print_stdout();
PH::print_stdout( " * snippets (templates / template-stacks): " . ( isset($change['snippets']) ? implode(", ", array_map( function($x){ return $x['name']; }, $change['snippets'] )) : "-" ) );
PH::print_stdout( " * device-group folders:" );
foreach( $change['folders'] as $f )
    PH::print_stdout( "   " . $f['name'] . " (parent " . $f['parent'] . ")" . ( isset($f['snippets']) ? " snippets: " . implode(" > ", $f['snippets']) : "" ) );
foreach( $counts as $t => $n )
    PH::print_stdout( sprintf( "   %-36s %4d", $t, $n ) );
if( isset($importer->summary['skipped']) )
    PH::print_stdout( " * not part of this step: " . json_encode($importer->summary['skipped']) );
PH::print_stdout( " * completed through the internal UI API (sections the public API does not have): " . $internalCount . " profile(s) ('_internal')" );
foreach( $appidMessages as $m )
    PH::print_stdout( "   ! " . $m );
PH::print_stdout( " * applications used by rules / groups: " . implode(", ", array_map( function($k, $v){ return $k . " " . $v; }, array_keys($appResolution), $appResolution )) );
PH::print_stdout( " * created because they are referenced (PAN-OS predefined copy / placeholder): " . count($placeholders) . " - listed in 'placeholders' of the change file" );
$byType = array();
foreach( $placeholders as $n )
    $byType[$n['type']] = ( isset($byType[$n['type']]) ? $byType[$n['type']] : 0 ) + 1;
foreach( $byType as $t => $n )
    PH::print_stdout( sprintf( "   %-36s %4d", $t, $n ) );
PH::print_stdout( " * imported, but not complete: " . count($incomplete) . " - listed with the missing content / references in 'incomplete' of the change file" );
$byType = array();
foreach( $incomplete as $n )
    $byType[$n['type']] = ( isset($byType[$n['type']]) ? $byType[$n['type']] : 0 ) + 1;
foreach( $byType as $t => $n )
    PH::print_stdout( sprintf( "   %-36s %4d", $t, $n ) );
PH::print_stdout( " * not importable (review): " . count($notImported) . " - listed in 'not_imported' of the change file" );
$byType = array();
foreach( $notImported as $n )
    $byType[$n['type']] = ( isset($byType[$n['type']]) ? $byType[$n['type']] : 0 ) + 1;
foreach( $byType as $t => $n )
    PH::print_stdout( sprintf( "   %-36s %4d", $t, $n ) );
foreach( $warnings as $w )
    PH::print_stdout( "   ! " . $w );
PH::print_stdout();
PH::print_stdout( " * change file: " . $args['out'] );
PH::print_stdout( " * next: php scm_pa_change.php in=scm-api://<TSG> changes=" . $args['out'] . "   (dry-run, then 'execute')" );
PH::print_stdout();
