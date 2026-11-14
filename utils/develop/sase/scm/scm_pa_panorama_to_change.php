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
    . "  cloud-appid-api  URL of the cloud App-ID API helper (github.com/swaschkut/pan-os_cloud-appid-API-helper, e.g.\n"
    . "                http://localhost:8080) to check SaaS applications; default: list lib/object-classes/cloud-appid\n"
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
// custom applications: rules refer to them - created with the attributes the SCM applications API takes; signatures,
// default ports, timeouts … are not imported -> placeholders list
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
$xpa = new DOMXPath($pano->xmldoc);
foreach( $appScopes as $as )
    foreach( $xpa->query("application/entry", $as[1]) as $app )
    {
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
            else
                $missing[] = $c->tagName;
        }
        $change['applications'][] = $item;
        $counts['applications'] = ( isset($counts['applications']) ? $counts['applications'] : 0 ) + 1;
        $appPlaceholders[] = array( 'type' => 'applications', 'name' => $item['name'], 'folder' => $as[0],
            'content' => array( "custom application created with category / subcategory / technology / risk / characteristics"
                . ( count($missing) ? " - not imported: " . implode(", ", $missing) . " (application identification not complete)" : "" ) ) );
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
$predefinedApps = AppStore::getPredefinedStore( $pano );
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
    if( isset($args['cloud-appid-api']) && is_string($args['cloud-appid-api']) )
    {
        $url = rtrim($args['cloud-appid-api'], '/') . "/?type=op&cmd=" . rawurlencode("<show><cloud-appid><application>" . htmlspecialchars($a, ENT_XML1) . "</application></cloud-appid></show>");
        $answer = @file_get_contents($url);
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
$change['incomplete'] = $incomplete;

// objects created because something refers to them (references are never removed): PAN-OS predefined copies,
// placeholders with unknown / not writable content
$placeholders = $appPlaceholders;
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
$change['not_imported'] = $notImported;
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
