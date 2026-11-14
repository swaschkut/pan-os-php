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

/**
 * scm_pa_xml_to_change.php
 *
 *   scm_pa_export.php ──► export folder ──► pan-os-php utilities (in=scm-export://<folder> … out=changed.xml)
 *   ──► scm_pa_xml_to_change.php ──► change.json ──► scm_pa_change.php (dry-run, execute, verify)
 *
 * The original is loaded from the same export with the same loader (all containers, all types), so only the changes
 * of the utilities show up. Deletes: only where the changed XML still holds objects of that type in that container
 * (a type a utility did not load is never deleted); without allow-delete they stay in the dry-run of scm_pa_change.
 */

set_include_path(dirname(__FILE__) . '/../../../../' . PATH_SEPARATOR . get_include_path());
require_once("lib/pan_php_framework.php");
require_once("utils/lib/UTIL.php");
require_once(dirname(__FILE__) . "/lib/SCMPrismaAccessExport.php");
if( !class_exists("SCMCHANGES") )
    require_once("utils/lib/SCMCHANGES.php");

$usage = "USAGE: php " . basename(__FILE__) . " in=scm-export://<export folder> file2=changed.xml out=change.json [original=original.xml]\n"
    . "  in        folder written by scm_pa_export.php (the original - the same folder the utilities read with\n"
    . "            in=scm-export://)\n"
    . "  file2     result of the pan-os-php utilities (out=… of the last one; chains with in=<previous out> work)\n"
    . "  out       change request for scm_pa_change.php\n"
    . "  original  optional: also write the original XML (for checks / a second comparison)\n"
    . "\n"
    . "  example (address merger of one folder):\n"
    . "    php utils/pan-os-php.php type=address-merger in=scm-export://export/1234 location=Lab out=merged.xml\n"
    . "    php " . basename(__FILE__) . " in=scm-export://export/1234 file2=merged.xml out=change.json\n"
    . "    php scm_pa_change.php in=scm-api://1234 changes=change.json            (dry-run, then execute)\n";

$args = array();
foreach( array_slice($argv, 1) as $a )
{
    $p = strpos($a, "=");
    $args[strtolower($p === false ? $a : substr($a, 0, $p))] = $p === false ? true : substr($a, $p + 1);
}
foreach( array_keys($args) as $a )
    if( !in_array($a, array('in', 'file2', 'out', 'original', 'help'), TRUE) )
    {
        print "unknown argument '" . $a . "'\n\n" . $usage;
        exit(1);
    }
if( isset($args['help']) || !isset($args['in']) || !isset($args['file2']) || !isset($args['out']) )
{
    print $usage;
    exit( isset($args['help']) ? 0 : 1 );
}
$dir = strpos($args['in'], 'scm-export://') === 0 ? substr($args['in'], strlen('scm-export://')) : $args['in'];
if( !is_file($args['file2']) )
    derr( "file2 not found: " . $args['file2'], null, FALSE );

PH::print_stdout( PH::boldText(" * [1/3] original from the export: " . $dir) );
$connector = new PanSCMExportConnector($dir);
$pan = new BuckbeakConf();
$doc = new DOMDocument();
if( !$doc->load(dirname(__FILE__) . "/../../buckbeak_baseconfig.xml", XML_PARSE_BIG_LINES) )
    derr( "buckbeak base configuration not readable", null, FALSE );
$pan->load_from_domxml($doc);
ob_start();
$loaded = $connector->loadAll($pan);
ob_end_clean();
$origFile = isset($args['original']) ? $args['original'] : tempnam(sys_get_temp_dir(), "scm-orig-") . ".xml";
$pan->save_to_file($origFile, FALSE);
PH::print_stdout( "   " . count($loaded) . " container(s) loaded" . ( isset($args['original']) ? ", written to " . $origFile : "" ) );

PH::print_stdout( PH::boldText(" * [2/3] difference original <-> " . $args['file2']) );
ob_start();
$json = SCMCHANGES::generate( $origFile, $args['file2'] );
ob_end_clean();
$gen = json_decode($json, TRUE);
$newDoc = new DOMDocument();
$newDoc->load($args['file2'], XML_PARSE_BIG_LINES);
$counter = new SCMChangeGenerator();
$newCounts = $counter->objectCounts($newDoc);
if( !isset($args['original']) )
    unlink($origFile);

// references from types the pan-os-php loader does not read (e.g. NAT / decryption rules): the utilities do not see
// them (no reference replacement) - such an object is never deleted, it is listed instead
$loadedTypes = array();
foreach( PanSCMExportConnector::ALL_UTIL_TYPES as $ut )
    foreach( $connector->getTypeArray($ut) as $t )
        $loadedTypes[$t] = TRUE;
$foreignRefs = array();     // value => list of "type 'name' [container]"
$collect = function( $v, $where ) use( &$collect, &$foreignRefs ){
    if( is_string($v) )
        $foreignRefs[$v][$where] = TRUE;
    elseif( is_array($v) )
        foreach( $v as $k => $x )
            if( $k !== 'name' && $k !== 'id' && $k !== 'folder' && $k !== 'snippet' && $k !== 'device' )
                $collect( $x, $where );
};
foreach( array('folders', 'snippets', 'devices') as $sub )
    foreach( glob(rtrim($dir, "/") . "/config/" . $sub . "/*/*.json") as $f )
    {
        $t = preg_replace(array('/^\d+_/', '/-(pre|post)$/'), '', basename($f, ".json"));
        if( isset($loadedTypes[$t]) )
            continue;
        $j = json_decode(file_get_contents($f), TRUE);
        foreach( isset($j['data']) && is_array($j['data']) ? $j['data'] : array() as $o )
            if( isset($o['name']) )
                $collect( $o, $t . " '" . $o['name'] . "' [" . basename(dirname($f)) . "]" );
    }

PH::print_stdout( PH::boldText(" * [3/3] change request") );
$known = array();
foreach( SCMPrismaAccessExport::getConfigTypes() as $t )
    $known[$t['name']] = $t;
$change = array(
    'format' => 'pan-os-php-scm-change-request',
    'description' => "pan-os-php utilities on export " . basename(rtrim($dir, "/")) . ": " . basename($args['file2']),
    'source' => array( 'export' => $dir, 'tsg_id' => isset($connector->manifest['tsg_id']) ? $connector->manifest['tsg_id'] : null,
        'export_created_at' => isset($connector->manifest['created_at']) ? $connector->manifest['created_at'] : null,
        'file2' => basename($args['file2']), 'created_at' => date('c'), 'tool' => basename(__FILE__) . " " . PH::frameworkVersion() ),
);
$notChanged = array();
$skippedDeletes = 0;
$counts = array();
foreach( $gen['requests'] as $r )
{
    $obj = $r['object'];
    $resource = $obj['resource'];
    $label = $resource . " '" . $obj['name'] . "' [" . $obj['scope_type'] . " " . $obj['scope'] . "]";
    if( in_array($resource, array('folders', 'snippets', 'devices'), TRUE) )
    {
        $notChanged[] = array( 'type' => $resource, 'name' => $obj['name'], 'reasons' => array( $r['method'] . ": folders / snippets / devices are not changed from utility results" ) );
        continue;
    }
    if( !in_array($obj['scope_type'], array('folder', 'snippet'), TRUE) || !isset($known[$resource]) )
    {
        $notChanged[] = array( 'type' => $resource, 'name' => $obj['name'], 'reasons' => array( "scope " . $obj['scope_type'] . " / type not supported by scm_pa_change.php" ) );
        continue;
    }
    $scopeKey = $obj['scope_type'];
    $item = array( $scopeKey => $obj['scope'], 'name' => $obj['name'] );
    if( !empty($known[$resource]['position']) && $scopeKey == 'folder' && $obj['position'] !== null )
        $item['position'] = $obj['position'];

    if( $r['method'] == 'DELETE' )
    {
        // a type that is not in the changed XML for this container was not loaded by the utility - never deleted
        if( !isset($newCounts[$obj['scope_type'] . "|" . $obj['scope'] . "|" . $resource]) )
        {
            $skippedDeletes++;
            continue;
        }
        if( isset($foreignRefs[$obj['name']]) )
        {
            $notChanged[] = array( 'type' => $resource, 'name' => $obj['name'], $scopeKey => $obj['scope'],
                'reasons' => array( "not deleted: referenced by " . implode(", ", array_slice(array_keys($foreignRefs[$obj['name']]), 0, 5))
                    . ( count($foreignRefs[$obj['name']]) > 5 ? " …" : "" ) . " - types pan-os-php does not load (references not replaced by the utility)" ) );
            continue;
        }
        $item['_delete'] = true;
    }
    else
    {
        if( $r['review'] )
        {
            $notChanged[] = array( 'type' => $resource, 'name' => $obj['name'], $scopeKey => $obj['scope'], 'reasons' => $r['warnings'] );
            continue;
        }
        $body = is_array($r['body']) ? $r['body'] : array();
        if( $r['method'] == 'PUT' && isset($body['name']) && $body['name'] !== $obj['name'] )
        {
            $notChanged[] = array( 'type' => $resource, 'name' => $obj['name'], $scopeKey => $obj['scope'], 'reasons' => array( "renamed (" . json_encode($r['before']) . ") - scm_pa_change.php does not rename" ) );
            continue;
        }
        $before = isset($r['before']) && is_array($r['before']) ? $r['before'] : array();
        $skip = false;
        foreach( $body as $k => $v )
        {
            if( in_array($k, array('folder', 'snippet', 'device', 'name', 'id'), TRUE) )
                continue;
            if( $v === null )
            {
                // field removed: a list becomes empty, a removed scalar / object cannot be expressed as "replace"
                if( isset($before[$k]) && is_array($before[$k]) && array_values($before[$k]) === $before[$k] )
                    $v = array();
                else
                {
                    $notChanged[] = array( 'type' => $resource, 'name' => $obj['name'], $scopeKey => $obj['scope'], 'reasons' => array( "field '" . $k . "' removed - not expressible in the change request" ) );
                    $skip = true;
                    break;
                }
            }
            $item[$k] = $v;
        }
        if( $skip )
            continue;
    }
    $change[$resource][] = $item;
    $c = $r['method'] == 'DELETE' ? 'delete' : ( $r['method'] == 'POST' ? 'create' : 'update' );
    $counts[$resource][$c] = ( isset($counts[$resource][$c]) ? $counts[$resource][$c] : 0 ) + 1;
}
if( count($notChanged) > 0 )
    $change['not_imported'] = $notChanged;
if( !empty($gen['warnings']) )
    $change['warnings'] = $gen['warnings'];

file_put_contents($args['out'], json_encode($change, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");

foreach( $counts as $res => $c )
{
    $parts = array();
    foreach( $c as $k => $n )
        $parts[] = $k . " " . $n;
    PH::print_stdout( sprintf("   %-34s %s", $res, implode(", ", $parts)) );
}
if( count($counts) == 0 )
    PH::print_stdout( "   no changes" );
if( $skippedDeletes > 0 )
    PH::print_stdout( "   (" . $skippedDeletes . " object(s) of types the utility did not load - unchanged, no delete)" );
if( count($notChanged) > 0 )
    PH::print_stdout( "   not in the change request: " . count($notChanged) . " (list 'not_imported' in " . $args['out'] . ")" );
foreach( isset($gen['warnings']) ? $gen['warnings'] : array() as $w )
    PH::print_stdout( "   ! " . $w );
PH::print_stdout( " * written: " . $args['out'] );
$tsg = isset($connector->manifest['tsg_id']) ? $connector->manifest['tsg_id'] : '<TSG>';
PH::print_stdout( " * next: php scm_pa_change.php in=scm-api://" . $tsg . " changes=" . $args['out'] . "   (dry-run"
    . ", then 'execute')" );
