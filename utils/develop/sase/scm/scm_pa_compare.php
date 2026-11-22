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

// Offline compare of two scm_pa_export.php exports - no API access needed
// see utils/develop/sase/scm/README_pa_compare.md and CONSULTANT_GUIDE_pa_export_compare.md
//
// php utils/develop/sase/scm/scm_pa_compare.php left=<export dir A> right=<export dir B> [out=<dir>]
//     [area=a,b] [container=c1,c2] [config-types=t1,t2] [ignore-fields=path1,path2] [name-map=file.csv]
//     [max-items=50] [fail-on-diff]

require_once("lib/pan_php_framework.php");
require_once(dirname(__FILE__) . "/lib/SCMPrismaAccessCompare.php");

$usage = "USAGE: php " . basename(__FILE__) . " left=<export dir> right=<export dir> [out=<dir>] [area=a,b] [container=c1,c2]\n"
    . "       [config-types=t1,t2] [ignore-fields=path1,path2] [name-map=file.csv] [max-items=50] [fail-on-diff]\n"
    . "  left / right   export directories <outdir>/<TSG>/<timestamp> written by scm_pa_export.php\n"
    . "  out            result directory (default: <left>/../../compare-<leftTSG>-vs-<rightTSG>-<timestamp>)\n"
    . "  area           only these areas: " . implode(",", SCMPrismaAccessExport::AREAS) . "\n"
    . "  container      config area: only these folders / snippets\n"
    . "  config-types   config area: only these types (e.g. addresses,security-rules)\n"
    . "  ignore-fields  additional dotted paths to ignore for every endpoint (e.g. description)\n"
    . "  name-map       CSV area,endpoint,left,right - left names that are called differently in right\n"
    . "  max-items      max. entries / changes listed per endpoint in DIFF_REPORT.md (default 50)\n"
    . "  fail-on-diff   exit code 2 if differences exist (for scripts / CI)\n";

$args = array();
foreach( array_slice($argv, 1) as $a )
{
    $p = strpos($a, "=");
    if( $p === false )
        $args[strtolower($a)] = true;
    else
        $args[strtolower(substr($a, 0, $p))] = substr($a, $p + 1);
}
if( isset($args['help']) || !isset($args['left']) || !isset($args['right']) )
{
    print $usage;
    exit( isset($args['help']) ? 0 : 1 );
}
$known = array('left', 'right', 'out', 'area', 'container', 'config-types', 'ignore-fields', 'name-map', 'max-items', 'fail-on-diff', 'help');
foreach( array_keys($args) as $a )
    if( !in_array($a, $known, TRUE) )
    {
        print "unknown argument '" . $a . "'\n\n" . $usage;
        exit(1);
    }
$list = function( $name ) use( $args ){
    if( !isset($args[$name]) || $args[$name] === true || $args[$name] === "" )
        return null;
    return array_values( array_filter( array_map('trim', explode(",", $args[$name])) ) );
};

PH::print_stdout();
PH::print_stdout("*********** " . basename(__FILE__) . " **************");
PH::print_stdout( "PAN-OS-PHP version: " . PH::frameworkVersion() );

$compare = new SCMPrismaAccessCompare( $args['left'], $args['right'] );
$compare->filter = array( 'areas' => $list('area'), 'containers' => $list('container'), 'types' => $list('config-types') );
if( $compare->filter['areas'] !== null )
    foreach( $compare->filter['areas'] as $a )
        if( !in_array($a, SCMPrismaAccessExport::AREAS, TRUE) )
            derr( "unknown area '" . $a . "' - supported: " . implode(",", SCMPrismaAccessExport::AREAS), null, FALSE );
$compare->extraIgnore = (array)$list('ignore-fields');
if( isset($args['name-map']) && $args['name-map'] !== true )
    $compare->loadNameMap( $args['name-map'] );
if( isset($args['max-items']) && (int)$args['max-items'] > 0 )
    $compare->reportMaxItems = (int)$args['max-items'];

$L = $compare->leftManifest;
$R = $compare->rightManifest;
PH::print_stdout( " * left : TSG " . $L['tsg_id'] . " exported " . $L['created_at'] . " (" . $args['left'] . ")" );
PH::print_stdout( " * right: TSG " . $R['tsg_id'] . " exported " . $R['created_at'] . " (" . $args['right'] . ")" );
foreach( array('left' => $L, 'right' => $R) as $side => $m )
    if( !isset($m['format_version']) || $m['format_version'] < 6 )
        PH::print_stdout( " ! " . $side . " export has format_version " . ( isset($m['format_version']) ? $m['format_version'] : '?' ) . " - re-export with the current scm_pa_export.php for a complete compare" );

$compare->run();

$out = isset($args['out']) && $args['out'] !== true ? $args['out']
    : dirname(dirname(rtrim($args['left'], "/"))) . "/compare-" . $L['tsg_id'] . "-vs-" . $R['tsg_id'] . "-" . date('Ymd-His');
$diff = $compare->write( $out );

PH::print_stdout();
foreach( $diff['summary']['areas'] as $a => $c )
    PH::print_stdout( sprintf( " - %-20s endpoints %3d | with differences %3d | only left %4d | only right %4d | changed %4d | order %2d",
        $a, $c['endpoints'], $c['endpoints_with_differences'], $c['only_left'], $c['only_right'], $c['changed'], $c['order'] ) );
PH::print_stdout( " - hierarchy differences: " . $diff['summary']['hierarchy_differences'] . " | not comparable: " . $diff['summary']['not_comparable'] . " | warnings: " . count($diff['warnings']) );
PH::print_stdout();
PH::print_stdout( $diff['summary']['identical'] ? " * no differences" : " * differences found" );
PH::print_stdout( " * report: " . $out . "/DIFF_REPORT.md" );
PH::print_stdout( " * machine readable: " . $out . "/diff.json, " . $out . "/diff-summary.csv" );
PH::print_stdout();

if( isset($args['fail-on-diff']) && !$diff['summary']['identical'] )
    exit(2);
