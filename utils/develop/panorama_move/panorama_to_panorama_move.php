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
 * panorama_to_panorama_move.php - move device groups (+ parents, firewalls, template stacks, templates, shared objects)
 * from Panorama A (file1) to Panorama B (file2), offline. CONCEPT_panorama_to_panorama_move.md
 *
 * pan-os-php type=panorama-move file1=A.xml file2=B.xml dg-list=dgs.txt [mode=check|execute] ...
 */

set_include_path(dirname(__FILE__) . '/../../../' . PATH_SEPARATOR . get_include_path());
require_once("lib/pan_php_framework.php");
require_once(dirname(__FILE__) . "/lib/PanoramaMove.php");

$usage = "USAGE: php " . basename(__FILE__) . " file1=<Panorama A.xml> file2=<Panorama B.xml> dg-list=<file> [options]\n"
    . "  file1=              source Panorama configuration\n"
    . "  file2=              target Panorama configuration\n"
    . "  dg-list=            text file, one device group of file1 per line (# comments)\n"
    . "  mode=check          (default) check run: plan, shared rule impact, name problems -> report only\n"
    . "  mode=execute        write out1 / out2 (refused while the check run has blocking findings, see accept-blocking)\n"
    . "  out1= out2=         output files (default <file1>_moved-out.xml / <file2>_moved-in.xml)\n"
    . "  report=             report folder (default panorama-move-report)\n"
    . "  target-parent-dg=   parent device group in file2 for the top moved device group (default shared)\n"
    . "  shared-rules=skip|to-top-dg   shared pre / post rules of file1 (default skip = not transferred, listed)\n"
    . "  shared-settings=report|copy-missing   shared setting blocks (ssl-decrypt, response pages, ...): report (default) or copy\n"
    . "                      the blocks missing in file2 (blocks that differ are never overwritten)\n"
    . "  accept-blocking     execute although there are blocking findings (conflicting objects are NOT copied)\n";

$args = array();
foreach( array_slice($argv, 1) as $a )
{
    $p = strpos($a, "=");
    $args[ strtolower($p === FALSE ? $a : substr($a, 0, $p)) ] = $p === FALSE ? TRUE : substr($a, $p + 1);
}
if( isset($args['help']) || !isset($args['file1']) || !isset($args['file2']) || !isset($args['dg-list']) )
{
    print $usage;
    exit( isset($args['help']) ? 0 : 1 );
}
foreach( array( 'file1', 'file2', 'dg-list' ) as $k )
    if( !is_file($args[$k]) )
    {
        fwrite( STDERR, "ERROR: " . $k . " '" . $args[$k] . "' not found\n" );
        exit( 1 );
    }
$mode = isset($args['mode']) ? $args['mode'] : 'check';
if( !in_array($mode, array( 'check', 'execute' ), TRUE) )
{
    fwrite( STDERR, "ERROR: mode=check|execute\n" );
    exit( 1 );
}
$sharedRules = isset($args['shared-rules']) ? $args['shared-rules'] : 'skip';
if( !in_array($sharedRules, array( 'skip', 'to-top-dg' ), TRUE) )
{
    fwrite( STDERR, "ERROR: shared-rules=skip|to-top-dg\n" );
    exit( 1 );
}
$sharedSettings = isset($args['shared-settings']) ? $args['shared-settings'] : 'report';
if( !in_array($sharedSettings, array( 'report', 'copy-missing' ), TRUE) )
{
    fwrite( STDERR, "ERROR: shared-settings=report|copy-missing\n" );
    exit( 1 );
}
$dgs = array();
foreach( file($args['dg-list'], FILE_IGNORE_NEW_LINES) as $l )
{
    $l = trim( preg_replace('/#.*$/', '', $l) );
    if( $l !== '' )
        $dgs[] = $l;
}
if( !count($dgs) )
{
    fwrite( STDERR, "ERROR: dg-list is empty\n" );
    exit( 1 );
}
$reportDir = isset($args['report']) ? $args['report'] : 'panorama-move-report';
$out1 = isset($args['out1']) ? $args['out1'] : preg_replace('/\.xml$/i', '', $args['file1']) . '_moved-out.xml';
$out2 = isset($args['out2']) ? $args['out2'] : preg_replace('/\.xml$/i', '', $args['file2']) . '_moved-in.xml';

PH::print_stdout();
PH::print_stdout( "*********** " . basename(__FILE__) . " (" . $mode . ") **************" );
$m = new PanoramaMove( $args['file1'], $args['file2'], $dgs, isset($args['target-parent-dg']) ? $args['target-parent-dg'] : null, $sharedRules, $sharedSettings );
$m->check();

$blocking = $m->blocking();
$rc = 0;
if( $mode == 'execute' )
{
    if( count($blocking) && !isset($args['accept-blocking']) )
    {
        PH::print_stdout( " * " . count($blocking) . " blocking finding(s) - nothing written (see the report, accept-blocking to override)" );
        $mode = 'check';
        $rc = 2;
    }
    else
    {
        $v = $m->execute( $out1, $out2 );
        PH::print_stdout( " * written: " . $out1 . " (device groups " . $v['file1']['device_groups'] . ", unresolved " . $v['file1']['unresolved'] . ")" );
        PH::print_stdout( " * written: " . $out2 . " (device groups " . $v['file2']['device_groups'] . ", unresolved " . $v['file2']['unresolved'] . ")" );
    }
}
if( !is_dir($reportDir) )
    mkdir( $reportDir, 0700, TRUE );
file_put_contents( $reportDir . "/plan.json", json_encode( $m->plan(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) );
file_put_contents( $reportDir . "/REPORT.md", $m->reportMarkdown($mode) );
$sev = array( 'blocking' => 0, 'warning' => 0, 'info' => 0 );
foreach( $m->findings as $f ) $sev[$f['severity']]++;
PH::print_stdout( " * device groups: " . count($m->dgAction) . ", firewalls: " . count($m->devices) . ", template stacks: " . count($m->stackAction) . ", templates: " . count($m->templateAction) . ", shared objects: " . count($m->sharedObjects) );
PH::print_stdout( " * findings: blocking " . $sev['blocking'] . ", warning " . $sev['warning'] . ", info " . $sev['info'] );
PH::print_stdout( " * report: " . $reportDir . "/REPORT.md, " . $reportDir . "/plan.json" );
PH::print_stdout();
exit( $rc ? $rc : ( $sev['blocking'] ? 2 : 0 ) );
