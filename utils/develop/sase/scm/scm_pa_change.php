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

// Change an SCM tenant in one step from a small change request file (folders, snippets, objects)
// export -> soll (export + changes) -> compare -> plan -> dry-run -> [execute -> verify]
// see utils/develop/sase/scm/README_pa_change.md
//
// php utils/develop/sase/scm/scm_pa_change.php in=scm-api://<TSG> changes=<file.json> [outdir=change]
//     [execute [yes]] [push] [continue-on-error] [config-parallel=8] [debugapi]

set_include_path(dirname(__FILE__) . '/../../../../' . PATH_SEPARATOR . get_include_path());
require_once("lib/pan_php_framework.php");
require_once("utils/lib/UTIL.php");
require_once(dirname(__FILE__) . "/lib/SCMPrismaAccessChange.php");

PH::print_stdout();
PH::print_stdout("*********** " . basename(__FILE__) . " **************");
PH::print_stdout( "PAN-OS-PHP version: " . PH::frameworkVersion() );

$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'tenant: in=scm-api://<TSG_ID>', 'argDesc' => 'scm-api://[TSG_ID]');
$supportedArguments['changes'] = Array('niceName' => 'changes', 'shortHelp' => 'change request JSON (folders, snippets, objects) - see README_pa_change.md', 'argDesc' => '[file]');
$supportedArguments['outdir'] = Array('niceName' => 'outdir', 'shortHelp' => 'base directory; run files go to <outdir>/<TSG>/change-<timestamp>/ (default: change)', 'argDesc' => '[directory]');
$supportedArguments['execute'] = Array('niceName' => 'execute', 'shortHelp' => 'send the requests (default: dry-run)');
$supportedArguments['psk-list'] = Array('niceName' => 'psk-list', 'shortHelp' => 'psk-list.csv with the IKE pre-shared keys (columns ike_gateway, psk_new) - never in the change file', 'argDesc' => '[file]');
$supportedArguments['yes'] = Array('niceName' => 'yes', 'shortHelp' => 'no confirmation prompt for execute');
$supportedArguments['push'] = Array('niceName' => 'push', 'shortHelp' => 'push the touched folders after the changes (only folders with a push target)');
$supportedArguments['continue-on-error'] = Array('niceName' => 'continue-on-error', 'shortHelp' => 'continue after a failed request (dependent requests are skipped)');
$supportedArguments['config-parallel'] = Array('niceName' => 'config-parallel', 'shortHelp' => 'concurrent API requests of the exports (default 8)', 'argDesc' => 'N');
$supportedArguments['ui-api-host'] = Array('niceName' => 'ui-api-host', 'shortHelp' => 'internal UI API host of the tenant region (default ' . SCMPrismaAccessExport::UI_API_HOST_DEFAULT . ') - for _internal profile sections', 'argDesc' => '[host]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$usage = "php " . basename(__FILE__) . " in=scm-api://<TSG> changes=<file.json> [outdir=change] [execute [yes]] [push] [continue-on-error]";

$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usage );
$util->utilInit();

/* @var PanSCMAPIConnector $connector */
$connector = $util->pan->connector;
if( !is_object($connector) || get_class($connector) !== "PanSCMAPIConnector" )
    derr( "argument in=scm-api://<TSG> is required", null, FALSE );
if( isset(PH::$args['debugapi']) )
    $connector->setShowApiCalls( TRUE );
if( !isset(PH::$args['changes']) )
    derr( "argument changes=<file.json> is required", null, FALSE );

$execute = isset(PH::$args['execute']);
$tsg = $connector->apihost;
$change = new SCMPrismaAccessChange( $connector, $tsg, isset(PH::$args['outdir']) ? PH::$args['outdir'] : "change" );
if( isset(PH::$args['ui-api-host']) && is_string(PH::$args['ui-api-host']) )
    $change->options['ui_api_host'] = PH::$args['ui-api-host'];
if( isset(PH::$args['psk-list']) && is_string(PH::$args['psk-list']) )
    $change->options['psk_list'] = PH::$args['psk-list'];
if( isset(PH::$args['config-parallel']) )
    $change->options['parallel'] = max( 1, (int)PH::$args['config-parallel'] );

$stop = function( $title ) use( $change ){
    PH::print_stdout();
    PH::print_stdout( PH::boldText(" x " . $title . ":") );
    foreach( $change->errors as $e )
        PH::print_stdout( "   - " . $e );
    PH::print_stdout( " * nothing was sent" );
    PH::print_stdout();
    exit(1);
};

// 1) change request
if( !$change->loadRequest( PH::$args['changes'] ) )
    $stop( "change file " . PH::$args['changes'] );
$scope = $change->scope();
PH::print_stdout( " * TSG " . $tsg . " | changes: " . count($change->request['folders']) . " folder(s), " . count($change->request['snippets']) . " snippet(s), "
    . count($change->request['objects']) . " object(s) | types: " . ( count($scope['types']) ? implode(",", $scope['types']) : "-" )
    . " | containers: " . implode(", ", $scope['containers']) );
if( count($change->placeholders) > 0 || count($change->incomplete) > 0 || count($change->notImported) > 0 )
    PH::print_stdout( PH::boldText( " ! change file lists " . count($change->placeholders) . " object(s) created because they are referenced ('placeholders'), "
        . count($change->incomplete) . " object(s) without part of their content ('incomplete'), "
        . count($change->notImported) . " object(s) not importable ('not_imported') - see the change file" ) );
PH::print_stdout();

// 2) export, soll, compare, plan, dry-run
PH::print_stdout( PH::boldText(" * [1/4] export (read only)") );
if( !$change->prepare() )
    $stop( "change request does not fit the tenant" );

PH::print_stdout();
PH::print_stdout( PH::boldText(" * [2/4] changes") );
foreach( $change->changes as $c )
    PH::print_stdout( sprintf( "   %-9s %s", $c['action'], $c['label'] ) );
foreach( $change->warnings as $w )
    PH::print_stdout( "   ! " . $w );

$ops = $change->plan['operations'];
PH::print_stdout();
PH::print_stdout( PH::boldText(" * [3/4] requests (dry-run)") );
$internalTodo = array_filter( $change->internalDry, function($r){ return $r['status'] !== 'unchanged'; } );
$printInternal = function( $results, $title ){
    if( count($results) == 0 )
        return;
    $sum = array();
    foreach( $results as $r )
        $sum[$r['status']] = ( isset($sum[$r['status']]) ? $sum[$r['status']] : 0 ) + 1;
    PH::print_stdout( "   " . $title . ": " . implode(", ", array_map( function($k, $v){ return $k . " " . $v; }, array_keys($sum), $sum )) );
    foreach( $results as $r )
        if( $r['status'] !== 'unchanged' )
            PH::print_stdout( sprintf( "   %-12s internal %s %s [folder %s]", $r['status'], $r['type'], $r['name'], $r['folder'] )
                . ( !empty($r['sections']) ? " - " . implode(", ", $r['sections']) : "" ) . ( isset($r['message']) ? " - " . $r['message'] : "" ) );
};
if( count($ops) == 0 && count($internalTodo) == 0 )
{
    PH::print_stdout( "   nothing to do - the tenant already matches the change request" );
    PH::print_stdout( " * run files: " . $change->runDir );
    PH::print_stdout();
    exit(0);
}
$dry = array();
foreach( $change->dryRunLog['results'] as $r )
    $dry[$r['op']] = $r;
foreach( $ops as $op )
{
    $method = $op['action'] == 'create' ? 'POST' : ( $op['action'] == 'delete' ? 'DELETE' : ( $op['action'] == 'move' ? 'POST' : 'PUT' ) );
    $url = $op['url'] . ( !empty($op['query']) && $op['action'] == 'create' ? "?" . http_build_query($op['query']) : "" );
    $line = sprintf( "   %-8s %-7s %-6s %s %s", $op['id'], $op['action'], $method, $url, $op['name'] );
    if( $op['blocked'] !== null )
        $line .= "  BLOCKED: " . $op['blocked'];
    elseif( isset($dry[$op['id']]['message']) )
        $line .= "  - " . $dry[$op['id']]['message'];
    PH::print_stdout( $line );
    if( $op['body'] !== null && $op['action'] != 'delete' )
        PH::print_stdout( "            body " . json_encode( $op['body'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) );
}
$summary = array();
foreach( $change->dryRunLog['summary'] as $k => $v )
    $summary[] = $k . " " . $v;
PH::print_stdout( "   dry-run: " . implode(", ", $summary) );
foreach( $change->plan['warnings'] as $w )
    PH::print_stdout( "   ! " . $w );
$printInternal( $change->internalDry, "internal UI API (sections the public API does not have, after the public requests)" );
$blocked = array_filter( $ops, function($o){ return $o['blocked'] !== null; } );
$failedDry = array_filter( $change->dryRunLog['results'], function($r){ return in_array($r['status'], array('failed', 'conflict', 'error'), TRUE); } );
$failedDry = array_merge( $failedDry, array_filter( $change->internalDry, function($r){ return $r['status'] == 'error'; } ) );

if( !$execute )
{
    PH::print_stdout();
    PH::print_stdout( " * dry-run - nothing was sent. Same command with 'execute' to apply." );
    PH::print_stdout( " * run files: " . $change->runDir . " (soll/, compare/DIFF_REPORT.md, PLAN_REPORT.md, plan.json)" );
    PH::print_stdout();
    exit(0);
}
if( count($blocked) > 0 || count($failedDry) > 0 )
{
    PH::print_stdout();
    PH::print_stdout( PH::boldText(" x blocked / failed requests in the dry-run - nothing was sent, see " . $change->runDir . "/PLAN_REPORT.md") );
    exit(1);
}

// 3) execute
PH::print_stdout();
PH::print_stdout( PH::boldText(" * [4/4] EXECUTE - " . count($ops) . " request(s)" . ( count($internalTodo) > 0 ? " + " . count($internalTodo) . " internal UI API edit(s)" : "" ) . " to TSG " . $tsg) );
if( !isset(PH::$args['yes']) )
{
    PH::print_stdout( " ** type the TSG id (" . $tsg . ") to continue:" );
    $answer = trim( (string)fgets( fopen("php://stdin", "r") ) );
    if( $answer !== (string)$tsg )
        derr( "aborted - nothing was sent", null, FALSE );
}
// live output: one line per request while it runs (the summary follows at the end)
$started = microtime(TRUE);
$progress = function( $r, $n, $total ) use( $started ){
    $elapsed = (int)( microtime(TRUE) - $started );
    if( !empty($r['internal']) )
        $line = sprintf( "   [internal %3d/%-3d %4ds] %-8s %s %s [folder %s]", $n, $total, $elapsed, $r['status'], $r['type'], $r['name'], $r['folder'] );
    else
        $line = sprintf( "   [%4d/%-4d %4ds] %-8s %-7s %s %s", $n, $total, $elapsed, $r['status'], $r['action'], $r['endpoint'], $r['name'] );
    if( isset($r['message']) )
        $line .= " - " . $r['message'];
    if( isset($r['requests']) )
        foreach( $r['requests'] as $q )
            if( isset($q['error']) )
                $line .= " - HTTP " . $q['http_code'] . " " . $q['error'];
    PH::print_stdout( $line );
};
PH::print_stdout( "   (one line per request while it runs; summary at the end)" );
$log = $change->execute( isset(PH::$args['push']), isset(PH::$args['continue-on-error']), $progress );
PH::print_stdout();
PH::print_stdout( PH::boldText(" * result") );
// the requests were shown while they ran - here only the ones that did not work, together
foreach( $log['results'] as $r )
{
    if( $r['status'] == 'done' )
        continue;
    $line = sprintf( "   %-8s %-8s %-7s %s %s", $r['op'], $r['status'], $r['action'], $r['endpoint'], $r['name'] );
    if( isset($r['message']) )
        $line .= " - " . $r['message'];
    if( isset($r['requests']) )
        foreach( $r['requests'] as $q )
            if( isset($q['error']) )
                $line .= " - HTTP " . $q['http_code'] . " " . $q['error'];
    PH::print_stdout( $line );
}
$summary = array();
foreach( $log['summary'] as $k => $v )
    $summary[] = $k . " " . $v;
PH::print_stdout( "   result: " . implode(", ", $summary) );
$printInternal( $change->internalLog, "internal UI API" );
if( $log['push'] !== null )
    PH::print_stdout( "   push: " . $log['push']['status']
        . ( !empty($log['push']['not_pushable']) ? " - not pushable: " . implode(", ", $log['push']['not_pushable']) : "" )
        . ( isset($log['push']['error']) ? " - " . $log['push']['error'] : "" ) );
elseif( count($log['folders']) > 0 )
    PH::print_stdout( "   candidate config changed in: " . implode(", ", $log['folders']) . " (not pushed - 'push' or push in SCM)" );

// 4) verify
PH::print_stdout();
PH::print_stdout( PH::boldText(" * verification (export again)") );
$results = $change->verify();
$ok = 0;
foreach( $results as $r )
{
    if( $r['status'] == 'verified' )
        $ok++;
    PH::print_stdout( sprintf( "   %-9s %-9s %s", $r['status'], $r['action'], $r['change'] ) . ( isset($r['message']) ? " - " . $r['message'] : "" ) );
}
PH::print_stdout();
PH::print_stdout( $ok == count($results) ? " * all " . $ok . " change(s) verified" : PH::boldText(" x " . ( count($results) - $ok ) . " of " . count($results) . " change(s) not verified") );
PH::print_stdout( " * run files: " . $change->runDir . " (apply-log-execute.json, verify.json, compare-verify/DIFF_REPORT.md)" );
PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
exit( $ok == count($results) ? 0 : 1 );
