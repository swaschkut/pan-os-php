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

// Sync the differences of two Prisma Access exports into a target tenant
// see utils/develop/sase/scm/README_pa_sync.md and CONSULTANT_GUIDE_pa_export_compare.md
//
// 1) plan  (offline): php scm_pa_sync.php plan diff=<compare dir>/diff.json source=left|right mode=additive|mirror|merge
//                         [allow-delete] [allow-infra] [area=..] [container=..] [config-types=..] [out=<dir>]
// 2) apply (API)    : php scm_pa_sync.php apply in=scm-api://<target TSG> plan=<dir>/plan.json [execute [yes]]
//                         [push] [continue-on-error] [ops=op-0001,..] [source-dir=<export dir>] [skip-hash-check]

require_once("lib/pan_php_framework.php");
require_once(dirname(__FILE__) . "/lib/SCMPrismaAccessSync.php");

$isApply = in_array("apply", array_slice($argv, 1), TRUE);
$isPlan = in_array("plan", array_slice($argv, 1), TRUE);

$usage = "USAGE:\n"
    . "  php " . basename(__FILE__) . " plan diff=<diff.json> source=left|right [mode=additive|mirror|merge] [allow-delete] [allow-infra] [allow-network]\n"
    . "        [area=a,b] [container=c1,c2] [config-types=t1,t2] [out=<dir>]\n"
    . "  php " . basename(__FILE__) . " apply in=scm-api://<target TSG> plan=<plan.json> [execute [yes]] [push] [continue-on-error]\n"
    . "        [ops=op-0001,op-0002] [source-dir=<source export dir>] [skip-hash-check] [debugapi]\n"
    . "\n"
    . "  plan   offline; writes plan.json + PLAN_REPORT.md next to diff.json (or out=). source = the export that wins.\n"
    . "         additive: create + update · mirror: + delete (only with allow-delete) · merge: two plans, conflicts not sent\n"
    . "         allow-infra: also update infrastructure singletons (shared infrastructure settings, BGP routing)\n"
    . "         allow-network: also write NGFW network / device settings of the config area (interfaces, routing, device setup)\n"
    . "  apply  dry-run unless 'execute'; 'execute' asks for confirmation unless 'yes'; 'push' pushes the touched folders\n";

if( !$isApply && !$isPlan )
{
    print $usage;
    exit(1);
}

$listArg = function( $value ){
    if( $value === null || $value === true || $value === "" )
        return null;
    return array_values( array_filter( array_map('trim', explode(",", $value)) ) );
};

########################################################################################################################
# plan
########################################################################################################################
if( $isPlan && !$isApply )
{
    $args = array();
    foreach( array_slice($argv, 1) as $a )
    {
        $p = strpos($a, "=");
        if( $p === false )
            $args[strtolower($a)] = true;
        else
            $args[strtolower(substr($a, 0, $p))] = substr($a, $p + 1);
    }
    $known = array('plan', 'diff', 'source', 'mode', 'allow-delete', 'allow-infra', 'allow-network', 'area', 'container', 'config-types', 'out', 'help');
    foreach( array_keys($args) as $a )
        if( !in_array($a, $known, TRUE) )
        {
            print "unknown argument '" . $a . "'\n\n" . $usage;
            exit(1);
        }
    if( !isset($args['diff']) || ( !isset($args['source']) && ( !isset($args['mode']) || $args['mode'] !== 'merge' ) ) )
    {
        print "plan needs diff= and source= (not needed for mode=merge)\n\n" . $usage;
        exit(1);
    }

    PH::print_stdout();
    PH::print_stdout("*********** " . basename(__FILE__) . " plan **************");
    PH::print_stdout( "PAN-OS-PHP version: " . PH::frameworkVersion() );

    $options = array(
        'source' => isset($args['source']) ? $args['source'] : 'left',
        'mode' => isset($args['mode']) ? $args['mode'] : 'additive',
        'allow_delete' => isset($args['allow-delete']),
        'allow_infra' => isset($args['allow-infra']),
        'allow_network' => isset($args['allow-network']),
        'areas' => $listArg( isset($args['area']) ? $args['area'] : null ),
        'containers' => $listArg( isset($args['container']) ? $args['container'] : null ),
        'types' => $listArg( isset($args['config-types']) ? $args['config-types'] : null ),
    );
    if( $options['allow_delete'] && $options['mode'] != 'mirror' )
        PH::print_stdout( " ! allow-delete has only an effect with mode=mirror" );

    $sync = new SCMPrismaAccessSync( $args['diff'], $options );
    $out = isset($args['out']) && $args['out'] !== true ? $args['out'] : dirname($args['diff']);

    foreach( $sync->buildPlans() as $plan )
    {
        $suffix = $plan['mode'] == 'merge' ? "-" . $plan['source']['side'] . "-to-" . $plan['target']['side'] : "";
        SCMPrismaAccessSync::writePlan( $plan, $out, $suffix );
        $s = $plan['summary'];
        $actions = array();
        foreach( $s['by_action'] as $a => $n )
            $actions[] = $a . " " . $n;
        PH::print_stdout();
        PH::print_stdout( " * plan " . $plan['source']['tsg_id'] . " (" . $plan['source']['side'] . ") -> " . $plan['target']['tsg_id'] . " (" . $plan['target']['side'] . "), mode " . $plan['mode'] );
        PH::print_stdout( "   " . $s['operations'] . " operation(s): " . $s['enabled'] . " to execute, " . $s['blocked'] . " blocked | " . implode(", ", $actions)
            . ( $s['conflicts'] > 0 ? " | " . $s['conflicts'] . " conflict(s)" : "" ) . " | warnings " . count($plan['warnings']) );
        PH::print_stdout( "   " . $out . "/PLAN_REPORT" . $suffix . ".md, " . $out . "/plan" . $suffix . ".json" );
    }
    PH::print_stdout();
    PH::print_stdout( " * nothing was sent - review the plan, then: scm_pa_sync.php apply in=scm-api://<target TSG> plan=<plan.json>" );
    PH::print_stdout();
    exit(0);
}

########################################################################################################################
# apply
########################################################################################################################
PH::print_stdout();
PH::print_stdout("*********** " . basename(__FILE__) . " apply **************");
PH::print_stdout( "PAN-OS-PHP version: " . PH::frameworkVersion() );

$supportedArguments = Array();
$supportedArguments['apply'] = Array('niceName' => 'apply', 'shortHelp' => 'apply a plan.json to the target tenant');
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'target tenant: in=scm-api://<TSG_ID>', 'argDesc' => 'scm-api://[TSG_ID]');
$supportedArguments['plan'] = Array('niceName' => 'plan', 'shortHelp' => 'plan.json written by scm_pa_sync.php plan', 'argDesc' => '[file]');
$supportedArguments['execute'] = Array('niceName' => 'execute', 'shortHelp' => 'send the requests (default: dry-run)');
$supportedArguments['yes'] = Array('niceName' => 'yes', 'shortHelp' => 'no confirmation prompt for execute');
$supportedArguments['push'] = Array('niceName' => 'push', 'shortHelp' => 'push the touched folders after the operations and wait for the job');
$supportedArguments['continue-on-error'] = Array('niceName' => 'continue-on-error', 'shortHelp' => 'continue with the next operation after an error (dependent operations are skipped)');
$supportedArguments['ops'] = Array('niceName' => 'ops', 'shortHelp' => 'only these operations, e.g. ops=op-0001,op-0002', 'argDesc' => '[op ids]');
$supportedArguments['source-dir'] = Array('niceName' => 'source-dir', 'shortHelp' => 'source export directory with the secret lists (default: from the plan)', 'argDesc' => '[dir]');
$supportedArguments['skip-hash-check'] = Array('niceName' => 'skip-hash-check', 'shortHelp' => 'do not check that target objects are unchanged since the export');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');

$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usage );
$util->utilInit();

/* @var PanSCMAPIConnector $connector */
$connector = $util->pan->connector;
if( !is_object($connector) || get_class($connector) !== "PanSCMAPIConnector" )
    derr( "argument in=scm-api://<target TSG> is required", null, FALSE );
if( isset(PH::$args['debugapi']) )
    $connector->setShowApiCalls( TRUE );

if( !isset(PH::$args['plan']) || !is_readable(PH::$args['plan']) )
    derr( "argument plan=<plan.json> is required / not readable", null, FALSE );
$plan = json_decode( file_get_contents(PH::$args['plan']), TRUE );
if( !is_array($plan) || !isset($plan['operations']) )
    derr( "not a plan.json of scm_pa_sync.php: " . PH::$args['plan'], null, FALSE );

if( (string)$plan['target']['tsg_id'] !== (string)$connector->apihost )
    derr( "plan target TSG " . $plan['target']['tsg_id'] . " does not match in=scm-api://" . $connector->apihost, null, FALSE );

$execute = isset(PH::$args['execute']);
$s = $plan['summary'];
PH::print_stdout( " * plan: " . PH::$args['plan'] . " (" . $plan['mode'] . ", " . $plan['source']['tsg_id'] . " -> " . $plan['target']['tsg_id'] . ")" );
PH::print_stdout( " * " . $s['operations'] . " operation(s), " . $s['enabled'] . " enabled, " . $s['blocked'] . " blocked" );
PH::print_stdout( $execute ? PH::boldText(" * EXECUTE - requests are sent to TSG " . $plan['target']['tsg_id']) : " * dry-run - nothing is sent (use 'execute')" );

if( $execute && !isset(PH::$args['yes']) )
{
    PH::print_stdout( " ** type the target TSG id (" . $plan['target']['tsg_id'] . ") to continue:" );
    $answer = trim( (string)fgets( fopen("php://stdin", "r") ) );
    if( $answer !== (string)$plan['target']['tsg_id'] )
        derr( "aborted", null, FALSE );
}

$log = SCMPrismaAccessSync::apply( $connector, $plan, array(
    'execute' => $execute,
    'continue_on_error' => isset(PH::$args['continue-on-error']),
    'push' => isset(PH::$args['push']),
    'ops' => $listArg( isset(PH::$args['ops']) ? PH::$args['ops'] : null ),
    'source_dir' => isset(PH::$args['source-dir']) ? PH::$args['source-dir'] : null,
    'skip_hash_check' => isset(PH::$args['skip-hash-check']),
) );

$logFile = dirname(PH::$args['plan']) . "/apply-log-" . ( $execute ? "execute" : "dry-run" ) . "-" . date('Ymd-His') . ".json";
file_put_contents( $logFile, json_encode( $log, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . "\n" );

PH::print_stdout();
foreach( $log['results'] as $r )
{
    if( $r['status'] == 'blocked' || $r['status'] == 'skipped' && !isset($r['message']) )
        continue;
    $line = sprintf( " %-8s %-8s %-7s %s %s %s", $r['op'], $r['status'], $r['action'], $r['endpoint'], $r['container'] !== null ? "[" . $r['container'] . "]" : "", $r['name'] );
    if( isset($r['message']) )
        $line .= " - " . $r['message'];
    if( isset($r['requests']) )
        foreach( $r['requests'] as $q )
            if( isset($q['error']) )
                $line .= " - HTTP " . $q['http_code'] . " " . $q['error'];
    PH::print_stdout( $line );
}
PH::print_stdout();
$summary = array();
foreach( $log['summary'] as $k => $v )
    $summary[] = $k . " " . $v;
PH::print_stdout( " * result: " . implode(", ", $summary) );
if( $log['push'] !== null )
    PH::print_stdout( " * push: " . $log['push']['status'] . " (" . implode(", ", $log['push']['folders']) . ")" );
elseif( count($log['folders']) > 0 )
    PH::print_stdout( " * folders to push: " . implode(", ", $log['folders']) . ( $execute ? " (not pushed - use 'push' or push in SCM)" : "" ) );
PH::print_stdout( " * log: " . $logFile );
if( $execute )
    PH::print_stdout( " * next: export the target again and compare with the source - only blocked / excluded differences should remain" );
PH::print_stdout();

PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
