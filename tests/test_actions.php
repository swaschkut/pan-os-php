<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
 * Copyright (c) 2019, Palo Alto Networks Inc.
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
 */

/**
 * Runs every action that needs no argument through the CLI ( utils/lib/util_action_filter.json lists the actions ):
 *   php pan-os-php.php type=<type> in=<input> out=/dev/null location=any actions=<action>
 * An action fails when the CLI ends with an error. The run does not stop at the first failure: all failures are
 * listed at the end and the exit code is 1. Actions with arguments are listed, they are tested by the tests of
 * their own ( tests/test_*_actions.php, test_regions.php, … ).
 *
 *   php tests/test_actions.php                     all types
 *   php tests/test_actions.php type=address,rule   only these types
 *   php tests/test_actions.php in=<file>           this configuration instead of tests/input/panorama-8.0.xml
 *   php tests/test_actions.php verbose             print the CLI output of every action (default: of failures only)
 *   php tests/test_actions.php stoponerror         stop at the first failure
 *   php tests/test_actions.php jobs=4              CLI runs at the same time (default 4)
 *   php tests/test_actions.php timeout=900         seconds a CLI run may take (default 900): then it is stopped and failed
 */

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__) . "/../lib/pan_php_framework.php";
require_once dirname(__FILE__) . "/cli_test_runner.php";

PH::print_stdout("\n*************************************************");
PH::print_stdout("**************** ACTION TESTERS *****************\n");

PH::processCliArgs();

if( ini_get('safe_mode') )
{
    derr("SAFE MODE IS ACTIVE");
}

// actions that are not run, with the reason; '*' : every type
$skippedActions = array(
    '*' => array(),
    'address' => array(
        'value-set-reverse-dns' => 'asks a DNS server',
        'value-set-ip-for-fqdn' => 'asks a DNS server',
    ),
    'device' => array(
        'authkey-display-all' => 'needs a device ( API )',
        'authkey-display-default' => 'needs a device ( API )',
        'system-restart' => 'needs a device ( API )',
    ),
    'interface' => array(
        'remove' => 'not implemented yet ( the action says so )',
    ),
    'routing' => array(
        'display-route-table-fast' => 'needs a device ( API )',
    ),
    'rule' => array(
        'position-move-to-bottom' => 'needs a rule selection',
        'position-move-to-top' => 'needs a rule selection',
        'display-app-seen' => 'needs a device ( API )',
    ),
);

$onlyTypes = null;
if( isset(PH::$args['type']) )
    $onlyTypes = array_map('trim', explode(',', PH::$args['type']));
$verbose = isset(PH::$args['verbose']);
$stopOnError = isset(PH::$args['stoponerror']);
$jobs = isset(PH::$args['jobs']) ? max(1, (int)PH::$args['jobs']) : 4;
$timeout = isset(PH::$args['timeout']) ? max(1, (int)PH::$args['timeout']) : 900;

$totalActionCount = 0;
$missingActionArgCount = 0;
$missing_actionsArgument = array();
$skipped = array();
$queue = array();

$path = dirname(__FILE__) . "/";
$JSONarray = file_get_contents($path . "../utils/lib/util_action_filter.json");
$json_a = json_decode($JSONarray, TRUE);
if( $json_a === null )
    derr("invalid JSON file provided", null, FALSE);

// the CLI runs in a folder of its own: a relative path is one of the folder the test is started in
if( isset(PH::$args['in']) )
    $input = realpath(PH::$args['in']) !== FALSE ? realpath(PH::$args['in']) : PH::$args['in'];
else
    $input = $path . 'input/panorama-8.0.xml';

foreach( $json_a as $type => $UTILtype )
{
    if( !isset($UTILtype['action']) || !is_array($UTILtype['action']) || count($UTILtype['action']) == 0 )
        continue;
    if( $onlyTypes !== null && !in_array($type, $onlyTypes) )
        continue;

    foreach( $UTILtype['action'] as $actionName => $action )
    {
        $totalActionCount++;

        if( strpos($actionName, '-FastAPI') !== FALSE )
        {
            $skipped[$type][$actionName] = 'needs a device ( API )';
            continue;
        }
        if( isset($skippedActions[$type][$actionName]) )
        {
            $skipped[$type][$actionName] = $skippedActions[$type][$actionName];
            continue;
        }
        if( isset($skippedActions['*'][$actionName]) )
        {
            $skipped[$type][$actionName] = $skippedActions['*'][$actionName];
            continue;
        }

        if( isset($action['args']) )
        {
            $missingActionArgCount++;
            $missing_actionsArgument[$type][] = $actionName;
            continue;
        }

        $cli = escapeshellarg(PHP_BINARY) . " " . escapeshellarg($path . "../utils/pan-os-php.php") . " type=" . escapeshellarg($type)
            . " in=" . escapeshellarg($input) . " out=/dev/null location=any " . escapeshellarg("actions=" . $actionName);
        if( $type == 'rule' )
            $cli .= " ruletype=any";
        $cli .= ' shadow-ignoreinvalidaddressobjects';
        $cli .= ' 2>&1';

        $queue[] = array('title' => "{$type} / {$actionName}", 'cli' => $cli);
    }
}

$failed = cliTestRun($queue, $jobs, $verbose, $stopOnError, $timeout);

PH::print_stdout("\n*****  *****");
PH::print_stdout(" - Processed {$totalActionCount} actions");
PH::print_stdout(" - Run: " . count($queue) . ", failed: " . count($failed));
PH::print_stdout(" - Found {$missingActionArgCount} that are not run because the action needs arguments");

if( count($skipped) > 0 )
{
    PH::print_stdout("\n - actions not run:");
    foreach( $skipped as $type => $actions )
        foreach( $actions as $actionName => $reason )
            PH::print_stdout("    {$type} / {$actionName}: {$reason}");
}

PH::print_stdout("\n");
PH::print_stdout(" - the following actions are not tested here ( they need arguments ):");
print_r($missing_actionsArgument);

if( count($failed) > 0 )
{
    PH::print_stdout("\n - FAILED actions:");
    foreach( $failed as $line )
        PH::print_stdout("    " . $line);
}

PH::print_stdout();
PH::print_stdout("\n*********** FINISHED TESTING ACTIONS ************");
PH::print_stdout("*************************************************\n");

exit( count($failed) > 0 ? 1 : 0 );
