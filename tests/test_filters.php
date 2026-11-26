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
 * Runs every filter that has a CI example ( 'ci' => array( 'fString' => …, 'input' => … ) ) through the CLI:
 *   php pan-os-php.php type=<type> in=<input> location=any actions=display 'filter=<example>'
 * A filter fails when the CLI ends with an error. The run does not stop at the first failure: all failures are
 * listed at the end and the exit code is 1.
 *
 *   php tests/test_filters.php                     all types
 *   php tests/test_filters.php type=address,rule   only these types
 *   php tests/test_filters.php in=<file>           this configuration instead of the input of the example
 *   php tests/test_filters.php verbose             print the CLI output of every filter (default: of failures only)
 *   php tests/test_filters.php stoponerror         stop at the first failure
 *   php tests/test_filters.php jobs=4              CLI runs at the same time (default 4)
 *   php tests/test_filters.php timeout=900         seconds a CLI run may take (default 900): then it is stopped and failed
 */

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/cli_test_runner.php";

PH::print_stdout( "\n*************************************************" );
PH::print_stdout( "**************** FILTER TESTERS *****************\n" );

PH::processCliArgs();

if( ini_get('safe_mode') )
{
    derr("SAFE MODE IS ACTIVE");
}

// filter type => type of the CLI, where the names differ
$cliTypeOf = array(
    'app' => 'application',
);

// types that are not run, with the reason
$skippedTypes = array();

$onlyTypes = null;
if( isset(PH::$args['type']) )
    $onlyTypes = array_map('trim', explode(',', PH::$args['type']));
$verbose = isset(PH::$args['verbose']);
$stopOnError = isset(PH::$args['stoponerror']);
$jobs = isset(PH::$args['jobs']) ? max(1, (int)PH::$args['jobs']) : 4;
$timeout = isset(PH::$args['timeout']) ? max(1, (int)PH::$args['timeout']) : 900;

$totalFilterCount = 0;
$totalFilterWithCiCount = 0;
$missing_filters = array();
$skipped = array();
$queue = array();

$path = dirname(__FILE__) . "/";

foreach( RQuery::$defaultFilters as $type => $filtersByField )
{
    if( $onlyTypes !== null && !in_array($type, $onlyTypes) )
        continue;

    foreach( $filtersByField as $fieldName => $filtersByOperator )
    {
        if( !isset($filtersByOperator['operators']) || !is_array($filtersByOperator['operators']) )
            continue;

        foreach( $filtersByOperator['operators'] as $operator => $filter )
        {
            $totalFilterCount++;

            if( !isset($filter['ci']) )
            {
                $missing_filters[$type][] = $fieldName . " " . $operator;
                continue;
            }

            $totalFilterWithCiCount++;

            if( $operator == '>,<,=,!' )
                $operator = '<';

            $ci = $filter['ci'];
            $filterString = str_replace('%PROP%', "{$fieldName} {$operator}", $ci['fString']);
            $title = "{$type} / {$filterString}";

            if( isset($skippedTypes[$type]) )
            {
                $skipped[$type] = $skippedTypes[$type];
                continue;
            }

            if( isset(PH::$args['in']) )
            {
                // the CLI runs in a folder of its own: a relative path is one of the folder the test is started in
                $input = realpath(PH::$args['in']) !== FALSE ? realpath(PH::$args['in']) : PH::$args['in'];
                if( strpos($filterString, "location") !== FALSE )
                    continue;
            }
            else
                $input = $path . $ci['input'];

            $cliType = isset($cliTypeOf[$type]) ? $cliTypeOf[$type] : $type;

            $cli = escapeshellarg(PHP_BINARY) . " " . escapeshellarg($path . "../utils/pan-os-php.php") . " type=" . escapeshellarg($cliType)
                . " in=" . escapeshellarg($input) . " out=/dev/null location=any actions=display " . escapeshellarg("filter=" . $filterString);
            if( $type == 'rule' )
                $cli .= " ruletype=any";
            $cli .= ' shadow-ignoreinvalidaddressobjects';
            $cli .= ' 2>&1';

            $queue[] = array('title' => $title, 'cli' => $cli);
        }
    }
}

$failed = cliTestRun($queue, $jobs, $verbose, $stopOnError, $timeout);
$totalRun = count($queue);

PH::print_stdout( "\n*****  *****" );
PH::print_stdout( " - Processed {$totalFilterCount} filters" );
PH::print_stdout( " - Found {$totalFilterWithCiCount} that are CI enabled" );
PH::print_stdout( " - Run: {$totalRun}, failed: " . count($failed) );

if( count($skipped) > 0 )
{
    PH::print_stdout( "\n - types not run:" );
    foreach( $skipped as $type => $reason )
        PH::print_stdout( "    {$type}: {$reason}" );
}

PH::print_stdout( "\n" );
PH::print_stdout( " - the following filters has no test argument:" );
print_r($missing_filters);

if( count($failed) > 0 )
{
    PH::print_stdout( "\n - FAILED filters:" );
    foreach( $failed as $line )
        PH::print_stdout( "    " . $line );
}

PH::print_stdout();
PH::print_stdout( "\n*********** FINISHED TESTING FILTERS ************" );
PH::print_stdout( "*************************************************\n" );

exit( count($failed) > 0 ? 1 : 0 );
