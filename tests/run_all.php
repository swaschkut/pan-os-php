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
 * Runs the tests of this folder ( tests/test_*.php ), one after the other, and lists at the end which passed and
 * which failed. Exit code 1 when a test failed. The output of every test is kept in a log file.
 *
 *   php tests/run_all.php                     every test
 *   php tests/run_all.php quick               without the long ones ( test_filters, test_actions: every filter /
 *                                             action through the CLI, about half an hour )
 *   php tests/run_all.php only=regions,mergers   only tests whose name contains one of these words
 *   php tests/run_all.php logdir=/path        where the log files go ( default: a new folder in the temp directory )
 *
 * A test passes with exit code 0 and without a line "PHP Fatal error" / "PHP Parse error" in its output.
 */

$dir = dirname(__FILE__);
$quick = FALSE;
$only = array();
$logDir = null;
foreach( array_slice($argv, 1) as $arg )
{
    if( $arg === 'quick' )
        $quick = TRUE;
    elseif( strpos($arg, 'only=') === 0 )
        $only = array_filter(array_map('trim', explode(',', substr($arg, 5))), 'strlen');
    elseif( strpos($arg, 'logdir=') === 0 )
        $logDir = substr($arg, 7);
    else
    {
        fwrite(STDERR, "unknown argument: {$arg}\n");
        exit(2);
    }
}

// every filter / every action through the CLI
$long = array('test_filters.php', 'test_actions.php');

// tests that work on files of their own and need arguments: not run here
$needsArguments = array(
    'test_template_manageddevice_with_no_dg.php' => 'needs folder=/path/to/configs',
);

if( $logDir === null )
    $logDir = sys_get_temp_dir() . '/pan-os-php-tests-' . date('Ymd-His') . '-' . getmypid();
if( !is_dir($logDir) && !mkdir($logDir, 0700, TRUE) )
{
    fwrite(STDERR, "cannot create the log folder {$logDir}\n");
    exit(2);
}

$tests = glob($dir . '/test_*.php');
sort($tests);

$results = array();
foreach( $tests as $file )
{
    $name = basename($file);
    if( isset($needsArguments[$name]) )
    {
        if( count($only) == 0 )
            $results[$name] = array('state' => 'skipped', 'seconds' => 0, 'note' => $needsArguments[$name]);
        continue;
    }
    if( $quick && in_array($name, $long) )
    {
        $results[$name] = array('state' => 'skipped', 'seconds' => 0, 'note' => 'long test, not run with "quick"');
        continue;
    }
    if( count($only) > 0 )
    {
        $wanted = FALSE;
        foreach( $only as $word )
            if( stripos($name, $word) !== FALSE )
                $wanted = TRUE;
        if( !$wanted )
            continue;
    }

    print str_pad($name, 50) . ' ... ';
    $log = $logDir . '/' . substr($name, 0, -4) . '.log';
    $start = microtime(TRUE);
    $exit = 0;
    $unused = array();
    exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($file) . ' > ' . escapeshellarg($log) . ' 2>&1', $unused, $exit);
    $seconds = (int)round(microtime(TRUE) - $start);

    $fatal = FALSE;
    $handle = fopen($log, 'r');
    if( $handle !== FALSE )
    {
        while( ( $line = fgets($handle) ) !== FALSE )
            if( preg_match('/^(PHP )?(Fatal error|Parse error)/', $line) )
            {
                $fatal = TRUE;
                break;
            }
        fclose($handle);
    }

    $ok = $exit === 0 && !$fatal;
    $results[$name] = array('state' => $ok ? 'ok' : 'FAILED', 'seconds' => $seconds,
        'note' => $ok ? '' : ( $exit !== 0 ? "exit code {$exit}" : 'PHP error in the output' ) . ", see {$log}");
    print ( $ok ? 'ok' : 'FAILED' ) . " ({$seconds} s)\n";
}

$failed = 0;
print "\n";
foreach( $results as $name => $r )
{
    if( $r['state'] === 'FAILED' )
        $failed++;
    if( $r['state'] !== 'ok' )
        print str_pad($r['state'], 8) . $name . ': ' . $r['note'] . "\n";
}
print "\n" . count($results) . " tests, {$failed} failed - logs in {$logDir}\n";
exit( $failed > 0 ? 1 : 0 );
