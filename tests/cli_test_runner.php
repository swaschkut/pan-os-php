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
 * Shared by tests/test_filters.php and tests/test_actions.php: runs a list of CLI commands, some at the same time,
 * prints one line per command ( ok / FAIL ) in the order of the list - with the output of the CLI for a failure - and
 * returns the failures. A command fails with an exit code other than 0, with a PHP error in its output, or when it
 * runs longer than $timeout seconds ( it is stopped ).
 *
 * @param array $queue list of array( 'title' => text of the line, 'cli' => command )
 * @return string[] title of every failed command, with the reason
 */
function cliTestRun(array $queue, int $jobs = 4, bool $verbose = FALSE, bool $stopOnError = FALSE, int $timeout = 900): array
{
    $queue = array_values($queue);
    $jobs = max(1, $jobs);

    // the CLI runs in a folder of its own: files an action writes ( reports as HTML, exports ) do not land in the
    // repository; the folder is removed at the end
    $workDir = sys_get_temp_dir() . '/pan-os-php-cli-test-work-' . getmypid() . '-' . mt_rand();
    if( !mkdir($workDir, 0700, TRUE) )
        derr("cannot create the working folder " . $workDir);
    $failed = array();
    $running = array();
    $results = array();
    $next = 0;
    $printed = 0;
    $stop = FALSE;

    while( ( $next < count($queue) && !$stop ) || count($running) > 0 )
    {
        while( !$stop && count($running) < $jobs && $next < count($queue) )
        {
            $tmp = tempnam(sys_get_temp_dir(), 'pan-os-php-cli-test-');
            $pipes = array();
            $process = proc_open('exec ' . $queue[$next]['cli'], array(0 => array('file', '/dev/null', 'r'), 1 => array('file', $tmp, 'w'), 2 => array('file', $tmp, 'a')), $pipes, $workDir);
            if( $process === FALSE )
                derr("cannot start: " . $queue[$next]['cli']);
            $running[$next] = array('process' => $process, 'file' => $tmp, 'start' => time());
            $next++;
        }

        foreach( $running as $index => $run )
        {
            $status = proc_get_status($run['process']);
            $timedOut = FALSE;
            if( $status['running'] )
            {
                if( time() - $run['start'] <= $timeout )
                    continue;
                // 'exec' in front: the signal reaches the CLI and not only a shell around it
                proc_terminate($run['process'], 9);
                $timedOut = TRUE;
            }
            proc_close($run['process']);
            $results[$index] = array('exit' => $timedOut ? 'timeout' : $status['exitcode'], 'output' => explode("\n", rtrim((string)file_get_contents($run['file']))));
            unlink($run['file']);
            unset($running[$index]);
        }

        while( isset($results[$printed]) )
        {
            $title = $queue[$printed]['title'];
            $cli = $queue[$printed]['cli'];
            $retValue = $results[$printed]['exit'];
            $output = $results[$printed]['output'];
            unset($results[$printed]);
            $printed++;

            // an error of PHP that does not end the run with an exit code
            $phpError = FALSE;
            foreach( $output as $line )
                if( preg_match('/^PHP (Parse error|Fatal error|Warning|Deprecated|Notice)|^(Parse error|Fatal error|Warning|Deprecated|Notice): /', $line) )
                    $phpError = TRUE;

            $ok = $retValue === 0 && !$phpError;
            PH::print_stdout( ($ok ? " ok    " : " FAIL  ") . $title );

            if( !$ok || $verbose )
            {
                PH::print_stdout( "   * CLI: {$cli}" );
                foreach( $output as $line )
                    PH::print_stdout( '   ##  ' . $line );
                PH::print_stdout();
            }

            if( !$ok )
            {
                if( $retValue === 'timeout' )
                    $failed[] = $title . "  (stopped after {$timeout} seconds)";
                else
                    $failed[] = $title . ( $retValue != 0 ? "  (exit code {$retValue})" : "  (PHP error in the output)" );
                if( $stopOnError )
                    $stop = TRUE;
            }
        }

        if( count($running) > 0 )
            usleep(20000);
    }

    cliTestRemoveFolder($workDir);

    return $failed;
}

/** removes a folder with everything in it ( links are removed, not followed ) */
function cliTestRemoveFolder(string $folder): void
{
    if( !is_dir($folder) || is_link($folder) )
        return;
    foreach( scandir($folder) as $entry )
    {
        if( $entry === '.' || $entry === '..' )
            continue;
        $path = $folder . '/' . $entry;
        if( is_dir($path) && !is_link($path) )
            cliTestRemoveFolder($path);
        else
            unlink($path);
    }
    rmdir($folder);
}
