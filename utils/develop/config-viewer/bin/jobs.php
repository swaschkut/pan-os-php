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

/**
 * config-viewer job runner: executes the queued runs (ViewerApp::JOB_TYPES, e.g. stats). The web server process
 * only writes a row into the queue; this process starts pan-os-php for it:
 *   - no shell (argument array), arguments only from the checked values stored with the job
 *   - in= is the version file, the working directory is the folder of the job (result files stay there)
 *   - output goes to run.log in that folder; a run is stopped after the time limit or when it is cancelled
 *
 *   php bin/jobs.php               run it as the same OS user as the web server (both need the data directory)
 *
 * Environment: PANOSPHP_VIEWER_DATA, PANOSPHP_VIEWER_JOBS (parallel runs, default 2),
 * PANOSPHP_VIEWER_JOB_TIMEOUT (seconds per run, default 3600).
 * Not yet: one container per job (todo/config-viewer-api.md, decision 2) - today a run is a process of this OS user.
 */
if( PHP_SAPI !== 'cli' )
{
    http_response_code( 404 );
    exit;
}
require_once dirname(__FILE__) . '/../lib/ViewerApp.php';

$app = new ViewerApp();
$parallel = max( 1, min( 16, (int)( getenv( 'PANOSPHP_VIEWER_JOBS' ) ?: 2 ) ) );
$timeout = max( 10, (int)( getenv( 'PANOSPHP_VIEWER_JOB_TIMEOUT' ) ?: 3600 ) );
$tool = $app->repoDir . '/utils/pan-os-php.php';

$lock = fopen( $app->dataDir . '/jobs.lock', 'c' );
if( !$lock || !flock( $lock, LOCK_EX | LOCK_NB ) )
{
    fwrite( STDERR, "config-viewer jobs: already running for " . $app->dataDir . "\n" );
    exit( 1 );
}
$app->runnerReset();

$running = array();   // job id => array( proc, started )
$stop = FALSE;
if( function_exists( 'pcntl_async_signals' ) )
{
    pcntl_async_signals( TRUE );
    foreach( array( SIGTERM, SIGINT ) as $sig )
        pcntl_signal( $sig, function() use ( &$stop ) { $stop = TRUE; } );
}
print "config-viewer jobs: running (" . $parallel . " parallel, data " . $app->dataDir . ")\n";

function jobsKill( $proc ): void
{
    $st = proc_get_status( $proc );
    if( $st['running'] )
    {
        proc_terminate( $proc, 15 );
        usleep( 300000 );
        $st = proc_get_status( $proc );
        if( $st['running'] )
            proc_terminate( $proc, 9 );
    }
    proc_close( $proc );
}

while( !$stop )
{
    // finished, cancelled, deleted or too long
    foreach( $running as $id => $r )
    {
        $st = proc_get_status( $r['proc'] );
        $state = $app->runnerState( $id );
        if( !$st['running'] )
        {
            proc_close( $r['proc'] );
            $app->runnerFinish( $id, $st['exitcode'] === 0 ? 'done' : 'failed', $st['exitcode'] === 0 ? null : 'pan-os-php ended with an error (see run.log)' );
            unset( $running[$id] );
        }
        elseif( $state !== 'running' )
        {
            jobsKill( $r['proc'] );
            if( $state === null )
                ViewerApp::rmTree( $r['dir'] );
            unset( $running[$id] );
        }
        elseif( time() - $r['started'] > $timeout )
        {
            jobsKill( $r['proc'] );
            $app->runnerFinish( $id, 'failed', 'stopped after ' . $timeout . ' seconds' );
            unset( $running[$id] );
        }
    }

    while( count( $running ) < $parallel && ( $job = $app->runnerTake() ) !== null )
    {
        $cmd = array_merge( array( PHP_BINARY, $tool, 'type=' . $job['type'], 'in=' . $job['config'] ), $job['args'] );
        $log = $job['dir'] . '/run.log';
        $proc = proc_open( $cmd, array( 0 => array( 'file', '/dev/null', 'r' ), 1 => array( 'file', $log, 'w' ), 2 => array( 'file', $log, 'a' ) ), $pipes, $job['dir'],
            array( 'PATH' => (string)getenv( 'PATH' ), 'HOME' => $job['dir'], 'TMPDIR' => $job['dir'] ) );
        if( !is_resource( $proc ) )
        {
            $app->runnerFinish( $job['id'], 'failed', 'the run could not be started' );
            continue;
        }
        $running[$job['id']] = array( 'proc' => $proc, 'started' => time(), 'dir' => $job['dir'] );
    }
    usleep( 250000 );
}

foreach( $running as $id => $r )
{
    jobsKill( $r['proc'] );
    $app->runnerFinish( $id, 'failed', 'the job runner was stopped' );
}
print "config-viewer jobs: stopped\n";
