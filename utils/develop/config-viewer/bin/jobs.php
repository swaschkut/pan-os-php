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
 * PANOSPHP_VIEWER_CONTAINER=docker|podman: every run is one container (lib/ViewerContainer.php: no network, read-only,
 * only the project folder read-only and the folder of the run). Then this process is the only part that needs the
 * container runtime - run it apart from the web part (own container / own OS user); the web part gets no access.
 * Without it a run is a process of this OS user.
 */
if( PHP_SAPI !== 'cli' )
{
    http_response_code( 404 );
    exit;
}
require_once dirname(__FILE__) . '/../lib/ViewerApp.php';
require_once dirname(__FILE__) . '/../lib/ViewerContainer.php';

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
try
{
    $container = ViewerContainer::fromEnv( $app->dataDir );
    if( $container !== null && ( $err = $container->check() ) !== null )
        throw new Exception( $err );
}
catch( Exception $e )
{
    // no fall back to runs without a container: that would be less isolation than configured
    fwrite( STDERR, "config-viewer jobs: container: " . $e->getMessage() . "\n" );
    exit( 1 );
}
$app->runnerReset();
if( $container !== null )
    $container->cleanup();

$running = array();   // job id => array( proc, started )
$stop = FALSE;
if( function_exists( 'pcntl_async_signals' ) )
{
    pcntl_async_signals( TRUE );
    foreach( array( SIGTERM, SIGINT ) as $sig )
        pcntl_signal( $sig, function() use ( &$stop ) { $stop = TRUE; } );
}
print "config-viewer jobs: running (" . $parallel . " parallel, data " . $app->dataDir . ", " . ( $container !== null ? "one " . $container->program . " container per run, image " . $container->image : "no container" ) . ")\n";

function jobsKill( $proc, ?string $jid = null ): void
{
    global $container;
    // the process is only the client of the runtime - the container itself has to be removed
    if( $container !== null && $jid !== null )
        $container->kill( $jid );
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
            jobsKill( $r['proc'], $r['jid'] );
            if( $state === null )
                ViewerApp::rmTree( $r['dir'] );
            unset( $running[$id] );
        }
        elseif( time() - $r['started'] > $timeout )
        {
            jobsKill( $r['proc'], $r['jid'] );
            $app->runnerFinish( $id, 'failed', 'stopped after ' . $timeout . ' seconds' );
            unset( $running[$id] );
        }
    }

    while( count( $running ) < $parallel && ( $job = $app->runnerTake() ) !== null )
    {
        $log = $job['dir'] . '/run.log';
        $env = array( 'PATH' => (string)getenv( 'PATH' ), 'HOME' => $job['dir'], 'TMPDIR' => $job['dir'] );
        if( $container !== null )
        {
            try
            {
                $cmd = $container->runCommand( $job );
            }
            catch( Exception $e )
            {
                $app->runnerFinish( $job['id'], 'failed', 'the run could not be started' );
                continue;
            }
            // the client of the runtime: where the runtime is (DOCKER_HOST, rootless podman), nothing of the job
            foreach( array( 'DOCKER_HOST', 'DOCKER_CONFIG', 'CONTAINER_HOST', 'XDG_RUNTIME_DIR' ) as $k )
                if( getenv( $k ) !== FALSE )
                    $env[$k] = (string)getenv( $k );
            $env['HOME'] = (string)( getenv( 'HOME' ) ?: '/' );
            unset( $env['TMPDIR'] );
        }
        else
            $cmd = array_merge( array( PHP_BINARY, $tool, 'type=' . $job['tool'], 'in=' . $job['config'] ), $job['args'] );
        $proc = proc_open( $cmd, array( 0 => array( 'file', '/dev/null', 'r' ), 1 => array( 'file', $log, 'w' ), 2 => array( 'file', $log, 'a' ) ), $pipes, $job['dir'], $env );
        if( !is_resource( $proc ) )
        {
            $app->runnerFinish( $job['id'], 'failed', 'the run could not be started' );
            continue;
        }
        $running[$job['id']] = array( 'proc' => $proc, 'started' => time(), 'dir' => $job['dir'], 'jid' => $job['jid'] );
    }
    usleep( 250000 );
}

foreach( $running as $id => $r )
{
    jobsKill( $r['proc'], $r['jid'] );
    $app->runnerFinish( $id, 'failed', 'the job runner was stopped' );
}
print "config-viewer jobs: stopped\n";
