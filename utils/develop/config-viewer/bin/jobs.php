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

/**
 * starts step $n of a run (most runs have one step; an import two for SCM). Only a step with 'network' gets a network
 * (in a container: PANOSPHP_VIEWER_CONTAINER_NETWORK, default bridge); every other one none. null: not started (finished
 * as failed).
 */
function jobsStart( array $job, int $n )
{
    global $app, $container, $tool;
    $step = $job['steps'][$n];
    $job = array_merge( $job, array( 'tool' => $step['tool'], 'args' => $step['args'], 'rawArgs' => $step['rawArgs'], 'network' => !empty( $step['network'] ) ) );
    // only the first step reads the version (in=); a later step works on what the first one wrote
    if( $n > 0 )
    {
        $job['config'] = null;
        $job['file'] = null;
    }
    $log = $job['dir'] . '/run.log';
    // the log of pan-os-php (tool-log.txt) goes to the folder of the run, not into the installation
    $env = array( 'PATH' => (string)getenv( 'PATH' ), 'HOME' => $job['dir'], 'TMPDIR' => $job['dir'], 'PANOSPHP_LOG_DIR' => $job['dir'] . '/log' );
    // what a run type of a plug-in sets (checked names: PANOSPHP_…, not PANOSPHP_VIEWER_…)
    $env += $job['env'];
    // tests only: the extra licence keys of the test (lib/misc-classes/PluginLicense.php)
    if( getenv( 'PANOSPHP_LICENSE_TEST_KEYS' ) )
        $env['PANOSPHP_LICENSE_TEST_KEYS'] = (string)getenv( 'PANOSPHP_LICENSE_TEST_KEYS' );
    if( $container !== null )
    {
        try
        {
            $cmd = $container->runCommand( $job );
        }
        catch( Exception $e )
        {
            $app->runnerFinish( $job['id'], 'failed', 'the run could not be started: ' . substr( $e->getMessage(), 0, 200 ) );
            return null;
        }
        foreach( array_keys( $job['env'] ) as $k )
            unset( $env[$k] );
        // the client of the runtime: where the runtime is (DOCKER_HOST, rootless podman), nothing of the job
        foreach( array( 'DOCKER_HOST', 'DOCKER_CONFIG', 'CONTAINER_HOST', 'XDG_RUNTIME_DIR' ) as $k )
            if( getenv( $k ) !== FALSE )
                $env[$k] = (string)getenv( $k );
        $env['HOME'] = (string)( getenv( 'HOME' ) ?: '/' );
        unset( $env['TMPDIR'], $env['PANOSPHP_LOG_DIR'] );
    }
    else
        $cmd = array_merge( array( PHP_BINARY, $tool, 'type=' . $job['tool'] ), $job['config'] !== null ? array( 'in=' . $job['config'] ) : array(), $job['args'] );
    $proc = proc_open( $cmd, array( 0 => array( 'file', '/dev/null', 'r' ), 1 => array( 'file', $log, $n > 0 ? 'a' : 'w' ), 2 => array( 'redirect', 1 ) ), $pipes, $job['dir'], $env );
    if( !is_resource( $proc ) )
    {
        $app->runnerFinish( $job['id'], 'failed', 'the run could not be started' );
        return null;
    }
    return $proc;
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
            $code = proc_close( $r['proc'] );
            // proc_get_status reports the exit code only once; proc_close gives it when the status had none (-1)
            $exit = $st['exitcode'] !== -1 ? (int)$st['exitcode'] : (int)$code;
            // a run with more steps (import: download, then offline conversion): the next one, same folder and log
            $next = $r['step'] + 1;
            if( $exit === 0 && empty( $st['signaled'] ) && $next < count( $r['job']['steps'] ) && $state === 'running' )
            {
                $proc = jobsStart( $r['job'], $next );
                if( $proc !== null )
                {
                    $running[$id]['proc'] = $proc;
                    $running[$id]['step'] = $next;
                }
                else
                    unset( $running[$id] );
                continue;
            }
            if( $exit === 0 && empty( $st['signaled'] ) )
                $app->runnerFinish( $id, 'done' );
            else
            {
                // out of memory (killed: exit code 137 / signal 9, or the log says so) is told apart from other errors
                $log = $r['dir'] . '/run.log';
                $tail = is_file( $log ) ? (string)file_get_contents( $log, FALSE, null, max( 0, filesize( $log ) - 65536 ) ) : '';
                list( $reason, $msg ) = ViewerApp::runFailure( $exit, !empty( $st['signaled'] ) ? (int)$st['termsig'] : null, $tail,
                    $container !== null ? $container->memory : null );
                $app->runnerFinish( $id, 'failed', $msg, $reason );
            }
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
            $app->runnerFinish( $id, 'failed', 'stopped after ' . $timeout . ' seconds (setting PANOSPHP_VIEWER_JOB_TIMEOUT)', 'timeout' );
            unset( $running[$id] );
        }
    }

    while( count( $running ) < $parallel && ( $job = $app->runnerTake() ) !== null )
    {
        $proc = jobsStart( $job, 0 );
        if( $proc === null )
            continue;
        $running[$job['id']] = array( 'proc' => $proc, 'started' => time(), 'dir' => $job['dir'], 'jid' => $job['jid'], 'job' => $job, 'step' => 0 );
    }
    usleep( 250000 );
}

foreach( $running as $id => $r )
{
    jobsKill( $r['proc'], $r['jid'] );
    $app->runnerFinish( $id, 'failed', 'the job runner was stopped' );
}
print "config-viewer jobs: stopped\n";
