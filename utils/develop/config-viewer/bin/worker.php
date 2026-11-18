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
 * config-viewer worker: loads ONE configuration once and keeps it in memory (UTIL::$sharedConfig). Started by
 * bin/service.php on request of ViewerApp::session(), never by a user. Requests arrive on a unix socket inside the project folder, one JSON line
 * per connection:
 *   read    type, args        -> runs in a forked child (a failing run / exit() can not hurt the loaded configuration)
 *   change  type, args, note  -> tried in a forked child first; only when that worked it runs on the real memory
 *   save    file              -> writes the memory to a new file (only when there are unsaved changes)
 *   status / close
 * Unsaved changes are written to the autosave file every <autosave> minutes and when the worker stops.
 *
 * Not started on its own: bin/service.php forks and includes this file.
 */
if( PHP_SAPI !== 'cli' )
{
    http_response_code( 404 );
    exit;
}
// included by bin/service.php in a forked child, with the (validated) parameters in $viewerWorker
if( !isset( $viewerWorker ) || !is_array( $viewerWorker ) )
{
    fwrite( STDERR, "config-viewer worker: started by bin/service.php only\n" );
    exit( 2 );
}
$configFile = $viewerWorker['config'];
$sockFile = $viewerWorker['sock'];
$pidFile = $viewerWorker['pid'];
$logFile = $viewerWorker['log'];
$autosaveFile = $viewerWorker['autosave'];
$autosaveSec = max( 60, (int)$viewerWorker['autosaveMin'] * 60 );
$idleSec = max( 60, (int)$viewerWorker['idleMin'] * 60 );

posix_setsid();
ini_set( 'error_log', $logFile );
ini_set( 'log_errors', '1' );
ini_set( 'display_errors', '0' );
// whatever pan-os-php prints outside of a captured run is dropped
ob_start( function( $buffer ) { return ''; }, 4096 );
file_put_contents( $pidFile, (string)getmypid(), LOCK_EX );
chmod( $pidFile, 0600 );

$GLOBALS['viewerIsChild'] = FALSE;
$GLOBALS['viewerState'] = array( 'dirty' => FALSE, 'changes' => array(), 'saved' => null, 'autosaved' => null, 'loaded' => time() );

/**
 * The pan-os-php framework turns every PHP warning into a fatal error (also with @). The worker's own file and
 * socket calls must not stop it, e.g. a select() interrupted by a finished child.
 */
function viewerQuiet( callable $fn )
{
    set_error_handler( function() { return TRUE; } );
    try
    {
        return $fn();
    }
    finally
    {
        restore_error_handler();
    }
}

function viewerUnlink( $file )
{
    viewerQuiet( function() use ( $file ) { if( file_exists( $file ) ) unlink( $file ); } );
}

function viewerLog( $text )
{
    global $logFile;
    viewerQuiet( function() use ( $logFile, $text ) { file_put_contents( $logFile, date( 'c' ) . ' ' . $text . "\n", FILE_APPEND ); } );
}

function viewerStatus()
{
    $s = $GLOBALS['viewerState'];
    return array( 'dirty' => $s['dirty'], 'changes' => $s['changes'], 'saved' => $s['saved'], 'autosaved' => $s['autosaved'], 'loaded' => $s['loaded'] );
}

function viewerWrite( $path )
{
    $tmp = $path . '.tmp';
    UTIL::$sharedConfig['pan']->save_to_file( $tmp, FALSE );
    if( !is_file( $tmp ) || filesize( $tmp ) < 10 )
        return FALSE;
    return viewerQuiet( function() use ( $tmp, $path ) { chmod( $tmp, 0600 ); return rename( $tmp, $path ); } );
}

/** one pan-os-php run on the configuration in memory; returns the JSON output as text */
function viewerRun( $type, array $args )
{
    global $configFile;
    $argv = array_merge( array( 'config-viewer', 'in=' . $configFile, 'shadow-json' ), $args );
    $argc = count( $argv );
    PH::resetCliArgs( $argv );
    PH::$JSON_OUT = array();
    PH::$JSON_TMP = array();
    PH::$JSON_OUTlog = '';
    ob_start();
    $util = PH::callPANOSPHP( $type, $argv, $argc, 'config-viewer' );
    unset( $util );
    return (string)ob_get_clean();
}

function viewerDecode( $out )
{
    $start = strpos( $out, '{' );
    $json = $start === FALSE ? null : json_decode( substr( $out, $start ), TRUE );
    if( is_array( $json ) && !isset( $json['error'] ) )
        return array( 'ok' => TRUE, 'json' => $json );
    $msg = '';
    if( is_array( $json ) )
        $msg = is_string( $json['error'] ) ? $json['error'] : json_encode( $json['error'] );
    elseif( preg_match( '/\*\*ERROR\*\*\s*(.+)/', $out, $m ) )
        $msg = $m[1];
    return array( 'ok' => FALSE, 'error' => trim( $msg ) !== '' ? trim( $msg ) : 'pan-os-php stopped with an error - check the syntax of filter / actions' );
}

function viewerSend( $conn, array $answer )
{
    viewerQuiet( function() use ( $conn, $answer ) {
        if( is_resource( $conn ) )
        {
            fwrite( $conn, json_encode( $answer, JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE ) );
            fclose( $conn );
        }
    } );
}

/**
 * Runs in a forked child and never returns. The answer is sent from a shutdown function, so an exit() inside
 * pan-os-php still gives an answer. $send = FALSE: only the exit code tells whether the run worked (trial of a change).
 */
function viewerChild( $conn, $type, array $args, $send )
{
    $GLOBALS['viewerIsChild'] = TRUE;
    pcntl_alarm( 600 );
    $done = FALSE;
    register_shutdown_function( function() use ( $conn, $send, &$done ) {
        $out = '';
        while( ob_get_level() > 0 )
            $out = (string)ob_get_clean() . $out;
        $r = viewerDecode( $out );
        if( !$done && $r['ok'] )
            $r = array( 'ok' => FALSE, 'error' => 'the run stopped' );
        if( $send || !$r['ok'] )
            viewerSend( $conn, $r + array( 'status' => viewerStatus() ) );
        posix_kill( getmypid(), $r['ok'] ? SIGUSR1 : SIGKILL );
    } );
    try
    {
        ob_start();
        print viewerRun( $type, $args );
        $done = TRUE;
    }
    catch( Throwable $e )
    {
        while( ob_get_level() > 0 )
            ob_end_clean();
        ob_start();
        print json_encode( array( 'error' => $e->getMessage() ) );
    }
    exit( 0 );
}

register_shutdown_function( function() use ( $sockFile, $pidFile, $autosaveFile ) {
    if( $GLOBALS['viewerIsChild'] )
        return;
    // the worker stops: unsaved changes go to the autosave file, the viewer turns it into a version
    if( $GLOBALS['viewerState']['dirty'] && isset( UTIL::$sharedConfig['pan'] ) && UTIL::$sharedConfig['pan'] !== null )
    {
        try { viewerWrite( $autosaveFile ); } catch( Throwable $e ) { }
    }
    viewerUnlink( $sockFile );
    viewerUnlink( $pidFile );
} );

$repo = dirname( __FILE__ ) . '/../../../..';
require_once $repo . '/lib/pan_php_framework.php';
require_once $repo . '/utils/lib/UTIL.php';

// ---- load once
$doc = new DOMDocument();
if( !$doc->load( $configFile, XML_PARSE_BIG_LINES | LIBXML_NONET ) )
{
    viewerLog( 'configuration can not be read' );
    exit( 5 );
}
UTIL::$sharedConfig = array( 'xmlDoc' => $doc, 'pan' => null );
$first = viewerDecode( viewerRun( 'tag', array( 'location=shared', 'actions=display', 'filter=(name eq config-viewer-load)' ) ) );
if( !$first['ok'] || UTIL::$sharedConfig['pan'] === null )
{
    viewerLog( 'configuration can not be loaded: ' . ( $first['error'] ?? '' ) );
    exit( 6 );
}

viewerUnlink( $sockFile );
$old = umask( 0177 );
$server = viewerQuiet( function() use ( $sockFile, &$errstr ) { return stream_socket_server( 'unix://' . $sockFile, $errno, $errstr ); } );
umask( $old );
if( !$server )
{
    viewerLog( 'socket: ' . $errstr );
    exit( 7 );
}
pcntl_signal( SIGUSR1, SIG_DFL );
// a stopped worker (kill, shutdown of the server) still writes its unsaved changes to the autosave file
pcntl_async_signals( TRUE );
foreach( array( SIGTERM, SIGINT, SIGHUP ) as $sig )
    pcntl_signal( $sig, function() { if( !$GLOBALS['viewerIsChild'] ) exit( 0 ); posix_kill( getmypid(), SIGKILL ); } );
$lastUsed = time();
$lastAutosave = time();
$trials = array();

while( TRUE )
{
    // reap finished children
    while( ( $done = pcntl_waitpid( -1, $st, WNOHANG ) ) > 0 )
        unset( $trials[$done] );

    $read = array( $server );
    $write = null;
    $except = null;
    $n = viewerQuiet( function() use ( &$read, &$write, &$except ) { return stream_select( $read, $write, $except, 15 ); } );

    if( $GLOBALS['viewerState']['dirty'] && time() - $lastAutosave >= $autosaveSec )
    {
        try
        {
            if( viewerWrite( $autosaveFile ) )
                $GLOBALS['viewerState']['autosaved'] = time();
        }
        catch( Throwable $e ) { viewerLog( 'autosave failed: ' . $e->getMessage() ); }
        $lastAutosave = time();
    }
    if( time() - $lastUsed > $idleSec )
        exit( 0 );
    if( $n === FALSE || $n === 0 )
        continue;

    $conn = viewerQuiet( function() use ( $server ) { return stream_socket_accept( $server, 5 ); } );
    if( !$conn )
        continue;
    stream_set_timeout( $conn, 10 );
    $cmd = json_decode( (string)viewerQuiet( function() use ( $conn ) { return fgets( $conn, 1048576 ); } ), TRUE );
    if( !is_array( $cmd ) || !isset( $cmd['cmd'] ) )
    {
        viewerSend( $conn, array( 'ok' => FALSE, 'error' => 'bad request' ) );
        continue;
    }
    $lastUsed = time();
    $type = isset( $cmd['type'] ) && is_string( $cmd['type'] ) ? $cmd['type'] : '';
    $args = isset( $cmd['args'] ) && is_array( $cmd['args'] ) ? array_values( array_filter( $cmd['args'], 'is_string' ) ) : array();

    if( $cmd['cmd'] === 'status' )
        viewerSend( $conn, array( 'ok' => TRUE, 'status' => viewerStatus() ) );
    elseif( $cmd['cmd'] === 'close' )
    {
        $GLOBALS['viewerState']['dirty'] = FALSE; // discard
        viewerUnlink( $autosaveFile );
        viewerSend( $conn, array( 'ok' => TRUE ) );
        exit( 0 );
    }
    elseif( $cmd['cmd'] === 'read' )
    {
        $child = pcntl_fork();
        if( $child === 0 )
        {
            fclose( $server );
            viewerChild( $conn, $type, $args, TRUE );
        }
        viewerQuiet( function() use ( $conn ) { fclose( $conn ); } );
        if( $child < 0 )
            viewerLog( 'fork failed' );
    }
    elseif( $cmd['cmd'] === 'change' )
    {
        // 1. trial in a child: a failing action must not stop or half-change the loaded configuration
        $child = pcntl_fork();
        if( $child === 0 )
        {
            fclose( $server );
            viewerChild( $conn, $type, $args, FALSE );
        }
        if( $child < 0 )
        {
            viewerSend( $conn, array( 'ok' => FALSE, 'error' => 'fork failed' ) );
            continue;
        }
        pcntl_waitpid( $child, $st );
        if( !( pcntl_wifsignaled( $st ) && pcntl_wtermsig( $st ) === SIGUSR1 ) )
        {
            viewerQuiet( function() use ( $conn ) { fclose( $conn ); } ); // the child sent the error already
            continue;
        }
        // 2. the real run on the memory
        try
        {
            $r = viewerDecode( viewerRun( $type, $args ) );
        }
        catch( Throwable $e )
        {
            $r = array( 'ok' => FALSE, 'error' => $e->getMessage() );
        }
        if( $r['ok'] )
        {
            if( !$GLOBALS['viewerState']['dirty'] )
                $lastAutosave = time();
            $GLOBALS['viewerState']['dirty'] = TRUE;
            $GLOBALS['viewerState']['changes'][] = isset( $cmd['note'] ) && is_string( $cmd['note'] ) ? substr( $cmd['note'], 0, 500 ) : $type;
        }
        viewerSend( $conn, $r + array( 'status' => viewerStatus() ) );
    }
    elseif( $cmd['cmd'] === 'save' )
    {
        $file = isset( $cmd['file'] ) && is_string( $cmd['file'] ) ? $cmd['file'] : '';
        // only into the folder of this project, only a new *.xml file
        if( !$GLOBALS['viewerState']['dirty'] )
            viewerSend( $conn, array( 'ok' => TRUE, 'saved' => FALSE, 'status' => viewerStatus() ) );
        elseif( dirname( $file ) !== dirname( $configFile ) || !preg_match( '/^[0-9a-f]{32}\.xml$/', basename( $file ) ) || file_exists( $file ) )
            viewerSend( $conn, array( 'ok' => FALSE, 'error' => 'bad target' ) );
        else
        {
            try { $ok = viewerWrite( $file ); } catch( Throwable $e ) { $ok = FALSE; viewerLog( 'save failed: ' . $e->getMessage() ); }
            if( !$ok )
                viewerSend( $conn, array( 'ok' => FALSE, 'error' => 'the configuration could not be written' ) );
            else
            {
                $changes = $GLOBALS['viewerState']['changes'];
                $GLOBALS['viewerState']['dirty'] = FALSE;
                $GLOBALS['viewerState']['changes'] = array();
                $GLOBALS['viewerState']['saved'] = time();
                viewerUnlink( $autosaveFile );
                $configFile = $file;
                viewerSend( $conn, array( 'ok' => TRUE, 'saved' => TRUE, 'changes' => $changes, 'status' => viewerStatus() ) );
            }
        }
    }
    else
        viewerSend( $conn, array( 'ok' => FALSE, 'error' => 'bad request' ) );
}
