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
 * config-viewer service: the one long running process that starts the workers (one per opened configuration
 * version, see worker.php). The web server process only asks this service over a unix socket in the data directory;
 * it never starts a process itself, and a worker never inherits a connection of the web server.
 *
 *   php bin/service.php            run it as the same OS user as the web server (both need the data directory)
 *
 * Environment: PANOSPHP_VIEWER_DATA (data directory), PANOSPHP_VIEWER_AUTOSAVE_MIN (default 5),
 * PANOSPHP_VIEWER_IDLE_MIN (default 60: a worker without requests stops, unsaved changes become a recovered version).
 */
if( PHP_SAPI !== 'cli' )
{
    http_response_code( 404 );
    exit;
}
foreach( array( 'pcntl_fork', 'posix_setsid', 'stream_socket_server' ) as $fn )
    if( !function_exists( $fn ) )
    {
        fwrite( STDERR, "config-viewer service: PHP CLI extensions pcntl and posix are needed\n" );
        exit( 3 );
    }
require_once dirname(__FILE__) . '/../lib/ViewerApp.php';

$app = new ViewerApp();
$dataDir = $app->dataDir;
unset( $app ); // no DB handle in this process or in the workers
$sockFile = $dataDir . '/service.sock';
$autosaveMin = max( 1, (int)( getenv( 'PANOSPHP_VIEWER_AUTOSAVE_MIN' ) ?: 5 ) );
$idleMin = max( 1, (int)( getenv( 'PANOSPHP_VIEWER_IDLE_MIN' ) ?: 60 ) );

if( file_exists( $sockFile ) )
{
    $probe = @stream_socket_client( 'unix://' . $sockFile, $errno, $errstr, 2 );
    if( $probe )
    {
        fwrite( STDERR, "config-viewer service: already running for " . $dataDir . "\n" );
        exit( 1 );
    }
    unlink( $sockFile );
}
$old = umask( 0177 );
$server = stream_socket_server( 'unix://' . $sockFile, $errno, $errstr );
umask( $old );
if( !$server )
{
    fwrite( STDERR, "config-viewer service: " . $errstr . "\n" );
    exit( 1 );
}
$servicePid = getmypid();
register_shutdown_function( function() use ( $sockFile, $servicePid ) {
    if( getmypid() === $servicePid && file_exists( $sockFile ) )
        unlink( $sockFile );
} );
pcntl_async_signals( TRUE );
foreach( array( SIGTERM, SIGINT ) as $sig )
    pcntl_signal( $sig, function() { exit( 0 ); } );
fwrite( STDERR, "config-viewer service: running, data directory " . $dataDir . "\n" );

/** every path of a start request must be a file of ONE project folder of the data directory */
function serviceCheck( array $cmd, string $dataDir ): ?array
{
    $names = array( 'config' => '/^[0-9a-f]{32}\.xml$/', 'sock' => '/^[0-9a-f]{32}\.sock$/', 'pid' => '/^[0-9a-f]{32}\.pid$/', 'log' => '/^[0-9a-f]{32}\.log$/',
        'autosave' => '/^[0-9a-f]{32}\.autosave\.xml$/' );
    $project = null;
    $out = array();
    foreach( $names as $key => $pattern )
    {
        if( !isset( $cmd[$key] ) || !is_string( $cmd[$key] ) || !preg_match( $pattern, basename( $cmd[$key] ) ) )
            return null;
        $dir = realpath( dirname( $cmd[$key] ) );
        if( $dir === FALSE )
            return null;
        if( $key === 'sock' )
        {
            if( $dir !== $dataDir . '/run' )
                return null;
            $out[$key] = $dir . '/' . basename( $cmd[$key] );
            continue;
        }
        $projectDir = $key === 'config' ? $dir : dirname( $dir );
        if( $key !== 'config' && basename( $dir ) !== 'work' )
            return null;
        if( dirname( $projectDir ) !== $dataDir . '/projects' || !preg_match( '/^[0-9a-f]{32}$/', basename( $projectDir ) ) )
            return null;
        if( $project !== null && $project !== $projectDir )
            return null;
        $project = $projectDir;
        $out[$key] = $dir . '/' . basename( $cmd[$key] );
    }
    if( !is_file( $out['config'] ) || is_link( $out['config'] ) || file_exists( $out['sock'] ) || file_exists( $out['pid'] ) )
        return null;
    return $out;
}

while( TRUE )
{
    while( pcntl_waitpid( -1, $st, WNOHANG ) > 0 );

    $read = array( $server );
    $write = null;
    $except = null;
    if( @stream_select( $read, $write, $except, 15 ) < 1 )
        continue;
    $conn = @stream_socket_accept( $server, 5 );
    if( !$conn )
        continue;
    stream_set_timeout( $conn, 5 );
    $cmd = json_decode( (string)fgets( $conn, 65536 ), TRUE );
    $worker = is_array( $cmd ) && ( $cmd['cmd'] ?? '' ) === 'start' ? serviceCheck( $cmd, $dataDir ) : null;
    if( $worker === null )
    {
        @fwrite( $conn, json_encode( array( 'ok' => FALSE ) ) );
        @fclose( $conn );
        continue;
    }

    $child = pcntl_fork();
    if( $child === 0 )
    {
        // worker: nothing of the service stays open
        fclose( $server );
        fclose( $conn );
        pcntl_signal( SIGTERM, SIG_DFL );
        pcntl_signal( SIGINT, SIG_DFL );
        $work = dirname( $worker['pid'] );
        putenv( 'HOME=' . $work );
        putenv( 'TMPDIR=' . $work );
        chdir( $work );
        $viewerWorker = $worker + array( 'autosaveMin' => $autosaveMin, 'idleMin' => $idleMin );
        require dirname(__FILE__) . '/worker.php';
        exit( 0 );
    }
    @fwrite( $conn, json_encode( array( 'ok' => $child > 0 ) ) );
    @fclose( $conn );
}
