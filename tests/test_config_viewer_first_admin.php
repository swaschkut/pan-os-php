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
 * config-viewer: a new installation - help pages without login, the first administrator with the one-time code,
 * users / projects / API tokens on the command line (bin/user.php, bin/token.php).
 *   php tests/test_config_viewer_first_admin.php
 */
$viewer = dirname( __FILE__ ) . '/../utils/develop/config-viewer';
if( !extension_loaded( 'pdo_sqlite' ) )
{
    print "SKIPPED: PHP extension pdo_sqlite missing\n";
    exit( 0 );
}
$failed = array(); $checks = 0;
function eq( $actual, $expected, $msg )
{
    global $failed, $checks;
    $checks++;
    if( $actual !== $expected )
        $failed[] = $msg . "\n      expected " . json_encode( $expected ) . "\n      got      " . json_encode( $actual );
}
$data = sys_get_temp_dir() . '/viewer-first-admin-' . getmypid();
mkdir( $data, 0700 );
$env = array( 'PATH' => getenv( 'PATH' ), 'PANOSPHP_VIEWER_DATA' => $data );
function cli( array $args, array $extra = array() ): array
{
    global $env;
    $p = proc_open( array_merge( array( PHP_BINARY ), $args ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes, null, $extra + $env );
    $out = stream_get_contents( $pipes[1] );
    $err = stream_get_contents( $pipes[2] );
    return array( proc_close( $p ), trim( $out ), trim( $err ) );
}
$sock = stream_socket_server( 'tcp://127.0.0.1:0' );
$port = (int)substr( strrchr( stream_socket_get_name( $sock, FALSE ), ':' ), 1 );
fclose( $sock );
$srv = proc_open( array( PHP_BINARY, '-S', '127.0.0.1:' . $port, '-t', $viewer ), array( 1 => array( 'file', '/dev/null', 'w' ), 2 => array( 'file', '/dev/null', 'w' ) ), $pipes, $viewer, $env );
for( $i = 0; $i < 50 && @file_get_contents( 'http://127.0.0.1:' . $port . '/index.html' ) === FALSE; $i++ )
    usleep( 100000 );
register_shutdown_function( function() use ( $srv, $data ) { proc_terminate( $srv ); exec( 'rm -rf ' . escapeshellarg( $data ) ); } );
$cookie = '';
function call( string $method, string $path, $body = null, array $headers = array() ): array
{
    global $port, $cookie;
    $h = array_merge( array( 'Content-Type: application/json' ), $cookie !== '' ? array( 'Cookie: ' . $cookie ) : array(), $headers );
    $raw = @file_get_contents( 'http://127.0.0.1:' . $port . '/api.php/' . $path, FALSE, stream_context_create( array( 'http' => array( 'method' => $method,
        'header' => implode( "\r\n", $h ), 'content' => $body === null ? null : json_encode( $body ), 'ignore_errors' => TRUE ) ) ) );
    $status = 0;
    foreach( $http_response_header ?? array() as $l )
    {
        if( preg_match( '#^HTTP/\S+ (\d+)#', $l, $m ) ) $status = (int)$m[1];
        if( preg_match( '#^Set-Cookie: (PANOSPHPVIEWER=[^;]*)#i', $l, $m ) ) $cookie = $m[1];
    }
    return array( $status, json_decode( (string)$raw, TRUE ) );
}

// ---- help pages: without login
$r = call( 'GET', 'docs' );
eq( array( $r[0], array_keys( $r[1]['docs'] ?? array() )[0] ?? null, $r[1]['docs']['1-first-steps'] ?? null ), array( 200, '1-first-steps', 'First steps' ), 'help pages: listed without login' );
$r = call( 'GET', 'docs/1-first-steps' );
eq( array( $r[0], strpos( $r[1]['markdown'] ?? '', 'one-time code' ) !== FALSE ), array( 200, TRUE ), 'help page: Markdown without login' );
foreach( array( 'docs/..%2Fapi', 'docs/x', 'docs/1-first-steps/x' ) as $bad )
    eq( call( 'GET', $bad )[0] >= 400, TRUE, 'help page: only the files of docs/ (' . $bad . ')' );
eq( call( 'GET', 'projects' )[0], 401, 'everything else still needs a login' );

// ---- the first administrator
eq( call( 'GET', 'setup' )[1]['first_admin'] ?? null, TRUE, 'new installation: the page offers the first administrator' );
list( $c, $code ) = cli( array( $viewer . '/bin/user.php', 'first-code' ) );
eq( array( $c, (bool)preg_match( '/^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){3}$/', $code ), cli( array( $viewer . '/bin/user.php', 'first-code' ) )[1] ),
    array( 0, TRUE, $code ), 'one-time code: made once, the same on the next call' );
eq( decoct( fileperms( $data . '/first-admin.code' ) & 0777 ), '600', 'one-time code: file only for the viewer' );
$r = call( 'POST', 'setup', array( 'code' => 'AAAA-BBBB-CCCC-DDDD', 'user' => 'boss', 'password' => 'boss-secret-12' ) );
eq( array( $r[0], strpos( $r[1]['error'] ?? '', 'the code is wrong' ) ), array( 403, 0 ), 'wrong code: refused' );
eq( call( 'POST', 'setup', array( 'code' => $code, 'user' => 'boss', 'password' => 'short' ) )[0], 400, 'right code, password too short: refused' );
$r = call( 'POST', 'setup', array( 'code' => strtolower( str_replace( '-', ' ', $code ) ), 'user' => 'boss', 'password' => 'boss-secret-12' ) );
eq( array( $r[0], $r[1]['user'] ?? null, $r[1]['admin'] ?? null, strlen( $r[1]['csrf'] ?? '' ) ), array( 201, 'boss', TRUE, 64 ), 'right code (written in any form): administrator made and logged in' );
eq( array( call( 'GET', 'me' )[1]['user'] ?? null, file_exists( $data . '/first-admin.code' ), call( 'GET', 'setup' )[1]['first_admin'] ?? null ), array( 'boss', FALSE, FALSE ), 'afterwards: the session works, the code is gone, no second first administrator' );
eq( call( 'POST', 'setup', array( 'code' => $code, 'user' => 'mallory', 'password' => 'mallory-secret-1' ) )[0], 409, 'the code does not work a second time' );
eq( cli( array( $viewer . '/bin/user.php', 'first-code' ) )[1], '', 'one-time code: nothing once there is a user' );

// too many wrong codes (a fresh installation)
$data2 = $data . '-2';
mkdir( $data2, 0700 );
$p = proc_open( array( PHP_BINARY, '-S', '127.0.0.1:' . ( $port + 1 ), '-t', $viewer ), array( 1 => array( 'file', '/dev/null', 'w' ), 2 => array( 'file', '/dev/null', 'w' ) ), $pipes, $viewer,
    array( 'PANOSPHP_VIEWER_DATA' => $data2 ) + $env );
usleep( 600000 );
$port0 = $port; $port = $port + 1; $cookie = '';
cli( array( $viewer . '/bin/user.php', 'first-code' ), array( 'PANOSPHP_VIEWER_DATA' => $data2 ) );
$codes = array();
for( $i = 0; $i < 6; $i++ )
    $codes[] = call( 'POST', 'setup', array( 'code' => 'WRONG', 'user' => 'x1', 'password' => 'x-secret-123' ) )[0];
eq( $codes, array( 403, 403, 403, 403, 403, 429 ), 'too many wrong codes: blocked for a while' );
proc_terminate( $p );
exec( 'rm -rf ' . escapeshellarg( $data2 ) );
$port = $port0;

// ---- users, projects, API tokens on the command line
eq( cli( array( $viewer . '/bin/user.php', 'add', 'anna' ), array( 'VIEWER_PASSWORD' => 'anna-secret-12' ) )[0], 0, 'user add on the command line' );
list( $c, $pid ) = cli( array( $viewer . '/bin/token.php', 'project-add', 'anna', 'Firewall A' ) );
eq( array( $c, (bool)preg_match( '/^[0-9a-f]{32}$/', $pid ) ), array( 0, TRUE ), 'project-add: prints the id' );
list( $c, $out ) = cli( array( $viewer . '/bin/token.php', 'projects', 'anna' ) );
eq( $out, $pid . '  owner  Firewall A', 'projects of a user' );
list( $c, $out ) = cli( array( $viewer . '/bin/token.php', 'create', 'anna', 'firewall a', 'write', '7', 'nightly script' ) );
$tok = preg_match( '/token \(shown only now\): (pvt_\S+)/', $out, $m ) ? $m[1] : '';
eq( array( $c, strlen( $tok ) > 40, strpos( $out, 'permission write' ) !== FALSE ), array( 0, TRUE, TRUE ), 'token create: by project name, shown once' );
$cookie = '';
$r = call( 'GET', 'projects/' . $pid . '/configs', null, array( 'Authorization: Bearer ' . $tok ) );
eq( array( $r[0], $r[1]['configs'] ?? null ), array( 200, array() ), 'the token works for its project' );
eq( call( 'GET', 'users', null, array( 'Authorization: Bearer ' . $tok ) )[0], 404, 'the token has no admin rights' );
list( $c, $out ) = cli( array( $viewer . '/bin/token.php', 'list', 'anna', $pid ) );
eq( array( $c, strpos( $out, 'nightly script' ) !== FALSE, strpos( $out, substr( $tok, 21 ) ) ), array( 0, TRUE, FALSE ), 'token list: without the secret' );
$tid = preg_match( '/^(\S+)\s/', $out, $m ) ? $m[1] : '';
eq( cli( array( $viewer . '/bin/token.php', 'delete', 'anna', $pid, $tid ) )[0], 0, 'token delete' );
eq( call( 'GET', 'projects/' . $pid . '/configs', null, array( 'Authorization: Bearer ' . $tok ) )[0], 401, 'a deleted token does not work' );
list( $c, , $err ) = cli( array( $viewer . '/bin/token.php', 'create', 'boss', 'Firewall A' ) );
eq( array( $c, $err ), array( 1, 'error: no project "Firewall A" of this user' ), 'token create: only for projects of the user' );
eq( cli( array( $viewer . '/bin/token.php', 'create', 'nobody', 'x' ) )[2], 'error: unknown user: nobody', 'token create: unknown user' );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
foreach( $failed as $m )
    print " - " . $m . "\n";
exit( count( $failed ) ? 1 : 0 );
