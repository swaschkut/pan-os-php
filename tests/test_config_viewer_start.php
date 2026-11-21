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
 * config-viewer: the start script panosphp-viewer and the licence command line bin/license.php.
 * No Docker needed: a stand-in "docker" records the calls; "compose exec … web <command>" runs the command here,
 * with a data directory of the test. Checks the calls and the flow, NOT that a real Docker accepts them.
 *   php tests/test_config_viewer_start.php
 */
$here = dirname( __FILE__ );
$viewer = $here . '/../utils/develop/config-viewer';
foreach( array( 'pdo_sqlite', 'sodium' ) as $ext )
    if( !extension_loaded( $ext ) )
    {
        print "SKIPPED: PHP extension " . $ext . " missing\n";
        exit( 0 );
    }
require_once $here . '/../lib/misc-classes/PluginLicense.php';
require_once $here . '/../lib/misc-classes/PluginPackage.php';
require_once $here . '/plugin_license_helper.php';

$failed = array(); $checks = 0;
function eq( $actual, $expected, $msg )
{
    global $failed, $checks;
    $checks++;
    if( $actual !== $expected )
        $failed[] = $msg . "\n      expected " . json_encode( $expected ) . "\n      got      " . json_encode( $actual );
}

$tmp = sys_get_temp_dir() . '/viewer-start-test-' . getmypid();
$dir = $tmp . '/viewer';      // where the script is installed (like an unpacked bundle)
$bin = $tmp . '/bin';
$data = $tmp . '/data';
foreach( array( $dir, $bin, $data ) as $d )
    mkdir( $d, 0700, TRUE );
foreach( array( 'panosphp-viewer', 'docker-compose.yml', 'docker-compose.https.yml' ) as $f )
    copy( $viewer . '/' . $f, $dir . '/' . $f );
chmod( $dir . '/panosphp-viewer', 0755 );
register_shutdown_function( function() use ( $tmp ) { exec( 'rm -rf ' . escapeshellarg( $tmp ) ); } );

// the stand-in docker
file_put_contents( $bin . '/docker', '#!' . PHP_BINARY . "\n" . <<<'FAKE'
<?php
$a = array_slice( $argv, 1 );
file_put_contents( getenv( 'FAKE_LOG' ), json_encode( $a ) . "\n", FILE_APPEND );
if( $a[0] === 'version' ) exit( 0 );
if( $a[0] === 'load' ) { stream_get_contents( STDIN ); echo "Loaded image\n"; exit( 0 ); }
if( $a[0] !== 'compose' ) exit( 1 );
if( ( $a[1] ?? '' ) === 'version' ) exit( 0 );
$i = 1;
while( isset( $a[$i] ) && $a[$i] === '-f' ) $i += 2;
$sub = $a[$i] ?? '';
if( $sub === 'logs' ) { echo "web-1  | config-viewer: first start - user \"admin\" created.\nweb-1  | config-viewer: password: 0123456789abcdef01234567   (shown only now - change it under Account)\n"; exit( 0 ); }
if( $sub === 'exec' )
{
    $env = array( 'PATH' => getenv( 'PATH' ), 'PANOSPHP_VIEWER_DATA' => getenv( 'FAKE_DATA' ), 'PANOSPHP_LICENSE_TEST_KEYS' => (string)getenv( 'PANOSPHP_LICENSE_TEST_KEYS' ),
        'PANOSPHP_VIEWER_PLUGINS' => getenv( 'FAKE_PLUGINS' ) );
    for( $j = $i + 1; $j < count( $a ); $j++ )
    {
        if( $a[$j] === '-T' ) continue;
        if( $a[$j] === '-u' ) { $j++; continue; }
        if( $a[$j] === '-e' ) { $kv = explode( '=', $a[++$j], 2 ); $env[$kv[0]] = $kv[1]; continue; }
        if( $a[$j] === 'web' ) break;
    }
    $cmd = array_slice( $a, $j + 1 );
    if( $cmd[0] === 'php' ) $cmd[0] = PHP_BINARY;
    $p = proc_open( $cmd, array( 0 => STDIN, 1 => STDOUT, 2 => STDERR ), $pipes, getenv( 'FAKE_VIEWER' ), $env );
    exit( proc_close( $p ) );
}
exit( 0 );
FAKE
);
chmod( $bin . '/docker', 0755 );

$log = $tmp . '/calls.log';
$baseEnv = array( 'PATH' => $bin . ':' . getenv( 'PATH' ), 'HOME' => $tmp, 'FAKE_LOG' => $log, 'FAKE_DATA' => $data, 'FAKE_VIEWER' => realpath( $viewer ),
    'FAKE_PLUGINS' => $dir . '/plugins' );
function pv( array $args, array $env = array(), string $stdin = '' ): array
{
    global $dir, $baseEnv, $log;
    @unlink( $log );
    $p = proc_open( array_merge( array( $dir . '/panosphp-viewer' ), $args ), array( 0 => array( 'pipe', 'r' ), 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes, $dir, $env + $baseEnv );
    fwrite( $pipes[0], $stdin );
    fclose( $pipes[0] );
    $out = stream_get_contents( $pipes[1] ) . stream_get_contents( $pipes[2] );
    $code = proc_close( $p );
    $calls = array_map( function( $l ) { return implode( ' ', json_decode( $l, TRUE ) ); }, file_exists( $log ) ? file( $log, FILE_IGNORE_NEW_LINES ) : array() );
    return array( $code, $out, $calls );
}
function env( string $k ): string
{
    global $dir;
    return preg_match( '/^' . $k . '="?([^"\n]*)"?$/m', (string)@file_get_contents( $dir . '/.env' ), $m ) ? $m[1] : '?';
}

// an admin user in the data directory of the test (as the web part makes it at the first start)
$p = proc_open( array( PHP_BINARY, $viewer . '/bin/user.php', 'add', 'admin', 'admin' ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes, null,
    array( 'PATH' => getenv( 'PATH' ), 'PANOSPHP_VIEWER_DATA' => $data, 'VIEWER_PASSWORD' => 'first-password-1' ) );
stream_get_contents( $pipes[1] );
proc_close( $p );

// ---- start: first time, no terminal -> defaults (the .env of a bundle holds only the image)
file_put_contents( $dir . '/.env', "VIEWER_IMAGE=example/pan-os-php:bundle\n" );
list( $code, $out, $calls ) = pv( array( 'start' ) );
eq( array( $code, env( 'VIEWER_HTTPS' ), env( 'VIEWER_PORT' ), env( 'VIEWER_PLUGINS_DIR' ), env( 'VIEWER_IMAGE' ), is_dir( $dir . '/plugins' ) ),
    array( 0, 'no', '8080', $dir . '/plugins', 'example/pan-os-php:bundle', TRUE ), 'start (first time): settings written with defaults, image of the bundle kept, plug-in folder made' );
eq( decoct( fileperms( $dir . '/.env' ) & 0777 ), '600', 'start: .env only for this user' );
eq( in_array( 'compose -f docker-compose.yml up -d', $calls, TRUE ), TRUE, 'start: compose up with the main file only' );
eq( array_search( 'compose -f docker-compose.yml pull', $calls, TRUE ) < array_search( 'compose -f docker-compose.yml up -d', $calls, TRUE )
    && array_search( 'compose -f docker-compose.yml pull', $calls, TRUE ) !== FALSE, TRUE, 'start (first time): the current images are pulled first' );
list( , , $calls ) = pv( array( 'start' ) );
eq( preg_grep( '/ pull$/', $calls ), array(), 'start (later): no pull' );
eq( array( strpos( $out, 'config viewer: http://127.0.0.1:8080/' ) !== FALSE, strpos( $out, 'password: 0123456789abcdef01234567' ) !== FALSE ), array( TRUE, TRUE ), 'start: address and first password shown' );

// ---- setup with HTTPS from the environment, start uses both files
list( $code, $out ) = pv( array( 'setup' ), array( 'VIEWER_HTTPS' => 'yes', 'VIEWER_DOMAIN' => 'viewer.example.com' ) );
unlink( $dir . '/.env' );
list( $code, $out ) = pv( array( 'setup' ), array( 'VIEWER_HTTPS' => 'yes', 'VIEWER_DOMAIN' => 'viewer.example.com' ) );
eq( array( $code, env( 'VIEWER_HTTPS' ), env( 'VIEWER_DOMAIN' ), env( 'VIEWER_TLS' ) ), array( 0, 'yes', 'viewer.example.com', 'internal' ), 'setup: HTTPS, own certificate authority' );
list( $code, $out, $calls ) = pv( array( 'restart' ) );
eq( array( in_array( 'compose -f docker-compose.yml -f docker-compose.https.yml down', $calls, TRUE ), in_array( 'compose -f docker-compose.yml -f docker-compose.https.yml up -d', $calls, TRUE ),
    strpos( $out, 'https://viewer.example.com/' ) !== FALSE ), array( TRUE, TRUE, TRUE ), 'restart with HTTPS: both compose files, https address' );
list( $code, $out ) = pv( array( 'setup' ), array( 'VIEWER_HTTPS' => 'yes', 'VIEWER_DOMAIN' => 'v.example.com', 'VIEWER_TLS' => '/certs/cert.pem /certs/key.pem', 'VIEWER_CERTS' => $tmp . '/nocerts' ) );
eq( array( $code !== 0, strpos( $out, 'no cert.pem / key.pem' ) !== FALSE, env( 'VIEWER_DOMAIN' ) ), array( TRUE, TRUE, 'viewer.example.com' ), 'setup: own certificate without files is refused, settings stay' );
unlink( $dir . '/.env' );
pv( array( 'setup' ) );

// ---- password: a new one, shown once, that works
list( $code, $out, $calls ) = pv( array( 'password' ) );
$pw = preg_match( '/new password of admin: ([A-Za-z0-9]{20})/', $out, $m ) ? $m[1] : null;
eq( array( $code, $pw !== null, strpos( implode( "\n", $calls ), 'VIEWER_PASSWORD=' ) !== FALSE ), array( 0, TRUE, TRUE ), 'password: set through the web container' );
putenv( 'PANOSPHP_VIEWER_DATA=' . $data );
require_once $viewer . '/lib/ViewerApp.php';
$app = new ViewerApp( $data );
$ok = function( $u, $p ) use ( $app ) { try { $app->login( $u, $p, '127.0.0.1' ); return TRUE; } catch( Exception $e ) { return FALSE; } };
eq( array( $ok( 'admin', $pw ), $ok( 'admin', 'first-password-1' ) ), array( TRUE, FALSE ), 'password: the new one works, the old one not' );
eq( pv( array( 'password', 'bad name;x' ) )[0] !== 0, TRUE, 'password: user name checked' );

// ---- plug-in and licence
$k = testLicenceKeys();
$baseEnv['PANOSPHP_LICENSE_TEST_KEYS'] = testTrustedJson( $k );
$pkgDir = $tmp . '/pkg';
mkdir( $pkgDir );
$rel = testPack( $pkgDir, 'demo', '1.0', 'demo-feature', array( 'plugin.php' => "<?php return array( 'api' => 1, 'name' => 'demo', 'title' => 'Demo', 'version' => '1.0', 'feature' => 'demo-feature' );" ) );
file_put_contents( $pkgDir . '/wrong.ppp', "not a package\n" );
eq( pv( array( 'plugin', $pkgDir . '/wrong.ppp' ) )[0] !== 0, TRUE, 'plugin: a file that is no package is refused' );
list( $code, $out ) = pv( array( 'plugin', $pkgDir . '/demo.ppp' ) );
eq( array( $code, is_file( $dir . '/plugins/demo.ppp' ) ), array( 0, TRUE ), 'plugin: package copied into plugins/' );
eq( trim( pv( array( 'plugin' ) )[1] ), 'demo.ppp', 'plugin: list' );
list( $code, $out ) = pv( array( 'license' ) );
eq( array( $code, strpos( $out, 'no licence installed' ) !== FALSE, strpos( $out, 'not licensed: no licence installed' ) !== FALSE ), array( 0, TRUE, TRUE ), 'license: none, the package is locked' );
file_put_contents( $tmp . '/acme.lic', testLicence( $k, array( 'id' => 'L-START', 'customer' => 'ACME AG', 'features' => array( 'demo-feature' ), 'keys' => array( $rel['kid'] => $rel['key'] ) ) ) );
list( $code, $out ) = pv( array( 'license', $tmp . '/acme.lic' ) );
eq( array( $code, strpos( $out, 'licence installed' ) !== FALSE, strpos( $out, 'licence L-START for ACME AG' ) !== FALSE, (bool)preg_match( '/plug-in demo +1\.0 +demo-feature +on/', $out ) ),
    array( 0, TRUE, TRUE, TRUE ), 'license: installed from the file, the package is on' );
file_put_contents( $tmp . '/bad.lic', "no licence\n" );
list( $code, $out ) = pv( array( 'license', $tmp . '/bad.lic' ) );
eq( array( $code !== 0, strpos( $out, 'no licence block found' ) !== FALSE ), array( TRUE, TRUE ), 'license: a wrong file is refused with the reason' );
eq( pv( array( 'license', $tmp . '/missing.lic' ) )[0] !== 0, TRUE, 'license: missing file' );

// ---- status, logs, stop, update
list( $code, $out, $calls ) = pv( array( 'status' ) );
eq( array( $code, in_array( 'compose -f docker-compose.yml ps', $calls, TRUE ), strpos( $out, 'licence L-START for ACME AG' ) !== FALSE ), array( 0, TRUE, TRUE ), 'status: containers, address, licence' );
list( , , $calls ) = pv( array( 'logs', 'jobs' ) );
eq( in_array( 'compose -f docker-compose.yml logs --tail 200 jobs', $calls, TRUE ), TRUE, 'logs of one part' );
list( , $out, $calls ) = pv( array( 'stop' ) );
eq( array( in_array( 'compose -f docker-compose.yml down', $calls, TRUE ), preg_grep( '/down -v/', $calls ) ), array( TRUE, array() ), 'stop: down, never down -v' );
list( , , $calls ) = pv( array( 'update' ) );
eq( array( in_array( 'compose -f docker-compose.yml pull', $calls, TRUE ), in_array( 'compose -f docker-compose.yml up -d', $calls, TRUE ) ), array( TRUE, TRUE ), 'update without images.tar.gz: pull, up' );
file_put_contents( $dir . '/images.tar.gz', gzencode( 'images' ) );
list( , , $calls ) = pv( array( 'update' ) );
eq( array( in_array( 'load', $calls, TRUE ), preg_grep( '/ pull$/', $calls ) ), array( TRUE, array() ), 'update with images.tar.gz (air gap): load, no pull' );
eq( pv( array( 'start' ), array( 'PATH' => '/usr/bin:/bin', 'DOCKER' => '/nonexistent/docker' ) )[0] !== 0, TRUE, 'no Docker: a clear error' );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
foreach( $failed as $m )
    print " - " . $m . "\n";
exit( count( $failed ) ? 1 : 0 );
