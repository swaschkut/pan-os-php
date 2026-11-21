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
if( $sub === 'logs' ) { echo "web-1  | config-viewer: web part on port 8080\n"; exit( 0 ); }
if( $sub === 'exec' )
{
    $env = array( 'PATH' => getenv( 'PATH' ), 'PANOSPHP_VIEWER_DATA' => getenv( 'FAKE_DATA' ), 'PANOSPHP_LICENSE_TEST_KEYS' => (string)getenv( 'PANOSPHP_LICENSE_TEST_KEYS' ),
        'PANOSPHP_VIEWER_PLUGINS' => getenv( 'FAKE_PLUGINS' ) );
    for( $j = $i + 1; $j < count( $a ); $j++ )
    {
        if( $a[$j] === '-T' ) continue;
        if( $a[$j] === '-u' ) { $j++; continue; }
        if( $a[$j] === '-w' ) { file_put_contents( getenv( 'FAKE_LOG' ) . '.workdir', $a[++$j] . "\n", FILE_APPEND ); continue; }
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
$code = preg_match( '/\n\s+([A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){3})\n/', $out, $m ) ? $m[1] : null;
eq( array( strpos( $out, 'config viewer: http://127.0.0.1:8080/' ) !== FALSE, $code !== null, trim( (string)@file_get_contents( $data . '/first-admin.code' ) ) === $code ),
    array( TRUE, TRUE, TRUE ), 'start (new installation): address and the one-time code for the first administrator' );
eq( array_unique( file( $log . '.workdir', FILE_IGNORE_NEW_LINES ) ), array( '/tools/pan-os-php/utils/develop/config-viewer' ), 'commands in the container run in the folder of the viewer' );
// the first setup: users on the command line until there is an administrator
list( $c, $out ) = pv( array( 'user', 'add', 'anna' ) );
eq( array( $c, (bool)preg_match( '/user anna created - password: [A-Za-z0-9]{20}/', $out ) ), array( 0, TRUE ), 'user add (setup): normal user' );
eq( pv( array( 'user', 'add', 'x;y' ) )[0] !== 0, TRUE, 'user add: name checked' );
// the administrator on the command line (without a browser)
list( $code2, $out ) = pv( array( 'user', 'add', 'admin', 'admin' ) );
$firstPw = preg_match( '/user admin created \(administrator\) - password: ([A-Za-z0-9]{20})/', $out, $m ) ? $m[1] : null;
eq( array( $code2, $firstPw !== null, file_exists( $data . '/first-admin.code' ) ), array( 0, TRUE, TRUE ), 'user add admin: administrator with a password shown once' );
list( , $out ) = pv( array( 'status' ) );
eq( strpos( $out, 'one-time code' ), FALSE, 'status: no one-time code once there is a user' );

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

// ---- after the setup: no changes on the command line (users, passwords, projects, tokens: in the browser)
list( $code, $out, $calls ) = pv( array( 'password', 'admin' ) );
eq( array( $code !== 0, strpos( $out, 'not on the command line' ) !== FALSE, strpos( implode( "\n", $calls ), 'VIEWER_PASSWORD=' ) ), array( TRUE, TRUE, FALSE ),
    'password: not on the command line, nothing sent to the container' );
list( $code, $out ) = pv( array( 'user', 'add', 'eve', 'admin' ) );
eq( array( $code !== 0, strpos( $out, 'refused: this viewer has an administrator' ) !== FALSE, strpos( $out, 'password:' ) ), array( TRUE, TRUE, FALSE ),
    'user add after the setup: refused by the viewer, no password shown' );
foreach( array( array( 'user', 'delete', 'anna' ), array( 'project', 'add', 'anna', 'FW1' ), array( 'token', 'anna', 'FW1', 'read', '5' ), array( 'token', 'delete', 'anna', 'FW1', 'x' ) ) as $a )
    eq( array( pv( $a )[0] !== 0, strpos( pv( $a )[1], 'not on the command line' ) !== FALSE ), array( TRUE, TRUE ), implode( ' ', array_slice( $a, 0, 2 ) ) . ': not on the command line' );
putenv( 'PANOSPHP_VIEWER_DATA=' . $data );
require_once $viewer . '/lib/ViewerApp.php';
$app = new ViewerApp( $data );
$ok = function( $u, $p ) use ( $app ) { try { $app->login( $u, $p, '127.0.0.1' ); return TRUE; } catch( Exception $e ) { return FALSE; } };
eq( array( $ok( 'admin', $firstPw ), $app->userByName( 'eve' ) ), array( TRUE, null ), 'nothing changed: the password of the administrator works, no new administrator' );
// looking works: users, projects, tokens (made in the browser - here directly)
$anna = $app->userByName( 'anna' );
$p = $app->projectCreate( $anna, 'FW1' );
$app->tokenCreate( $anna, $p['pid'], 'browser token', 'read', 5 );
eq( (bool)preg_match( '/admin \(admin\)\s+anna/', pv( array( 'user', 'list' ) )[1] ), TRUE, 'user list' );
eq( trim( pv( array( 'projects', 'anna' ) )[1] ), $p['pid'] . '  owner  FW1', 'projects of a user' );
eq( strpos( pv( array( 'token', 'list', 'anna', 'FW1' ) )[1], 'browser token' ) !== FALSE, TRUE, 'token list' );
eq( count( $app->cliNotices( $app->userByName( 'admin' ) ) ) > 0, TRUE, 'the refused tries are shown to the administrator' );

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

// ---- install-viewer.sh: one file for a computer with internet (downloads from a file:// address here)
function inst( string $cwd, array $args, array $env = array() ): array
{
    global $viewer, $baseEnv, $log;
    @unlink( $log );
    $p = proc_open( array_merge( array( 'bash', realpath( $viewer ) . '/install-viewer.sh' ), $args ), array( 0 => array( 'file', '/dev/null', 'r' ), 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ),
        $pipes, $cwd, $env + array( 'PANOSPHP_VIEWER_BASE_URL' => 'file://' . realpath( $viewer ) ) + $baseEnv );
    $out = stream_get_contents( $pipes[1] ) . stream_get_contents( $pipes[2] );
    $code = proc_close( $p );
    $calls = array_map( function( $l ) { return implode( ' ', json_decode( $l, TRUE ) ); }, file_exists( $log ) ? file( $log, FILE_IGNORE_NEW_LINES ) : array() );
    return array( $code, $out, $calls );
}
$site = $tmp . '/site';
mkdir( $site );
list( $code, $out, $calls ) = inst( $site, array() );
$inst = $site . '/panosphp-viewer';
eq( array( $code, is_executable( $inst . '/panosphp-viewer' ), is_file( $inst . '/docker-compose.yml' ), is_file( $inst . '/docker-compose.https.yml' ), is_file( $inst . '/docker/Caddyfile' ), is_dir( $inst . '/plugins' ) ),
    array( 0, TRUE, TRUE, TRUE, TRUE, TRUE ), 'install-viewer: folder with script, compose files, Caddyfile, plugins/' );
$envText = (string)file_get_contents( $inst . '/.env' );
eq( array( strpos( $envText, 'VIEWER_IMAGE=swaschkut/pan-os-php:alpha' ) !== FALSE, strpos( $envText, 'VIEWER_PORT=8080' ) !== FALSE, decoct( fileperms( $inst . '/.env' ) & 0777 ) ),
    array( TRUE, TRUE, '600' ), 'install-viewer: settings of the first start, image of the channel' );
eq( array( in_array( 'compose -f docker-compose.yml pull', $calls, TRUE ), in_array( 'compose -f docker-compose.yml up -d', $calls, TRUE ) ), array( TRUE, TRUE ), 'install-viewer: pulls the images and starts' );
file_put_contents( $inst . '/plugins/x.ppp', 'keep' );
list( $code, $out, $calls ) = inst( $site, array() );
eq( array( $code, (string)file_get_contents( $inst . '/.env' ) === $envText, is_file( $inst . '/plugins/x.ppp' ), in_array( 'compose -f docker-compose.yml pull', $calls, TRUE ) ),
    array( 0, TRUE, TRUE, TRUE ), 'install-viewer again (update): settings and plug-ins stay, images pulled' );
list( $code, $out ) = inst( $site, array( 'other' ), array( 'PANOSPHP_CHANNEL' => 'main' ) );
eq( array( $code, strpos( (string)@file_get_contents( $site . '/other/.env' ), 'VIEWER_IMAGE=swaschkut/pan-os-php:latest' ) !== FALSE ), array( 0, TRUE ), 'install-viewer: channel main uses the image latest, own folder' );
$before = md5_file( $inst . '/panosphp-viewer' );
list( $code, $out ) = inst( $site, array(), array( 'PANOSPHP_VIEWER_BASE_URL' => 'file:///nonexistent' ) );
eq( array( $code !== 0, strpos( $out, 'download failed' ) !== FALSE, md5_file( $inst . '/panosphp-viewer' ) === $before ), array( TRUE, TRUE, TRUE ), 'install-viewer: a failed download changes nothing' );
eq( inst( $site, array(), array( 'PANOSPHP_CHANNEL' => 'x' ) )[0] !== 0, TRUE, 'install-viewer: unknown channel refused' );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
foreach( $failed as $m )
    print " - " . $m . "\n";
exit( count( $failed ) ? 1 : 0 );
