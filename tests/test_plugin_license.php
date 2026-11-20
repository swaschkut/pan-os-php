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
 * Licences and encrypted plug-in packages (lib/misc-classes/PluginLicense.php, PluginPackage.php).
 *   php tests/test_plugin_license.php
 */
require_once dirname( __FILE__ ) . '/../lib/misc-classes/PluginLicense.php';
require_once dirname( __FILE__ ) . '/../lib/misc-classes/PluginPackage.php';
require_once dirname( __FILE__ ) . '/plugin_license_helper.php';

$failed = array(); $checks = 0;
function eq( $actual, $expected, $msg )
{
    global $failed, $checks;
    $checks++;
    if( $actual !== $expected )
        $failed[] = $msg . "\n      expected " . json_encode( $expected ) . "\n      got      " . json_encode( $actual );
}
function err( callable $f ): string
{
    try { $f(); return 'no error'; }
    catch( Exception $e ) { return $e->getMessage(); }
}

$k = testLicenceKeys();
putenv( 'PANOSPHP_LICENSE_TEST_KEYS=' . testTrustedJson( $k ) );
$dir = sys_get_temp_dir() . '/plugin-license-test-' . getmypid();
mkdir( $dir );

// ---- licences
$text = testLicence( $k, array( 'id' => 'L-1', 'customer' => 'ACME', 'features' => array( 'migration-cisco' ) ) );
$l = PluginLicense::parse( "some text before\n" . $text . "and after" );
eq( array( $l->data['customer'], $l->hasFeature( 'migration-cisco' ), $l->hasFeature( 'migration-cp' ), $l->state() ), array( 'ACME', TRUE, FALSE, 'valid' ), 'licence: parsed, features' );
eq( PluginLicense::parse( $l->compact() )->data['id'], 'L-1', 'licence: one-line form for runs' );
eq( array_key_exists( 'keys', $l->summary() ), FALSE, 'licence: the summary holds no keys' );
// changed content: the payload of a licence with another customer, the signature of the first
$b = strpos( $text, PluginLicense::BEGIN ) + strlen( PluginLicense::BEGIN );
$outer = json_decode( base64_decode( preg_replace( '/\s+/', '', substr( $text, $b, strpos( $text, PluginLicense::END ) - $b ) ) ), TRUE );
$p = json_decode( base64_decode( $outer['payload'] ), TRUE );
$p['valid_until'] = '2099-12-31';
$outer['payload'] = base64_encode( json_encode( $p, JSON_UNESCAPED_SLASHES ) );
$forged = PluginLicense::BEGIN . base64_encode( json_encode( $outer ) ) . PluginLicense::END;
eq( err( function() use ( $forged ) { PluginLicense::parse( $forged ); } ), 'licence: the signature does not match - the licence was changed or is not genuine', 'licence: extended end date is refused' );
$other = testLicenceKeys();
eq( strpos( err( function() use ( $other ) { PluginLicense::parse( testLicence( $other, array() ) ); } ), 'licence: signed with an unknown key' ), 0, 'licence: a key that is not trusted' );
eq( err( function() { PluginLicense::parse( 'no licence' ); } ), 'licence: no licence block found', 'licence: no block' );
// states: warning 30 days before the end, grace after it, then expired
$l2 = PluginLicense::parse( testLicence( $k, array( 'valid_until' => '2027-01-31', 'grace_days' => 14, 'features' => array( 'f' ) ) ) );
$end = strtotime( '2027-01-31 23:59:59 UTC' );
eq( array( $l2->state( $end - 86400 * 40 ), $l2->state( $end - 86400 * 10 ), $l2->state( $end + 86400 * 5 ), $l2->state( $end + 86400 * 15 ) ),
    array( 'valid', 'warning', 'grace', 'expired' ), 'licence: valid / warning / grace / expired' );
eq( array( $l2->hasFeature( 'f', $end + 86400 * 13 ), $l2->hasFeature( 'f', $end + 86400 * 15 ) ), array( TRUE, FALSE ), 'licence: features within the grace days, not after' );

// ---- packages
$files = array( 'plugin.php' => '<?php return array( "name" => "demo" );',
    'parser/A/A.php' => '<?php require_once dirname(__FILE__) . "/Amisc.php"; function demoA() { return demoAmisc() . "+A"; }',
    'parser/A/Amisc.php' => '<?php function demoAmisc() { return "misc"; }',
    'data/list.txt' => "one\ntwo\n" );
$r1 = testPack( $dir, 'demo', '1.0', 'demo-feature', $files );
$pkg = $dir . '/demo.ppp';
eq( strpos( (string)file_get_contents( $pkg ), 'demoAmisc' ), FALSE, 'package: the code is not readable in the file' );
eq( PluginPackage::header( $pkg )['feature'], 'demo-feature', 'package: header without the key' );
eq( err( function() use ( $pkg ) { PluginPackage::mount( $pkg, null ); } ), 'not licensed: no licence installed', 'package: no licence' );
$noFeature = PluginLicense::parse( testLicence( $k, array( 'features' => array( 'other' ), 'keys' => array( $r1['kid'] => $r1['key'] ) ) ) );
eq( err( function() use ( $pkg, $noFeature ) { PluginPackage::mount( $pkg, $noFeature ); } ), 'not licensed: the licence does not hold the feature demo-feature', 'package: feature missing' );
$ended = PluginLicense::parse( testLicence( $k, array( 'valid_until' => '2020-01-01', 'grace_days' => 0, 'features' => array( 'demo-feature' ), 'keys' => array( $r1['kid'] => $r1['key'] ) ) ) );
eq( err( function() use ( $pkg, $ended ) { PluginPackage::mount( $pkg, $ended ); } ), 'not licensed: the licence ended on 2020-01-01', 'package: licence ended' );
$good = PluginLicense::parse( testLicence( $k, array( 'features' => array( 'demo-feature' ), 'keys' => array( $r1['kid'] => $r1['key'] ) ) ) );
// a newer release has a new key: the old licence does not open it
$r2 = testPack( $dir, 'demo', '2.0', 'demo-feature', $files );
eq( strpos( err( function() use ( $pkg, $good ) { PluginPackage::mount( $pkg, $good ); } ), 'not licensed: the licence does not hold the key of this release (2.0)' ), 0, 'package: new release, old licence' );
$good2 = PluginLicense::parse( testLicence( $k, array( 'features' => array( 'demo-feature' ), 'keys' => array( $r1['kid'] => $r1['key'], $r2['kid'] => $r2['key'] ) ) ) );
// changed header (other feature): the cipher text does not fit any more
$c = file( $pkg );
$h = json_decode( $c[1], TRUE ); $h['feature'] = 'other';
file_put_contents( $dir . '/demo-changed.ppp', $c[0] . json_encode( $h, JSON_UNESCAPED_SLASHES ) . "\n" . $c[2] );
$both = PluginLicense::parse( testLicence( $k, array( 'features' => array( 'demo-feature', 'other' ), 'keys' => array( $r2['kid'] => $r2['key'] ) ) ) );
eq( err( function() use ( $dir, $both ) { PluginPackage::mount( $dir . '/demo-changed.ppp', $both ); } ), 'plug-in package: damaged or changed', 'package: changed header is refused' );
eq( PluginPackage::mount( $pkg, $good2 )['version'], '2.0', 'package: renewed licence opens the new release' );
eq( array( is_file( 'ppp://demo/parser/A/A.php' ), is_dir( 'ppp://demo/parser' ), is_file( 'ppp://demo/nothing.php' ), file_get_contents( 'ppp://demo/data/list.txt' ) ),
    array( TRUE, TRUE, FALSE, "one\ntwo\n" ), 'package: files readable through ppp://' );
require 'ppp://demo/parser/A/A.php';
eq( demoA(), 'misc+A', 'package: require from memory, with dirname(__FILE__) includes' );
eq( file_get_contents( 'ppp://demo/parser/A/../A/Amisc.php' ) !== FALSE, TRUE, 'package: paths with ..' );
eq( @file_put_contents( 'ppp://demo/x.php', 'x' ), FALSE, 'package: nothing can be written' );
eq( glob( $dir . '/*.php' ), array(), 'package: no clear text on disk' );

// ---- a run: PANOSPHP_PLUGIN_PACKAGES + PANOSPHP_LICENSE (separate process)
$code = 'require "' . dirname( __FILE__ ) . '/../lib/misc-classes/PluginLicense.php"; require "' . dirname( __FILE__ ) . '/../lib/misc-classes/PluginPackage.php";'
    . ' PluginPackage::bootFromEnv(); if( is_file( "ppp://demo/parser/A/A.php" ) ) { require "ppp://demo/parser/A/A.php"; echo demoA(); } else echo "locked";';
foreach( array( 'with licence' => $good2->compact(), 'without' => '' ) as $what => $licText )
{
    $p = proc_open( array( PHP_BINARY, '-r', $code ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes, null,
        array( 'PANOSPHP_PLUGIN_PACKAGES' => $pkg, 'PANOSPHP_LICENSE' => $licText, 'PANOSPHP_LICENSE_TEST_KEYS' => testTrustedJson( $k ), 'PATH' => getenv( 'PATH' ) ) );
    $out = stream_get_contents( $pipes[1] );
    $errOut = stream_get_contents( $pipes[2] );
    proc_close( $p );
    eq( $out, $what === 'without' ? 'locked' : 'misc+A', 'run ' . $what . ': ' . trim( $errOut ) );
}

exec( 'rm -rf ' . escapeshellarg( $dir ) );
print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
foreach( $failed as $m )
    print " - " . $m . "\n";
exit( count( $failed ) ? 1 : 0 );
