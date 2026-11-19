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
 * PH::ironSkilletVersion() and the iron-skillet snippets for a PAN-OS version without an own snippet
 * (e.g. 12.2): the snippet of the newest version below is used, older than the oldest snippet -> error.
 *
 *   php tests/test_ironskillet_version.php
 */

$here = dirname(__FILE__);
require_once $here . '/../lib/pan_php_framework.php';
PH::processCliArgs();

$failed = array();
$checks = 0;

function check( $cond, $msg )
{
    global $failed, $checks;
    $checks++;
    if( !$cond )
    {
        $failed[] = $msg;
        print "  FAIL " . $msg . "\n";
    }
}

function eq( $actual, $expected, $msg )
{
    check( $actual === $expected, $msg . ' - expected ' . json_encode($expected) . ', got ' . json_encode($actual) );
}

/** run $fn, return the derr() message or null */
function derrOf( $fn )
{
    PH::enableExceptionSupport();
    try { ob_start(); $fn(); ob_end_clean(); return null; }
    catch( Exception $e ) { ob_end_clean(); return $e->getMessage(); }
    finally { PH::disableExceptionSupport(); }
}

function quiet( $fn ) { ob_start(); $r = $fn(); ob_end_clean(); return $r; }

$all = array( '8.1', '9.1', '10.0', '10.1', '10.2', '11.0', '11.1', '11.2', '12.1' );

// helper
eq( PH::ironSkilletVersion( '12.1', $all, 'x' ), '12.1', 'own snippet' );
eq( PH::ironSkilletVersion( '10.0', $all, 'x' ), '10.0', 'own snippet 10.0' );
eq( quiet( function() use ( $all ) { return PH::ironSkilletVersion( '12.2', $all, 'x' ); } ), '12.1', '12.2 -> newest snippet 12.1' );
eq( quiet( function() use ( $all ) { return PH::ironSkilletVersion( '13.0', $all, 'x' ); } ), '12.1', '13.0 -> newest snippet 12.1' );
eq( quiet( function() use ( $all ) { return PH::ironSkilletVersion( '9.0', $all, 'x' ); } ), '8.1', '9.0 (between two snippets) -> 8.1' );
eq( quiet( function() { return PH::ironSkilletVersion( '12.2', array( '11.1' ), 'x' ); } ), '11.1', 'single snippet 11.1 -> used for 12.2' );
$m = derrOf( function() use ( $all ) { PH::ironSkilletVersion( '7.1', $all, 'test profiles' ); } );
check( $m !== null && strpos($m, "iron-skillet test profiles are not available for PAN-OS version '7.1'") !== FALSE, 'older than the oldest snippet -> error: ' . $m );
eq( derrOf( function() { PH::ironSkilletVersion( '10.0', array( '11.1' ), 'x' ); } ) !== null, TRUE, 'older than the only snippet -> error' );

// the message is printed once per snippet type and version
ob_start();
PH::ironSkilletVersion( '12.3', $all, 'once' );
PH::ironSkilletVersion( '12.3', $all, 'once' );
$out = ob_get_clean();
eq( substr_count( $out, 'no snippet for PAN-OS 12.3 - using the snippet of PAN-OS 12.1' ), 1, 'fallback message once' );

// every iron-skillet snippet: 12.2 gives the 12.1 snippet (11.1 for the SCM-only snippets), 7.1 is refused
$snippets = array(
    'LogProfile' => array( 'LogProfile', 'ironSkilletXml', '12.1' ),
    'ZoneProtectionProfile' => array( 'ZoneProtectionProfile', 'ironSkilletXml', '12.1' ),
    'AntiVirusProfile' => array( 'AntiVirusProfile', 'ironSkilletXml', '12.1' ),
    'AntiSpywareProfile' => array( 'AntiSpywareProfile', 'ironSkilletXml', '12.1' ),
    'AntiSpywareProfile SCM' => array( 'AntiSpywareProfile', 'ironSkilletXmlScm', '11.1' ),
    'VulnerabilityProfile' => array( 'VulnerabilityProfile', 'ironSkilletXml', '12.1' ),
    'URLProfile' => array( 'URLProfile', 'ironSkilletXml', '12.1' ),
    'FileBlockingProfile' => array( 'FileBlockingProfile', 'ironSkilletXml', '12.1' ),
    'WildfireProfile' => array( 'WildfireProfile', 'ironSkilletXml', '12.1' ),
    'DNSSecurityProfile' => array( 'DNSSecurityProfile', 'ironSkilletXml', '11.1' ),
    'VirusAndWildfireProfile' => array( 'VirusAndWildfireProfile', 'ironSkilletXml', '11.1' ),
);
foreach( $snippets as $label => $s )
{
    list( $class, $fn, $newest ) = $s;
    $new = quiet( function() use ( $class, $fn ) { return call_user_func( array( $class, $fn ), '12.2' ); } );
    $ref = call_user_func( array( $class, $fn ), $newest );
    check( is_string($new) && $new !== '', $label . ': snippet for 12.2' );
    eq( $new, $ref, $label . ': 12.2 snippet = ' . $newest . ' snippet' );
    $d = new DOMDocument();
    check( is_string($new) && @$d->loadXML( $new ) !== FALSE, $label . ': 12.2 snippet is valid XML' );
    check( derrOf( function() use ( $class, $fn ) { call_user_func( array( $class, $fn ), '7.1' ); } ) !== null, $label . ': 7.1 refused' );
}

print "\n" . $checks . " checks, " . count($failed) . " failed\n";
if( count($failed) )
{
    foreach( $failed as $f ) print " - " . $f . "\n";
    exit( 1 );
}
exit( 0 );
