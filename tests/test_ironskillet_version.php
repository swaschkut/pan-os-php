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
 * (e.g. 13.0): the snippet of the newest version below is used, older than the oldest snippet -> error.
 * 12.1 and 12.2 have their own snippets; 12.2 differs from 12.1 only in VP (local deep learning, SQL / Command Injection).
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

// one central list: PH::IRONSKILLET_VERSIONS, per snippet the oldest (and for SCM the only) version
$newest = PH::IRONSKILLET_VERSIONS[ count(PH::IRONSKILLET_VERSIONS) - 1 ];
eq( $newest, '12.2', 'newest iron-skillet version' );
eq( array_keys( PH::IRONSKILLET_SNIPPETS ), array( 'antivirus profiles', 'anti-spyware profiles', 'URL filtering profiles',
    'vulnerability protection profiles', 'file blocking profiles', 'WildFire analysis profiles', 'log forwarding profiles',
    'zone protection profiles', 'SCM anti-spyware profiles', 'DNS security profiles', 'antivirus and WildFire profiles' ), 'snippet names' );

// helper
eq( PH::ironSkilletVersion( '12.1', 'antivirus profiles' ), '12.1', 'own snippet' );
eq( PH::ironSkilletVersion( '10.0', 'log forwarding profiles' ), '10.0', 'own snippet 10.0' );
eq( PH::ironSkilletVersion( '8.1', 'antivirus profiles' ), '8.1', 'own snippet 8.1 (AV)' );
eq( PH::ironSkilletVersion( '12.2', 'log forwarding profiles' ), '12.2', 'own snippet 12.2' );
eq( quiet( function() { return PH::ironSkilletVersion( '12.3', 'log forwarding profiles' ); } ), '12.2', '12.3 -> newest snippet 12.2' );
eq( quiet( function() { return PH::ironSkilletVersion( '13.0', 'zone protection profiles' ); } ), '12.2', '13.0 -> newest snippet 12.2' );
eq( quiet( function() { return PH::ironSkilletVersion( '9.0', 'anti-spyware profiles' ); } ), '8.1', '9.0 (between two snippets) -> 8.1' );
eq( quiet( function() { return PH::ironSkilletVersion( '12.2', 'DNS security profiles' ); } ), '11.1', 'SCM snippet 11.1 -> used for 12.2' );
eq( quiet( function() { return PH::ironSkilletVersion( '11.2', 'DNS security profiles' ); } ), '11.1', 'SCM snippet: 11.2 -> 11.1 (only version)' );
$m = derrOf( function() { PH::ironSkilletVersion( '7.1', 'antivirus profiles' ); } );
check( $m !== null && strpos($m, "iron-skillet antivirus profiles are not available for PAN-OS version '7.1' (oldest iron-skillet version: 8.1)") !== FALSE, 'older than the oldest snippet -> error: ' . $m );
check( derrOf( function() { PH::ironSkilletVersion( '9.1', 'log forwarding profiles' ); } ) !== null, 'log forwarding: 9.1 older than 10.0 -> error' );
check( derrOf( function() { PH::ironSkilletVersion( '10.0', 'DNS security profiles' ); } ) !== null, 'SCM: older than 11.1 -> error' );
check( derrOf( function() { PH::ironSkilletVersion( '12.1', 'no such snippet' ); } ) !== null, 'unknown snippet name -> error' );

// the message is printed once per snippet type and version
ob_start();
PH::ironSkilletVersion( '12.4', 'file blocking profiles' );
PH::ironSkilletVersion( '12.4', 'file blocking profiles' );
$out = ob_get_clean();
eq( substr_count( $out, 'no snippet for PAN-OS 12.4 - using the snippet of PAN-OS 12.2' ), 1, 'fallback message once' );

// every iron-skillet snippet: 13.0 gives the 12.2 snippet (11.1 for the SCM-only snippets), 7.1 is refused
$snippets = array(
    'LogProfile' => array( 'LogProfile', 'ironSkilletXml', '12.2' ),
    'ZoneProtectionProfile' => array( 'ZoneProtectionProfile', 'ironSkilletXml', '12.2' ),
    'AntiVirusProfile' => array( 'AntiVirusProfile', 'ironSkilletXml', '12.2' ),
    'AntiSpywareProfile' => array( 'AntiSpywareProfile', 'ironSkilletXml', '12.2' ),
    'AntiSpywareProfile SCM' => array( 'AntiSpywareProfile', 'ironSkilletXmlScm', '11.1' ),
    'VulnerabilityProfile' => array( 'VulnerabilityProfile', 'ironSkilletXml', '12.2' ),
    'URLProfile' => array( 'URLProfile', 'ironSkilletXml', '12.2' ),
    'FileBlockingProfile' => array( 'FileBlockingProfile', 'ironSkilletXml', '12.2' ),
    'WildfireProfile' => array( 'WildfireProfile', 'ironSkilletXml', '12.2' ),
    'DNSSecurityProfile' => array( 'DNSSecurityProfile', 'ironSkilletXml', '11.1' ),
    'VirusAndWildfireProfile' => array( 'VirusAndWildfireProfile', 'ironSkilletXml', '11.1' ),
);
foreach( $snippets as $label => $s )
{
    list( $class, $fn, $newest ) = $s;
    $new = quiet( function() use ( $class, $fn ) { return call_user_func( array( $class, $fn ), '13.0' ); } );
    $ref = call_user_func( array( $class, $fn ), $newest );
    check( is_string($new) && $new !== '', $label . ': snippet for 13.0' );
    eq( $new, $ref, $label . ': 13.0 snippet = ' . $newest . ' snippet' );
    $d = new DOMDocument();
    check( is_string($new) && @$d->loadXML( $new ) !== FALSE, $label . ': 13.0 snippet is valid XML' );
    check( derrOf( function() use ( $class, $fn ) { call_user_func( array( $class, $fn ), '7.1' ); } ) !== null, $label . ': 7.1 refused' );

    // 12.2 own snippet: same as 12.1 except VP (local deep learning)
    if( $newest == '12.2' )
    {
        $s121 = call_user_func( array( $class, $fn ), '12.1' );
        $s122 = call_user_func( array( $class, $fn ), '12.2' );
        // local-deep-learning is not in any snippet (set from the BP JSON), so also VP 12.2 = 12.1
        eq( $s122, $s121, $label . ': 12.2 snippet = 12.1 snippet' );
    }
}

// VP 12.1 / 12.2: no local-deep-learning in the snippet (as the firewall writes a new profile; set from the BP JSON)
$d = new DOMDocument();
foreach( array( '12.1', '12.2' ) as $version )
{
    $d->loadXML( VulnerabilityProfile::ironSkilletXml( $version ) );
    eq( (new DOMXPath( $d ))->query( '//local-deep-learning' )->length, 0, 'VP ' . $version . ': no local-deep-learning' );
}

print "\n" . $checks . " checks, " . count($failed) . " failed\n";
if( count($failed) )
{
    foreach( $failed as $f ) print " - " . $f . "\n";
    exit( 1 );
}
exit( 0 );
