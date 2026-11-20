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
 * local deep learning (LDL) per PAN-OS version: SecurityProfile2::$localDeepLearningMinVersion
 * - AS: HTTP / HTTP2 C2 detectors from 11.2 (SSL, Unknown-TCP, Unknown-UDP never)
 * - VP: SQL Injection / Command Injection from 12.2
 * load (missing element), alert-only-set, best-practice-set, iron-skillet anti-spyware snippet.
 *
 *   php tests/test_local_deep_learning.php
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

const AS_DETECTORS = array( 'HTTP', 'HTTP2', 'SSL', 'Unknown-TCP', 'Unknown-UDP' );

/** firewall configuration of PAN-OS $version with one AS and one VP profile (inline ML entries without LDL) */
function config( $version )
{
    $as = '';
    foreach( AS_DETECTORS as $d )
        $as .= '<entry name="' . $d . ' Command and Control detector"><inline-policy-action>alert</inline-policy-action></entry>';
    $xml = '<config version="' . $version . '.0" urldb="paloaltonetworks"><mgt-config><users/></mgt-config><shared/>'
        . '<devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><profiles>'
        . '<spyware><entry name="AS-1"><rules/><mica-engine-spyware-enabled>' . $as . '</mica-engine-spyware-enabled>'
        . '<cloud-inline-analysis>no</cloud-inline-analysis></entry></spyware>'
        . '<vulnerability><entry name="VP-1"><rules/><mica-engine-vulnerability-enabled>'
        . '<entry name="SQL Injection"><inline-policy-action>alert</inline-policy-action></entry>'
        . '<entry name="Command Injection"><inline-policy-action>alert</inline-policy-action></entry>'
        . '</mica-engine-vulnerability-enabled><cloud-inline-analysis>no</cloud-inline-analysis></entry></vulnerability>'
        . '</profiles></entry></vsys></entry></devices></config>';
    $pan = new PANConf();
    ob_start();
    $pan->load_from_xmlstring( $xml );
    ob_end_clean();
    $vsys = $pan->findVirtualSystem( 'vsys1' );
    return array( $vsys->AntiSpywareProfileStore->find( 'AS-1' ), $vsys->VulnerabilityProfileStore->find( 'VP-1' ) );
}

/** model => local-deep-learning value in the XML ('-' = no element) */
function ldl( $profile, $container )
{
    $out = array();
    $node = DH::findFirstElement( $container, $profile->xmlroot );
    foreach( $node->childNodes as $e )
    {
        if( $e->nodeType != XML_ELEMENT_NODE )
            continue;
        $l = DH::findFirstElement( 'local-deep-learning', $e );
        $out[ str_replace( ' Command and Control detector', '', $e->getAttribute('name') ) ] = $l === FALSE ? '-' : $l->textContent;
    }
    return $out;
}

$asNone = array( 'HTTP' => '-', 'HTTP2' => '-', 'SSL' => '-', 'Unknown-TCP' => '-', 'Unknown-UDP' => '-' );
$vpNone = array( 'SQL Injection' => '-', 'Command Injection' => '-' );

// version table
check( SecurityProfile2::localDeepLearningSupportedInVersion( 'spyware', 'HTTP Command and Control detector', 112 ), 'AS HTTP 11.2' );
check( !SecurityProfile2::localDeepLearningSupportedInVersion( 'spyware', 'HTTP Command and Control detector', 111 ), 'AS HTTP not 11.1' );
check( !SecurityProfile2::localDeepLearningSupportedInVersion( 'spyware', 'SSL Command and Control detector', 122 ), 'AS SSL never' );
check( SecurityProfile2::localDeepLearningSupportedInVersion( 'vulnerability', 'Command Injection', 122 ), 'VP Command Injection 12.2' );
check( SecurityProfile2::localDeepLearningSupportedInVersion( 'vulnerability', 'SQL Injection', 122 ), 'VP SQL Injection 12.2' );
check( !SecurityProfile2::localDeepLearningSupportedInVersion( 'vulnerability', 'Command Injection', 121 ), 'VP Command Injection not 12.1' );

foreach( array(
             // version => array( after load AS, after load VP, after alert-only-set AS, after alert-only-set VP )
             '11.1' => array( $asNone, $vpNone, $asNone, $vpNone ),
             '11.2' => array( array( 'HTTP' => 'disable', 'HTTP2' => 'disable' ) + $asNone, $vpNone,
                              array( 'HTTP' => 'enable', 'HTTP2' => 'enable' ) + $asNone, $vpNone ),
             '12.1' => array( array( 'HTTP' => 'disable', 'HTTP2' => 'disable' ) + $asNone, $vpNone,
                              array( 'HTTP' => 'enable', 'HTTP2' => 'enable' ) + $asNone, $vpNone ),
             '12.2' => array( array( 'HTTP' => 'disable', 'HTTP2' => 'disable' ) + $asNone, array( 'SQL Injection' => 'disable', 'Command Injection' => 'disable' ),
                              array( 'HTTP' => 'enable', 'HTTP2' => 'enable' ) + $asNone, array( 'SQL Injection' => 'enable', 'Command Injection' => 'enable' ) ),
         ) as $version => $expect )
{
    list( $as, $vp ) = config( $version );
    eq( ldl( $as, 'mica-engine-spyware-enabled' ), $expect[0], $version . ' AS after load' );
    eq( ldl( $vp, 'mica-engine-vulnerability-enabled' ), $expect[1], $version . ' VP after load' );

    ob_start();
    $as->inlineML_AlertOnlySet();
    $sendAPI = false;
    $vp->inlineML_AlertOnlySet( $sendAPI );
    ob_end_clean();
    eq( ldl( $as, 'mica-engine-spyware-enabled' ), $expect[2], $version . ' AS after alert-only-set' );
    eq( ldl( $vp, 'mica-engine-vulnerability-enabled' ), $expect[3], $version . ' VP after alert-only-set' );
    if( $version == '12.2' )
        eq( $vp->additional['mica-engine-vulnerability-enabled']['Command Injection']['local-deep-learning'] ?? null, 'enable', '12.2 VP additional[] updated' );

    // best-practice-set: same local deep learning result
    list( $as, $vp ) = config( $version );
    ob_start();
    $as->inlineML_BestPracticeSet();
    $vp->inlineML_BestPracticeSet();
    ob_end_clean();
    eq( ldl( $as, 'mica-engine-spyware-enabled' ), $expect[2], $version . ' AS after best-practice-set' );
    eq( ldl( $vp, 'mica-engine-vulnerability-enabled' ), $expect[3], $version . ' VP after best-practice-set' );
}

// iron-skillet anti-spyware snippet: local-deep-learning only for HTTP / HTTP2 from 11.2
foreach( array( '11.1' => 0, '11.2' => 2, '12.1' => 2 ) as $version => $count )
{
    $d = new DOMDocument();
    $d->loadXML( AntiSpywareProfile::ironSkilletXml( $version ) );
    $x = new DOMXPath( $d );
    $per = $x->query( '//entry[mica-engine-spyware-enabled][1]/mica-engine-spyware-enabled/entry[local-deep-learning]' );
    eq( $per->length, $count, 'iron-skillet ' . $version . ': detectors with local-deep-learning in the first profile' );
    eq( $x->query( '//mica-engine-spyware-enabled/entry[local-deep-learning][not(starts-with(@name,"HTTP"))]' )->length, 0, 'iron-skillet ' . $version . ': only HTTP / HTTP2' );
}

print "\n" . $checks . " checks, " . count($failed) . " failed\n";
if( count($failed) )
{
    foreach( $failed as $f ) print " - " . $f . "\n";
    exit( 1 );
}
exit( 0 );
