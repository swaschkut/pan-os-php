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
 * local deep learning follows the BP JSON (cloud-inline 'bp' / 'visibility', entries with "local-deep-learning"):
 * alert-only-set (visibility), best-practice-set (bp) and the BP / visibility check, AS and VP, PAN-OS 12.2.
 * JSON variants: shipped scm_bp_sp_panw.json, no entry, enable / disable / !disable / !enable for 'any', one model.
 *
 *   php tests/test_local_deep_learning_json.php
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

$shipped = json_decode( file_get_contents( $here . '/../utils/api/v1/bp/scm_bp_sp_panw.json' ), true );

/** BP JSON with the local-deep-learning entries of $variant (AS and VP, bp and visibility) */
function bpJson( $variant )
{
    global $shipped;
    $json = $shipped;
    foreach( array( 'spyware', 'vulnerability' ) as $t )
        foreach( array( 'bp', 'visibility' ) as $s )
        {
            if( $variant == 'shipped' )
                continue;
            $list = array_values( array_filter( $json[$t]['cloud-inline'][$s]['inline-policy-action'], function( $e ) { return !isset( $e['local-deep-learning'] ); } ) );
            $one = $t == 'spyware' ? 'HTTP Command and Control detector' : 'Command Injection';
            $map = array( 'enable-any' => array( array( 'any' ), 'enable' ), 'disable-any' => array( array( 'any' ), 'disable' ),
                '!disable-any' => array( array( 'any' ), '!disable' ), '!enable-any' => array( array( 'any' ), '!enable' ),
                'enable-one' => array( array( $one ), 'enable' ) );
            if( isset( $map[$variant] ) )
                $list[] = array( 'type' => $map[$variant][0], 'local-deep-learning' => array( $map[$variant][1] ) );
            $json[$t]['cloud-inline'][$s]['inline-policy-action'] = $list;
        }
    return $json;
}

/** PAN-OS 12.2 firewall: AS-1 / VP-1, inline cloud analysis on, local-deep-learning $start on the LDL models */
function config( $start )
{
    $l = '<local-deep-learning>' . $start . '</local-deep-learning>';
    $as = '';
    foreach( array( 'HTTP', 'HTTP2', 'SSL', 'Unknown-TCP', 'Unknown-UDP' ) as $d )
        $as .= '<entry name="' . $d . ' Command and Control detector"><inline-policy-action>alert</inline-policy-action>'
            . ( in_array( $d, array( 'HTTP', 'HTTP2' ) ) ? $l : '' ) . '</entry>';
    $xml = '<config version="12.2.0" urldb="paloaltonetworks"><mgt-config><users/></mgt-config><shared/>'
        . '<devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><profiles>'
        . '<spyware><entry name="AS-1"><rules/><mica-engine-spyware-enabled>' . $as . '</mica-engine-spyware-enabled>'
        . '<cloud-inline-analysis>yes</cloud-inline-analysis></entry></spyware>'
        . '<vulnerability><entry name="VP-1"><rules/><mica-engine-vulnerability-enabled>'
        . '<entry name="SQL Injection"><inline-policy-action>alert</inline-policy-action>' . $l . '</entry>'
        . '<entry name="Command Injection"><inline-policy-action>alert</inline-policy-action>' . $l . '</entry>'
        . '</mica-engine-vulnerability-enabled><cloud-inline-analysis>yes</cloud-inline-analysis></entry></vulnerability>'
        . '</profiles></entry></vsys></entry></devices></config>';
    $pan = new PANConf();
    ob_start();
    $pan->load_from_xmlstring( $xml );
    ob_end_clean();
    $v = $pan->findVirtualSystem( 'vsys1' );
    return array( $v->AntiSpywareProfileStore->find( 'AS-1' ), $v->VulnerabilityProfileStore->find( 'VP-1' ) );
}

/** "HTTP=enable,HTTP2=enable,SSL=-|SQL Injection=enable,Command Injection=enable" */
function ldl( $as, $vp )
{
    $o = array();
    foreach( array( array( $as, 'mica-engine-spyware-enabled', array( 'HTTP', 'HTTP2', 'SSL' ) ), array( $vp, 'mica-engine-vulnerability-enabled', array( 'SQL Injection', 'Command Injection' ) ) ) as $x )
    {
        $p = array();
        foreach( DH::findFirstElement( $x[1], $x[0]->xmlroot )->childNodes as $e )
        {
            if( $e->nodeType != XML_ELEMENT_NODE ) continue;
            $n = str_replace( ' Command and Control detector', '', $e->getAttribute('name') );
            if( !in_array( $n, $x[2] ) ) continue;
            $l = DH::findFirstElement( 'local-deep-learning', $e );
            $p[] = $n . '=' . ( $l === FALSE ? '-' : $l->textContent );
        }
        $o[] = implode( ',', $p );
    }
    return implode( '|', $o );
}

function vals( $as, $vp ) { return 'HTTP=' . $as . ',HTTP2=' . $as . ',SSL=-|SQL Injection=' . $vp . ',Command Injection=' . $vp; }

$res = function( $v ) { return $v === null ? 'n/a' : ( $v ? 'ok' : 'FAIL' ); };

// variant => start => array( result of alert-only-set and best-practice-set, local deep learning check )
$expect = array(
    'shipped'      => array( 'disable' => array( vals('enable','enable'), 'FAIL' ), 'enable' => array( vals('enable','enable'), 'ok' ) ),
    'none'         => array( 'disable' => array( vals('disable','disable'), 'n/a' ), 'enable' => array( vals('enable','enable'), 'n/a' ) ),
    'enable-any'   => array( 'disable' => array( vals('enable','enable'), 'FAIL' ), 'enable' => array( vals('enable','enable'), 'ok' ) ),
    'disable-any'  => array( 'disable' => array( vals('disable','disable'), 'ok' ), 'enable' => array( vals('disable','disable'), 'FAIL' ) ),
    '!disable-any' => array( 'disable' => array( vals('enable','enable'), 'FAIL' ), 'enable' => array( vals('enable','enable'), 'ok' ) ),
    '!enable-any'  => array( 'disable' => array( vals('disable','disable'), 'ok' ), 'enable' => array( vals('disable','disable'), 'FAIL' ) ),
    'enable-one'   => array( 'disable' => array( 'HTTP=enable,HTTP2=disable,SSL=-|SQL Injection=disable,Command Injection=enable', 'FAIL' ),
                             'enable' => array( vals('enable','enable'), 'ok' ) ),
);

foreach( $expect as $variant => $starts )
{
    PH::$shadow_bp_jsonfilename = 'test';
    PH::$shadow_bp_jsonfile = bpJson( $variant );
    foreach( $starts as $start => $e )
    {
        list( $want, $wantCheck ) = $e;
        $label = $variant . ' / start ' . $start;

        list( $as, $vp ) = config( $start );
        ob_start();
        $as->inlineML_AlertOnlySet();
        $sendAPI = false;
        $vp->inlineML_AlertOnlySet( $sendAPI );
        ob_end_clean();
        eq( ldl( $as, $vp ), $want, $label . ': alert-only-set' );

        list( $as, $vp ) = config( $start );
        ob_start();
        $as->inlineML_BestPracticeSet();
        $vp->inlineML_BestPracticeSet();
        ob_end_clean();
        eq( ldl( $as, $vp ), $want, $label . ': best-practice-set' );

        list( $as, $vp ) = config( $start );
        ob_start();
        foreach( array( 'visibility', 'bp' ) as $section )
        {
            eq( $res( $as->inlineML_localDeepLearningComplies( $section, 'spyware' ) ), $wantCheck, $label . ': AS check ' . $section );
            eq( $res( $vp->inlineML_localDeepLearningComplies( $section, 'vulnerability' ) ), $wantCheck, $label . ': VP check ' . $section );
        }
        // the profile check: local deep learning not complying -> not visible; complying / not listed -> visible
        // (inline-policy-action alert is visible; for bp the AS / VP action reset-both fails anyway)
        $wantVis = $wantCheck == 'FAIL' ? 'FAIL' : 'ok';
        eq( $res( $as->cloud_inline_analysis_visibility() ), $wantVis, $label . ': AS cloud_inline_analysis_visibility()' );
        eq( $res( $vp->cloud_inline_analysis_visibility() ), $wantVis, $label . ': VP cloud_inline_analysis_visibility()' );
        ob_end_clean();
    }
}

print "\n" . $checks . " checks, " . count($failed) . " failed\n";
if( count($failed) )
{
    foreach( $failed as $f ) print " - " . $f . "\n";
    exit( 1 );
}
exit( 0 );
