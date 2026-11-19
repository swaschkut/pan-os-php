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
 * Panorama 'ancestor-objects-take-precedence yes': a rule naming a profile group that exists in its device group
 * AND higher up (shared) uses the highest copy (applyAncestorObjectsPrecedence()). The rule filters
 * 'secprof <type>-profile.is.set', 'secprof has.from.query', 'secprofgroup has.from.query' and
 * SecurityRule::securityProfiles_obj() must read that copy, not look the name up again in the rule's device group.
 *
 * shared:                group TST-Group = URL profile TST-URL
 * Datacenter-Firewalls:  group TST-Group = (no URL profile)        <- shadowed with precedence yes
 * FR Datacenter (child): pre rule tst-rule, profile group TST-Group
 *
 *   php tests/test_ancestor_precedence_profile_group.php
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

function child( DOMDocument $d, DOMElement $parent, $path )
{
    foreach( explode( '/', $path ) as $part )
    {
        $name = $part; $entry = null;
        if( preg_match( '/^entry\[(.*)\]$/', $part, $m ) ) { $name = 'entry'; $entry = $m[1]; }
        $found = null;
        foreach( $parent->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE && $c->nodeName == $name && ( $entry === null || $c->getAttribute('name') === $entry ) )
                { $found = $c; break; }
        if( $found === null )
        {
            $found = $d->createElement( $name );
            if( $entry !== null ) $found->setAttribute( 'name', $entry );
            $parent->appendChild( $found );
        }
        $parent = $found;
    }
    return $parent;
}

function member( DOMDocument $d, DOMElement $parent, $path, $value )
{
    child( $d, $parent, $path )->appendChild( $d->createElement( 'member', $value ) );
}

/** Panorama with the case above; $precedence: ancestor-objects-take-precedence yes / no */
function panorama( $precedence )
{
    global $here;
    $d = new DOMDocument();
    $d->load( $here . '/input/panorama-11.0-merger.xml' );
    $x = new DOMXPath( $d );
    $dev = $x->query( "/config/devices/entry[@name='localhost.localdomain']" )->item(0);
    child( $d, $dev, 'deviceconfig/setting/management/ancestor-objects-take-precedence' )->textContent = $precedence ? 'yes' : 'no';

    $shared = $x->query( '/config/shared' )->item(0);
    child( $d, $shared, 'profiles/url-filtering/entry[TST-URL]' );
    member( $d, $shared, 'profile-group/entry[TST-Group]/url-filtering', 'TST-URL' );

    $parent = $x->query( "/config/devices/entry/device-group/entry[@name='Datacenter-Firewalls']" )->item(0);
    child( $d, $parent, 'profile-group/entry[TST-Group]' );

    $dg = $x->query( "/config/devices/entry/device-group/entry[@name='FR Datacenter']" )->item(0);
    $r = child( $d, $dg, 'pre-rulebase/security/rules/entry[tst-rule]' );
    foreach( array( 'from', 'to', 'source', 'destination', 'source-user', 'category', 'application', 'service' ) as $f )
        member( $d, $r, $f, 'any' );
    child( $d, $r, 'action' )->textContent = 'allow';
    member( $d, $r, 'profile-setting/group', 'TST-Group' );

    $pan = new PanoramaConf();
    $xml = $d->saveXML();
    ob_start();
    $pan->load_from_xmlstring( $xml );
    ob_end_clean();
    return $pan->findDeviceGroup( 'FR Datacenter' )->securityRules->find( 'tst-rule' );
}

function ruleMatches( $rule, $filter, $nested = array() )
{
    $q = new RQuery( 'rule' );
    $err = '';
    if( $q->parseFromString( $filter, $err ) === FALSE )
        derr( $err );
    return $q->matchSingleObject( array( 'object' => $rule, 'nestedQueries' => $nested ) );
}

foreach( array( TRUE, FALSE ) as $precedence )
{
    $label = $precedence ? 'precedence yes' : 'precedence no';
    $rule = panorama( $precedence );
    check( $rule !== null, $label . ': rule loaded' );
    if( $rule === null )
        continue;

    $group = $rule->securityProfileGroup_obj();
    eq( $group !== null ? $group->owner->owner->name() : null, $precedence ? '' : 'Datacenter-Firewalls',
        $label . ': rule uses the profile group of ' . ( $precedence ? 'shared' : 'the device group' ) );

    // shared group has a URL profile, the device group's group has none
    eq( ruleMatches( $rule, '(secprof url-profile.is.set)' ), $precedence, $label . ': secprof url-profile.is.set' );
    eq( ruleMatches( $rule, '(secprof has.from.query sq)', array( 'sq' => '(name eq TST-URL)' ) ), $precedence, $label . ': secprof has.from.query' );
    eq( ruleMatches( $rule, '(secprofgroup has.from.query sq)', array( 'sq' => '(name eq TST-Group)' ) ), TRUE, $label . ': secprofgroup has.from.query (name)' );
    $names = array();
    foreach( $rule->securityProfiles_obj() as $type => $p )
        if( is_object($p) ) $names[] = $p->name();
    eq( $names, $precedence ? array( 'TST-URL' ) : array(), $label . ': securityProfiles_obj()' );
}

print "\n" . $checks . " checks, " . count($failed) . " failed\n";
if( count($failed) )
{
    foreach( $failed as $f ) print " - " . $f . "\n";
    exit( 1 );
}
exit( 0 );
