<?php
/**
 * Tests of utils/common/RuleResolver.php (rules resolved to values as the firewalls of a location see them) - used by
 * type=panorama-move, intended for type=rule-compare.
 *
 *   cd tests && php test_rule_resolver.php
 *
 * Builds its configuration in memory from input/panorama-11.0-merger.xml plus the objects below. Exit code 0 = passed.
 */

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__) . "/../lib/pan_php_framework.php";
require_once dirname(__FILE__) . "/../utils/common/RuleResolver.php";
PH::$ignoreDestructors = TRUE;

$failed = array();
$checks = 0;
function eq( $actual, $expected, $msg )
{
    global $failed, $checks;
    $checks++;
    if( $actual !== $expected )
    {
        $failed[] = $msg . ' - expected ' . json_encode($expected) . ', got ' . json_encode($actual);
        print "    FAIL " . end($failed) . "\n";
    }
}

// configuration: base + objects for the tests
$d = new DOMDocument();
$d->load( dirname(__FILE__) . '/input/panorama-11.0-merger.xml' );
$x = new DOMXPath( $d );
$shared = $x->query('/config/shared')->item(0);
$add = function( $parent, $xml ) use ( $d ) {
    $f = $d->createDocumentFragment(); $f->appendXML( $xml ); $parent->appendChild( $f );
};
$child = function( $parent, $name ) use ( $d, $x ) {
    $n = $x->query($name, $parent)->item(0);
    if( $n === null ) { $n = $d->createElement($name); $parent->appendChild($n); }
    return $n;
};
$add( $child($shared, 'address'), '<entry name="fqdn-host"><fqdn>www.example.net</fqdn></entry>'
    . '<entry name="v6-net"><ip-netmask>2001:db8:1::/64</ip-netmask></entry><entry name="v6-host"><ip-netmask>2001:db8:1::5</ip-netmask></entry>'
    . '<entry name="v4-a"><ip-netmask>10.1.0.0/24</ip-netmask></entry><entry name="v4-b"><ip-range>10.1.1.0-10.1.1.255</ip-range></entry>' );
$add( $child($shared, 'address-group'), '<entry name="v6-grp"><static><member>v6-host</member><member>v6-net</member></static></entry>'
    . '<entry name="v4-grp"><static><member>v4-a</member><member>v4-b</member></static></entry>' );
$add( $child($shared, 'application-group'), '<entry name="web-apps"><members><member>ssl</member><member>web-browsing</member></members></entry>'
    . '<entry name="all-apps"><members><member>web-apps</member><member>dns</member></members></entry>' );
$add( $child($shared, 'service'), '<entry name="svc-src"><protocol><tcp><port>443</port><source-port>1024</source-port></tcp></protocol></entry>' );
$pg = $x->query('/config/shared/profile-group/entry[@name="Shared Production Profile"]')->item(0);
$add( $pg, '<virus><member>default</member></virus><spyware><member>strict</member></spyware>' );
// device group override of a shared name
$perim = $x->query('/config/devices/entry/device-group/entry[@name="Perimeter-FWs"]')->item(0);
$add( $child($perim, 'address'), '<entry name="fqdn-host"><ip-netmask>192.0.2.99</ip-netmask></entry>' );
$tmp = sys_get_temp_dir() . '/rule-resolver-test-' . getmypid() . '.xml';
$d->save( $tmp );
$p = new PanoramaConf();
$p->load_from_file( $tmp );
unlink( $tmp );
$perimDG = $p->findDeviceGroup( 'Perimeter-FWs' );
$berlin = $p->findDeviceGroup( 'DE-Berlin Office' );

/** rule entry from XML (detached - resolve() reads only the node) */
function rule( $xml )
{
    $d = new DOMDocument();
    $d->loadXML( '<entry name="r">' . $xml . '</entry>' );
    return $d->documentElement;
}

print "  addresses\n";
eq( RuleResolver::addresses( array( 'any' ), $p ), array( 'any' ), 'any' );
eq( RuleResolver::addresses( array( 'v4-grp' ), $p ), array( '10.1.0.0-10.1.1.255' ), 'group expanded, netmask + range merged' );
eq( RuleResolver::addresses( array( '10.0.0.0/24', '10.0.1.0/24', '10.0.1.7' ), $p ), array( '10.0.0.0-10.0.1.255' ), 'literals merged' );
eq( RuleResolver::addresses( array( 'v6-grp' ), $p ), array( '2001:db8:1::-2001:db8:1:0:ffff:ffff:ffff:ffff' ), 'IPv6 group merged (RFC 5952: a single 0 group is not shortened)' );
eq( RuleResolver::addresses( array( 'v6-host', 'v6-net' ), $p ), RuleResolver::addresses( array( 'v6-net', 'v6-host' ), $p ), 'IPv6 merge independent of the order' );
eq( RuleResolver::addresses( array( '2001:db8::', '2001:db8::1' ), $p ), array( '2001:db8::-2001:db8::1' ), 'neighbouring IPv6 addresses (float precision)' );
eq( RuleResolver::addresses( array( 'fqdn-host', 'no-such-object' ), $p ), array( 'fqdn:www.example.net', 'unresolved:no-such-object' ), 'FQDN and unresolved' );

print "  name resolution per location\n";
eq( RuleResolver::addresses( array( 'fqdn-host' ), $perimDG ), array( '192.0.2.99' ), 'device group object overrides shared' );
eq( RuleResolver::addresses( array( 'fqdn-host' ), $berlin ), array( '192.0.2.99' ), 'child device group sees the parent object' );

print "  services / applications / profiles\n";
eq( RuleResolver::services( array( 'application-default' ), $p ), array( 'application-default' ), 'application-default' );
eq( RuleResolver::services( array( 'any' ), $p ), array( 'any' ), 'any' );
eq( RuleResolver::services( array( 'service-http' ), $p ), array( 'tcp/80', 'tcp/8080' ), 'predefined service, no default source port' );
eq( RuleResolver::services( array( 'svc-src' ), $p ), array( 'sport:tcp/1024', 'tcp/443' ), 'source port kept' );
eq( RuleResolver::applications( array( 'all-apps' ), $p ), array( 'dns', 'ssl', 'web-browsing' ), 'nested application groups expanded' );
eq( RuleResolver::applications( array( 'web-browsing', 'web-apps' ), $p ), array( 'ssl', 'web-browsing' ), 'duplicates removed' );
$ps = rule( '<profile-setting><group><member>Shared Production Profile</member></group></profile-setting>' );
eq( RuleResolver::profiles( $ps->firstChild, $p ), array( 'spyware:strict', 'virus:default' ), 'profile group resolved to its profiles' );
$ps = rule( '<profile-setting><profiles><virus><member>default</member></virus><spyware><member>strict</member></spyware></profiles></profile-setting>' );
eq( RuleResolver::profiles( $ps->firstChild, $p ), array( 'spyware:strict', 'virus:default' ), 'same profiles directly = same value' );

print "  resolve / signature / diff\n";
$base = '<from><member>trust</member></from><to><member>untrust</member></to><source><member>v4-grp</member></source>'
    . '<destination><member>any</member></destination><application><member>web-apps</member></application>'
    . '<service><member>application-default</member></service><source-user><member>any</member></source-user>'
    . '<category><member>any</member></category>';
$r1 = RuleResolver::resolve( rule( $base . '<action>allow</action><description>one</description><tag><member>x</member></tag>' ), 'security', $p );
$r2 = RuleResolver::resolve( rule( str_replace('<member>v4-grp</member>', '<member>v4-a</member><member>10.1.1.0/24</member>', $base) . '<action>allow</action>' ), 'security', $p );
$r3 = RuleResolver::resolve( rule( $base . '<action>deny</action>' ), 'security', $p );
$r4 = RuleResolver::resolve( rule( $base . '<action>allow</action><negate-source>yes</negate-source>' ), 'security', $p );
eq( RuleResolver::signature($r1), RuleResolver::signature($r2), 'same values, other objects / description / tag -> same signature' );
eq( RuleResolver::signature($r1)[0], RuleResolver::signature($r3)[0], 'other action: same match' );
check_ne( RuleResolver::signature($r1)[1], RuleResolver::signature($r3)[1], 'other action: other action hash' );
check_ne( RuleResolver::signature($r1)[0], RuleResolver::signature($r4)[0], 'negate-source changes the match' );
eq( array_keys( RuleResolver::diff($r1, $r3) ), array( 'action' ), 'diff names the field' );
$n1 = RuleResolver::resolve( rule( '<from><member>any</member></from><source><member>v4-a</member></source><source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/1</interface></interface-address></dynamic-ip-and-port></source-translation>' ), 'nat', $p );
$n2 = RuleResolver::resolve( rule( '<from><member>any</member></from><source><member>v4-a</member></source><source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/2</interface></interface-address></dynamic-ip-and-port></source-translation>' ), 'nat', $p );
check_ne( RuleResolver::signature($n1)[0], RuleResolver::signature($n2)[0], 'nat: translation (other) is part of the match' );

print "  firewall rule base / compare\n";
$view = RuleResolver::firewallRulebase( $p, $berlin, array( 'security' ) );
$keys = array_column( $view, 'key' );
$pos = function( $prefix ) use ( $keys ) { foreach( $keys as $i => $k ) if( strpos($k, $prefix) === 0 ) return $i; return -1; };
eq( $pos('shared/pre/') < $pos('Perimeter-FWs/pre/') && $pos('Perimeter-FWs/pre/') < $pos('DE-Berlin Office/pre/'), TRUE, 'pre rules: shared, parent, child' );
eq( $pos('DE-Berlin Office/post/') === -1 || $pos('DE-Berlin Office/post/') < $pos('Perimeter-FWs/post/'), TRUE, 'post rules: child before parent' );
eq( $pos('Perimeter-FWs/post/') < $pos('shared/post/'), TRUE, 'post rules: parent before shared' );
$va = RuleResolver::resolveView( $view, $berlin );
$cmp = RuleResolver::compare( $va, $va );
eq( array( count($cmp['same']), count($cmp['changed']), count($cmp['only_a']), count($cmp['only_b']) ), array( count($va), 0, 0, 0 ), 'view equals itself' );
$vb = $va;
$vb[0]['resolved']['action'] = array( 'deny' ); $vb[0]['signature'] = RuleResolver::signature( $vb[0]['resolved'] );
$vb[1]['key'] = 'renamed';
$cmp = RuleResolver::compare( $va, $vb );
eq( array( array_keys($cmp['changed']), $cmp['only_a'], $cmp['only_b'] ), array( array( $va[0]['key'] ), array( $va[1]['key'] ), array( 'renamed' ) ), 'changed / only in A / only in B' );
$cmp = RuleResolver::compare( $va, $vb, array( $va[1]['key'] => 'renamed' ) );
eq( count($cmp['only_a']) + count($cmp['only_b']), 0, 'key map' );

function check_ne( $a, $b, $msg ) { eq( $a !== $b, TRUE, $msg ); }

print "\n" . $checks . " checks, " . count($failed) . " failed\n";
exit( count($failed) ? 1 : 0 );
