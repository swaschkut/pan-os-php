<?php
/**
 * Tests of VirtualRouter / LogicalRouter::getIPtoZoneRouteMapping() (lib/network-classes/trait/RouteZoneMapping.php):
 * IP -> zone records from connected networks and static routes, IPv4 and IPv6.
 *
 * Fixed: IPv6 records were sorted by a float key ('end - start', truncated to int), not returned ('ipv6' key missing),
 * routes with next hop 'ipv6-address' ignored ('unknown type'), next-vr routes built an IP4Map for IPv6 and did not
 * separate the address families, and next-vr died ('Undefined array key network') when the destination was split.
 *
 * Firewall built in memory from examples/sample-configs/panos-example-2.xml:
 *   zones   internal  ethernet1/2  192.168.1.1/24   2001:db8:1::1/64
 *           external  ethernet1/1  203.0.113.2/24   2001:db8:ffff::2/64
 *           dmz       ethernet1/3  172.16.0.1/24    2001:db8:3::1/64
 *   default (ethernet1/1, ethernet1/3): 0.0.0.0/0 + ::/0 via ethernet1/1; 10.20.0.0/16 next hop 172.16.0.254,
 *           2001:db8:20::/48 next hop 2001:db8:3::fe (no interface - next hop in the dmz network)
 *   vr-in   (ethernet1/2): 10.0.0.0/8 and 2001:db8::/32 next-vr default
 *
 *   cd tests && php test_route_zone_mapping.php      exit code 0 = passed
 */

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__) . "/../lib/pan_php_framework.php";
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

/** @param bool $logical build logical routers (advanced routing) instead of virtual routers; without next-vr */
function buildFirewall( $logical = FALSE )
{
    $d = new DOMDocument(); $d->load( dirname(__FILE__) . '/../examples/sample-configs/panos-example-2.xml' ); $x = new DOMXPath($d);
    $add = function( $parentQ, $xml ) use ( $d, $x ) { $p = $x->query($parentQ)->item(0); $f = $d->createDocumentFragment(); $f->appendXML($xml); $p->appendChild($f); };
    $net = '/config/devices/entry/network';
    $eth1 = $x->query($net . '/interface/ethernet/entry[@name="ethernet1/1"]')->item(0);
    foreach( iterator_to_array($eth1->childNodes) as $c ) if( $c->nodeName == 'layer3' ) $eth1->removeChild($c);
    $add( $net . '/interface/ethernet/entry[@name="ethernet1/1"]', '<layer3><ip><entry name="203.0.113.2/24"/></ip><ipv6><enabled>yes</enabled><address><entry name="2001:db8:ffff::2/64"/></address></ipv6></layer3>' );
    $add( $net . '/interface/ethernet', '<entry name="ethernet1/2"><layer3><ip><entry name="192.168.1.1/24"/></ip><ipv6><enabled>yes</enabled><address><entry name="2001:db8:1::1/64"/></address></ipv6></layer3></entry>' );
    $add( $net . '/interface/ethernet', '<entry name="ethernet1/3"><layer3><ip><entry name="172.16.0.1/24"/></ip><ipv6><enabled>yes</enabled><address><entry name="2001:db8:3::1/64"/></address></ipv6></layer3></entry>' );
    $add( '/config/devices/entry/vsys/entry[@name="vsys1"]/zone/entry[@name="internal"]/network', '<layer3><member>ethernet1/2</member></layer3>' );
    $add( '/config/devices/entry/vsys/entry[@name="vsys1"]/zone', '<entry name="dmz"><network><layer3><member>ethernet1/3</member></layer3></network></entry>' );
    foreach( array( 'ethernet1/2', 'ethernet1/3' ) as $i )
        $x->query('/config/devices/entry/vsys/entry[@name="vsys1"]/import/network/interface')->item(0)->appendChild( $d->createElement('member', $i) );
    $rt = '<routing-table>'
        . '<ip><static-route>'
        . '<entry name="v4-default"><destination>0.0.0.0/0</destination><interface>ethernet1/1</interface><nexthop><ip-address>203.0.113.1</ip-address></nexthop></entry>'
        . '<entry name="v4-dmz-net"><destination>10.20.0.0/16</destination><nexthop><ip-address>172.16.0.254</ip-address></nexthop></entry>'
        . '</static-route></ip>'
        . '<ipv6><static-route>'
        . '<entry name="v6-default"><destination>::/0</destination><interface>ethernet1/1</interface><nexthop><ipv6-address>2001:db8:ffff::1</ipv6-address></nexthop></entry>'
        . '<entry name="v6-dmz-net"><destination>2001:db8:20::/48</destination><nexthop><ipv6-address>2001:db8:3::fe</ipv6-address></nexthop></entry>'
        . '</static-route></ipv6>'
        . '</routing-table>';
    // a security rule for the zone calculation of address containers
    $vs = $x->query('/config/devices/entry/vsys/entry[@name="vsys1"]')->item(0);
    foreach( array( 'rulebase', 'security', 'rules' ) as $el )
    {
        $n = $x->query($el, $vs)->item(0);
        if( $n === null ) { $n = $d->createElement($el); $vs->appendChild($n); }
        $vs = $n;
    }
    $f = $d->createDocumentFragment();
    $f->appendXML( '<entry name="r1"><from><member>any</member></from><to><member>any</member></to>'
        . '<source><member>10.20.1.1</member></source><destination><member>2001:db8:20::5</member><member>2001:db8:9::1</member></destination>'
        . '<application><member>any</member></application><service><member>any</member></service><action>allow</action></entry>' );
    $vs->appendChild( $f );
    if( !$logical )
    {
        $add( $net . '/virtual-router/entry[@name="default"]/interface', '<member>ethernet1/3</member>' );
        $add( $net . '/virtual-router/entry[@name="default"]', $rt );
        $add( $net . '/virtual-router', '<entry name="vr-in"><interface><member>ethernet1/2</member></interface><routing-table>'
            . '<ip><static-route><entry name="to-dc-v4"><destination>10.0.0.0/8</destination><nexthop><next-vr>default</next-vr></nexthop></entry></static-route></ip>'
            . '<ipv6><static-route><entry name="to-dc-v6"><destination>2001:db8::/32</destination><nexthop><next-vr>default</next-vr></nexthop></entry></static-route></ipv6>'
            . '</routing-table></entry>' );
    }
    else
    {
        foreach( iterator_to_array($x->query($net . '/virtual-router')) as $n ) $n->parentNode->removeChild( $n );
        $add( $net, '<logical-router><entry name="lr-default"><vrf><entry name="default"><interface><member>ethernet1/1</member><member>ethernet1/3</member></interface>' . $rt . '</entry></vrf></entry></logical-router>' );
        $setting = $x->query('/config/devices/entry/deviceconfig/setting')->item(0);
        if( $setting === null )
        {
            $add( '/config/devices/entry/deviceconfig', '<setting/>' );
            $setting = $x->query('/config/devices/entry/deviceconfig/setting')->item(0);
        }
        $setting->appendChild( $d->createElement('advance-routing', 'yes') );
    }
    $xml = $d->saveXML();
    $fw = new PANConf();
    $fw->load_from_xmlstring( $xml );
    return $fw;
}

/** records as 'start-end zone' lines */
function lines( array $records, $v6 )
{
    $o = array();
    foreach( $records as $r )
        $o[] = ( $v6 ? cidr::inet_itop($r['start']) . '-' . cidr::inet_itop($r['end']) : long2ip($r['start']) . '-' . long2ip($r['end']) ) . ' ' . $r['zone'];
    return $o;
}

$defaultV4 = array( '172.16.0.0-172.16.0.255 dmz', '203.0.113.0-203.0.113.255 external', '10.20.0.0-10.20.255.255 dmz', '0.0.0.0-255.255.255.255 external' );
$defaultV6 = array(
    '2001:db8:3::-2001:db8:3:0:ffff:ffff:ffff:ffff dmz',
    '2001:db8:ffff::-2001:db8:ffff:0:ffff:ffff:ffff:ffff external',
    '2001:db8:20::-2001:db8:20:ffff:ffff:ffff:ffff:ffff dmz',
    '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff external' );

print "  VirtualRouter default (connected, static via interface / next hop)\n";
$fw = buildFirewall();
$vsys = $fw->findVirtualSystem( 'vsys1' );
$map = $fw->network->virtualRouterStore->findVirtualRouter('default')->getIPtoZoneRouteMapping( $vsys );
eq( array_keys($map), array( 'ipv4', 'ipv6' ), 'result has ipv4 and ipv6' );
eq( lines($map['ipv4'], FALSE), $defaultV4, 'IPv4 records, narrowest first (unchanged)' );
eq( lines($map['ipv6'], TRUE), $defaultV6, 'IPv6 records incl. next hop ipv6-address, narrowest first' );
eq( array_map( function($r){ return is_int($r['start']) && is_int($r['end']); }, $map['ipv4'] ), array_fill(0, 4, TRUE), 'IPv4 values int' );
eq( array_map( function($r){ return is_string($r['start']) && is_string($r['end']); }, $map['ipv6'] ), array_fill(0, 4, TRUE), 'IPv6 values decimal strings (no float)' );

print "  VirtualRouter vr-in (next-vr)\n";
$map = $fw->network->virtualRouterStore->findVirtualRouter('vr-in')->getIPtoZoneRouteMapping( $vsys );
eq( lines($map['ipv4'], FALSE), array(
    '192.168.1.0-192.168.1.255 internal',
    '10.20.0.0-10.20.255.255 dmz',
    '10.0.0.0-10.19.255.255 external',
    '10.21.0.0-10.255.255.255 external' ), 'IPv4: 10.0.0.0/8 split by the records of default (only its own destination)' );
eq( lines($map['ipv6'], TRUE), array(
    '2001:db8:1::-2001:db8:1:0:ffff:ffff:ffff:ffff internal',
    '2001:db8:3::-2001:db8:3:0:ffff:ffff:ffff:ffff dmz',
    '2001:db8:ffff::-2001:db8:ffff:0:ffff:ffff:ffff:ffff external',
    '2001:db8:ffff:1::-2001:db8:ffff:ffff:ffff:ffff:ffff:ffff external',
    '2001:db8:20::-2001:db8:20:ffff:ffff:ffff:ffff:ffff dmz',
    '2001:db8::-2001:db8:2:ffff:ffff:ffff:ffff:ffff external',
    '2001:db8:3:1::-2001:db8:1f:ffff:ffff:ffff:ffff:ffff external',
    '2001:db8:21::-2001:db8:fffe:ffff:ffff:ffff:ffff:ffff external' ), 'IPv6: 2001:db8::/32 split by the IPv6 records of default' );
$union = new IP6Map();
foreach( $map['ipv6'] as $r )
    if( $r['origin'] == 'static' )
        $union->addMap( IP6Map::mapFromText( cidr::inet_itop($r['start']) . '-' . cidr::inet_itop($r['end']) ), TRUE );
$union->sortAndRecalculate();
eq( $union->dumpToString(), '2001:db8::-2001:db8:ffff:ffff:ffff:ffff:ffff:ffff', 'IPv6 next-vr pieces cover the route destination without gap' );
eq( $map['ipv6'][1]['network'], '2001:db8:3::-2001:db8:3:0:ffff:ffff:ffff:ffff', 'next-vr record network = range' );
eq( $map['ipv4'][1]['network'], '10.20.0.0-10.20.255.255', 'next-vr IPv4 record network = range (was the start address only)' );

print "  zones of address containers (AddressRuleContainer)\n";
$rule = $vsys->securityRules->find( 'r1' );
eq( array_values( $rule->source->calculateZonesFromIP4Mapping( $map['ipv4'] ) ), array( 'dmz' ), 'IPv4 source 10.20.1.1 -> dmz' );
eq( array_values( $rule->destination->calculateZonesFromIP6Mapping( $map['ipv6'] ) ), array( 'dmz', 'external' ), 'IPv6 destinations 2001:db8:20::5 / 2001:db8:9::1 -> dmz, external' );

print "  LogicalRouter (advanced routing)\n";
$fw = buildFirewall( TRUE );
$vsys = $fw->findVirtualSystem( 'vsys1' );
$lr = $fw->network->logicalRouterStore->findVirtualRouter( 'lr-default' );
eq( $lr === null, FALSE, 'logical router loaded' );
if( $lr !== null )
{
    $map = $lr->getIPtoZoneRouteMapping( $vsys );
    eq( lines($map['ipv4'], FALSE), $defaultV4, 'IPv4 records' );
    eq( lines($map['ipv6'], TRUE), $defaultV6, 'IPv6 records (were dropped by IPvalidation64bit)' );
}

print "\n" . $checks . " checks, " . count($failed) . " failed\n";
exit( count($failed) ? 1 : 0 );
