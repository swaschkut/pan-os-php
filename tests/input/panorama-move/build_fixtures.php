<?php
/**
 * Builds the fixtures of tests/test_panorama_move.php from tests/input/panorama-11.0-merger.xml (deterministic).
 * The generated XML files are committed; run this script again only when the fixtures have to change:
 *
 *   php tests/input/panorama-move/build_fixtures.php
 *
 * panorama-move-A.xml          source Panorama (file1)
 *   Perimeter-FWs                  parent with two children: DE-Berlin Office (fw 000000000101), Hamburg Office (fw 007200006721)
 *   Datacenter-Firewalls           parent, no own firewall: FR Datacenter (fw 000007777)
 *   testDG                         under shared, fw 007100000290, reference-templates Paris_Datacenter_Stack,
 *                                  log forwarding profile -> shared HTTP server profile http-siem (encrypted password)
 *   Paris_Datacenter_Stack         only fw 007100000290 -> moves with testDG; template Paris Datacenter (encrypted IKE
 *                                  pre-shared key) moves, Datacenter Master Template is also in DE_Berlin_Office_Stack -> copy
 *   DE_Berlin_Office_Stack         fws 000000000101 + 007200006721
 *   MV-Left / MV-Right             one multi-vsys firewall 000000000555: vsys1 / vsys2 (blocking D2)
 *   Amb-DG                         local SERVICE "shared-host1" + reference to shared ADDRESS shared-host1 (ambiguous rename)
 *   Panorama server (D8)           Paris Datacenter: panorama/local-panorama/panorama-server(-2) 192.0.2.1 / .2;
 *                                  Internet Perimeter Master: old format system/panorama-server; DE_Berlin_Office_Stack:
 *                                  variable $panorama_primary
 *   follow-up                      access domain ad-paris (testDG, Paris_Datacenter_Stack, fw 007100000290) + admin
 *                                  paris-admin, log collector group lcg-paris, plugin sd_wan, testDG master-device
 *                                  000000000101 (not moved with testDG)
 *   a-to-dc                        shared pre rule to shared-host1 (1.2.2.3)
 * panorama-move-B-clean.xml    target without templates / stacks / firewalls; shared like the source except shared
 *                              address "new test 1" (missing -> copy); shared rule b-to-dc to dc-host (1.2.2.3 - same
 *                              value as a-to-dc, other object name); device group Region-EU with a local address
 *                              shared-host1 = 198.51.100.77 (overrides the shared object for its children)
 * panorama-move-B-conflict.xml target with the same container names, shared-host1 / shared-host2 with other values,
 *                              shared pre authentication rule "DC Firewall level CP rules 1", "shared pre rule 1" with
 *                              another destination, device group "FR Datacenter_taken"
 *
 * Encrypted values are fake strings with the master key prefix (-AQ==); the test checks they never appear in a report.
 */

$dir = dirname(__FILE__);
$src = $dir . '/../panorama-11.0-merger.xml';

const SECRET_PSK = '-AQ==FIXTUREpskPARISgw1AAAAAAAAAAAAAAAA=';
const SECRET_HTTP = '-AQ==FIXTUREhttpSIEMpwdBBBBBBBBBBBBBBBB=';

function load( $f )
{
    $d = new DOMDocument();
    $d->preserveWhiteSpace = FALSE;
    $d->formatOutput = TRUE;
    $d->load( $f ) or die( "cannot load $f\n" );
    return array( $d, new DOMXPath($d) );
}

function one( DOMXPath $x, $q )
{
    $n = $x->query( $q );
    if( $n->length != 1 )
        die( "expected one node for $q, found " . $n->length . "\n" );
    return $n->item(0);
}

/** element path below $parent, created when missing; "entry[name]" creates / finds a named entry */
function path( DOMDocument $d, DOMElement $parent, $path )
{
    $n = $parent;
    foreach( explode('/', $path) as $p )
    {
        $name = null;
        if( preg_match('/^entry\[(.+)\]$/', $p, $m) ) { $p = 'entry'; $name = $m[1]; }
        $found = null;
        foreach( $n->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE && $c->nodeName == $p && ( $name === null || $c->getAttribute('name') === $name ) )
                { $found = $c; break; }
        if( $found === null )
        {
            $found = $d->createElement( $p );
            if( $name !== null ) $found->setAttribute( 'name', $name );
            $n->appendChild( $found );
        }
        $n = $found;
    }
    return $n;
}

function text( DOMDocument $d, DOMElement $parent, $path, $value )
{
    $e = path( $d, $parent, $path );
    while( $e->firstChild ) $e->removeChild( $e->firstChild );
    $e->appendChild( $d->createTextNode($value) );
    return $e;
}

function members( DOMDocument $d, DOMElement $parent, $path, $list )
{
    $e = path( $d, $parent, $path );
    foreach( $list as $v ) { $m = $d->createElement('member'); $m->appendChild($d->createTextNode($v)); $e->appendChild($m); }
    return $e;
}

function removeAll( DOMXPath $x, $q )
{
    foreach( iterator_to_array($x->query($q)) as $n ) $n->parentNode->removeChild( $n );
}

/** new device group entry + readonly id / parent-dg */
function addDG( DOMDocument $d, DOMXPath $x, $name, $parent = null )
{
    $dg = path( $d, one($x, '/config/devices/entry/device-group'), 'entry[' . $name . ']' );
    $mi = one( $x, '/config/readonly/max-internal-id' );
    $id = (int)$mi->textContent + 1;
    $mi->nodeValue = (string)$id;
    $ro = path( $d, one($x, '/config/readonly/devices/entry/device-group'), 'entry[' . $name . ']' );
    if( $parent !== null ) text( $d, $ro, 'parent-dg', $parent );
    text( $d, $ro, 'id', (string)$id );
    return $dg;
}

/** shared pre security rule: any -> $destination, application ssl, application-default, allow */
function securityRule( DOMDocument $d, DOMElement $shared, $name, $destination )
{
    $r = path( $d, $shared, 'pre-rulebase/security/rules/entry[' . $name . ']' );
    foreach( array( 'from' => 'any', 'to' => 'any', 'source' => 'any', 'destination' => $destination, 'source-user' => 'any',
                 'category' => 'any', 'application' => 'ssl', 'service' => 'application-default' ) as $f => $v )
        members( $d, $r, $f, array( $v ) );
    text( $d, $r, 'action', 'allow' );
    return $r;
}

function addFirewall( DOMDocument $d, DOMXPath $x, DOMElement $container, $serial, $vsys = array() )
{
    $e = path( $d, $container, 'devices/entry[' . $serial . ']' );
    foreach( $vsys as $v ) path( $d, $e, 'vsys/entry[' . $v . ']' );
    $m = path( $d, one($x, '/config/mgt-config/devices'), 'entry[' . $serial . ']' );
    foreach( $vsys as $v ) path( $d, $m, 'vsys/entry[' . $v . ']' );
}

////////////////////////////////////////////////////////////////////////////////
// A
list( $d, $x ) = load( $src );
$dgPath = '/config/devices/entry/device-group/entry';
// Perimeter-FWs: second child with its own firewall -> parent is copied when only DE-Berlin Office moves
addFirewall( $d, $x, one($x, $dgPath . '[@name="DE-Berlin Office"]'), '000000000101' );
$hh = addDG( $d, $x, 'Hamburg Office', 'Perimeter-FWs' );
addFirewall( $d, $x, $hh, '007200006721' );
// stacks / templates
$paris = one( $x, '/config/devices/entry/template-stack/entry[@name="Paris_Datacenter_Stack"]' );
path( $d, $paris, 'devices/entry[007100000290]' );
$de = one( $x, '/config/devices/entry/template-stack/entry[@name="DE_Berlin_Office_Stack"]' );
path( $d, $de, 'devices/entry[000000000101]' );
path( $d, $de, 'devices/entry[007200006721]' );
members( $d, $de, 'templates', array( 'Datacenter Master Template' ) );
$testDG = one( $x, $dgPath . '[@name="testDG"]' );
members( $d, $testDG, 'reference-templates', array( 'Paris_Datacenter_Stack' ) );
// encrypted values: IKE pre-shared key in a moved template, password of a shared HTTP server profile used by testDG
$tpl = one( $x, '/config/devices/entry/template/entry[@name="Paris Datacenter"]' );
$gw = path( $d, $tpl, 'config/devices/entry[localhost.localdomain]/network/ike/gateway/entry[gw-paris]' );
text( $d, $gw, 'authentication/pre-shared-key/key', SECRET_PSK );
text( $d, $gw, 'peer-address/ip', '198.51.100.10' );
$http = path( $d, one($x, '/config/shared'), 'log-settings/http/entry[http-siem]' );
$srv = path( $d, $http, 'server/entry[siem1]' );
text( $d, $srv, 'address', 'siem.example.net' );
text( $d, $srv, 'username', 'panorama' );
text( $d, $srv, 'password', SECRET_HTTP );
$lf = path( $d, $testDG, 'log-settings/profiles/entry[lf-siem]/match-list/entry[traffic-all]' );
text( $d, $lf, 'log-type', 'traffic' );
text( $d, $lf, 'filter', 'All Logs' );
members( $d, $lf, 'send-http', array( 'http-siem' ) );
// Panorama server settings (D8): PAN-OS 9.1+ format with secondary in a moved template, old format in a copied template,
// a template variable in a copied stack
$sys = path( $d, $tpl, 'config/devices/entry[localhost.localdomain]/deviceconfig/system/panorama/local-panorama' );
text( $d, $sys, 'panorama-server', '192.0.2.1' );
text( $d, $sys, 'panorama-server-2', '192.0.2.2' );
$ipm = one( $x, '/config/devices/entry/template/entry[@name="Internet Perimeter Master"]' );
text( $d, $ipm, 'config/devices/entry[localhost.localdomain]/deviceconfig/system/panorama-server', '192.0.2.1' );
text( $d, $de, 'config/devices/entry[localhost.localdomain]/deviceconfig/system/panorama/local-panorama/panorama-server', '$panorama_primary' );
text( $d, $de, 'variable/entry[$panorama_primary]/type/fqdn', 'panorama-a.example.net' );
// access domain + administrator (matched by name; the role-based layout is illustrative), log collector group, plugin,
// master device of testDG that is not moved with it
$ad = path( $d, one($x, '/config/mgt-config/access-domain'), 'entry[ad-paris]' );
members( $d, $ad, 'device-groups', array( 'testDG' ) );
members( $d, $ad, 'templates', array( 'Paris_Datacenter_Stack' ) );
path( $d, $ad, 'devices/entry[007100000290]' );
$adm = path( $d, one($x, '/config/mgt-config/users'), 'entry[paris-admin]' );
text( $d, $adm, 'permissions/role-based/custom/profile', 'dg-template-admin' );
members( $d, $adm, 'permissions/role-based/custom/access-domain', array( 'ad-paris' ) );
$lcg = path( $d, one($x, '/config/devices/entry[@name="localhost.localdomain"]'), 'log-collector-group/entry[lcg-paris]' );
path( $d, $lcg, 'logfwd-setting/devices/entry[007100000290]/collector/entry[000000000901]' );
path( $d, one($x, '/config/devices/entry[@name="localhost.localdomain"]'), 'plugins/sd_wan/devices/entry[007100000290]' );
text( $d, $testDG, 'master-device/device', '000000000101' );
// shared pre rule to the address shared-host1 (1.2.2.3) - file2 (clean) has an equivalent rule to an object with
// another name and the same value (rule equivalence by resolved values)
securityRule( $d, one($x, '/config/shared'), 'a-to-dc', 'shared-host1' );
// multi-vsys firewall split over two device groups
$mvl = addDG( $d, $x, 'MV-Left' );
$mvr = addDG( $d, $x, 'MV-Right' );
addFirewall( $d, $x, $mvl, '000000000555', array( 'vsys1' ) );
path( $d, $mvr, 'devices/entry[000000000555]/vsys/entry[vsys2]' );
path( $d, one($x, '/config/mgt-config/devices/entry[@name="000000000555"]'), 'vsys/entry[vsys2]' );
// ambiguous name: local service "shared-host1" next to a reference to the shared address shared-host1
$amb = addDG( $d, $x, 'Amb-DG' );
text( $d, path( $d, $amb, 'service/entry[shared-host1]' ), 'protocol/tcp/port', '8080' );
members( $d, path( $d, $amb, 'address-group/entry[amb-group]' ), 'static', array( 'shared-host1' ) );
$d->save( $dir . '/panorama-move-A.xml' );

////////////////////////////////////////////////////////////////////////////////
// B clean
list( $d, $x ) = load( $src );
removeAll( $x, '/config/devices/entry/device-group/entry | /config/devices/entry/template/entry | /config/devices/entry/template-stack/entry' );
removeAll( $x, '/config/readonly/devices/entry/device-group/entry | /config/readonly/devices/entry/template/entry | /config/readonly/devices/entry/template-stack/entry' );
removeAll( $x, '/config/mgt-config/devices/entry' );
removeAll( $x, '/config/mgt-config/access-domain/entry' );
removeAll( $x, '/config/shared/address/entry[@name="new test 1"]' );
// rule equivalent to a-to-dc of the source: object dc-host has another name, the same value
text( $d, path( $d, one($x, '/config/shared/address'), 'entry[dc-host]' ), 'ip-netmask', '1.2.2.3/32' );
securityRule( $d, one($x, '/config/shared'), 'b-to-dc', 'dc-host' );
// possible target parent whose local object overrides the shared object shared-host1 for its children
$eu = addDG( $d, $x, 'Region-EU' );
text( $d, path( $d, $eu, 'address/entry[shared-host1]' ), 'ip-netmask', '198.51.100.77/32' );
$d->save( $dir . '/panorama-move-B-clean.xml' );

////////////////////////////////////////////////////////////////////////////////
// B conflict
list( $d, $x ) = load( $src );
removeAll( $x, '/config/mgt-config/devices/entry' );
foreach( array( 'shared-host1' => '9.9.9.1/32', 'shared-host2' => '9.9.9.2/32' ) as $n => $ip )
    one( $x, '/config/shared/address/entry[@name="' . $n . '"]/ip-netmask' )->nodeValue = $ip;
$rule = path( $d, one($x, '/config/shared'), 'pre-rulebase/authentication/rules/entry[DC Firewall level CP rules 1]' );
foreach( array( 'from', 'to', 'source', 'destination' ) as $f ) members( $d, $rule, $f, array( 'any' ) );
text( $d, $rule, 'authentication-enforcement', 'default-web-form' );
$dst = one( $x, '/config/shared/pre-rulebase/security/rules/entry[@name="shared pre rule 1"]/destination' );
while( $dst->firstChild ) $dst->removeChild( $dst->firstChild );
members( $d, $dst->parentNode, 'destination', array( '203.0.113.9' ) );
addDG( $d, $x, 'FR Datacenter_taken' );
$d->save( $dir . '/panorama-move-B-conflict.xml' );

print "written: panorama-move-A.xml, panorama-move-B-clean.xml, panorama-move-B-conflict.xml\n";
