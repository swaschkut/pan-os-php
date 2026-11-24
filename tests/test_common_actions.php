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
 * Common actions (utils/common/actions-common.php, CallContext::registerAction): one definition for several types -
 * add-member / remove-member (address / service groups), description-set (address, service, rule, security profile) -
 * interface-add / interface-remove (router, zone), name-rename of the network objects (users updated), the value actions of address / service (value-set, protocol-set,
 * dstport-set), URL categories of rules and ObjectCandidates (what a field can take). Synthetic inputs
 * tests/input/group-members.xml, zones-interfaces.xml, network-rename.xml; panorama-10.0-merger.xml, SCM-import.xml.
 * php tests/test_common_actions.php
 */

$repo = dirname( __DIR__ );
require_once $repo . '/lib/pan_php_framework.php';
require_once $repo . '/utils/common/actions.php';

$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};

$dir = sys_get_temp_dir() . '/commonact-' . getmypid();
if( !is_dir( $dir ) )
    mkdir( $dir, 0700, TRUE );
$in = __DIR__ . '/input/group-members.xml';

$cli = function( string $type, ?string $out, string $filter, string $actions ) use ( $repo, &$in ) {
    $args = array( 'type=' . $type, 'in=' . $in, 'location=vsys1', 'filter=' . $filter, 'actions=' . $actions );
    if( $out !== null )
        $args[] = 'out=' . $out;
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' ' . implode( ' ', array_map( 'escapeshellarg', $args ) ) . ' 2>&1', $o, $rc );
    return array( $rc, implode( "\n", $o ) );
};
$x = function( string $file, string $xpath ) {
    $d = new DOMDocument();
    $d->load( $file );
    $r = array();
    foreach( ( new DOMXPath( $d ) )->query( $xpath ) as $n )
        $r[] = $n->textContent;
    return $r;
};

// ---- registration: one definition in both types, a type-specific action of the same name wins
$eq( array( AddressCallContext::$supportedActions['add-member']['MainFunction'] === ServiceCallContext::$supportedActions['add-member']['MainFunction'],
        AddressCallContext::$supportedActions['remove-member']['MainFunction'] === ServiceCallContext::$supportedActions['remove-member']['MainFunction'] ),
    array( TRUE, TRUE ), 'add-member / remove-member: one definition for address and service' );
$own = TagCallContext::$supportedActions['delete'];
CallContext::registerAction( array( 'TagCallContext' ), array( 'name' => 'delete', 'MainFunction' => function() {} ) );
$eq( TagCallContext::$supportedActions['delete'] === $own, TRUE, 'registerAction: a type-specific action of the same name is kept' );
CallContext::registerAction( array( 'TagCallContext' ), array( 'name' => 'zz-Common-Test', 'MainFunction' => function() {} ) );
$eq( array( isset( TagCallContext::$supportedActions['zz-common-test'] ), array_keys( TagCallContext::$supportedActions ) === array_values( array_unique( array_keys( TagCallContext::$supportedActions ) ) ) ),
    array( TRUE, TRUE ), 'registerAction: added under its lower case name' );

// ---- address groups
$G = "//address-group/entry";
list( $rc, $o ) = $cli( 'address', $dir . '/a.xml', '(name eq g-1)', 'add-member:h-3/add-member:h-shared/remove-member:h-1' );
$eq( array( $rc, $x( $dir . '/a.xml', $G . "[@name='g-1']/static/member" ) ), array( 0, array( 'h-2', 'h-3', 'h-shared' ) ),
    'address group: members added (also from shared) and removed' );
foreach( array(
        array( '(name eq g-1)', 'add-member:h-1', 'already a member' ),
        array( '(name eq g-1)', 'add-member:nope', "'nope' not found" ),
        array( '(name eq g-1)', 'add-member:w-1', 'wildcard' ),
        array( '(name eq g-1)', 'add-member:g-2', 'loop' ),
        array( '(name eq g-1)', 'add-member:g-1', 'loop' ),
        array( '(name eq g-1)', 'remove-member:h-3', 'not a member' ),
        array( '(name eq g-2)', 'remove-member:g-1', 'last member' ),
        array( '(name eq g-dyn)', 'add-member:h-1', 'dynamic' ),
        array( '(name eq h-1)', 'remove-member:h-2', 'not a group' ) ) as $t )
{
    list( $rc, $o ) = $cli( 'address', $dir . '/b.xml', $t[0], $t[1] );
    $eq( array( $rc, strpos( $o, 'SKIPPED' ) !== FALSE && strpos( $o, $t[2] ) !== FALSE, $x( $dir . '/b.xml', $G . "/static/member" ) ),
        array( 0, TRUE, array( 'h-1', 'h-2', 'g-1' ) ), 'address ' . $t[0] . ' ' . $t[1] . ': SKIPPED (' . $t[2] . '), nothing changed, the run goes on' );
}
// a run over several groups: a skipped group does not stop the others
list( $rc, $o ) = $cli( 'address', $dir . '/c.xml', '(name regex /^g-/)', 'add-member:h-3' );
$eq( array( $rc, $x( $dir . '/c.xml', $G . "[@name='g-1']/static/member|" . $G . "[@name='g-2']/static/member" ) ), array( 0, array( 'h-1', 'h-2', 'h-3', 'g-1', 'h-3' ) ),
    'address: several groups (one dynamic: skipped) - the others changed' );

// ---- service groups
$S = "//service-group/entry";
list( $rc, $o ) = $cli( 'service', $dir . '/s.xml', '(name eq sg-1)', 'add-member:tcp-2/add-member:tcp-shared/remove-member:tcp-1' );
$eq( array( $rc, $x( $dir . '/s.xml', $S . "[@name='sg-1']/members/member" ) ), array( 0, array( 'tcp-2', 'tcp-shared' ) ),
    'service group: members added (also from shared) and removed' );
foreach( array(
        array( '(name eq sg-1)', 'add-member:tcp-1', 'already a member' ),
        array( '(name eq sg-1)', 'add-member:sg-2', 'loop' ),
        array( '(name eq sg-1)', 'remove-member:tcp-1', 'last member' ),
        array( '(name eq sg-1)', 'remove-member:tcp-2', 'not a member' ),
        array( '(name eq tcp-1)', 'add-member:tcp-2', 'not a group' ) ) as $t )
{
    list( $rc, $o ) = $cli( 'service', $dir . '/b.xml', $t[0], $t[1] );
    $eq( array( $rc, strpos( $o, 'SKIPPED' ) !== FALSE && strpos( $o, $t[2] ) !== FALSE, $x( $dir . '/b.xml', $S . "/members/member" ) ),
        array( 0, TRUE, array( 'tcp-1', 'sg-1' ) ), 'service ' . $t[0] . ' ' . $t[1] . ': SKIPPED (' . $t[2] . '), nothing changed' );
}

// references follow the members
$pan = new PANConf();
ob_start();
$pan->load_from_file( $dir . '/s.xml' );
ob_end_clean();
$v = $pan->findVirtualSystem( 'vsys1' );
$names = function( $o ) { return array_map( function( $r ) { return $r->name(); }, $o->getReferences() ); };
$eq( array( in_array( 'sg-1', $names( $v->serviceStore->find( 'tcp-2' ) ), TRUE ), in_array( 'sg-1', $names( $v->serviceStore->find( 'tcp-1' ) ), TRUE ) ),
    array( TRUE, FALSE ), 'service group: references of the members' );

// ---- description-set (common): replaces, empty removes, aliases, UTF-8 kept as it is
$eq( array( AddressCallContext::$supportedActions['description-set']['MainFunction'] === RuleCallContext::$supportedActions['description-set']['MainFunction'],
        isset( SecurityProfileCallContext::$supportedActions['description-set'], ServiceCallContext::$supportedActions['description-set'] ) ),
    array( TRUE, TRUE ), 'description-set: one definition for address, service, rule, security profile' );
list( $rc, $o ) = $cli( 'address', $dir . '/d.xml', '(name eq h-1)', 'description-set:Prüfung$$comma$$ DMZ$$colon$$ a$$forwardslash$$b' );
$eq( array( $rc, $x( $dir . '/d.xml', "//address/entry[@name='h-1']/description" ) ), array( 0, array( 'Prüfung, DMZ: a/b' ) ), 'address description-set: aliases, umlaut not converted twice' );
list( $rc, $o ) = $cli( 'service', $dir . '/d2.xml', '(name eq tcp-1)', 'description-set:x/description-set' );
$eq( array( $rc, $x( $dir . '/d2.xml', "//service/entry[@name='tcp-1']/description" ) ), array( 0, array() ), 'service description-set: set, then empty removes it' );
list( $rc, $o ) = $cli( 'service', $dir . '/b.xml', '(name eq sg-1)', 'description-set:x' );
$eq( strpos( $o, 'has no description' ) !== FALSE, TRUE, 'service group: SKIPPED (no description)' );

// ---- address value-set
$A = "//vsys/entry/address/entry";
foreach( array(
        array( 'h-1', 'value-set:10.0.0.0//24', 'ip-netmask', '10.0.0.0/24' ),
        array( 'h-1', 'value-set:www.example.com,fqdn', 'fqdn', 'www.example.com' ),
        array( 'h-1', 'value-set:2001$$colon$$db8$$colon$$$$colon$$//32', 'ip-netmask', '2001:db8::/32' ),
        array( 'h-1', 'value-set:10.0.0.1-10.0.0.9,ip-range', 'ip-range', '10.0.0.1-10.0.0.9' ),
        array( 'w-1', 'value-set:10.1.0.1//0.0.255.255', 'ip-wildcard', '10.1.0.1/0.0.255.255' ) ) as $t )
{
    list( $rc, $o ) = $cli( 'address', $dir . '/v.xml', '(name eq ' . $t[0] . ')', $t[1] );
    $eq( array( $rc, $x( $dir . '/v.xml', $A . "[@name='" . $t[0] . "']/" . $t[2] ), count( $x( $dir . '/v.xml', $A . "[@name='" . $t[0] . "']/*[not(self::description) and not(self::tag)]" ) ) ),
        array( 0, array( $t[3] ), 1 ), 'address ' . $t[0] . ' ' . $t[1] . ': ' . $t[2] . ' ' . $t[3] . ' (one value element)' );
}
foreach( array(
        array( 'h-1', 'value-set:10.0.0.0//33', 'mask 0-32' ),
        array( 'h-1', 'value-set:10.0.0.9-10.0.0.1,ip-range', 'above the last' ),
        array( 'h-1', 'value-set:10.0.0.1-2001$$colon$$db8$$colon$$$$colon$$1,ip-range', 'same family' ),
        array( 'h-1', 'value-set:a b,fqdn', 'without spaces' ),
        array( 'h-1', 'value-set:1.2.3.4,host', 'type:' ),
        array( 'h-1', 'value-set:10.0.0.1//0.255.0.255,ip-wildcard', "member of address group 'g-1'" ),
        array( 'h-1', 'value-set:192.0.2.1//32', 'the same' ),
        array( 'g-1', 'value-set:1.1.1.1', 'no address of type' ) ) as $t )
{
    list( $rc, $o ) = $cli( 'address', $dir . '/b.xml', '(name eq ' . $t[0] . ')', $t[1] );
    $eq( array( $rc, strpos( $o, 'SKIPPED' ) !== FALSE && strpos( $o, $t[2] ) !== FALSE, $x( $dir . '/b.xml', $A . "[@name='h-1']/ip-netmask" ) ),
        array( 0, TRUE, array( '192.0.2.1/32' ) ), 'address ' . $t[0] . ' ' . $t[1] . ': SKIPPED (' . $t[2] . ')' );
}

// ---- service protocol-set / dstport-set (and Service::setProtocol: source port and timeout kept)
$in0 = $in;
$in = $dir . '/svc.xml';
file_put_contents( $in, str_replace( '<entry name="tcp-2"><protocol><tcp><port>8444</port></tcp></protocol></entry>',
    '<entry name="tcp-2"><protocol><tcp><port>8444</port><source-port>1024-2048</source-port><override><yes><timeout>600</timeout><halfclose-timeout>60</halfclose-timeout></yes></override></tcp></protocol></entry>',
    file_get_contents( $in0 ) ) );
$T = "//vsys/entry/service/entry[@name='tcp-2']/protocol";
list( $rc, $o ) = $cli( 'service', $dir . '/p.xml', '(name eq tcp-2)', 'protocol-set:udp/dstport-set:53|5353;6000-6010' );
$eq( array( $rc, $x( $dir . '/p.xml', $T . "/udp/port|" . $T . "/udp/source-port|" . $T . "/udp/override/yes/*" ), count( $x( $dir . '/p.xml', $T . "/tcp" ) ) ),
    array( 0, array( '53,5353,6000-6010', '1024-2048', '600' ), 0 ), 'service protocol-set udp: ports, source port and timeout kept, half-close gone; dstport-set with | and ;' );
foreach( array( array( 'tcp-1', 'dstport-set:70000', 'no list of ports' ), array( 'tcp-1', 'dstport-set:90-80', 'no list of ports' ),
        array( 'tcp-1', 'protocol-set:tcp', 'already' ), array( 'sg-1', 'dstport-set:80', 'no service of tcp' ) ) as $t )
{
    list( $rc, $o ) = $cli( 'service', $dir . '/b.xml', '(name eq ' . $t[0] . ')', $t[1] );
    $eq( array( $rc, strpos( $o, 'SKIPPED' ) !== FALSE && strpos( $o, $t[2] ) !== FALSE ), array( 0, TRUE ), 'service ' . $t[0] . ' ' . $t[1] . ': SKIPPED (' . $t[2] . ')' );
}
$in = $in0;

// ---- interface-add / interface-remove (common: zone and router)
$eq( ZoneCallContext::$supportedActions['interface-add']['MainFunction'] === RoutingCallContext::$supportedActions['interface-add']['MainFunction'], TRUE,
    'interface-add: one definition for zone and router' );
$zin = __DIR__ . '/input/zones-interfaces.xml';
$zcli = function( string $type, string $file, ?string $out, string $filter, string $actions ) use ( $repo ) {
    $args = array( 'type=' . $type, 'in=' . $file, 'location=any', 'filter=' . $filter, 'actions=' . $actions );
    if( $type === 'rule' )
        $args[] = 'ruletype=decryption';
    if( $out !== null )
        $args[] = 'out=' . $out;
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' ' . implode( ' ', array_map( 'escapeshellarg', $args ) ) . ' 2>&1', $o, $rc );
    return array( $rc, implode( "\n", $o ) );
};
$Z = "//vsys/entry/zone/entry";
list( $rc, $o ) = $zcli( 'zone', $zin, $dir . '/z1.xml', '(name eq untrust)', 'interface-add:ethernet1//1.10/interface-add:tunnel.1/interface-remove:tunnel.1/interface-add:loopback.1' );
list( $rc2, $o2 ) = $zcli( 'zone', $dir . '/z1.xml', $dir . '/z2.xml', '(name eq l2)', 'interface-add:ethernet1//2' );
$eq( array( $rc, $rc2, $x( $dir . '/z2.xml', $Z . "[@name='untrust']/network/layer3/member" ), $x( $dir . '/z2.xml', $Z . "[@name='l2']/network/layer2/member" ) ),
    array( 0, 0, array( 'ethernet1/1.10', 'loopback.1' ), array( 'ethernet1/2' ) ), 'zone: interfaces added / removed (layer3 with sub-interface, loopback; layer2)' );
foreach( array( array( 'untrust', 'interface-add:ethernet1//1', 'is in zone trust' ), array( 'untrust', 'interface-add:ethernet1//2', 'is layer2 - the zone is layer3' ),
        array( 'untrust', 'interface-add:ethernet9//9', 'not found' ), array( 'l2', 'interface-add:ethernet1//3', 'not imported into vsys1' ),
        array( 'trust', 'interface-remove:loopback.1', 'is not in the zone' ) ) as $t )
{
    list( $rc, $o ) = $zcli( 'zone', $zin, $dir . '/b.xml', '(name eq ' . $t[0] . ')', $t[1] );
    $eq( array( $rc, strpos( $o, 'SKIPPED' ) !== FALSE && strpos( $o, $t[2] ) !== FALSE ), array( 0, TRUE ), 'zone ' . $t[0] . ' ' . $t[1] . ': SKIPPED (' . $t[2] . ')' );
}
list( $rc, $o ) = $zcli( 'routing', __DIR__ . '/input/network-edit-2.xml', $dir . '/b.xml', '(name eq vr-b)', 'interface-add:ethernet1//1' );
$eq( strpos( $o, 'is in router default' ) !== FALSE, TRUE, 'router: an interface of another router is SKIPPED' );

// ---- URL categories of a rule
$U = "//entry[@name='shared pre decrypt 1']/category/member";
list( $rc, $o ) = $zcli( 'rule', __DIR__ . '/input/panorama-10.0-merger.xml', $dir . '/u.xml', '(name eq shared pre decrypt 1)',
    'category-add:social-networking/category-add:gambling/category-remove:social-networking/category-add:nope/category-remove:gambling' );
$eq( array( $rc, $x( $dir . '/u.xml', $U ), strpos( $o, "'nope' not found" ) !== FALSE, strpos( $o, 'last URL category' ) !== FALSE ),
    array( 0, array( 'gambling' ), TRUE, TRUE ), 'rule: URL category added / removed; unknown and last one SKIPPED' );
list( $rc, $o ) = $zcli( 'rule', $dir . '/u.xml', $dir . '/u2.xml', '(name eq shared pre decrypt 1)', 'category-add:social-networking/display/category-set-any/display' );
$eq( array( $x( $dir . '/u2.xml', $U ), preg_match_all( '/URL Category: (.*)/', $o, $mm ) ? array_map( 'trim', $mm[1] ) : null ),
    array( array( 'any' ), array( 'gambling, social-networking', '**ANY**' ) ), 'rule: category-set-any; the rule shows the categories after each change' );
file_put_contents( $dir . '/unk.xml', str_replace( '<member>gambling</member>', '<member>gambling</member><member>not-known-cat</member>', file_get_contents( $dir . '/u.xml' ) ) );
list( $rc, $o ) = $zcli( 'rule', $dir . '/unk.xml', $dir . '/u3.xml', '(name eq shared pre decrypt 1)', 'category-add:adult' );
$eq( array( strpos( $o, 'does not know (not-known-cat)' ) !== FALSE, $x( $dir . '/u3.xml', $U ) ), array( TRUE, array( 'gambling', 'not-known-cat' ) ),
    'rule: a category pan-os-php does not know - SKIPPED, nothing dropped' );

// ---- name-rename of the network objects (common): the object and every user that names it
$eq( IKEprofileCallContext::$supportedActions['name-rename']['MainFunction'] === RoutingCallContext::$supportedActions['name-rename']['MainFunction'], TRUE,
    'name-rename: one definition for the network types' );
$rin = __DIR__ . '/input/network-rename.xml';
$steps = array( array( 'ike-profile', 'ike-a', 'ike-aes128' ), array( 'ipsec-profile', 'ipsec-a', 'ipsec-aes128' ), array( 'ike-gateway', 'gw-1', 'gw-berlin' ),
    array( 'interface-management-profile', 'mgmt-a', 'mgmt ping' ), array( 'zone-protection-profile', 'zpp-1', 'zpp-strict' ), array( 'routing', 'vr-b', 'vr-vpn' ),
    array( 'static-route', 'r-2', 'r-dc' ), array( 'ipsec-tunnel', 'tun-1', 'tun-berlin' ) );
$cur = $rin;
foreach( $steps as $i => $t )
{
    list( $rc, $o ) = $zcli( $t[0], $cur, $dir . '/rn' . $i . '.xml', '(name eq ' . $t[1] . ')', 'name-rename:' . $t[2] );
    $eq( array( $rc, strpos( $o, "renamed '" . $t[1] . "' -> '" . $t[2] . "'" ) !== FALSE ), array( 0, TRUE ), 'name-rename ' . $t[0] . ' ' . $t[1] . ' -> ' . $t[2] );
    $cur = $dir . '/rn' . $i . '.xml';
}
$N = "//devices/entry/network";
$eq( array( $x( $cur, $N . "/ike/gateway/entry/protocol/*/ike-crypto-profile" ), $x( $cur, $N . "/tunnel/ipsec/entry/auto-key/ipsec-crypto-profile" ),
        $x( $cur, $N . "/tunnel/ipsec/entry/auto-key/ike-gateway/entry/@name" ), $x( $cur, $N . "/interface//interface-management-profile" ),
        $x( $cur, "//zone/entry/network/zone-protection-profile" ), $x( $cur, $N . "/virtual-router//next-vr" ), $x( $cur, $N . "/tunnel/ipsec/entry/@name" ) ),
    array( array( 'ike-aes128', 'ike-aes128' ), array( 'ipsec-aes128' ), array( 'gw-berlin' ), array( 'mgmt ping', 'mgmt ping', 'mgmt-b' ), array( 'zpp-strict' ), array( 'vr-vpn' ), array( 'tun-berlin' ) ),
    'name-rename: every user names the new name (IKE gateway v1 / v2, IPsec tunnel, interface and sub-interface, zone, static route next-vr)' );
$rc = ( function( $f ) { $c = new PANConf(); ob_start(); $c->load_from_file( $f ); ob_end_clean(); return $c; } )( $cur );
$cnt = function( $o ) { return is_object( $o ) ? count( $o->getReferences() ) : -1; };
$eq( array( $cnt( $rc->network->ikeCryptoProfileStore->findIKECryptoProfil( 'ike-aes128' ) ), $cnt( $rc->network->interfaceManagementProfileStore->find( 'mgmt ping' ) ),
        $cnt( $rc->network->ikeGatewayStore->findIKEGateway( 'gw-berlin' ) ), $cnt( $rc->network->zoneProtectionProfileStore->find( 'zpp-strict' ) ) ),
    array( 1, 2, 1, 1 ), 'name-rename: loaded again, the renamed objects have their users (references)' );
foreach( array( array( 'ike-profile', 'ike-b', 'name-rename:ike-aes128', 'the name of another' ), array( 'ike-gateway', 'gw-berlin', 'name-rename:gw berlin', 'up to 63 characters' ),
        array( 'ike-profile', 'ike-b', 'name-rename:-x', 'starting with a letter' ), array( 'ike-profile', 'ike-b', 'name-rename:' . str_repeat( 'a', 32 ), 'up to 31 characters' ),
        array( 'static-route', 'to-b', 'name-rename:r-dc', 'the name of another' ), array( 'ike-profile', 'ike-b', 'name-rename:ike-b', 'already' ) ) as $t )
{
    list( $rc2, $o ) = $zcli( $t[0], $cur, $dir . '/b.xml', '(name eq ' . $t[1] . ')', $t[2] );
    $eq( array( $rc2, strpos( $o, 'SKIPPED' ) !== FALSE && strpos( $o, $t[3] ) !== FALSE ), array( 0, TRUE ), 'name-rename ' . $t[0] . ' ' . $t[2] . ': SKIPPED (' . $t[3] . ')' );
}

// ---- ObjectCandidates: the names a field can take - own location and above (firewall, Panorama, SCM)
$loadConf = function( string $class, string $file ) {
    $c = new $class();
    ob_start();
    $c->load_from_file( $file );
    ob_end_clean();
    return $c;
};
$flat = function( array $groups ) { $o = array(); foreach( $groups as $g ) $o[$g['location']] = $g['names']; return $o; };
$fw = $loadConf( 'PANConf', __DIR__ . '/input/group-members.xml' );
$g1 = $fw->findVirtualSystem( 'vsys1' )->addressStore->find( 'g-1' );
$eq( $flat( ObjectCandidates::forObject( $g1, 'address' ) ), array( 'vsys1' => array( 'g-dyn', 'h-1', 'h-2', 'h-3' ), 'shared' => array( 'h-shared' ) ),
    'candidates firewall: address of a vsys group - vsys1, then shared; not the group itself, not g-2 (holds it: loop), not the wildcard w-1' );
$eq( $flat( ObjectCandidates::forObject( $fw->findVirtualSystem( 'vsys1' )->serviceStore->find( 'sg-1' ), 'service' ) ), array( 'vsys1' => array( 'tcp-1', 'tcp-2' ), 'shared' => array( 'tcp-shared' ) ),
    'candidates firewall: service of a service group - not itself, not sg-2 (holds it)' );
$zfw = $loadConf( 'PANConf', $zin );
$eq( array( $flat( ObjectCandidates::forObject( $zfw->findVirtualSystem( 'vsys1' )->zoneStore->find( 'untrust' ), 'interface' ) ),
        $flat( ObjectCandidates::forObject( $zfw->findVirtualSystem( 'vsys1' )->zoneStore->find( 'l2' ), 'interface' ) ) ),
    array( array( 'firewall' => array( 'ae1', 'ethernet1/1.10', 'loopback.1', 'tunnel.1', 'vlan.5' ) ), array( 'firewall' => array( 'ethernet1/2' ) ) ),
    'candidates firewall: interfaces of a zone - imported into the vsys, of the zone type, in no other zone (not ethernet1/1: zone trust; not ethernet1/3: aggregate group member)' );
$rfw = $loadConf( 'PANConf', __DIR__ . '/input/network-edit-2.xml' );
$eq( in_array( 'ethernet1/1', $flat( ObjectCandidates::forObject( $rfw->network->virtualRouterStore->findVirtualRouter( 'vr-b' ), 'interface' ) )['firewall'] ?? array(), TRUE ), FALSE,
    'candidates firewall: interfaces of a router - not the ones of another router' );
$pano = $loadConf( 'PanoramaConf', __DIR__ . '/input/panorama-10.0-merger.xml' );
$dg = $pano->findDeviceGroup( 'testDG' );
$rule = $dg->securityRules->rules()[0];
$c = $flat( ObjectCandidates::forObject( $rule, 'address' ) );
$eq( array( array_keys( $c ), in_array( 'test-addr1', $c['testDG'], TRUE ), in_array( 'shared-host1', $c['shared'], TRUE ) ), array( array( 'testDG', 'shared' ), TRUE, TRUE ),
    'candidates Panorama: address of a device group rule - the device group, then shared' );
$z = $flat( ObjectCandidates::forObject( $rule, 'zone' ) );
$eq( array( isset( $z['template Datacenter Master Template / vsys1'] ), isset( $z['template Internet Perimeter Master / vsys1'] ) ), array( TRUE, TRUE ),
    'candidates Panorama: zones of a device group rule - the zones of the templates' );
$eq( array( count( $flat( ObjectCandidates::forObject( $rule, 'url-category' ) )['predefined'] ?? array() ) > 50,
        count( $flat( ObjectCandidates::forObject( $rule, 'application' ) )['predefined'] ?? array() ) > 1000 ), array( TRUE, TRUE ),
    'candidates: predefined URL categories and applications' );
$scm = $loadConf( 'BuckbeakConf', __DIR__ . '/input/SCM-import.xml' );
$a = $scm->findContainer( 'testDG' )->addressStore->find( 'test-addr1' );
$eq( array_keys( $flat( ObjectCandidates::forObject( $a, 'address' ) ) ), array( 'testDG', 'Panorama-Shared' ),
    'candidates SCM: address of a folder - the folder, then the levels above with objects (scmResolutionLevels)' );
$eq( array_keys( $flat( ObjectCandidates::forObject( $scm->findContainer( 'Perimeter-FWs' ), 'ike-crypto-profile' ) ) ), array( 'All' ),
    'candidates SCM: network profiles of the parent folders' );
try { ObjectCandidates::forObject( $g1, 'nope' ); $eq( 'no exception', 'exception', 'candidates: unknown kind' ); }
catch( Exception $e ) { $eq( strpos( $e->getMessage(), "unknown kind 'nope'" ) !== FALSE, TRUE, 'candidates: an unknown kind is an error' ); }

exec( 'rm -rf ' . escapeshellarg( $dir ) );
print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
