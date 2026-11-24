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
 * The change actions of the network objects (IKE / IPsec, interfaces, profiles, routing, GRE, DHCP, virtual wire,
 * GlobalProtect):
 * XML, references, refused values (SKIPPED with the reason) - on a synthetic firewall configuration. pan-os-php type=… as on the command line.
 *
 *   php tests/test_network_edit_actions.php
 */
$repo = dirname( __DIR__ );
require_once $repo . '/lib/pan_php_framework.php';

$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};

$dir = sys_get_temp_dir() . '/netedit-' . getmypid();
if( !is_dir( $dir ) )
    mkdir( $dir, 0700, TRUE );
$crypto = new PanosCrypto();
file_put_contents( $dir . '/in.xml', '<config version="11.1.0" urldb="paloaltonetworks"><mgt-config><users/></mgt-config><shared/><devices><entry name="localhost.localdomain"><network>'
    . '<interface><ethernet><entry name="ethernet1/1"><layer3><ip><entry name="198.51.100.1/24"/></ip></layer3></entry></ethernet>'
    . '<tunnel><units><entry name="tunnel.1"/><entry name="tunnel.2"/></units></tunnel></interface>'
    . '<ike><crypto-profiles><ike-crypto-profiles>'
    . '<entry name="ike-a"><encryption><member>aes-128-cbc</member></encryption><hash><member>sha1</member></hash><dh-group><member>group2</member></dh-group><lifetime><hours>8</hours></lifetime></entry>'
    . '<entry name="ike-b"><encryption><member>aes-256-cbc</member></encryption><hash><member>sha256</member></hash><dh-group><member>group14</member></dh-group><lifetime><hours>8</hours></lifetime></entry>'
    . '</ike-crypto-profiles><ipsec-crypto-profiles>'
    . '<entry name="ipsec-a"><esp><encryption><member>aes-128-cbc</member></encryption><authentication><member>sha1</member></authentication></esp><dh-group>group2</dh-group><lifetime><hours>1</hours></lifetime></entry>'
    . '<entry name="ipsec-b"><ah><authentication><member>sha256</member></authentication></ah><dh-group>group14</dh-group><lifetime><hours>1</hours></lifetime></entry>'
    . '</ipsec-crypto-profiles></crypto-profiles><gateway>'
    . '<entry name="gw-1"><authentication><pre-shared-key><key>' . $crypto->encrypt( 'synthetic-psk' ) . '</key></pre-shared-key></authentication><peer-address><ip>203.0.113.10</ip></peer-address>'
    . '<local-address><interface>ethernet1/1</interface></local-address><protocol><version>ikev2</version><ikev2><ike-crypto-profile>ike-a</ike-crypto-profile></ikev2></protocol></entry>'
    . '<entry name="gw-2"><peer-address><dynamic/></peer-address><local-address><interface>ethernet1/1</interface></local-address><protocol><version>ikev1</version><ikev1><ike-crypto-profile>ike-a</ike-crypto-profile></ikev1></protocol></entry>'
    . '</gateway></ike><tunnel><ipsec>'
    . '<entry name="tun-1"><tunnel-interface>tunnel.1</tunnel-interface><auto-key><ike-gateway><entry name="gw-1"/></ike-gateway><ipsec-crypto-profile>ipsec-a</ipsec-crypto-profile>'
    . '<proxy-id><entry name="p1"><local>10.0.0.0/24</local><remote>10.1.0.0/24</remote><protocol><any/></protocol></entry></proxy-id></auto-key></entry>'
    . '</ipsec></tunnel></network><vsys><entry name="vsys1"><import><network><interface><member>ethernet1/1</member><member>tunnel.1</member><member>tunnel.2</member></interface></network></import></entry></vsys></entry></devices></config>' );

$cli = function( string $type, string $in, ?string $out, string $name, string $actions ) use ( $repo ) {
    // $name '': no filter (the filter does not know every type, e.g. virtualwire)
    $args = array( 'type=' . $type, 'in=' . $in, 'location=any', 'actions=' . $actions );
    if( $name !== '' )
        $args[] = 'filter=(name eq ' . $name . ')';
    if( $out !== null )
        $args[] = 'out=' . $out;
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' ' . implode( ' ', array_map( 'escapeshellarg', $args ) ) . ' 2>&1', $o, $rc );
    return array( $rc, implode( "\n", $o ) );
};
$load = function( string $file ) {
    $pan = new PANConf();
    ob_start();
    $pan->load_from_file( $file );
    ob_end_clean();
    return $pan;
};
$x = function( string $file, string $q ) {
    $d = new DOMDocument(); $d->load( $file );
    $n = ( new DOMXPath( $d ) )->query( $q );
    $out = array();
    foreach( $n as $e )
        $out[] = trim( $e->textContent );
    return $out;
};
$refs = function( $o ) { return $o === null ? null : array_values( array_unique( array_map( function( $r ) { return $r->name(); }, $o->getReferences() ) ) ); };
$G = "//network/ike/gateway/entry[@name='gw-1']";

// ---- IKE gateway
list( $rc, $o ) = $cli( 'ike-gateway', $dir . '/in.xml', $dir . '/g.xml', 'gw-1',
    'version-set:ikev2-preferred/ike-crypto-profile-set:ike-b,ikev2/ike-crypto-profile-set:ike-a,ikev1/peer-address-set:fqdn,vpn.example.net/local-ip-set:198.51.100.1//24'
    . '/local-id-set:fqdn,fw.example.net/peer-id-set:ipaddr,203.0.113.10/nat-traversal-set:yes/fragmentation-set:no/passive-mode-set:yes/dpd-set:ikev2,yes/exchange-mode-set:main/disabled-set:no' );
$eq( array( $rc, $x( $dir . '/g.xml', $G . "/protocol/version" ), $x( $dir . '/g.xml', $G . "/protocol/ikev2/ike-crypto-profile" ), $x( $dir . '/g.xml', $G . "/protocol/ikev1/ike-crypto-profile" ),
        $x( $dir . '/g.xml', $G . "/peer-address/*" ), $x( $dir . '/g.xml', $G . "/peer-address/fqdn" ), $x( $dir . '/g.xml', $G . "/local-address/ip" ),
        $x( $dir . '/g.xml', $G . "/local-id/type|" . $G . "/local-id/id" ), $x( $dir . '/g.xml', $G . "/peer-id/type|" . $G . "/peer-id/id" ),
        $x( $dir . '/g.xml', $G . "/protocol-common/nat-traversal/enable|" . $G . "/protocol-common/fragmentation/enable|" . $G . "/protocol-common/passive-mode" ),
        $x( $dir . '/g.xml', $G . "/protocol/ikev2/dpd/enable|" . $G . "/protocol/ikev1/exchange-mode|" . $G . "/disabled" ),
        strpos( $o, 'synthetic' ) ),
    array( 0, array( 'ikev2-preferred' ), array( 'ike-b' ), array( 'ike-a' ), array( 'vpn.example.net' ), array( 'vpn.example.net' ), array( '198.51.100.1/24' ),
        array( 'fqdn', 'fw.example.net' ), array( 'ipaddr', '203.0.113.10' ), array( 'yes', 'no', 'yes' ), array( 'yes', 'main', 'no' ), FALSE ),
    'ike-gateway: version, IKE crypto profile per IKE version, peer address (choice), local IP, identifications, protocol-common, DPD, exchange mode, disabled' );
$pan = $load( $dir . '/g.xml' );
$gw = $pan->network->ikeGatewayStore->findIKEGateway( 'gw-1' );
$ra = $refs( $pan->network->ikeCryptoProfileStore->findIKECryptoProfil( 'ike-a' ) ); sort( $ra );
$eq( array( $gw->proposal, $refs( $pan->network->ikeCryptoProfileStore->findIKECryptoProfil( 'ike-b' ) ), $ra ),
    array( 'ike-b', array( 'gw-1' ), array( 'gw-1', 'gw-2' ) ), 'ike-gateway: the profile of the version used (ikev2-preferred: IKEv2), references of both profiles' );
list( $rc, $o ) = $cli( 'ike-gateway', $dir . '/g.xml', $dir . '/g2.xml', 'gw-1', 'ike-crypto-profile-set:ike-b,ikev1/peer-address-set:dynamic/local-ip-set/local-id-set' );
$pan = $load( $dir . '/g2.xml' );
$eq( array( $rc, $refs( $pan->network->ikeCryptoProfileStore->findIKECryptoProfil( 'ike-a' ) ), $x( $dir . '/g2.xml', $G . "/peer-address/*" ),
        count( $x( $dir . '/g2.xml', $G . "/peer-address/dynamic" ) ), $x( $dir . '/g2.xml', $G . "/local-address/ip|" . $G . "/local-id" ), $x( $dir . '/g2.xml', $G . "/local-address/interface" ) ),
    array( 0, array( 'gw-2' ), array( '' ), 1, array(), array( 'ethernet1/1' ) ),
    'ike-gateway: the old profile loses the reference; dynamic peer; local IP / local identification removed (the interface stays)' );
foreach( array( 'ike-crypto-profile-set:nope,ikev2' => "IKE crypto profile 'nope' not found", 'peer-address-set:ip' => 'peer address: a value',
        'local-id-set:email,x' => 'unsupported value', 'version-set:ikev3' => 'unsupported value' ) as $a => $why )
{
    list( $rc, $o ) = $cli( 'ike-gateway', $dir . '/in.xml', $dir . '/bad.xml', 'gw-1', $a );
    $eq( array( strpos( $o, $why ) !== FALSE, ( strpos( $o, 'SKIPPED' ) !== FALSE || strpos( $o, 'ERROR' ) !== FALSE ) ), array( TRUE, TRUE ), 'ike-gateway ' . $a . ': refused (' . $why . ')' );
}

// ---- IKE crypto profile
$P = "//ike-crypto-profiles/entry[@name='ike-a']";
list( $rc, $o ) = $cli( 'ike-profile', $dir . '/in.xml', $dir . '/p.xml', 'ike-a', 'encryption-set:aes-256-gcm|aes-128-cbc/hash-set:sha384/dh-group-set:group19|group20/lifetime-set:days,1/authentication-multiple-set:3' );
$eq( array( $rc, $x( $dir . '/p.xml', $P . "/encryption/member" ), $x( $dir . '/p.xml', $P . "/hash/member" ), $x( $dir . '/p.xml', $P . "/dh-group/member" ),
        $x( $dir . '/p.xml', $P . "/lifetime/*" ), count( $x( $dir . '/p.xml', $P . "/lifetime/days" ) ), $x( $dir . '/p.xml', $P . "/authentication-multiple" ) ),
    array( 0, array( 'aes-256-gcm', 'aes-128-cbc' ), array( 'sha384' ), array( 'group19', 'group20' ), array( '1' ), 1, array( '3' ) ),
    'ike-profile: encryption / hash / DH groups as members, lifetime (one unit), authentication multiple' );
list( $rc, $o ) = $cli( 'ike-profile', $dir . '/in.xml', $dir . '/bad.xml', 'ike-a', 'lifetime-set:seconds,60' );
$eq( array( strpos( $o, 'seconds 180-65535' ) !== FALSE, ( strpos( $o, 'SKIPPED' ) !== FALSE || strpos( $o, 'ERROR' ) !== FALSE ) ), array( TRUE, TRUE ), 'ike-profile lifetime-set:seconds,60: refused (range)' );

// ---- IPsec crypto profile
$Q = "//ipsec-crypto-profiles/entry[@name='ipsec-b']";
list( $rc, $o ) = $cli( 'ipsec-profile', $dir . '/in.xml', $dir . '/q.xml', 'ipsec-b', 'esp-encryption-set:aes-256-gcm/esp-authentication-set:none/dh-group-set:no-pfs/lifetime-set:minutes,30/lifesize-set:gb,10' );
list( $rc2, $o2 ) = $cli( 'ipsec-profile', $dir . '/q.xml', $dir . '/q2.xml', 'ipsec-b', 'lifesize-set' );
$eq( array( $rc, count( $x( $dir . '/q.xml', $Q . "/ah" ) ), $x( $dir . '/q.xml', $Q . "/esp/encryption/member" ), $x( $dir . '/q.xml', $Q . "/esp/authentication/member" ),
        $x( $dir . '/q.xml', $Q . "/dh-group" ), $x( $dir . '/q.xml', $Q . "/lifetime/minutes" ), $x( $dir . '/q.xml', $Q . "/lifesize/gb" ), $rc2, count( $x( $dir . '/q2.xml', $Q . "/lifesize" ) ) ),
    array( 0, 0, array( 'aes-256-gcm' ), array( 'none' ), array( 'no-pfs' ), array( '30' ), array( '10' ), 0, 0 ),
    'ipsec-profile: an AH profile becomes ESP, DH group no-pfs, lifetime, lifesize (and removed again)' );

// ---- IPsec tunnel
$T = "//tunnel/ipsec/entry[@name='tun-1']";
list( $rc, $o ) = $cli( 'ipsec-tunnel', $dir . '/in.xml', $dir . '/t.xml', 'tun-1',
    'ike-gateway-set:gw-2/ipsec-crypto-profile-set:ipsec-b/tunnel-interface-set:tunnel.2/anti-replay-set:no/copy-tos-set:yes/tunnel-monitor-set:yes,10.9.9.9/proxy-id-add:p2,10.2.0.0//24,10.3.0.0//24/proxy-id-remove:p1/disabled-set:yes' );
$pan = $load( $dir . '/t.xml' );
$eq( array( $rc, $x( $dir . '/t.xml', $T . "/auto-key/ike-gateway/entry/@name" ), $x( $dir . '/t.xml', $T . "/auto-key/ipsec-crypto-profile" ), $x( $dir . '/t.xml', $T . "/tunnel-interface" ),
        $x( $dir . '/t.xml', $T . "/anti-replay|" . $T . "/copy-tos|" . $T . "/disabled" ), $x( $dir . '/t.xml', $T . "/tunnel-monitor/enable|" . $T . "/tunnel-monitor/destination-ip" ),
        $x( $dir . '/t.xml', $T . "/auto-key/proxy-id/entry/@name" ), $x( $dir . '/t.xml', $T . "/auto-key/proxy-id/entry/local|" . $T . "/auto-key/proxy-id/entry/remote" ) ),
    array( 0, array( 'gw-2' ), array( 'ipsec-b' ), array( 'tunnel.2' ), array( 'no', 'yes', 'yes' ), array( 'yes', '10.9.9.9' ), array( 'p2' ), array( '10.2.0.0/24', '10.3.0.0/24' ) ),
    'ipsec-tunnel: IKE gateway, IPsec crypto profile, tunnel interface, flags, tunnel monitor, proxy ID added / removed' );
$eq( array( $refs( $pan->network->ikeGatewayStore->findIKEGateway( 'gw-1' ) ), $refs( $pan->network->ikeGatewayStore->findIKEGateway( 'gw-2' ) ),
        $refs( $pan->network->ipsecCryptoProfileStore->findIpsecCryptoProfil( 'ipsec-a' ) ), $refs( $pan->network->ipsecCryptoProfileStore->findIpsecCryptoProfil( 'ipsec-b' ) ) ),
    array( array(), array( 'tun-1' ), array(), array( 'tun-1' ) ), 'ipsec-tunnel: references moved to the new gateway / profile' );
list( $rc, $o ) = $cli( 'ipsec-tunnel', $dir . '/in.xml', $dir . '/bad.xml', 'tun-1', 'ike-gateway-set:gw-nope' );
$eq( array( strpos( $o, "IKE gateway 'gw-nope' not found" ) !== FALSE, ( strpos( $o, 'SKIPPED' ) !== FALSE || strpos( $o, 'ERROR' ) !== FALSE ) ), array( TRUE, TRUE ), 'ipsec-tunnel ike-gateway-set: an unknown gateway is refused' );

// ---- interfaces (ethernet layer3 / sub-interface / aggregate / tunnel), interface management profile, zone protection profile
copy( $hereIn = __DIR__ . '/input/network-edit.xml', $dir . '/if.xml' );
$E = "//ethernet/entry[@name='ethernet1/1']/layer3";
list( $rc, $o ) = $cli( 'interface', $dir . '/if.xml', $dir . '/i1.xml', 'ethernet1/1',
    'comment-set:uplink/ip-add:198.51.100.2//24/ip-remove:198.51.100.1//24/mtu-set:1400/interface-management-profile-set:mgmt-a/adjust-tcp-mss-set:yes/link-state-set:up' );
list( $rc2, $o2 ) = $cli( 'interface', $dir . '/i1.xml', $dir . '/i2.xml', 'ethernet1/1.10', 'tag-set:20/ip-add:10.20.0.1//24/interface-management-profile-set:mgmt-b' );
list( $rc3, $o3 ) = $cli( 'interface', $dir . '/i2.xml', $dir . '/i3.xml', 'tunnel.1', 'ip-add:169.254.1.1//30/mtu-set:1400/interface-management-profile-set:mgmt-a/comment-set:to-peer' );
list( $rc4, $o4 ) = $cli( 'interface', $dir . '/i3.xml', $dir . '/i4.xml', 'ae1', 'mtu-set:9000/interface-management-profile-set:mgmt-a/mtu-set' );
$f = $dir . '/i4.xml';
$eq( array( $rc, $rc2, $rc3, $rc4, $x( $f, "//ethernet/entry[@name='ethernet1/1']/comment|//ethernet/entry[@name='ethernet1/1']/link-state" ), $x( $f, $E . "/ip/entry/@name" ),
        $x( $f, $E . "/mtu|" . $E . "/interface-management-profile|" . $E . "/adjust-tcp-mss/enable" ),
        $x( $f, $E . "/units/entry[@name='ethernet1/1.10']/tag|" . $E . "/units/entry[@name='ethernet1/1.10']/interface-management-profile" ),
        $x( $f, $E . "/units/entry[@name='ethernet1/1.10']/ip/entry/@name" ),
        $x( $f, "//tunnel/units/entry[@name='tunnel.1']/ip/entry/@name|//tunnel/units/entry[@name='tunnel.1']/mtu|//tunnel/units/entry[@name='tunnel.1']/comment" ),
        $x( $f, "//aggregate-ethernet/entry[@name='ae1']/layer3/mtu|//aggregate-ethernet/entry[@name='ae1']/layer3/interface-management-profile" ) ),
    array( 0, 0, 0, 0, array( 'uplink', 'up' ), array( '198.51.100.2/24' ), array( '1400', 'mgmt-a', 'yes' ), array( '20', 'mgmt-b' ), array( '10.10.0.1/24', '10.20.0.1/24' ),
        array( '169.254.1.1/30', '1400', 'to-peer' ), array( 'mgmt-a' ) ),
    'interface: ethernet layer3 (below layer3), sub-interface (tag), tunnel, aggregate (MTU set and removed again)' );
$pan = $load( $f );
$ra = $refs( $pan->network->interfaceManagementProfileStore->find( 'mgmt-a' ) ); sort( $ra );
$eq( array( $ra, $refs( $pan->network->interfaceManagementProfileStore->find( 'mgmt-b' ) ) ), array( array( 'ae1', 'ethernet1/1', 'tunnel.1' ), array( 'ethernet1/1.10' ) ),
    'interface: references of the interface management profiles' );
foreach( array( array( 'ethernet1/2', 'mtu-set:1400', 'only a layer3 interface' ), array( 'tunnel.1', 'interface-management-profile-set:nope', "'nope' not found" ),
        array( 'loopback.1', 'tag-set:5', 'only a sub-interface' ), array( 'tunnel.1', 'mtu-set:100', 'MTU: 576-9216' ), array( 'tunnel.1', 'ip-remove:10.9.9.9//32', 'is not set' ) ) as $t )
{
    list( $rc, $o ) = $cli( 'interface', $dir . '/if.xml', $dir . '/bad.xml', $t[0], $t[1] );
    $eq( array( strpos( $o, $t[2] ) !== FALSE, ( strpos( $o, 'SKIPPED' ) !== FALSE || strpos( $o, 'ERROR' ) !== FALSE ) ), array( TRUE, TRUE ), 'interface ' . $t[0] . ' ' . $t[1] . ': refused (' . $t[2] . ')' );
}
$M = "//interface-management-profile/entry[@name='mgmt-a']";
list( $rc, $o ) = $cli( 'interface-management-profile', $dir . '/if.xml', $dir . '/m.xml', 'mgmt-a', 'service-set:ssh,yes/service-set:ping,no/permitted-ip-add:10.0.0.0//8/permitted-ip-add:192.0.2.0//24/permitted-ip-remove:192.0.2.0//24' );
$eq( array( $rc, $x( $dir . '/m.xml', $M . "/ping|" . $M . "/ssh" ), $x( $dir . '/m.xml', $M . "/permitted-ip/entry/@name" ) ), array( 0, array( 'no', 'yes' ), array( '10.0.0.0/8' ) ),
    'interface-management-profile: services yes / no, permitted IPs added / removed' );
$Z = "//zone-protection-profile/entry[@name='zpp-1']";
list( $rc, $o ) = $cli( 'zone-protection-profile', $dir . '/if.xml', $dir . '/z.xml', 'zpp-1',
    'description-set:edge/flood-set:tcp-syn,yes,5000,,30000,syn-cookies/flood-set:udp,yes,1000,2000,3000/scan-set:host-sweep,block-ip,10,100,source,600/scan-set:tcp-port-scan,alert/packet-set:discard-ip-spoof,yes/packet-set:routing-header-0,yes/packet-set:tcp-reject-non-syn,global' );
$z = $dir . '/z.xml';
$eq( array( $rc, $x( $z, $Z . "/description" ), count( $x( $z, $Z . "/flood/tcp-syn/red" ) ), $x( $z, $Z . "/flood/tcp-syn/enable|" . $Z . "/flood/tcp-syn/syn-cookies/*" ),
        $x( $z, $Z . "/flood/udp/red/*" ), $x( $z, $Z . "/scan/entry[@name='8002']/action/block-ip/*|" . $Z . "/scan/entry[@name='8002']/interval|" . $Z . "/scan/entry[@name='8002']/threshold" ),
        count( $x( $z, $Z . "/scan/entry[@name='8001']/action/alert" ) ), $x( $z, $Z . "/discard-ip-spoof|" . $Z . "/ipv6/routing-header-0|" . $Z . "/tcp-reject-non-syn" ) ),
    array( 0, array( 'edge' ), 0, array( 'yes', '5000', '10000', '30000' ), array( '1000', '2000', '3000' ), array( 'source', '600', '10', '100' ), 1, array( 'yes', 'yes', 'global' ) ),
    'zone-protection-profile: description, flood (tcp-syn red -> syn-cookies with its rates), scans (block-ip, alert), packet based (also below ipv6)' );
foreach( array( 'packet-set:discard-ip-spoof,maybe' => 'discard-ip-spoof: yes, no', 'packet-set:nope,yes' => 'option: one of', 'scan-set:host-sweep,block-ip' => 'track by',
        'flood-set:udp,yes,1,2,3,syn-cookies' => 'only for tcp-syn' ) as $a => $why )
{
    list( $rc, $o ) = $cli( 'zone-protection-profile', $dir . '/if.xml', $dir . '/bad.xml', 'zpp-1', $a );
    $eq( array( strpos( $o, $why ) !== FALSE, ( strpos( $o, 'SKIPPED' ) !== FALSE || strpos( $o, 'ERROR' ) !== FALSE ) ), array( TRUE, TRUE ), 'zone-protection-profile ' . $a . ': refused (' . $why . ')' );
}

// ---- routing (virtual router, logical router), static routes, GRE tunnel, DHCP, virtual wire, GlobalProtect
$in2 = $dir . '/n2.xml';
copy( __DIR__ . '/input/network-edit-2.xml', $in2 );
$R = "//network/virtual-router/entry[@name='default']";
list( $rc, $o ) = $cli( 'routing', $in2, $dir . '/r.xml', 'default',
    'interface-add:ethernet1//2/interface-add:tunnel.1/interface-remove:tunnel.1/ecmp-set:yes/admin-distance-set:static,15/static-route-add:r-branch,10.20.0.0//16,ip-address,192.0.2.254,ethernet1//2,20/static-route-add:r-null,10.99.0.0//16,discard' );
$r = $dir . '/r.xml';
$eq( array( $rc, $x( $r, $R . "/interface/member" ), $x( $r, $R . "/ecmp/enable|" . $R . "/admin-dists/static" ), $x( $r, $R . "/routing-table/ip/static-route/entry/@name" ),
        $x( $r, $R . "//entry[@name='r-branch']/nexthop/ip-address|" . $R . "//entry[@name='r-branch']/interface|" . $R . "//entry[@name='r-branch']/metric" ),
        count( $x( $r, $R . "//entry[@name='r-null']/nexthop/discard" ) ) ),
    array( 0, array( 'ethernet1/1', 'ethernet1/2' ), array( 'yes', '15' ), array( 'r-default', 'r-branch', 'r-null' ), array( '192.0.2.254', 'ethernet1/2', '20' ), 1 ),
    'routing: interfaces added / removed, ECMP, admin distance, static routes added' );
list( $rc, $o ) = $cli( 'static-route', $r, $dir . '/r2.xml', 'r-default', 'nexthop-set:next-vr,vr-b/interface-set/metric-set:5/admin-distance-set:20/route-table-set:unicast/destination-set:0.0.0.0//1' );
$S = $R . "//entry[@name='r-default']";
$eq( array( $rc, $x( $dir . '/r2.xml', $S . "/destination|" . $S . "/nexthop/next-vr|" . $S . "/metric|" . $S . "/admin-dist" ), count( $x( $dir . '/r2.xml', $S . "/interface" ) ),
        count( $x( $dir . '/r2.xml', $S . "/route-table/unicast" ) ) ),
    array( 0, array( '0.0.0.0/1', 'vr-b', '5', '20' ), 0, 1 ), 'static-route: destination, next hop (next VR), interface removed, metric, admin distance, route table' );
foreach( array( array( 'routing', 'default', 'interface-add:ethernet9//9', 'not found' ), array( 'static-route', 'r-default', 'destination-set:10.0.0.0//99', 'destination' ),
        array( 'static-route', 'r-default', 'nexthop-set:next-vr,nope', 'nope' ), array( 'routing', 'default', 'admin-distance-set:static,5', '10-240' ) ) as $t )
{
    list( $rc, $o ) = $cli( $t[0], $in2, $dir . '/bad.xml', $t[1], $t[2] );
    $eq( array( strpos( $o, $t[3] ) !== FALSE, ( strpos( $o, 'SKIPPED' ) !== FALSE || strpos( $o, 'ERROR' ) !== FALSE ) ), array( TRUE, TRUE ), $t[0] . ' ' . $t[2] . ': refused (' . $t[3] . ')' );
}
// logical router (advanced routing): the settings of vrf "default"
file_put_contents( $dir . '/lr.xml', '<config version="11.1.0" urldb="paloaltonetworks"><mgt-config><users/></mgt-config><shared/><devices><entry name="localhost.localdomain">'
    . '<deviceconfig><setting><advance-routing>yes</advance-routing></setting></deviceconfig><network>'
    . '<interface><ethernet><entry name="ethernet1/1"><layer3><ip><entry name="198.51.100.1/24"/></ip></layer3></entry><entry name="ethernet1/2"><layer3/></entry></ethernet></interface>'
    . '<logical-router><entry name="lr-1"><vrf><entry name="default"><interface><member>ethernet1/1</member></interface></entry></vrf></entry></logical-router></network>'
    . '<vsys><entry name="vsys1"><import><network><interface><member>ethernet1/1</member><member>ethernet1/2</member></interface></network></import></entry></vsys></entry></devices></config>' );
list( $rc, $o ) = $cli( 'routing', $dir . '/lr.xml', $dir . '/lr1.xml', 'lr-1', 'interface-add:ethernet1//2/ecmp-set:yes/static-route-add:r-b,10.20.0.0//16,ip-address,192.0.2.254' );
$L = "//logical-router/entry[@name='lr-1']/vrf/entry[@name='default']";
$eq( array( $rc, $x( $dir . '/lr1.xml', $L . "/interface/member" ), $x( $dir . '/lr1.xml', $L . "/ecmp/enable|" . $L . "/routing-table/ip/static-route/entry/destination" ) ),
    array( 0, array( 'ethernet1/1', 'ethernet1/2' ), array( '10.20.0.0/16', 'yes' ) ), 'routing: logical router - interface, ECMP, static route in vrf default' );

$T = "//network/tunnel/gre/entry[@name='gre-1']";
list( $rc, $o ) = $cli( 'gre-tunnel', $in2, $dir . '/g.xml', 'gre-1', 'local-ip-set:10.0.0.2//24/peer-address-set:203.0.113.9/ttl-set:100/copy-tos-set:yes/keep-alive-set:yes,10,3,5/local-interface-set:ethernet1//2/tunnel-interface-set:tunnel.2' );
$g = $dir . '/g.xml';
$eq( array( $rc, $x( $g, $T . "/local-address/*|" . $T . "/peer-address/ip|" . $T . "/tunnel-interface|" . $T . "/ttl|" . $T . "/copy-tos" ), $x( $g, $T . "/keep-alive/*" ) ),
    array( 0, array( 'ethernet1/2', '10.0.0.2/24', '203.0.113.9', 'tunnel.2', '100', 'yes' ), array( 'yes', '10', '3', '5' ) ),
    'gre-tunnel: local interface / IP, peer, tunnel interface, TTL, copy TOS, keep alive' );
$pan = $load( $g );
$eq( array( $refs( $pan->network->findInterface( 'tunnel.2' ) ) !== array(), $pan->network->greTunnelStore->findGreTunnel( 'gre-1' )->localInterface->interfaces()[0]->name() ),
    array( TRUE, 'ethernet1/2' ), 'gre-tunnel: interface containers / references follow' );
foreach( array( 'tunnel-interface-set:ethernet1//2' => 'not a tunnel interface', 'ttl-set:300' => 'TTL: 1-255', 'keep-alive-set:yes,99' => 'interval: 1-50' ) as $a => $why )
{
    list( $rc, $o ) = $cli( 'gre-tunnel', $in2, $dir . '/bad.xml', 'gre-1', $a );
    $eq( array( strpos( $o, $why ) !== FALSE, ( strpos( $o, 'SKIPPED' ) !== FALSE || strpos( $o, 'ERROR' ) !== FALSE ) ), array( TRUE, TRUE ), 'gre-tunnel ' . $a . ': refused (' . $why . ')' );
}

$D = "//network/dhcp/interface/entry[@name='ethernet1/2']/server";
list( $rc, $o ) = $cli( 'dhcp', $in2, $dir . '/d.xml', 'ethernet1/2',
    'mode-set:enabled/ip-pool-add:10.2.1.0//24/ip-pool-remove:10.2.0.10-10.2.0.99/gateway-set:10.2.1.1/subnet-mask-set:255.255.255.0/dns-set:10.9.9.9,10.9.9.8/lease-set:timeout,720/reservation-add:10.2.1.50,00-11-22-33-44-55,printer/reservation-add:10.2.1.51,00.11.22.33.44.66/reservation-remove:10.2.1.51' );
$d = $dir . '/d.xml';
$eq( array( $rc, $x( $d, $D . "/mode|" . $D . "/ip-pool/member" ), $x( $d, $D . "/option/gateway|" . $D . "/option/subnet-mask|" . $D . "/option/dns/*|" . $D . "/option/lease/timeout" ),
        $x( $d, $D . "/reserved/entry/@name|" . $D . "/reserved/entry/mac" ) ),
    array( 0, array( 'enabled', '10.2.1.0/24' ), array( '10.2.1.1', '255.255.255.0', '10.9.9.9', '10.9.9.8', '720' ), array( '10.2.1.50', '00:11:22:33:44:55' ) ),
    'dhcp server: mode, IP pool, gateway, mask, DNS, lease, reservations' );
$DR = "//network/dhcp/interface/entry[@name='ethernet1/1']/relay/ip";
list( $rc, $o ) = $cli( 'dhcp', $in2, $dir . '/d2.xml', 'ethernet1/1', 'relay-set:yes/relay-server-add:192.0.2.54/relay-server-remove:192.0.2.53' );
$eq( array( $rc, $x( $dir . '/d2.xml', $DR . "/enabled|" . $DR . "/server/member" ) ), array( 0, array( 'yes', '192.0.2.54' ) ), 'dhcp relay: enabled, servers added / removed' );
foreach( array( array( 'ethernet1/2', 'relay-set:yes', 'not a relay' ), array( 'ethernet1/1', 'mode-set:auto', 'not a server' ),
        array( 'ethernet1/2', 'reservation-add:10.2.1.9,zz', 'MAC' ) ) as $t )
{
    list( $rc, $o ) = $cli( 'dhcp', $in2, $dir . '/bad.xml', $t[0], $t[1] );
    $eq( array( strpos( $o, $t[2] ) !== FALSE, ( strpos( $o, 'SKIPPED' ) !== FALSE || strpos( $o, 'ERROR' ) !== FALSE ) ), array( TRUE, TRUE ), 'dhcp ' . $t[0] . ' ' . $t[1] . ': refused (' . $t[2] . ')' );
}

$V = "//network/virtual-wire/entry[@name='vw-1']";
list( $rc, $o ) = $cli( 'virtualwire', $in2, $dir . '/v.xml', '', 'interface-set:2,ethernet1//5/tag-allowed-set:0|10-20/multicast-firewalling-set:yes/link-state-pass-through-set:yes' );
$eq( array( $rc, $x( $dir . '/v.xml', $V . "/interface2|" . $V . "/tag-allowed|" . $V . "/multicast-firewalling/enable|" . $V . "/link-state-pass-through/enable" ) ),
    array( 0, array( 'ethernet1/5', '0,10-20', 'yes', 'yes' ) ), 'virtualwire: interface 2, tags, multicast firewalling, link state pass through' );
foreach( array( 'interface-set:1,ethernet1//1' => 'needs a virtual-wire interface', 'interface-set:1,ethernet1//4' => 'other side', 'tag-allowed-set:abc' => 'tag allowed' ) as $a => $why )
{
    list( $rc, $o ) = $cli( 'virtualwire', $in2, $dir . '/bad.xml', '', $a );
    $eq( array( strpos( $o, $why ) !== FALSE, ( strpos( $o, 'SKIPPED' ) !== FALSE || strpos( $o, 'ERROR' ) !== FALSE ) ), array( TRUE, TRUE ), 'virtualwire ' . $a . ': refused (' . $why . ')' );
}

$P = "//global-protect-portal/entry[@name='portal-1']/portal-config";
list( $rc, $o ) = $cli( 'gp-portal', $in2, $dir . '/p.xml', 'portal-1', 'local-interface-set:ethernet1//2/local-ip-set:192.0.2.1//24/ssl-tls-profile-set:ssl-b' );
$eq( array( $rc, $x( $dir . '/p.xml', $P . "/local-address/interface|" . $P . "/local-address/ip/ipv4|" . $P . "/ssl-tls-service-profile" ) ),
    array( 0, array( 'ethernet1/2', '192.0.2.1/24', 'ssl-b' ) ), 'gp-portal: local interface, local IP, SSL/TLS service profile' );
$W = "//global-protect-gateway/entry[@name='gw-1']";
list( $rc, $o ) = $cli( 'gp-gateway', $in2, $dir . '/w.xml', 'gw-1',
    'local-interface-set:ethernet1//2/local-ip-set:gp-pool/ssl-tls-profile-set:ssl-b/tunnel-interface-set:tunnel.2/client-ip-pool-add:cfg-1,gp-pool/client-ip-pool-remove:cfg-1,10.60.0.0//24/client-access-route-add:cfg-1,10.0.0.0//8/client-exclude-access-route-add:cfg-1,10.9.0.0//16/client-exclude-access-route-remove:cfg-1,10.9.0.0//16' );
$w = $dir . '/w.xml';
$C = $W . "/remote-user-tunnel-configs/entry[@name='cfg-1']";
$eq( array( $rc, $x( $w, $W . "/local-address/interface|" . $W . "/local-address/ip/ipv4|" . $W . "/ssl-tls-service-profile|" . $W . "/remote-user-tunnel" ),
        $x( $w, $C . "/ip-pool/member|" . $C . "/split-tunneling/access-route/member" ), count( $x( $w, $C . "/split-tunneling/exclude-access-route" ) ) ),
    array( 0, array( 'ethernet1/2', 'gp-pool', 'ssl-b', 'tunnel.2' ), array( 'gp-pool', '10.0.0.0/8' ), 0 ),
    'gp-gateway: local interface / IP, SSL/TLS profile, tunnel interface, client setting lists' );
$pan = $load( $w );
$v1 = $pan->findVirtualSystem( 'vsys1' );
$eq( in_array( 'gw-1', $refs( $v1->addressStore->find( 'gp-pool' ) ), TRUE ), TRUE, 'gp-gateway: reference of the address object (local IP / IP pool)' );
list( $rc, $o ) = $cli( 'gpgateway-tunnel', $in2, $dir . '/t.xml', 'gw-N', 'local-interface-set:ethernet1//2/local-ip-set:192.0.2.1//24/tunnel-interface-set:tunnel.2/disabled-set:yes' );
$N = "//tunnel/global-protect-gateway/entry[@name='gw-N']";
$eq( array( $rc, $x( $dir . '/t.xml', $N . "/local-address/interface|" . $N . "/local-address/ip/ipv4|" . $N . "/tunnel-interface|" . $N . "/disabled" ) ),
    array( 0, array( 'ethernet1/2', '192.0.2.1/24', 'tunnel.2', 'yes' ) ), 'gpgateway-tunnel: local interface / IP, tunnel interface, disabled' );
foreach( array( array( 'gp-portal', 'portal-1', 'ssl-tls-profile-set:nope', "'nope' not found" ), array( 'gp-gateway', 'gw-1', 'tunnel-interface-set:ethernet1//1', 'not a tunnel interface' ),
        array( 'gp-gateway', 'gw-1', 'client-ip-pool-add:cfg-x,10.1.0.0//24', "'cfg-x' not found" ), array( 'gp-portal', 'portal-1', 'local-interface-set:ethernet9//9', 'not an interface of vsys1' ) ) as $t )
{
    list( $rc, $o ) = $cli( $t[0], $in2, $dir . '/bad.xml', $t[1], $t[2] );
    $eq( array( strpos( $o, $t[3] ) !== FALSE, ( strpos( $o, 'SKIPPED' ) !== FALSE || strpos( $o, 'ERROR' ) !== FALSE ) ), array( TRUE, TRUE ), $t[0] . ' ' . $t[2] . ': refused (' . $t[3] . ')' );
}

exec( 'rm -rf ' . escapeshellarg( $dir ) );
print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( empty( $failed ) ? 0 : 1 );
