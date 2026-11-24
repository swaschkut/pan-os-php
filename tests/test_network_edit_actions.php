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
 * The change actions of IKE gateways, IKE / IPsec crypto profiles and IPsec tunnels (…-set, proxy-id-add / -remove):
 * XML, references, refused values - on a synthetic firewall configuration. pan-os-php type=… as on the command line.
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
    $args = array( 'type=' . $type, 'in=' . $in, 'location=any', 'filter=(name eq ' . $name . ')', 'actions=' . $actions );
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
    $eq( array( $rc !== 0 || strpos( $o, 'ERROR' ) !== FALSE, strpos( $o, $why ) !== FALSE, is_file( $dir . '/bad.xml' ) ), array( TRUE, TRUE, FALSE ), 'ike-gateway ' . $a . ': refused (' . $why . '), nothing written' );
}

// ---- IKE crypto profile
$P = "//ike-crypto-profiles/entry[@name='ike-a']";
list( $rc, $o ) = $cli( 'ike-profile', $dir . '/in.xml', $dir . '/p.xml', 'ike-a', 'encryption-set:aes-256-gcm|aes-128-cbc/hash-set:sha384/dh-group-set:group19|group20/lifetime-set:days,1/authentication-multiple-set:3' );
$eq( array( $rc, $x( $dir . '/p.xml', $P . "/encryption/member" ), $x( $dir . '/p.xml', $P . "/hash/member" ), $x( $dir . '/p.xml', $P . "/dh-group/member" ),
        $x( $dir . '/p.xml', $P . "/lifetime/*" ), count( $x( $dir . '/p.xml', $P . "/lifetime/days" ) ), $x( $dir . '/p.xml', $P . "/authentication-multiple" ) ),
    array( 0, array( 'aes-256-gcm', 'aes-128-cbc' ), array( 'sha384' ), array( 'group19', 'group20' ), array( '1' ), 1, array( '3' ) ),
    'ike-profile: encryption / hash / DH groups as members, lifetime (one unit), authentication multiple' );
list( $rc, $o ) = $cli( 'ike-profile', $dir . '/in.xml', $dir . '/bad.xml', 'ike-a', 'lifetime-set:seconds,60' );
$eq( array( strpos( $o, 'seconds 180-65535' ) !== FALSE, is_file( $dir . '/bad.xml' ) ), array( TRUE, FALSE ), 'ike-profile lifetime-set:seconds,60: refused (range)' );

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
$eq( array( strpos( $o, "IKE gateway 'gw-nope' not found" ) !== FALSE, is_file( $dir . '/bad.xml' ) ), array( TRUE, FALSE ), 'ipsec-tunnel ike-gateway-set: an unknown gateway is refused' );

exec( 'rm -rf ' . escapeshellarg( $dir ) );
print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( empty( $failed ) ? 0 : 1 );
