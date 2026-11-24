<?php
/**
 * type=scm-export-xml: the IKE / IPsec objects of the NGFW folders (/config/network/v1: IKE / IPsec crypto profiles,
 * tunnel interfaces, IKE gateways, IPsec tunnels) into <network> of the XML, as on a firewall - before, the export had
 * them as JSON but the XML not. Below devices/entry[@name='localhost.localdomain']/network of the folder, where SCM keeps
 * it; the loaders read that place (before: only <network> directly below the folder). Synthetic export, no customer data.
 *
 *   php tests/test_scm_export_network.php
 */
$repo = dirname( __DIR__ );
require_once $repo . '/lib/pan_php_framework.php';

$dir = sys_get_temp_dir() . '/scmnet-' . getmypid();
$exp = $dir . '/1234567890/20261124-010000';
@mkdir( $exp . '/config', 0700, TRUE );
file_put_contents( $exp . '/manifest.json', json_encode( array( 'tsg_id' => '1234567890', 'areas' => array( 'config' ) ) ) );
file_put_contents( $exp . '/config/01_folders.json', json_encode( array( 'data' => array(
    array( 'id' => 'f1', 'name' => 'All', 'parent' => '', 'type' => 'container', 'display_name' => 'Global' ),
    array( 'id' => 'f2', 'name' => 'ngfw-shared', 'parent' => 'All', 'type' => 'container' ),
    array( 'id' => 'f3', 'name' => 'Branches', 'parent' => 'ngfw-shared', 'type' => 'container' ) ) ) ) );
file_put_contents( $exp . '/config/02_snippets.json', json_encode( array( 'data' => array() ) ) );
file_put_contents( $exp . '/config/03_devices.json', json_encode( array( 'data' => array() ) ) );
$put = function( $container, $file, $data ) use ( $exp ) {
    $d = $exp . '/config/folders/' . preg_replace( '/[^A-Za-z0-9._-]+/', '_', $container );
    if( !is_dir( $d ) ) mkdir( $d, 0700, TRUE );
    file_put_contents( $d . '/' . $file, json_encode( array( 'container' => $container, 'data' => $data ) ) );
};
$crypto = new PanosCrypto();
$psk = $crypto->encrypt( 'synthetic-branch-psk' );
$put( 'Branches', '50_ike-crypto-profiles.json', array(
    array( 'id' => 'c1', 'name' => 'ike-p1', 'folder' => 'Branches', 'encryption' => array( 'aes-256-cbc' ), 'hash' => array( 'sha256' ),
        'dh_group' => array( 'group14' ), 'lifetime' => array( 'hours' => 8 ) ) ) );
$put( 'Branches', '51_ipsec-crypto-profiles.json', array(
    array( 'id' => 'c2', 'name' => 'ipsec-p2', 'folder' => 'Branches', 'esp' => array( 'encryption' => array( 'aes-256-gcm' ), 'authentication' => array( 'none' ) ),
        'dh_group' => 'group14', 'lifetime' => array( 'hours' => 1 ) ) ) );
$put( 'Branches', '41_tunnel-interfaces.json', array(
    array( 'id' => 't1', 'name' => 'tunnel.1', 'folder' => 'Branches', 'ip' => array( '169.254.0.1/30' ), 'mtu' => 1400, 'comment' => 'to branch' ),
    array( 'id' => 't2', 'name' => 'tunnel.2', 'folder' => 'Branches', 'ip' => array( array( 'name' => '169.254.0.5/30' ) ) ) ) );
$put( 'Branches', '52_ike-gateways.json', array(
    array( 'id' => 'g1', 'name' => 'gw-branch', 'folder' => 'Branches', 'authentication' => array( 'pre_shared_key' => array( 'key' => $psk ) ),
        'peer_address' => array( 'ip' => '203.0.113.10' ), 'local_address' => array( 'interface' => 'ethernet1/1' ),
        'peer_id' => array( 'type' => 'ipaddr', 'id' => '203.0.113.10' ),
        'protocol' => array( 'version' => 'ikev2', 'ikev2' => array( 'ike_crypto_profile' => 'ike-p1', 'dpd' => array( 'enable' => TRUE ) ) ),
        'protocol_common' => array( 'nat_traversal' => array( 'enable' => TRUE ), 'fragmentation' => array( 'enable' => FALSE ) ) ),
    array( 'id' => 'g2', 'name' => 'gw-dynamic', 'folder' => 'Branches', 'authentication' => array( 'pre_shared_key' => array( 'key' => $psk ) ),
        'peer_address' => array( 'dynamic' => array() ), 'protocol' => array( 'version' => 'ikev1', 'ikev1' => array( 'ike_crypto_profile' => 'ike-p1' ) ) ),
    // an object of another folder in the answer (the API returns the parents too): not in Branches
    array( 'id' => 'g3', 'name' => 'gw-parent', 'folder' => 'ngfw-shared', 'peer_address' => array( 'fqdn' => 'peer.example.net' ),
        'protocol' => array( 'version' => 'ikev2' ) ) ) );
$put( 'Branches', '53_ipsec-tunnels.json', array(
    array( 'id' => 'p1', 'name' => 'tun-branch', 'folder' => 'Branches', 'tunnel_interface' => 'tunnel.1', 'anti_replay' => TRUE,
        'auto_key' => array( 'ike_gateway' => array( array( 'name' => 'gw-branch' ) ), 'ipsec_crypto_profile' => 'ipsec-p2',
            'proxy_id' => array( array( 'name' => 'pid1', 'local' => '10.0.0.0/24', 'remote' => '10.1.0.0/24', 'protocol' => array( 'any' => array() ) ) ) ) ) ) );

$out = $dir . '/out.xml';
exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' type=scm-export-xml ' . escapeshellarg( 'in=scm-export://' . $dir . '/1234567890' )
    . ' ' . escapeshellarg( 'out=' . $out ) . ' 2>&1', $lines, $rc );

$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};
$doc = new DOMDocument();
$loaded = is_file( $out ) && $doc->loadXML( (string)file_get_contents( $out ) );
$eq( array( $rc, $loaded ), array( 0, TRUE ), 'the conversion runs through' );
$xp = new DOMXPath( $doc );
$net = "//container/entry[@name='Branches']/devices/entry[@name='localhost.localdomain']/network";
$s = function( $q ) use ( $xp, $net ) { return trim( (string)$xp->evaluate( 'string(' . $net . $q . ')' ) ); };
$n = function( $q ) use ( $xp, $net ) { return $xp->query( $net . $q )->length; };

$eq( array( $s( "/ike/crypto-profiles/ike-crypto-profiles/entry[@name='ike-p1']/encryption/member" ), $s( "/ike/crypto-profiles/ike-crypto-profiles/entry[@name='ike-p1']/dh-group/member" ),
        $s( "/ike/crypto-profiles/ike-crypto-profiles/entry[@name='ike-p1']/lifetime/hours" ) ),
    array( 'aes-256-cbc', 'group14', '8' ), 'IKE crypto profile: ike/crypto-profiles/ike-crypto-profiles, lists as <member>' );
$eq( array( $s( "/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name='ipsec-p2']/esp/encryption/member" ), $s( "/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name='ipsec-p2']/dh-group" ) ),
    array( 'aes-256-gcm', 'group14' ), 'IPsec crypto profile: ike/crypto-profiles/ipsec-crypto-profiles' );
$eq( array( $n( "/interface/tunnel/units/entry[@name='tunnel.1']/ip/entry[@name='169.254.0.1/30']" ), $s( "/interface/tunnel/units/entry[@name='tunnel.1']/mtu" ),
        $n( "/interface/tunnel/units/entry[@name='tunnel.2']/ip/entry[@name='169.254.0.5/30']" ) ),
    array( 1, '1400', 1 ), 'tunnel interfaces: interface/tunnel/units, IP as <entry name> (SCM: list of texts or of objects)' );
$g = "/ike/gateway/entry[@name='gw-branch']";
$eq( array( $s( $g . "/authentication/pre-shared-key/key" ) === $psk, $s( $g . "/peer-address/ip" ), $s( $g . "/local-address/interface" ), $s( $g . "/protocol/version" ),
        $s( $g . "/protocol/ikev2/ike-crypto-profile" ), $s( $g . "/protocol/ikev2/dpd/enable" ), $s( $g . "/protocol-common/fragmentation/enable" ), $s( $g . "/peer-id/id" ),
        $n( "/ike/gateway/entry[@name='gw-dynamic']/peer-address/dynamic" ), $n( "/ike/gateway/entry[@name='gw-parent']" ), $n( $g . "/@uuid|" . $net . $g . "/id|" . $net . $g . "/folder" ) ),
    array( TRUE, '203.0.113.10', 'ethernet1/1', 'ikev2', 'ike-p1', 'yes', 'no', '203.0.113.10', 1, 0, 0 ),
    'IKE gateways: ike/gateway, the pre-shared key as given (encrypted), yes / no, dynamic peer; an object of another folder not here; no id / folder' );
$t = "/tunnel/ipsec/entry[@name='tun-branch']";
$eq( array( $s( $t . "/tunnel-interface" ), $n( $t . "/auto-key/ike-gateway/entry[@name='gw-branch']" ), $s( $t . "/auto-key/ipsec-crypto-profile" ),
        $s( $t . "/auto-key/proxy-id/entry[@name='pid1']/remote" ), $s( $t . "/anti-replay" ) ),
    array( 'tunnel.1', 1, 'ipsec-p2', '10.1.0.0/24', 'yes' ), 'IPsec tunnels: tunnel/ipsec, gateway list as <entry name>, proxy IDs' );

// the loader reads it as on a firewall
$pan = new BuckbeakConf();
PH::$shadow_scm_no_internal_api = TRUE;
ob_start();
$pan->load_from_file( $out );
ob_end_clean();
$sub = $pan->findContainer( 'Branches' );
$gw = $sub !== null ? $sub->network->ikeGatewayStore->findIKEGateway( 'gw-branch' ) : null;
$tun = $sub !== null ? $sub->network->ipsecTunnelStore->findIPsecTunnel( 'tun-branch' ) : null;
$eq( array( $sub !== null, $gw !== null, $tun !== null, $sub !== null ? count( $sub->network->ikeGatewayStore->gateways() ) : -1,
        $sub !== null && $sub->network->ikeCryptoProfileStore->findIkeCryptoProfil( 'ike-p1' ) !== null,
        $sub !== null && $sub->network->ipsecCryptoProfileStore->findIpsecCryptoProfil( 'ipsec-p2' ) !== null ),
    array( TRUE, TRUE, TRUE, 2, TRUE, TRUE ), 'BuckbeakConf loads the XML: gateways, tunnel, crypto profiles of the folder Branches' );
$all = $pan->findContainer( 'All' );
$eq( array( $n( '' ), $xp->query( "//container/entry[@name='Branches']/network" )->length, $all !== null && count( $all->network->ikeCryptoProfileStore->ikeCryptoProfil() ) > 0 ),
    array( 1, 0, TRUE ), 'the network part where SCM keeps it (devices/entry[@name=localhost.localdomain]/network) - read by the loader, also the one of the base configuration (All)' );

if( !getenv( 'KEEP' ) ) exec( 'rm -rf ' . escapeshellarg( $dir ) );
print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
if( count( $failed ) ) { print implode( "\n", array_slice( $lines, -15 ) ) . "\n"; exit( 1 ); }
exit( 0 );
