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
 * SCMLocalConfig (type=scm-ngfw-psk-list, scm-local-config-probe): firewalls of a tenant (pages), the URL of the
 * operations API found by trying, the newest version, download, IKE gateways and the PSK list (chmod 600).
 * A synthetic connector, synthetic configurations - no network.
 */
$repo = dirname( __DIR__ );
require_once $repo . '/lib/pan_php_framework.php';
require_once $repo . '/utils/develop/sase/scm/lib/SCMLocalConfig.php';

$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};

$c = new PanosCrypto();
$fwXml = '<config version="11.1.0"><devices><entry name="localhost.localdomain"><network><ike><gateway>'
    . '<entry name="gw-a"><protocol><version>ikev2</version></protocol><local-address><interface>ethernet1/1</interface><ip>198.51.100.1/24</ip></local-address>'
    . '<peer-address><ip>203.0.113.10</ip></peer-address><authentication><pre-shared-key><key>' . $c->encrypt( 'synthetic-psk-a' ) . '</key></pre-shared-key></authentication></entry>'
    . '<entry name="gw-b"><peer-address><dynamic/></peer-address><authentication><pre-shared-key><key>' . $c->encrypt( 'synthetic-psk-b', 'abcdefghijklmnop' ) . '</key></pre-shared-key></authentication></entry>'
    . '<entry name="gw-c"><peer-address><fqdn>peer.example.net</fqdn></peer-address><authentication><pre-shared-key><key>-AA==xyz</key></pre-shared-key></authentication></entry>'
    . '<entry name="gw-d"><authentication><certificate/></authentication></entry>'
    . '</gateway></ike></network></entry></devices></config>';

// the SCM API of a synthetic tenant: 3 firewalls on 2 pages (limit 200 -> test with total), the operations API under
// /config/operations/v1 with parameter device (the first tried URLs answer 404)
class FakeSCMConnector
{
    public $url_api = 'https://api.test';
    public $calls = array();
    public $xml;
    public function sendSCMAPIRequest( $method, $url, $body = false, $exitOnError = TRUE )
    {
        $this->calls[] = $method . ' ' . substr( $url, strlen( $this->url_api ) );
        $q = array(); parse_str( (string)parse_url( $url, PHP_URL_QUERY ), $q );
        $path = parse_url( $url, PHP_URL_PATH );
        $ans = function( $code, $json, $raw = null ) { return array( 'http_code' => $code, 'response' => $raw !== null ? $raw : json_encode( $json ), 'json' => $json, 'errors' => null ); };
        if( $path === '/config/setup/v1/devices' )
        {
            $all = array();
            for( $i = 1; $i <= 201; $i++ )
                $all[] = array( 'id' => sprintf( '0079%011d', $i ), 'serial_number' => sprintf( '0079%011d', $i ), 'display_name' => 'fw-' . $i, 'folder' => 'Branches', 'model' => 'PA-440', 'software_version' => '11.1.6' );
            return $ans( 200, array( 'data' => array_slice( $all, (int)$q['offset'], (int)$q['limit'] ), 'total' => count( $all ), 'limit' => (int)$q['limit'], 'offset' => (int)$q['offset'] ) );
        }
        if( $path !== '/config/operations/v1/local-config/versions' && $path !== '/config/operations/v1/local-config/download' || !isset( $q['device'] ) )
            return $ans( 404, array( '_errors' => array( array( 'message' => 'not found' ) ) ) );
        if( $path === '/config/operations/v1/local-config/versions' )
        {
            if( $q['device'] === '007900000000001' )
                return $ans( 200, array(
                    array( 'id' => 1, 'serial' => $q['device'], 'local_version' => '10', 'timestamp' => '2026-11-01T10:00:00Z', 'xfmed_version' => '1', 'md5' => 'x' ),
                    array( 'id' => 3, 'serial' => $q['device'], 'local_version' => '12', 'timestamp' => '2026-11-20T10:00:00Z', 'xfmed_version' => '3', 'md5' => 'y' ),
                    array( 'id' => 2, 'serial' => $q['device'], 'local_version' => '11', 'timestamp' => '2026-11-10T10:00:00Z', 'xfmed_version' => '2', 'md5' => 'z' ) ) );
            return $ans( 200, array() );
        }
        return $q['device'] === '007900000000001' && $q['version'] === '3' ? $ans( 200, null, $this->xml ) : $ans( 404, null, '' );
    }
}
$con = new FakeSCMConnector();
$con->xml = $fwXml;
$lc = new SCMLocalConfig( $con );
$log = array();
$lc->log = function( $l ) use ( &$log ) { $log[] = $l; };

$devices = $lc->devices();
$eq( array( count( $devices ), $devices[0]['serial'], $devices[0]['name'], $devices[200]['serial'], count( preg_grep( '#/config/setup/v1/devices#', $con->calls ) ) ),
    array( 201, '007900000000001', 'fw-1', '007900000000201', 2 ), 'devices(): every page of GET /config/setup/v1/devices (201 firewalls, 2 calls)' );

$versions = $lc->versions( '007900000000001' );
$eq( array( count( $versions ), $lc->found(), count( preg_grep( '#local-config/versions#', $con->calls ) ) ),
    array( 3, array( 'base' => 'https://api.test/config/operations/v1', 'param' => 'device' ), 3 ), 'versions(): the probable URLs tried until one answers 200' );
$eq( array( SCMLocalConfig::versionId( SCMLocalConfig::newest( $versions ) ), SCMLocalConfig::newest( array() ) ), array( '3', null ), 'newest(): the latest timestamp' );
$n = count( $con->calls );
$eq( array( $lc->versions( '007900000000002' ), count( $con->calls ) - $n ), array( array(), 1 ), 'versions(): the found URL is used for the next firewall (one call); no version: empty list' );

$xml = $lc->download( '007900000000001', '3' );
$eq( array( $xml === $fwXml, $lc->download( '007900000000001', '9' ) ), array( TRUE, null ), 'download(): the XML of the version; null on HTTP 404' );

$doc = new DOMDocument(); $doc->loadXML( $xml );
$gws = IKEPSKList::gateways( new DOMXPath( $doc ) );
$by = array_column( $gws, null, 'ike_gateway' );
$eq( array( count( $gws ), $by['gw-a']['psk_status'], $by['gw-a']['psk_current'], $by['gw-a']['peer_address'], $by['gw-a']['local_address'], $by['gw-a']['ike_version'],
        $by['gw-a']['psk_sha1'] === IKEPSKList::cleartextSha1( 'synthetic-psk-a' ) ),
    array( 4, 'default-master-key', 'synthetic-psk-a', '203.0.113.10', 'ethernet1/1 | 198.51.100.1/24', 'ikev2', TRUE ), 'gateways(): default master key - clear text, peer, local address, IKE version, SHA-1' );
$eq( array( $by['gw-b']['psk_status'], $by['gw-b']['psk_current'], $by['gw-b']['peer_address'], $by['gw-b']['psk_sha1'] === IKEPSKList::cleartextSha1( 'synthetic-psk-b' ),
        $by['gw-c']['psk_status'], $by['gw-c']['psk_prefix'], $by['gw-c']['peer_address'], $by['gw-d']['psk_status'] ),
    array( 'not-decryptable', '', 'dynamic', TRUE, 'other-format', '-AA==', 'peer.example.net', 'no-psk' ), 'gateways(): other master key (SHA-1 still known), other format, certificate' );
$by2 = array_column( IKEPSKList::gateways( new DOMXPath( $doc ), 'abcdefghijklmnop' ), null, 'ike_gateway' );
$eq( array( $by2['gw-a']['psk_status'], $by2['gw-b']['psk_status'], $by2['gw-b']['psk_current'] ), array( 'default-master-key', 'given-master-key', 'synthetic-psk-b' ),
    'gateways() master key: the default one first, then the given one' );
$lines = implode( "\n", array_map( array( 'IKEPSKList', 'gatewayLine' ), $gws ) ) . implode( "\n", $log );
$eq( strpos( $lines, 'synthetic-psk' ), FALSE, 'gatewayLine() / progress lines: no secret' );

$dir = sys_get_temp_dir() . '/ngfwpsk-' . getmypid();
@mkdir( $dir, 0700, TRUE );
$file = $dir . '/psk-list.csv';
$rows = IKEPSKList::writePSKList( $file, array( array( 'serial' => '007900000000001', 'firewall' => 'fw-1', 'config_version' => '3', 'config_timestamp' => '2026-11-20T10:00:00Z', 'gateways' => $gws ) ) );
$csv = array_map( function( $l ) { return str_getcsv( $l, ',', '"', '' ); }, file( $file, FILE_IGNORE_NEW_LINES ) );
$eq( array( $rows, decoct( fileperms( $file ) & 0777 ), $csv[0], array_slice( $csv[1], 0, 10 ), $csv[1][10] ),
    array( 4, '600', IKEPSKList::PSK_LIST_COLUMNS, array( '007900000000001', 'fw-1', '3', '2026-11-20T10:00:00Z', '', 'gw-a', '203.0.113.10', 'ethernet1/1 | 198.51.100.1/24', 'ikev2', 'default-master-key' ), 'synthetic-psk-a' ),
    'writePSKList(): one row per gateway, chmod 600, clear text only in this file' );

// in=<file.xml>: a configuration offline (here an SCM folder: the gateway below devices/entry/network of the folder),
// SHA-1 list without clear text, comparison with another list by gateway name and SHA-1
$scmXml = function( $gwB, $pskB ) use ( $c ) {
    return '<config><devices><entry name="localhost.localdomain"><container><entry name="Branches"><devices><entry name="localhost.localdomain"><network><ike><gateway>'
        . '<entry name="gw-a"><peer-address><ip>203.0.113.10</ip></peer-address><authentication><pre-shared-key><key>' . $c->encrypt( 'synthetic-psk-a' ) . '</key></pre-shared-key></authentication></entry>'
        . '<entry name="' . $gwB . '"><peer-address><ip>203.0.113.11</ip></peer-address><authentication><pre-shared-key><key>' . $c->encrypt( $pskB ) . '</key></pre-shared-key></authentication></entry>'
        . '<entry name="gw-cert"><authentication><certificate/></authentication></entry>'
        . '</gateway></ike></network></entry></devices></entry></container></entry></devices></config>';
};
file_put_contents( $dir . '/a.xml', $scmXml( 'gw-b', 'synthetic-psk-b' ) );
file_put_contents( $dir . '/b.xml', $scmXml( 'gw-c', 'synthetic-psk-b' ) );
file_put_contents( $dir . '/b2.xml', $scmXml( 'gw-b', 'synthetic-psk-b-new' ) );
$cli = function( array $args ) use ( $repo ) {
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' type=scm-ngfw-psk-list ' . implode( ' ', array_map( 'escapeshellarg', $args ) ) . ' 2>&1', $o, $rc );
    return array( $rc, implode( "\n", $o ) );
};
list( $rcA, $oA ) = $cli( array( 'in=' . $dir . '/a.xml', 'psk-list=' . $dir . '/.sensitive/a.csv', 'sha1-list=' . $dir . '/a-sha1.csv' ) );
$sha1 = (string)@file_get_contents( $dir . '/a-sha1.csv' );
$eq( array( $rcA, strpos( $oA, 'gw-a (container Branches)' ) !== FALSE, strpos( $oA, 'synthetic' ), decoct( fileperms( $dir . '/.sensitive/a.csv' ) & 0777 ),
        strpos( (string)file_get_contents( $dir . '/.sensitive/a.csv' ), 'synthetic-psk-a' ) !== FALSE, strpos( $sha1, 'synthetic' ), strpos( $sha1, IKEPSKList::cleartextSha1( 'synthetic-psk-a' ) ) !== FALSE,
        strpos( $sha1, 'psk_current' ) ),
    array( 0, TRUE, FALSE, '600', TRUE, FALSE, TRUE, FALSE ),
    'in=<file.xml>: gateways of an SCM folder (location), PSK list chmod 600 with clear text, SHA-1 list without, output without secret' );
list( $rcB, $oB ) = $cli( array( 'in=' . $dir . '/b.xml', 'compare=' . $dir . '/a-sha1.csv', 'compare-out=' . $dir . '/cmp.csv' ) );
list( $rcB2, $oB2 ) = $cli( array( 'in=' . $dir . '/b2.xml', 'compare=' . $dir . '/.sensitive/a.csv' ) );
$cmp = array_column( array_map( function( $l ) { return str_getcsv( $l, ',', '"', '' ); }, array_slice( file( $dir . '/cmp.csv', FILE_IGNORE_NEW_LINES ), 1 ) ), 1, 0 );
$eq( array( $rcB, $cmp, strpos( (string)file_get_contents( $dir . '/cmp.csv' ), 'synthetic' ), strpos( $oB, '1 same, 0 different, 1 only in a, 1 only in b, 1 unknown' ) !== FALSE,
        $rcB2, strpos( $oB2, '1 same, 1 different, 0 only in a, 0 only in b, 1 unknown' ) !== FALSE, strpos( $oB2, 'synthetic' ) ),
    array( 0, array( 'gw-a' => 'same', 'gw-b' => 'only-a', 'gw-c' => 'only-b', 'gw-cert' => 'unknown' ), FALSE, TRUE, 0, TRUE, FALSE ),
    'compare=: by gateway name and SHA-1 (same / different / only in a / only in b / unknown); a PSK list as input is read without its clear text' );
$eq( array( IKEPSKList::compare( array( array( 'ike_gateway' => 'x', 'psk_sha1' => 'S1' ), array( 'ike_gateway' => 'x', 'psk_sha1' => 'S2' ) ), array( array( 'ike_gateway' => 'x', 'psk_sha1' => 'S1' ) ) )[0]['result'],
        IKEPSKList::compare( array( array( 'ike_gateway' => 'x', 'psk_sha1' => 'S1', 'firewall' => 'fw-1', 'serial' => '0079', 'location' => 'vsys vsys1' ) ), array( array( 'ike_gateway' => 'x', 'psk_sha1' => 'S1' ) ) )[0]['a_where'] ),
    array( 'different', 'fw-1 (0079) / vsys vsys1' ), 'compare(): a name with two different keys on one side is different; where = firewall (serial) / location' );

// pan-os-php type=scm-ngfw-psk-list reaches the script
exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' type=scm-ngfw-psk-list help 2>&1', $out, $rc );
$o = implode( "\n", $out );
$eq( array( strpos( $o, 'scm_ngfw_psk_list.php in=scm-api://' ) !== FALSE, strpos( $o, 'psk-list=' ) !== FALSE, strpos( $o, 'Actions=action' ) !== FALSE ),
    array( TRUE, TRUE, FALSE ), 'pan-os-php type=scm-ngfw-psk-list help: help of the script' );

exec( 'rm -rf ' . escapeshellarg( $dir ) );
print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( empty( $failed ) ? 0 : 1 );
