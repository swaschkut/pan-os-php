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
 * Read only: the configuration of the firewalls managed by Strata Cloud Manager (SCM NGFW operations API
 * GET /local-config/versions, GET /local-config/download) and the pre-shared keys of their IKE gateways.
 *
 * One implementation for scm_local_config_probe.php, scm_ngfw_psk_list.php (and the config viewer, which runs them).
 * Nothing here prints or logs a secret: the clear text of a pre-shared key is only returned (gateways()) and written by
 * writePSKList() into a file with chmod 600.
 */
require_once(dirname(__FILE__) . "/SCMPrismaAccessExport.php");

class SCMLocalConfig
{
    /** the base URL of the operations API is not documented (only the paths): the probable ones, in this order */
    const BASE_PATHS = array( '/config/ngfw-operations/v1', '/config/operations/v1', '/operations/v1', '/config/device-operations/v1' );
    const SERIAL_PARAMS = array( 'device', 'serial' );

    const PSK_LIST_COLUMNS = array( 'serial', 'firewall', 'config_version', 'config_timestamp', 'location', 'ike_gateway',
        'peer_address', 'local_address', 'ike_version', 'psk_status', 'psk_current', 'psk_sha1' );

    /** psk_status of a gateway */
    const PSK_DEFAULT = 'default-master-key';
    const PSK_GIVEN = 'given-master-key';
    const PSK_NOT_DECRYPTABLE = 'not-decryptable';
    const PSK_OTHER_FORMAT = 'other-format';
    const PSK_NONE = 'no-psk';

    /** @var object PanSCMAPIConnector (or an object with sendSCMAPIRequest() and $url_api) */
    private $connector;
    private $api;
    private $bases;
    /** @var array|null ['base' => url, 'param' => name] once an answer 200 was found */
    private $found = null;
    /** @var callable|null function( string $line ) - progress lines (URLs tried, HTTP codes; never a secret) */
    public $log = null;

    public function __construct( $connector, ?string $base = null )
    {
        $this->connector = $connector;
        $this->api = rtrim( (string)$connector->url_api, "/" );
        $this->bases = $base !== null && $base !== '' ? array( rtrim($base, "/") )
            : array_map( function( $p ) { return $this->api . $p; }, self::BASE_PATHS );
    }

    private function log( string $line ): void
    {
        if( $this->log !== null )
            call_user_func( $this->log, $line );
    }

    private function get( string $url ): array
    {
        return $this->connector->sendSCMAPIRequest( "GET", $url, false, FALSE );
    }

    /** the base URL / parameter name the API answered with (null: none yet) */
    public function found(): ?array
    {
        return $this->found;
    }

    /**
     * the firewalls of the tenant (GET /config/setup/v1/devices, all pages)
     * @return array of ['serial', 'name', 'folder', 'model', 'software_version', 'connected']
     */
    public function devices(): array
    {
        $out = array();
        $limit = 200;
        for( $offset = 0; ; $offset += $limit )
        {
            $r = $this->get( $this->api . "/config/setup/v1/devices?limit=" . $limit . "&offset=" . $offset );
            if( $r['http_code'] != 200 )
                throw new Exception( "GET /config/setup/v1/devices: HTTP " . $r['http_code'] );
            $page = PanSCMAPIConnector::listOfAnswer( $r['json'] );
            $list = $page !== null ? $page['list'] : array();
            foreach( $list as $d )
            {
                $serial = (string)( $d['serial_number'] ?? $d['id'] ?? '' );
                if( $serial === '' )
                    continue;
                $out[$serial] = array( 'serial' => $serial, 'name' => (string)( $d['display_name'] ?? $d['name'] ?? $d['hostname'] ?? '' ),
                    'folder' => (string)( $d['folder'] ?? '' ), 'model' => (string)( $d['model'] ?? '' ),
                    'software_version' => (string)( $d['software_version'] ?? $d['sw_version'] ?? '' ),
                    'connected' => isset($d['is_connected']) ? (bool)$d['is_connected'] : null );
            }
            $total = $page !== null ? $page['total'] : null;
            if( count($list) < $limit || ( $total !== null && $offset + $limit >= $total ) )
                break;
        }
        ksort( $out );
        return array_values( $out );
    }

    /**
     * the configuration versions of a firewall; the first call tries the probable base URLs / parameter names
     * @return array|null the versions (may be empty), null when no URL answered 200
     */
    public function versions( string $serial ): ?array
    {
        $candidates = array();
        if( $this->found !== null )
            $candidates[] = $this->found;
        foreach( $this->bases as $base )
            foreach( self::SERIAL_PARAMS as $param )
                if( $this->found === null )
                    $candidates[] = array( 'base' => $base, 'param' => $param );

        foreach( $candidates as $c )
        {
            $url = $c['base'] . "/local-config/versions?" . $c['param'] . "=" . rawurlencode($serial);
            $r = $this->get( $url );
            $this->log( "GET " . ( strpos($url, $this->api) === 0 ? substr($url, strlen($this->api)) : $url ) . ": HTTP " . $r['http_code'] );
            if( $r['http_code'] == 200 && is_array($r['json']) )
            {
                $this->found = $c;
                $page = PanSCMAPIConnector::listOfAnswer( $r['json'] );
                return $page !== null ? $page['list'] : array();
            }
        }
        return null;
    }

    /** the newest version: latest timestamp, then highest id */
    public static function newest( array $versions ): ?array
    {
        if( empty($versions) )
            return null;
        usort( $versions, function( $a, $b ) {
            return strcmp( (string)( $b['timestamp'] ?? '' ), (string)( $a['timestamp'] ?? '' ) ) ?: ( (int)( $b['id'] ?? 0 ) <=> (int)( $a['id'] ?? 0 ) );
        } );
        return $versions[0];
    }

    /** the id to download a version with */
    public static function versionId( array $version ): string
    {
        return (string)( $version['id'] ?? $version['local_version'] ?? '' );
    }

    /** the XML of one version (after versions() found the URL); null on error */
    public function download( string $serial, string $version ): ?string
    {
        if( $this->found === null && $this->versions($serial) === null )
            return null;
        $url = $this->found['base'] . "/local-config/download?" . $this->found['param'] . "=" . rawurlencode($serial) . "&version=" . rawurlencode($version);
        $r = $this->get( $url );
        $this->log( "GET " . ( strpos($url, $this->api) === 0 ? substr($url, strlen($this->api)) : $url ) . ": HTTP " . $r['http_code'] . ", " . strlen((string)$r['response']) . " bytes" );
        if( $r['http_code'] != 200 || !is_string($r['response']) || $r['response'] === '' )
            return null;
        return $r['response'];
    }

    /**
     * the IKE gateways of a configuration
     * @return array of ['location', 'ike_gateway', 'peer_address', 'local_address', 'ike_version', 'psk_status',
     *               'psk_current' (clear text, only when decrypted), 'psk_sha1' (base64 SHA-1 of the clear text, from the
     *               encrypted value - also when it can not be decrypted), 'psk_prefix' (first 5 characters of the encrypted
 *               value: its format)]
     */
    public static function gateways( DOMXPath $xp, ?string $masterKey = null ): array
    {
        $crypto = new PanosCrypto();
        $out = array();
        foreach( $xp->query("//network/ike/gateway/entry") as $gw )
        {
            $where = $xp->query("ancestor::entry[parent::vsys or parent::template or parent::device-group]", $gw)->item(0);
            $peer = array();
            foreach( $xp->query("peer-address/ip|peer-address/fqdn", $gw) as $n )
                $peer[] = trim($n->textContent);
            if( empty($peer) && $xp->query("peer-address/dynamic", $gw)->length > 0 )
                $peer[] = 'dynamic';
            $local = array();
            foreach( $xp->query("local-address/interface|local-address/ip", $gw) as $n )
                $local[] = trim($n->textContent);
            $ver = $xp->query("protocol/version", $gw)->item(0);

            $row = array( 'location' => $where !== null ? $where->parentNode->nodeName . " " . $where->getAttribute('name') : '',
                'ike_gateway' => $gw->getAttribute('name'), 'peer_address' => implode(" | ", $peer), 'local_address' => implode(" | ", $local),
                'ike_version' => $ver !== null ? trim($ver->textContent) : '', 'psk_status' => self::PSK_NONE, 'psk_current' => '', 'psk_sha1' => '', 'psk_prefix' => '' );

            $key = $xp->query("authentication/pre-shared-key/key", $gw)->item(0);
            if( $key !== null )
            {
                $value = trim($key->textContent);
                $row['psk_prefix'] = substr($value, 0, 5);
                if( strpos($value, "-AQ==") !== 0 )
                    $row['psk_status'] = self::PSK_OTHER_FORMAT;
                else
                {
                    $sha1 = SCMPrismaAccessExport::encryptedSha1( $value );
                    $row['psk_sha1'] = $sha1 !== null ? $sha1 : '';
                    // PanosCrypto::decrypt(): '' when the key does not fit (the SHA-1 in the value is checked)
                    $clear = $crypto->decrypt( $value, null );
                    $status = self::PSK_DEFAULT;
                    if( $clear === '' && $masterKey !== null )
                    {
                        $clear = $crypto->decrypt( $value, $masterKey );
                        $status = self::PSK_GIVEN;
                    }
                    if( $clear === '' )
                        $status = self::PSK_NOT_DECRYPTABLE;
                    $row['psk_status'] = $status;
                    $row['psk_current'] = $clear;
                }
            }
            $out[] = $row;
        }
        return $out;
    }

    /** a gateway for an output line: never the clear text */
    public static function gatewayLine( array $g ): string
    {
        $text = array( self::PSK_DEFAULT => 'decryptable with the DEFAULT master key', self::PSK_GIVEN => 'decryptable with the given master key',
            self::PSK_NOT_DECRYPTABLE => 'NOT decryptable', self::PSK_OTHER_FORMAT => 'other format - not readable by pan-os-php',
            self::PSK_NONE => 'no pre-shared key' );
        return $g['ike_gateway'] . ( $g['location'] !== '' ? " (" . $g['location'] . ")" : "" )
            . ( $g['peer_address'] !== '' ? "  peer " . $g['peer_address'] : "" ) . ": " . $text[$g['psk_status']];
    }

    /** opens a file for secrets: created with chmod 600 */
    public static function openSecretFile( string $file )
    {
        $old = umask(0077);
        $fh = @fopen( $file, "w" );
        umask($old);
        if( $fh === false )
            throw new Exception( "not possible to write " . $file );
        chmod( $file, 0600 );
        return $fh;
    }

    /**
     * the PSK list: one row per IKE gateway of every firewall, the clear text when decrypted (chmod 600)
     * @param array $firewalls of ['serial', 'firewall', 'config_version', 'config_timestamp', 'gateways' => gateways()]
     */
    public static function writePSKList( string $file, array $firewalls ): int
    {
        $fh = self::openSecretFile( $file );
        fputcsv( $fh, self::PSK_LIST_COLUMNS, ',', '"', '' );
        $n = 0;
        foreach( $firewalls as $fw )
            foreach( $fw['gateways'] as $g )
            {
                $line = array();
                foreach( self::PSK_LIST_COLUMNS as $col )
                    $line[] = (string)( array_key_exists($col, $g) ? $g[$col] : ( $fw[$col] ?? '' ) );
                fputcsv( $fh, $line, ',', '"', '' );
                $n++;
            }
        fclose( $fh );
        return $n;
    }
}
