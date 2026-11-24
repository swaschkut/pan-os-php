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
 * GET /local-config/versions, GET /local-config/download).
 *
 * One implementation for scm_local_config_probe.php, scm_ngfw_psk_list.php (and the config viewer, which runs them);
 * the IKE gateways / pre-shared keys of a configuration: IKEPSKList. Nothing here prints or logs a secret.
 */
class SCMLocalConfig
{
    /** the base URL of the operations API is not documented (only the paths): the probable ones, in this order */
    const BASE_PATHS = array( '/config/ngfw-operations/v1', '/config/operations/v1', '/operations/v1', '/config/device-operations/v1' );
    const SERIAL_PARAMS = array( 'device', 'serial' );

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
}
