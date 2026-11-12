<?php
/**
 * ISC License
 *
 * Copyright (c) 2024, Sven Waschkut - pan-os-php@waschkut.net
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
 * Export of all Prisma Access Remote Network (RN / RN-SPN) related configuration of one tenant (TSG)
 * into a local directory:
 *
 *   <outdir>/<TSG>/<YYYYmmdd-HHMMSS>/
 *       manifest.json
 *       01_ike-crypto-profiles.json
 *       02_ipsec-crypto-profiles.json
 *       03_ike-gateways.json
 *       04_ipsec-tunnels.json
 *       05_bandwidth-allocations.json
 *       06_remote-networks.json
 *       90_locations.json             (context)
 *       91_bgp-routing.json           (context)
 *       92_egress-ip.json             (optional, egress-IP API)
 *       ip-mapping.json / ip-mapping.csv
 *
 * The numbered "dependency" endpoints are listed in import order: an entry only references entries with a lower number.
 * Every file keeps the unmodified API data; normalisation happens later in compare/import.
 */
class SCMRemoteNetworkExport
{
    const FORMAT_VERSION = 1;

    /** @var PanSCMAPIConnector */
    public $connector;

    public $tsg;
    public $folder = "Remote Networks";
    public $baseDir;
    public $exportDir;

    /** @var array endpoint result per endpoint name: ['meta' => ..., 'data' => ...] */
    public $results = array();
    public $manifest = array();

    public function __construct( $connector, $tsg, $baseDir, $folder = "Remote Networks" )
    {
        $this->connector = $connector;
        $this->tsg = $tsg;
        $this->baseDir = rtrim($baseDir, "/\\");
        $this->folder = $folder;
    }

    /**
     * ordered endpoint list - order == import order for 'dependency' entries
     */
    public function getEndpoints()
    {
        $f = $this->folder;

        return array(
            array( 'order' => 1, 'name' => 'ike-crypto-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => "/config/network/v1/ike-crypto-profiles?folder=" . $f, 'depends_on' => array() ),
            array( 'order' => 2, 'name' => 'ipsec-crypto-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => "/config/network/v1/ipsec-crypto-profiles?folder=" . $f, 'depends_on' => array() ),
            array( 'order' => 3, 'name' => 'ike-gateways', 'category' => 'dependency', 'scope' => 'folder', 'url' => "/config/network/v1/ike-gateways?folder=" . $f, 'depends_on' => array('ike-crypto-profiles') ),
            array( 'order' => 4, 'name' => 'ipsec-tunnels', 'category' => 'dependency', 'scope' => 'folder', 'url' => "/config/network/v1/ipsec-tunnels?folder=" . $f, 'depends_on' => array('ike-gateways', 'ipsec-crypto-profiles') ),
            array( 'order' => 5, 'name' => 'bandwidth-allocations', 'category' => 'dependency', 'scope' => 'tenant', 'url' => "/config/deployment/v1/bandwidth-allocations", 'depends_on' => array() ),
            array( 'order' => 6, 'name' => 'remote-networks', 'category' => 'dependency', 'scope' => 'tenant', 'url' => "/config/deployment/v1/remote-networks", 'depends_on' => array('ipsec-tunnels', 'bandwidth-allocations') ),

            array( 'order' => 90, 'name' => 'locations', 'category' => 'context', 'scope' => 'tenant', 'url' => "/config/deployment/v1/locations", 'depends_on' => array() ),
            array( 'order' => 91, 'name' => 'bgp-routing', 'category' => 'context', 'scope' => 'tenant', 'url' => "/config/deployment/v1/bgp-routing", 'depends_on' => array() ),
        );
    }

    public function prepareDirectory( $timestamp = null )
    {
        if( $timestamp === null )
            $timestamp = date('Ymd-His');

        $this->exportDir = $this->baseDir . "/" . $this->tsg . "/" . $timestamp;
        if( !is_dir($this->exportDir) && !mkdir($this->exportDir, 0700, TRUE) )
            derr("not possible to create export directory: " . $this->exportDir, null, FALSE);

        return $this->exportDir;
    }

    public static function fileName( $endpoint )
    {
        return sprintf("%02d", $endpoint['order']) . "_" . $endpoint['name'] . ".json";
    }

    public function exportEndpoints()
    {
        foreach( $this->getEndpoints() as $endpoint )
        {
            PH::print_stdout( " - [" . sprintf("%02d", $endpoint['order']) . "] " . $endpoint['name'] . " ... " );

            $result = $this->connector->getSCMResourceAll( $endpoint['url'] );

            $meta = $endpoint;
            $meta['file'] = self::fileName($endpoint);
            $meta['http_code'] = $result['http_code'];
            $meta['fetched_at'] = date('c');

            if( $result['errors'] !== null )
            {
                $meta['status'] = 'error';
                $meta['count'] = null;
                $meta['error'] = self::errorMessage($result['errors']);
                PH::print_stdout( "     x ERROR: " . $meta['error'] );
            }
            else
            {
                $meta['status'] = 'ok';
                $meta['count'] = $result['is_list'] ? count($result['data']) : 1;
                $meta['is_list'] = $result['is_list'];
                PH::print_stdout( "     " . $meta['count'] . " entr" . ($meta['count'] == 1 ? "y" : "ies") );
            }

            $fileContent = array(
                'endpoint' => $endpoint['name'],
                'url' => $endpoint['url'],
                'tsg_id' => $this->tsg,
                'fetched_at' => $meta['fetched_at'],
                'http_code' => $result['http_code'],
                'status' => $meta['status'],
                'error' => isset($meta['error']) ? $result['errors'] : null,
                'data' => $result['data'],
            );
            $this->writeJson( $meta['file'], $fileContent );

            $this->results[$endpoint['name']] = array( 'meta' => $meta, 'data' => $result['data'] );
        }
    }

    /**
     * @param string|null $apiKey egress-IP API key; null = skip
     */
    public function exportEgressIP( $apiKey, $environment = "prod" )
    {
        $meta = array( 'order' => 92, 'name' => 'egress-ip', 'category' => 'context', 'scope' => 'tenant',
            'url' => 'getPrismaAccessIP/v2', 'depends_on' => array(), 'file' => '92_egress-ip.json' );

        if( $apiKey === null )
        {
            $meta['status'] = 'skipped';
            $this->results['egress-ip'] = array( 'meta' => $meta, 'data' => null );
            return;
        }

        PH::print_stdout( " - [92] egress-ip (serviceType=remote_network) ... " );
        $result = $this->connector->getPrismaAccessEgressIP( $apiKey, "remote_network", "all", "all", $environment );

        $meta['url'] = $result['url'];
        $meta['http_code'] = $result['http_code'];
        $meta['fetched_at'] = date('c');
        if( $result['errors'] !== null )
        {
            $meta['status'] = 'error';
            $meta['error'] = self::errorMessage($result['errors']);
            PH::print_stdout( "     x ERROR: " . $meta['error'] );
            $data = null;
        }
        else
        {
            $meta['status'] = 'ok';
            $data = isset($result['json']['result']) ? $result['json']['result'] : array();
            $meta['count'] = count($data);
            PH::print_stdout( "     " . $meta['count'] . " location(s)" );
        }

        $this->writeJson( $meta['file'], array(
            'endpoint' => 'egress-ip', 'url' => $meta['url'], 'tsg_id' => $this->tsg, 'fetched_at' => $meta['fetched_at'],
            'http_code' => $meta['http_code'], 'status' => $meta['status'],
            'error' => $result['errors'], 'data' => $data ) );

        $this->results['egress-ip'] = array( 'meta' => $meta, 'data' => $data );
    }

    /**
     * one row per Remote Network: Prisma side (service IP / FQDN / egress), branch side (IKE peer, BGP peer)
     */
    public function buildIPMapping()
    {
        $rns = $this->listData('remote-networks');
        $tunnels = self::indexByName( $this->listData('ipsec-tunnels') );
        $gateways = self::indexByName( $this->listData('ike-gateways') );
        $locations = $this->listData('locations');
        $egress = $this->listData('egress-ip');

        //egress result is per zone (display name of a location)
        $egressByZone = array();
        foreach( $egress as $zoneEntry )
        {
            if( isset($zoneEntry['zone']) )
                $egressByZone[$zoneEntry['zone']] = $zoneEntry;
        }

        $rows = array();
        foreach( $rns as $rn )
        {
            $row = array(
                'remote_network' => self::get($rn, 'name'),
                'region' => self::get($rn, 'region'),
                'spn_name' => self::get($rn, 'spn_name'),
                'license_type' => self::get($rn, 'license_type'),
                'ipsec_tunnel' => self::get($rn, 'ipsec_tunnel'),
                'secondary_ipsec_tunnel' => self::get($rn, 'secondary_ipsec_tunnel'),
                'service_ip_address' => self::get($rn, 'details.service_ip_address'),
                'fqdn' => self::get($rn, 'details.fqdn'),
                'loopback_ip_address' => self::get($rn, 'details.loopback_ip_address'),
                'bgp_enabled' => self::get($rn, 'protocol.bgp.enable'),
                'bgp_peer_ip_address' => self::get($rn, 'protocol.bgp.peer_ip_address'),
                'bgp_peer_as' => self::get($rn, 'protocol.bgp.peer_as'),
                'bgp_local_ip_address' => self::get($rn, 'protocol.bgp.local_ip_address'),
                'branch_peer_address' => array(),
                'location_display' => null,
                'egress_ip_addresses' => array(),
                'egress_match' => 'none',
            );

            //branch side: RN -> ipsec tunnel(s) -> ike gateway(s) -> peer_address
            foreach( array($row['ipsec_tunnel'], $row['secondary_ipsec_tunnel']) as $tunnelName )
            {
                if( $tunnelName === null || !isset($tunnels[$tunnelName]) )
                    continue;
                $gwList = self::get($tunnels[$tunnelName], 'auto_key.ike_gateway');
                if( !is_array($gwList) )
                    continue;
                foreach( $gwList as $gwRef )
                {
                    $gwName = is_array($gwRef) ? self::get($gwRef, 'name') : $gwRef;
                    if( $gwName === null || !isset($gateways[$gwName]) )
                        continue;
                    $peer = self::get($gateways[$gwName], 'peer_address');
                    if( is_array($peer) )
                    {
                        foreach( $peer as $peerType => $peerValue )
                            $row['branch_peer_address'][] = $tunnelName . " / " . $gwName . ": " . $peerType . "=" . (is_array($peerValue) ? json_encode($peerValue) : (string)$peerValue);
                    }
                }
            }

            //Prisma side egress: RN region -> location display name -> egress zone
            $display = self::locationDisplayForRegion( $locations, $row['region'] );
            $row['location_display'] = $display;
            if( $display !== null && isset($egressByZone[$display]) )
            {
                $zoneEntry = $egressByZone[$display];
                $row['egress_ip_addresses'] = isset($zoneEntry['addresses']) ? $zoneEntry['addresses'] : array();
                $row['egress_match'] = 'location';
            }

            $rows[] = $row;
        }

        $mapping = array(
            'tsg_id' => $this->tsg,
            'created_at' => date('c'),
            'note' => 'egress_ip_addresses are per Prisma Access location (zone), mapped via remote-network region -> locations[].display; egress_match=none means no automatic match, check 92_egress-ip.json manually',
            'remote_networks' => $rows,
            'egress_zones_without_remote_network' => array_values( array_diff( array_keys($egressByZone), array_filter(array_column($rows, 'location_display')) ) ),
        );

        $this->writeJson( 'ip-mapping.json', $mapping );
        $this->writeIPMappingCSV( $rows );

        return $mapping;
    }

    public function writeIPMappingCSV( $rows )
    {
        $fh = fopen( $this->exportDir . "/ip-mapping.csv", "w" );
        $columns = array( 'remote_network', 'region', 'spn_name', 'license_type', 'ipsec_tunnel', 'secondary_ipsec_tunnel',
            'service_ip_address', 'fqdn', 'loopback_ip_address', 'bgp_enabled', 'bgp_peer_ip_address', 'bgp_peer_as',
            'bgp_local_ip_address', 'branch_peer_address', 'location_display', 'egress_ip_addresses', 'egress_match' );
        fputcsv( $fh, $columns, ',', '"', '' );
        foreach( $rows as $row )
        {
            $line = array();
            foreach( $columns as $c )
            {
                $v = $row[$c];
                if( is_array($v) )
                    $v = implode(" | ", $v);
                elseif( is_bool($v) )
                    $v = $v ? "true" : "false";
                $line[] = $v;
            }
            fputcsv( $fh, $line, ',', '"', '' );
        }
        fclose( $fh );
    }

    /**
     * hints for later import - nothing secret is written, only counts / names
     */
    public function collectImportHints()
    {
        $hints = array();

        $pskGateways = array();
        foreach( $this->listData('ike-gateways') as $gw )
        {
            if( self::get($gw, 'authentication.pre_shared_key') !== null )
                $pskGateways[] = self::get($gw, 'name');
        }
        if( count($pskGateways) > 0 )
            $hints[] = array( 'type' => 'pre_shared_key', 'objects' => $pskGateways,
                'message' => 'IKE gateways use pre-shared keys; values returned by the API are tenant-encrypted and most likely not usable on another tenant - provide them separately for import' );

        foreach( array('ike-crypto-profiles', 'ipsec-crypto-profiles', 'ike-gateways', 'ipsec-tunnels') as $type )
        {
            $inherited = array();
            foreach( $this->listData($type) as $entry )
            {
                $snippet = self::get($entry, 'snippet');
                $folder = self::get($entry, 'folder');
                if( $snippet !== null || ( $folder !== null && $folder !== $this->folder ) )
                    $inherited[] = self::get($entry, 'name') . " [" . ( $snippet !== null ? "snippet=" . $snippet : "folder=" . $folder ) . "]";
            }
            if( count($inherited) > 0 )
                $hints[] = array( 'type' => 'inherited_or_predefined', 'endpoint' => $type, 'objects' => $inherited,
                    'message' => 'entries not defined in folder "' . $this->folder . '" itself (predefined / snippet / parent folder) - reference only, do not create on import' );
        }

        return $hints;
    }

    public function writeManifest( $frameworkVersion, $ipMapping = null )
    {
        $endpoints = array();
        foreach( $this->results as $name => $r )
            $endpoints[] = $r['meta'];

        $this->manifest = array(
            'format_version' => self::FORMAT_VERSION,
            'tool' => 'pan-os-php scm_rn_export.php',
            'pan_os_php_version' => $frameworkVersion,
            'tsg_id' => $this->tsg,
            'api_url' => $this->connector->url_api,
            'folder' => $this->folder,
            'created_at' => date('c'),
            'import_order' => array_values( array_map( function($e){ return $e['name']; },
                array_filter( $this->getEndpoints(), function($e){ return $e['category'] == 'dependency'; } ) ) ),
            'endpoints' => $endpoints,
            'ip_mapping' => $ipMapping === null ? null : array(
                'files' => array('ip-mapping.json', 'ip-mapping.csv'),
                'remote_networks' => count($ipMapping['remote_networks']),
                'egress_matched' => count( array_filter($ipMapping['remote_networks'], function($r){ return $r['egress_match'] !== 'none'; }) ),
            ),
            'import_hints' => $this->collectImportHints(),
            'errors' => count( array_filter($endpoints, function($e){ return isset($e['status']) && $e['status'] == 'error'; }) ),
        );

        $this->writeJson( 'manifest.json', $this->manifest );

        return $this->manifest;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // helpers

    public function listData( $name )
    {
        if( !isset($this->results[$name]) || !is_array($this->results[$name]['data']) )
            return array();
        $data = $this->results[$name]['data'];
        //single object endpoint
        if( array_keys($data) !== range(0, count($data) - 1) )
            return array();
        return $data;
    }

    public function writeJson( $file, $content )
    {
        $json = json_encode( $content, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
        if( $json === false )
            derr( "JSON encode failed for " . $file . ": " . json_last_error_msg(), null, FALSE );
        file_put_contents( $this->exportDir . "/" . $file, $json . "\n" );
    }

    public static function indexByName( $list )
    {
        $index = array();
        foreach( $list as $entry )
        {
            if( isset($entry['name']) )
                $index[$entry['name']] = $entry;
        }
        return $index;
    }

    /**
     * dotted path access: get($rn, 'protocol.bgp.peer_as')
     */
    public static function get( $array, $path, $default = null )
    {
        $current = $array;
        foreach( explode('.', $path) as $key )
        {
            if( !is_array($current) || !array_key_exists($key, $current) )
                return $default;
            $current = $current[$key];
        }
        return $current;
    }

    public static function locationDisplayForRegion( $locations, $region )
    {
        if( $region === null )
            return null;
        foreach( $locations as $loc )
        {
            if( self::get($loc, 'value') === $region || self::get($loc, 'region') === $region )
                return self::get($loc, 'display');
        }
        return null;
    }

    public static function errorMessage( $errors )
    {
        $messages = array();
        foreach( (array)$errors as $error )
        {
            $msg = isset($error['message']) ? $error['message'] : json_encode($error);
            if( isset($error['details']) && !is_array($error['details']) )
                $msg .= " - " . substr((string)$error['details'], 0, 200);
            elseif( isset($error['details']) )
                $msg .= " - " . substr(json_encode($error['details']), 0, 200);
            $messages[] = $msg;
        }
        return implode("; ", $messages);
    }
}
