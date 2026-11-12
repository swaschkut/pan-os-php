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
 * Export of Prisma Access configuration of one tenant (TSG) into a local directory, per area:
 *
 *   <outdir>/<TSG>/<YYYYmmdd-HHMMSS>/
 *       manifest.json
 *       infra/
 *           01_shared-infrastructure-settings.json   (api_key redacted)
 *           02_bgp-routing.json
 *           03_internal-dns-servers.json
 *           90_locations.json                      (context)
 *           92_egress-ip.json                      (optional, egress-IP API, serviceType=all)
 *       remote-networks/
 *           01_ike-crypto-profiles.json ... 06_remote-networks.json
 *           ip-mapping.json / ip-mapping.csv
 *           psk-list.csv                           (optional, cleartext PSKs, chmod 600)
 *
 * Areas are exported/imported in the order infra -> remote-networks; inside an area the numbered "dependency"
 * endpoints are in import order (an entry only references entries with a lower number or of an earlier area).
 * Every file keeps the API data unmodified, except secrets which are redacted; normalisation happens in compare/import.
 */
class SCMPrismaAccessExport
{
    const FORMAT_VERSION = 2;

    const AREA_INFRA = 'infra';
    const AREA_RN = 'remote-networks';
    /** area order == import order */
    const AREAS = array( self::AREA_INFRA, self::AREA_RN );

    const REDACTED = '***REDACTED***';
    /** keys whose values are never written to disk: endpoint => [dotted path, ...] */
    const SECRET_FIELDS = array( 'shared-infrastructure-settings' => array( 'api_key' ) );

    /** @var string[] areas selected for this export */
    public $areas = array( self::AREA_INFRA, self::AREA_RN );

    /** @var array secret values kept in memory only, e.g. ['shared-infrastructure-settings.api_key' => '...'] */
    private $secrets = array();

    /** @var PanSCMAPIConnector */
    public $connector;

    public $tsg;
    public $folder = "Remote Networks";
    public $baseDir;
    public $exportDir;

    /** @var array endpoint result per endpoint name: ['meta' => ..., 'data' => ...] */
    public $results = array();
    public $manifest = array();

    /**
     * @param string[]|null $areas subset of self::AREAS, null = all
     */
    public function __construct( $connector, $tsg, $baseDir, $folder = "Remote Networks", $areas = null )
    {
        if( $areas !== null )
        {
            foreach( $areas as $area )
            {
                if( !in_array($area, self::AREAS, TRUE) )
                    derr( "unknown area '" . $area . "' - supported: " . implode(", ", self::AREAS), null, FALSE );
            }
            //keep import order
            $this->areas = array_values( array_intersect(self::AREAS, $areas) );
        }
        $this->connector = $connector;
        $this->tsg = $tsg;
        $this->baseDir = rtrim($baseDir, "/\\");
        $this->folder = $folder;
    }

    /**
     * all known endpoints, per area in import order
     */
    public function getAllEndpoints()
    {
        $f = $this->folder;
        $infra = self::AREA_INFRA;
        $rn = self::AREA_RN;

        return array(
            //Prisma Access infrastructure - tenant wide, mostly single objects
            array( 'area' => $infra, 'order' => 1, 'name' => 'shared-infrastructure-settings', 'category' => 'dependency', 'scope' => 'tenant', 'url' => "/config/deployment/v1/shared-infrastructure-settings", 'depends_on' => array() ),
            array( 'area' => $infra, 'order' => 2, 'name' => 'bgp-routing', 'category' => 'dependency', 'scope' => 'tenant', 'url' => "/config/deployment/v1/bgp-routing", 'depends_on' => array('shared-infrastructure-settings') ),
            array( 'area' => $infra, 'order' => 3, 'name' => 'internal-dns-servers', 'category' => 'dependency', 'scope' => 'tenant', 'url' => "/config/deployment/v1/internal-dns-servers", 'depends_on' => array() ),
            array( 'area' => $infra, 'order' => 90, 'name' => 'locations', 'category' => 'context', 'scope' => 'tenant', 'url' => "/config/deployment/v1/locations", 'depends_on' => array() ),

            //Remote Networks
            array( 'area' => $rn, 'order' => 1, 'name' => 'ike-crypto-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => "/config/network/v1/ike-crypto-profiles?folder=" . $f, 'depends_on' => array() ),
            array( 'area' => $rn, 'order' => 2, 'name' => 'ipsec-crypto-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => "/config/network/v1/ipsec-crypto-profiles?folder=" . $f, 'depends_on' => array() ),
            array( 'area' => $rn, 'order' => 3, 'name' => 'ike-gateways', 'category' => 'dependency', 'scope' => 'folder', 'url' => "/config/network/v1/ike-gateways?folder=" . $f, 'depends_on' => array('ike-crypto-profiles') ),
            array( 'area' => $rn, 'order' => 4, 'name' => 'ipsec-tunnels', 'category' => 'dependency', 'scope' => 'folder', 'url' => "/config/network/v1/ipsec-tunnels?folder=" . $f, 'depends_on' => array('ike-gateways', 'ipsec-crypto-profiles') ),
            array( 'area' => $rn, 'order' => 5, 'name' => 'bandwidth-allocations', 'category' => 'dependency', 'scope' => 'tenant', 'url' => "/config/deployment/v1/bandwidth-allocations", 'depends_on' => array() ),
            array( 'area' => $rn, 'order' => 6, 'name' => 'remote-networks', 'category' => 'dependency', 'scope' => 'tenant', 'url' => "/config/deployment/v1/remote-networks", 'depends_on' => array('ipsec-tunnels', 'bandwidth-allocations', 'shared-infrastructure-settings', 'bgp-routing') ),
        );
    }

    /**
     * endpoints of the selected areas; endpoints of other areas which are needed as context
     * (remote-networks -> infra/locations for the IP mapping) are added with 'fetched_as' => 'context'
     */
    public function getEndpoints()
    {
        $needAsContext = array();
        if( in_array(self::AREA_RN, $this->areas, TRUE) )
            $needAsContext[] = 'locations';

        $endpoints = array();
        foreach( $this->getAllEndpoints() as $endpoint )
        {
            if( in_array($endpoint['area'], $this->areas, TRUE) )
            {
                $endpoint['fetched_as'] = 'selected';
                $endpoints[] = $endpoint;
            }
            elseif( in_array($endpoint['name'], $needAsContext, TRUE) )
            {
                $endpoint['fetched_as'] = 'context';
                $endpoints[] = $endpoint;
            }
        }

        //keep area order
        usort( $endpoints, function($a, $b){
            $ai = array_search($a['area'], self::AREAS); $bi = array_search($b['area'], self::AREAS);
            return $ai == $bi ? $a['order'] - $b['order'] : $ai - $bi;
        } );

        return $endpoints;
    }

    public function prepareDirectory( $timestamp = null )
    {
        if( $timestamp === null )
            $timestamp = date('Ymd-His');

        $this->exportDir = $this->baseDir . "/" . $this->tsg . "/" . $timestamp;
        foreach( array_merge( array(""), self::AREAS ) as $sub )
        {
            $dir = $this->exportDir . ( $sub === "" ? "" : "/" . $sub );
            if( !is_dir($dir) && !mkdir($dir, 0700, TRUE) )
                derr("not possible to create export directory: " . $dir, null, FALSE);
        }

        return $this->exportDir;
    }

    public static function fileName( $endpoint )
    {
        return $endpoint['area'] . "/" . sprintf("%02d", $endpoint['order']) . "_" . $endpoint['name'] . ".json";
    }

    public function exportEndpoints()
    {
        foreach( $this->getEndpoints() as $endpoint )
        {
            PH::print_stdout( " - [" . $endpoint['area'] . " " . sprintf("%02d", $endpoint['order']) . "] " . $endpoint['name'] . ( $endpoint['fetched_as'] == 'context' ? " (context)" : "" ) . " ... " );

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
                'data' => $this->redactSecrets( $endpoint['name'], $result['data'] ),
            );
            if( array_key_exists($endpoint['name'], self::SECRET_FIELDS) )
                $fileContent['redacted'] = self::SECRET_FIELDS[$endpoint['name']];
            $this->writeJson( $meta['file'], $fileContent );

            $this->results[$endpoint['name']] = array( 'meta' => $meta, 'data' => $this->redactSecrets( $endpoint['name'], $result['data'], TRUE ) );
        }
    }

    /**
     * replaces secret fields by self::REDACTED; with $remember the original value is kept in memory ($this->getSecret())
     */
    public function redactSecrets( $endpointName, $data, $remember = FALSE )
    {
        if( !array_key_exists($endpointName, self::SECRET_FIELDS) || !is_array($data) )
            return $data;

        foreach( self::SECRET_FIELDS[$endpointName] as $path )
        {
            $keys = explode('.', $path);
            $ref = &$data;
            $found = TRUE;
            foreach( $keys as $key )
            {
                if( !is_array($ref) || !array_key_exists($key, $ref) )
                {
                    $found = FALSE;
                    break;
                }
                $ref = &$ref[$key];
            }
            if( $found && $ref !== null && $ref !== "" && $ref !== self::REDACTED )
            {
                if( $remember )
                    $this->secrets[$endpointName . "." . $path] = $ref;
                $ref = self::REDACTED;
            }
            unset($ref);
        }
        return $data;
    }

    public function getSecret( $name )
    {
        return isset($this->secrets[$name]) ? $this->secrets[$name] : null;
    }

    /**
     * @param string|null $apiKey egress-IP API key; null = skip
     */
    public function exportEgressIP( $apiKey, $environment = "prod" )
    {
        $meta = array( 'area' => self::AREA_INFRA, 'order' => 92, 'name' => 'egress-ip', 'category' => 'context', 'scope' => 'tenant',
            'url' => 'getPrismaAccessIP/v2', 'depends_on' => array(), 'file' => self::AREA_INFRA . '/92_egress-ip.json', 'fetched_as' => 'selected' );

        if( $apiKey === null )
        {
            $meta['status'] = 'skipped';
            $this->results['egress-ip'] = array( 'meta' => $meta, 'data' => null );
            return;
        }

        PH::print_stdout( " - [infra 92] egress-ip (serviceType=all) ... " );
        $result = $this->connector->getPrismaAccessEgressIP( $apiKey, "all", "all", "all", $environment );

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
            'endpoint' => 'egress-ip', 'request' => array( 'serviceType' => 'all', 'addrType' => 'all', 'location' => 'all' ), 'url' => $meta['url'], 'tsg_id' => $this->tsg, 'fetched_at' => $meta['fetched_at'],
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
                $row['egress_ip_addresses'] = self::egressAddressesForServiceType( $zoneEntry, 'remote_network' );
                $row['egress_match'] = 'location';
            }

            $rows[] = $row;
        }

        $mapping = array(
            'tsg_id' => $this->tsg,
            'created_at' => date('c'),
            'note' => 'egress_ip_addresses are per Prisma Access location (zone), mapped via remote-network region -> locations[].display; egress_match=none means no automatic match, check infra/92_egress-ip.json manually',
            'remote_networks' => $rows,
            'egress_zones_without_remote_network' => array_values( array_diff( array_keys($egressByZone), array_filter(array_column($rows, 'location_display')) ) ),
        );

        $this->writeJson( self::AREA_RN . '/ip-mapping.json', $mapping );
        $this->writeIPMappingCSV( $rows );

        return $mapping;
    }

    public function writeIPMappingCSV( $rows )
    {
        $fh = fopen( $this->exportDir . "/" . self::AREA_RN . "/ip-mapping.csv", "w" );
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

        foreach( self::SECRET_FIELDS as $endpointName => $paths )
        {
            if( isset($this->results[$endpointName]) && $this->results[$endpointName]['meta']['status'] == 'ok' )
                $hints[] = array( 'type' => 'redacted', 'endpoint' => $endpointName, 'objects' => $paths,
                    'message' => 'secret fields are not written to disk; they are tenant specific and must not be imported' );
        }

        $readOnly = array();
        foreach( array('loopback_ips', 'tunnel_monitor_ip_address', 'captive_portal_redirect_ip_address', 'egress_ip_notification_url') as $field )
        {
            if( self::get( $this->singleData('shared-infrastructure-settings'), $field ) !== null )
                $readOnly[] = $field;
        }
        if( count($readOnly) > 0 )
            $hints[] = array( 'type' => 'derived_read_only', 'endpoint' => 'shared-infrastructure-settings', 'objects' => $readOnly,
                'message' => 'values derived by Prisma Access from infrastructure_subnet / tenant - compare only, do not import' );

        $pskGateways = array();
        foreach( $this->listData('ike-gateways') as $gw )
        {
            if( self::get($gw, 'authentication.pre_shared_key') !== null )
                $pskGateways[] = self::get($gw, 'name');
        }
        if( count($pskGateways) > 0 )
            $hints[] = array( 'type' => 'pre_shared_key', 'objects' => $pskGateways,
                'message' => 'IKE gateways use pre-shared keys (encrypted with the master key) - create psk-list.csv (argument psk-list) to provide them for import' );

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

    public function writeManifest( $frameworkVersion, $ipMapping = null, $pskStats = null )
    {
        $endpoints = array();
        foreach( $this->results as $name => $r )
            $endpoints[] = $r['meta'];

        $this->manifest = array(
            'format_version' => self::FORMAT_VERSION,
            'tool' => 'pan-os-php scm_pa_export.php',
            'areas' => $this->areas,
            'pan_os_php_version' => $frameworkVersion,
            'tsg_id' => $this->tsg,
            'api_url' => $this->connector->url_api,
            'folder' => $this->folder,
            'created_at' => date('c'),
            'import_order' => array_values( array_map( function($e){ return $e['area'] . "/" . $e['name']; },
                array_filter( $this->getEndpoints(), function($e){ return $e['category'] == 'dependency' && $e['fetched_as'] == 'selected'; } ) ) ),
            'endpoints' => $endpoints,
            'infra' => $this->buildInfraSummary(),
            'ip_mapping' => $ipMapping === null ? null : array(
                'files' => array(self::AREA_RN . '/ip-mapping.json', self::AREA_RN . '/ip-mapping.csv'),
                'remote_networks' => count($ipMapping['remote_networks']),
                'egress_matched' => count( array_filter($ipMapping['remote_networks'], function($r){ return $r['egress_match'] !== 'none'; }) ),
            ),
            'psk_list' => $pskStats,
            'import_hints' => $this->collectImportHints(),
            'errors' => count( array_filter($endpoints, function($e){ return isset($e['status']) && $e['status'] == 'error'; }) ),
        );

        $this->writeJson( 'manifest.json', $this->manifest );

        return $this->manifest;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // PSK list

    const PSK_DECRYPT_FAILED = 'DECRYPT_FAILED';
    const PSK_LIST_COLUMNS = array( 'ike_gateway', 'ipsec_tunnel', 'remote_network', 'branch_peer_address', 'psk_current', 'psk_new' );

    /**
     * writes psk-list.csv (one row per IKE gateway) with the decrypted current PSK and an empty psk_new column
     * file permissions 0600 - contains cleartext secrets, never referenced by name in manifest / ip-mapping
     *
     * @param string|null $masterKey null = PAN-OS default master key
     * @return array statistics ['gateways' => int, 'decrypted' => int, 'decrypt_failed' => int, 'without_psk' => int]
     */
    public function writePSKList( $masterKey = null )
    {
        $crypto = new PanosCrypto();

        //reverse references: gateway -> tunnels, tunnel -> remote networks
        $gatewayTunnels = array();
        foreach( $this->listData('ipsec-tunnels') as $tunnel )
        {
            $gwList = self::get($tunnel, 'auto_key.ike_gateway');
            if( !is_array($gwList) )
                continue;
            foreach( $gwList as $gwRef )
            {
                $gwName = is_array($gwRef) ? self::get($gwRef, 'name') : $gwRef;
                if( $gwName !== null )
                    $gatewayTunnels[$gwName][] = self::get($tunnel, 'name');
            }
        }
        $tunnelRNs = array();
        foreach( $this->listData('remote-networks') as $rn )
        {
            foreach( array('ipsec_tunnel', 'secondary_ipsec_tunnel') as $field )
            {
                $tunnelName = self::get($rn, $field);
                if( $tunnelName !== null )
                    $tunnelRNs[$tunnelName][] = self::get($rn, 'name');
            }
        }

        $stats = array( 'gateways' => 0, 'decrypted' => 0, 'decrypt_failed' => 0, 'without_psk' => 0 );

        $file = $this->exportDir . "/" . self::AREA_RN . "/psk-list.csv";
        $oldUmask = umask(0077);
        $fh = fopen( $file, "w" );
        umask($oldUmask);
        if( $fh === false )
            derr( "not possible to write " . $file, null, FALSE );
        chmod( $file, 0600 );

        fputcsv( $fh, self::PSK_LIST_COLUMNS, ',', '"', '' );

        foreach( $this->listData('ike-gateways') as $gw )
        {
            $encrypted = self::get($gw, 'authentication.pre_shared_key.key');
            if( $encrypted === null )
            {
                $stats['without_psk']++;
                continue;
            }
            $stats['gateways']++;

            try
            {
                //PanosCrypto::decrypt() returns "" instead of throwing on wrong master key / invalid format
                $cleartext = $crypto->decrypt( (string)$encrypted, $masterKey );
                if( $cleartext === "" )
                    throw new Exception("decrypt failed");
                $stats['decrypted']++;
            }
            catch( Exception $e )
            {
                $cleartext = self::PSK_DECRYPT_FAILED;
                $stats['decrypt_failed']++;
            }

            $gwName = self::get($gw, 'name');
            $tunnels = isset($gatewayTunnels[$gwName]) ? $gatewayTunnels[$gwName] : array();
            $rns = array();
            foreach( $tunnels as $tunnelName )
            {
                if( isset($tunnelRNs[$tunnelName]) )
                    $rns = array_merge( $rns, $tunnelRNs[$tunnelName] );
            }

            $peer = self::get($gw, 'peer_address');
            $peerText = array();
            if( is_array($peer) )
            {
                foreach( $peer as $peerType => $peerValue )
                    $peerText[] = $peerType . "=" . ( is_array($peerValue) ? json_encode($peerValue) : (string)$peerValue );
            }

            fputcsv( $fh, array( $gwName, implode(" | ", $tunnels), implode(" | ", array_unique($rns)), implode(" | ", $peerText), $cleartext, "" ), ',', '"', '' );
        }
        fclose( $fh );

        return $stats;
    }

    /**
     * reads a psk-list.csv for import: psk_new if filled, otherwise psk_current
     *
     * @return array ['psk' => [gateway => cleartext], 'source' => [gateway => 'new'|'current'], 'errors' => [gateway => message]]
     */
    public static function loadPSKList( $file )
    {
        if( !is_readable($file) )
            derr( "PSK list not readable: " . $file, null, FALSE );

        $fh = fopen( $file, "r" );
        $header = fgetcsv( $fh, 0, ',', '"', '' );
        if( $header === false )
            derr( "PSK list is empty: " . $file, null, FALSE );
        $header = array_map( 'trim', $header );
        foreach( array('ike_gateway', 'psk_current', 'psk_new') as $required )
        {
            if( !in_array($required, $header, TRUE) )
                derr( "PSK list " . $file . " has no column '" . $required . "'", null, FALSE );
        }

        $result = array( 'psk' => array(), 'source' => array(), 'errors' => array() );
        $lineNo = 1;
        while( ($line = fgetcsv( $fh, 0, ',', '"', '' )) !== false )
        {
            $lineNo++;
            if( count($line) == 1 && trim((string)$line[0]) === "" )
                continue;
            $row = array();
            foreach( $header as $i => $col )
                $row[$col] = isset($line[$i]) ? $line[$i] : "";

            $gw = trim( $row['ike_gateway'] );
            if( $gw === "" )
            {
                $result['errors']["line " . $lineNo] = "no ike_gateway";
                continue;
            }
            if( isset($result['psk'][$gw]) || isset($result['errors'][$gw]) )
            {
                $result['errors'][$gw] = "duplicate entry (line " . $lineNo . ")";
                unset( $result['psk'][$gw], $result['source'][$gw] );
                continue;
            }

            //PSK values are used as written - no trim, whitespace may be part of the key
            if( $row['psk_new'] !== "" )
            {
                $result['psk'][$gw] = $row['psk_new'];
                $result['source'][$gw] = 'new';
            }
            elseif( $row['psk_current'] !== "" && $row['psk_current'] !== self::PSK_DECRYPT_FAILED )
            {
                $result['psk'][$gw] = $row['psk_current'];
                $result['source'][$gw] = 'current';
            }
            else
                $result['errors'][$gw] = "psk_new empty and psk_current not available (" . ( $row['psk_current'] === "" ? "empty" : $row['psk_current'] ) . ")";
        }
        fclose( $fh );

        return $result;
    }


    ////////////////////////////////////////////////////////////////////////////////
    // infra

    /**
     * short, comparable summary of the infrastructure settings (written to manifest.json)
     */
    public function buildInfraSummary()
    {
        if( !in_array(self::AREA_INFRA, $this->areas, TRUE) )
            return null;

        $shared = $this->singleData('shared-infrastructure-settings');
        $bgp = $this->singleData('bgp-routing');

        $dnsServers = array();
        foreach( $this->listData('internal-dns-servers') as $dns )
            $dnsServers[] = array(
                'name' => self::get($dns, 'name'),
                'domain_name' => self::get($dns, 'domain_name'),
                'primary' => self::get($dns, 'primary'),
                'secondary' => self::get($dns, 'secondary'),
            );

        return array(
            'infrastructure_subnet' => self::get($shared, 'infrastructure_subnet'),
            'infrastructure_subnet_ipv6' => self::get($shared, 'infrastructure_subnet_ipv6'),
            'ipv6' => self::get($shared, 'ipv6'),
            'infra_bgp_as' => self::get($shared, 'infra_bgp_as'),
            'tunnel_monitor_ip_address' => self::get($shared, 'tunnel_monitor_ip_address'),
            'loopback_ips' => self::get($shared, 'loopback_ips'),
            'bgp_routing' => $bgp === null ? null : array(
                'routing_preference' => self::get($bgp, 'routing_preference'),
                'backbone_routing' => self::get($bgp, 'backbone_routing'),
                'accept_route_over_SC' => self::get($bgp, 'accept_route_over_SC'),
                'outbound_routes_for_services' => self::get($bgp, 'outbound_routes_for_services'),
                'add_host_route_to_ike_peer' => self::get($bgp, 'add_host_route_to_ike_peer'),
                'withdraw_static_route' => self::get($bgp, 'withdraw_static_route'),
            ),
            'internal_dns_servers' => $dnsServers,
            'locations' => count( $this->listData('locations') ),
        );
    }

    /**
     * egress addresses of one zone entry for one serviceType (address_details), fallback 'addresses'
     */
    public static function egressAddressesForServiceType( $zoneEntry, $serviceType )
    {
        if( isset($zoneEntry['address_details']) && is_array($zoneEntry['address_details']) && count($zoneEntry['address_details']) > 0 )
        {
            $list = array();
            foreach( $zoneEntry['address_details'] as $detail )
            {
                if( self::get($detail, 'serviceType') === $serviceType && self::get($detail, 'address') !== null )
                    $list[] = $detail['address'];
            }
            return $list;
        }
        return isset($zoneEntry['addresses']) ? $zoneEntry['addresses'] : array();
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

    /**
     * data of a single-object endpoint (e.g. shared-infrastructure-settings); a list with one entry is unwrapped
     */
    public function singleData( $name )
    {
        if( !isset($this->results[$name]) || !is_array($this->results[$name]['data']) )
            return null;
        $data = $this->results[$name]['data'];
        if( array_keys($data) === range(0, count($data) - 1) )
            return count($data) == 1 ? $data[0] : null;
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

//backward compatibility for code written against the first RN-only version
class_alias( 'SCMPrismaAccessExport', 'SCMRemoteNetworkExport' );
