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
 *           psk-list.csv / bgp-secret-list.csv      (optional, cleartext, chmod 600)
 *       service-connections/
 *           01_ike-crypto-profiles.json ... 08_traffic-steering-rules.json
 *           ip-mapping.json / ip-mapping.csv
 *           psk-list.csv / bgp-secret-list.csv      (optional, cleartext, chmod 600)
 *       mobile-users/
 *           01_certificates.json ... 14_authentication-sequences.json   (identity dependencies)
 *           20_mobile-agent-infrastructure-settings.json ... 27_mobile-agent-enable.json
 *           ip-mapping.json / ip-mapping.csv
 *           secret-list.csv                         (optional, cleartext, chmod 600)
 *       prisma-browser/
 *           01_user-groups.json ... 09_policy-customization.json, 90_pending-changes.json
 *       iam/                                        (documentation / compare only, not imported)
 *           01_roles.json ... 06_access-policies.json, access-policies.csv
 *       MIGRATION_CHECKLIST.md
 *
 * Areas are exported/imported in the order of self::AREAS; inside an area the numbered "dependency" endpoints are in
 * import order (an entry only references entries with a lower number or of an earlier area).
 * Every file keeps the API data unmodified, except secrets which are redacted; normalisation happens in compare/import.
 */
class SCMPrismaAccessExport
{
    const FORMAT_VERSION = 5;

    const AREA_INFRA = 'infra';
    const AREA_RN = 'remote-networks';
    const AREA_SC = 'service-connections';
    const AREA_MU = 'mobile-users';
    const AREA_PB = 'prisma-browser';
    const AREA_IAM = 'iam';
    /** area order == import order (iam: documentation only) */
    const AREAS = array( self::AREA_INFRA, self::AREA_RN, self::AREA_SC, self::AREA_MU, self::AREA_PB, self::AREA_IAM );

    /** host of the IAM and Prisma Browser APIs */
    const SASE_API = 'https://api.sase.paloaltonetworks.com';

    const MU_FOLDER = 'Mobile Users';

    /**
     * areas built on IKE/IPsec tunnels: folder of the network objects, connection endpoint, name of the connection column
     */
    const CONNECTION_AREAS = array(
        self::AREA_RN => array( 'folder' => 'Remote Networks', 'endpoint' => 'remote-networks', 'label' => 'remote_network' ),
        self::AREA_SC => array( 'folder' => 'Service Connections', 'endpoint' => 'service-connections', 'label' => 'service_connection' ),
    );

    const REDACTED = '***REDACTED***';
    /** keys whose values are never written to disk: endpoint => [dotted path, ...] */
    const SECRET_FIELDS = array( 'shared-infrastructure-settings' => array( 'api_key' ) );

    /** BGP secrets (encrypted with the master key) per connection endpoint */
    const BGP_SECRET_FIELDS = array(
        'remote-networks' => array( 'protocol.bgp.secret' ),
        'service-connections' => array( 'protocol.bgp.secret', 'bgp_peer.secret' ),
    );

    /** @var PanSCMAPIConnector */
    public $connector;

    public $tsg;
    public $baseDir;
    public $exportDir;

    /** @var string[] areas selected for this export */
    public $areas = self::AREAS;

    /** @var array folder per connection area, see CONNECTION_AREAS */
    public $folders = array();

    /** @var array endpoint result per "area/endpoint": ['meta' => ..., 'data' => ...] */
    public $results = array();
    public $manifest = array();

    /** @var array secret values kept in memory only, e.g. ['shared-infrastructure-settings.api_key' => '...'] */
    private $secrets = array();

    /**
     * @param string|null $rnFolder folder of the Remote Network IKE/IPsec objects (null: "Remote Networks")
     * @param string[]|null $areas subset of self::AREAS, null = all
     */
    public function __construct( $connector, $tsg, $baseDir, $rnFolder = null, $areas = null )
    {
        $this->connector = $connector;
        $this->tsg = $tsg;
        $this->baseDir = rtrim($baseDir, "/\\");

        foreach( self::CONNECTION_AREAS as $area => $def )
            $this->folders[$area] = $def['folder'];
        $this->folders[self::AREA_MU] = self::MU_FOLDER;
        if( $rnFolder !== null && $rnFolder !== "" )
            $this->folders[self::AREA_RN] = $rnFolder;

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
    }

    /**
     * IAM / Prisma Browser host; for QA tenants (url_api qa.*) the connector host is used
     */
    public function saseApiUrl()
    {
        $api = is_object($this->connector) && isset($this->connector->url_api) ? $this->connector->url_api : "";
        if( strpos($api, "://qa.") !== FALSE )
            return rtrim($api, "/");
        return self::SASE_API;
    }

    public function hasArea( $area )
    {
        return in_array($area, $this->areas, TRUE);
    }

    public function connectionAreas()
    {
        return array_values( array_filter( $this->areas, function($a){ return isset(self::CONNECTION_AREAS[$a]); } ) );
    }

    ////////////////////////////////////////////////////////////////////////////////
    // endpoints

    /**
     * all known endpoints, per area in import order
     */
    public function getAllEndpoints()
    {
        $infra = self::AREA_INFRA;
        $rn = self::AREA_RN;
        $sc = self::AREA_SC;
        $rnF = $this->folders[$rn];
        $scF = $this->folders[$sc];
        $mu = self::AREA_MU;
        $muF = $this->folders[$mu];
        $id = "/config/identity/v1/";
        $ma = "/config/mobile-agent/v1/";
        $pb = self::AREA_PB;
        $iam = self::AREA_IAM;
        $seb = $this->saseApiUrl() . "/seb-api/v1/";
        $iamUrl = $this->saseApiUrl() . "/iam/v1/";

        return array(
            //Prisma Access infrastructure - tenant wide, mostly single objects
            array( 'area' => $infra, 'order' => 1, 'name' => 'shared-infrastructure-settings', 'category' => 'dependency', 'scope' => 'tenant', 'url' => "/config/deployment/v1/shared-infrastructure-settings", 'depends_on' => array() ),
            array( 'area' => $infra, 'order' => 2, 'name' => 'bgp-routing', 'category' => 'dependency', 'scope' => 'tenant', 'url' => "/config/deployment/v1/bgp-routing", 'depends_on' => array('infra/shared-infrastructure-settings') ),
            array( 'area' => $infra, 'order' => 3, 'name' => 'internal-dns-servers', 'category' => 'dependency', 'scope' => 'tenant', 'url' => "/config/deployment/v1/internal-dns-servers", 'depends_on' => array() ),
            array( 'area' => $infra, 'order' => 90, 'name' => 'locations', 'category' => 'context', 'scope' => 'tenant', 'url' => "/config/deployment/v1/locations", 'depends_on' => array() ),

            //Remote Networks
            array( 'area' => $rn, 'order' => 1, 'name' => 'ike-crypto-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => "/config/network/v1/ike-crypto-profiles?folder=" . $rnF, 'depends_on' => array() ),
            array( 'area' => $rn, 'order' => 2, 'name' => 'ipsec-crypto-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => "/config/network/v1/ipsec-crypto-profiles?folder=" . $rnF, 'depends_on' => array() ),
            array( 'area' => $rn, 'order' => 3, 'name' => 'ike-gateways', 'category' => 'dependency', 'scope' => 'folder', 'url' => "/config/network/v1/ike-gateways?folder=" . $rnF, 'depends_on' => array('remote-networks/ike-crypto-profiles') ),
            array( 'area' => $rn, 'order' => 4, 'name' => 'ipsec-tunnels', 'category' => 'dependency', 'scope' => 'folder', 'url' => "/config/network/v1/ipsec-tunnels?folder=" . $rnF, 'depends_on' => array('remote-networks/ike-gateways', 'remote-networks/ipsec-crypto-profiles') ),
            array( 'area' => $rn, 'order' => 5, 'name' => 'qos-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => "/config/network/v1/qos-profiles?folder=" . $rnF, 'depends_on' => array() ),
            array( 'area' => $rn, 'order' => 6, 'name' => 'bandwidth-allocations', 'category' => 'dependency', 'scope' => 'tenant', 'url' => "/config/deployment/v1/bandwidth-allocations", 'depends_on' => array('remote-networks/qos-profiles') ),
            array( 'area' => $rn, 'order' => 7, 'name' => 'remote-networks', 'category' => 'dependency', 'scope' => 'tenant', 'url' => "/config/deployment/v1/remote-networks", 'depends_on' => array('remote-networks/ipsec-tunnels', 'remote-networks/bandwidth-allocations', 'infra/shared-infrastructure-settings', 'infra/bgp-routing') ),

            //Service Connections (SC-CAN)
            array( 'area' => $sc, 'order' => 1, 'name' => 'ike-crypto-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => "/config/network/v1/ike-crypto-profiles?folder=" . $scF, 'depends_on' => array() ),
            array( 'area' => $sc, 'order' => 2, 'name' => 'ipsec-crypto-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => "/config/network/v1/ipsec-crypto-profiles?folder=" . $scF, 'depends_on' => array() ),
            array( 'area' => $sc, 'order' => 3, 'name' => 'ike-gateways', 'category' => 'dependency', 'scope' => 'folder', 'url' => "/config/network/v1/ike-gateways?folder=" . $scF, 'depends_on' => array('service-connections/ike-crypto-profiles') ),
            array( 'area' => $sc, 'order' => 4, 'name' => 'ipsec-tunnels', 'category' => 'dependency', 'scope' => 'folder', 'url' => "/config/network/v1/ipsec-tunnels?folder=" . $scF, 'depends_on' => array('service-connections/ike-gateways', 'service-connections/ipsec-crypto-profiles') ),
            array( 'area' => $sc, 'order' => 5, 'name' => 'qos-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => "/config/network/v1/qos-profiles?folder=" . $scF, 'depends_on' => array() ),
            array( 'area' => $sc, 'order' => 6, 'name' => 'service-connections', 'category' => 'dependency', 'scope' => 'tenant', 'url' => "/config/deployment/v1/service-connections", 'depends_on' => array('service-connections/ipsec-tunnels', 'service-connections/qos-profiles', 'infra/shared-infrastructure-settings', 'infra/bgp-routing') ),
            array( 'area' => $sc, 'order' => 7, 'name' => 'service-connection-groups', 'category' => 'dependency', 'scope' => 'tenant', 'url' => "/config/deployment/v1/service-connection-groups", 'depends_on' => array('service-connections/service-connections') ),
            array( 'area' => $sc, 'order' => 8, 'name' => 'traffic-steering-rules', 'category' => 'dependency', 'scope' => 'tenant', 'url' => "/config/deployment/v1/traffic-steering-rules", 'depends_on' => array('service-connections/service-connections') ),

            //Mobile Users - identity dependencies (folder Mobile Users)
            array( 'area' => $mu, 'order' => 1, 'name' => 'certificates', 'category' => 'dependency', 'scope' => 'folder', 'url' => $id . "certificates?folder=" . $muF, 'depends_on' => array() ),
            array( 'area' => $mu, 'order' => 2, 'name' => 'trusted-certificate-authorities', 'category' => 'dependency', 'scope' => 'folder', 'url' => $id . "trusted-certificate-authorities?folder=" . $muF, 'depends_on' => array() ),
            array( 'area' => $mu, 'order' => 3, 'name' => 'certificate-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => $id . "certificate-profiles?folder=" . $muF, 'depends_on' => array('mobile-users/certificates', 'mobile-users/trusted-certificate-authorities') ),
            array( 'area' => $mu, 'order' => 4, 'name' => 'tls-service-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => $id . "tls-service-profiles?folder=" . $muF, 'depends_on' => array('mobile-users/certificates') ),
            array( 'area' => $mu, 'order' => 5, 'name' => 'saml-server-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => $id . "saml-server-profiles?folder=" . $muF, 'depends_on' => array('mobile-users/certificates') ),
            array( 'area' => $mu, 'order' => 6, 'name' => 'ldap-server-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => $id . "ldap-server-profiles?folder=" . $muF, 'depends_on' => array() ),
            array( 'area' => $mu, 'order' => 7, 'name' => 'radius-server-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => $id . "radius-server-profiles?folder=" . $muF, 'depends_on' => array() ),
            array( 'area' => $mu, 'order' => 8, 'name' => 'tacacs-server-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => $id . "tacacs-server-profiles?folder=" . $muF, 'depends_on' => array() ),
            array( 'area' => $mu, 'order' => 9, 'name' => 'kerberos-server-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => $id . "kerberos-server-profiles?folder=" . $muF, 'depends_on' => array() ),
            array( 'area' => $mu, 'order' => 10, 'name' => 'mfa-servers', 'category' => 'dependency', 'scope' => 'folder', 'url' => $id . "mfa-servers?folder=" . $muF, 'depends_on' => array() ),
            array( 'area' => $mu, 'order' => 11, 'name' => 'local-users', 'category' => 'dependency', 'scope' => 'folder', 'url' => $id . "local-users?folder=" . $muF, 'depends_on' => array() ),
            array( 'area' => $mu, 'order' => 12, 'name' => 'local-user-groups', 'category' => 'dependency', 'scope' => 'folder', 'url' => $id . "local-user-groups?folder=" . $muF, 'depends_on' => array('mobile-users/local-users') ),
            array( 'area' => $mu, 'order' => 13, 'name' => 'authentication-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => $id . "authentication-profiles?folder=" . $muF, 'depends_on' => array('mobile-users/certificate-profiles', 'mobile-users/saml-server-profiles', 'mobile-users/ldap-server-profiles', 'mobile-users/radius-server-profiles', 'mobile-users/tacacs-server-profiles', 'mobile-users/kerberos-server-profiles', 'mobile-users/mfa-servers', 'mobile-users/local-user-groups') ),
            array( 'area' => $mu, 'order' => 14, 'name' => 'authentication-sequences', 'category' => 'dependency', 'scope' => 'folder', 'url' => $id . "authentication-sequences?folder=" . $muF, 'depends_on' => array('mobile-users/authentication-profiles') ),

            //Mobile Users - GlobalProtect (mobile agent)
            array( 'area' => $mu, 'order' => 20, 'name' => 'mobile-agent-infrastructure-settings', 'category' => 'dependency', 'scope' => 'folder', 'url' => $ma . "infrastructure-settings?folder=" . $muF, 'depends_on' => array('infra/shared-infrastructure-settings', 'mobile-users/tls-service-profiles') ),
            array( 'area' => $mu, 'order' => 21, 'name' => 'mobile-agent-locations', 'category' => 'dependency', 'scope' => 'folder', 'url' => $ma . "locations?folder=" . $muF, 'depends_on' => array('mobile-users/mobile-agent-infrastructure-settings') ),
            array( 'area' => $mu, 'order' => 22, 'name' => 'mobile-agent-authentication-settings', 'category' => 'dependency', 'scope' => 'folder', 'url' => $ma . "authentication-settings?folder=" . $muF, 'depends_on' => array('mobile-users/authentication-profiles', 'mobile-users/authentication-sequences') ),
            array( 'area' => $mu, 'order' => 23, 'name' => 'mobile-agent-tunnel-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => $ma . "tunnel-profiles?folder=" . $muF, 'depends_on' => array('mobile-users/certificates') ),
            array( 'area' => $mu, 'order' => 24, 'name' => 'mobile-agent-agent-profiles', 'category' => 'dependency', 'scope' => 'folder', 'url' => $ma . "agent-profiles?folder=" . $muF, 'depends_on' => array('mobile-users/certificates', 'mobile-users/mobile-agent-infrastructure-settings') ),
            array( 'area' => $mu, 'order' => 25, 'name' => 'mobile-agent-global-settings', 'category' => 'dependency', 'scope' => 'folder', 'url' => $ma . "global-settings?folder=" . $muF, 'depends_on' => array() ),
            array( 'area' => $mu, 'order' => 26, 'name' => 'mobile-agent-agent-versions', 'category' => 'dependency', 'scope' => 'folder', 'url' => $ma . "agent-versions?folder=" . $muF, 'depends_on' => array() ),
            array( 'area' => $mu, 'order' => 27, 'name' => 'mobile-agent-enable', 'category' => 'dependency', 'scope' => 'folder', 'url' => $ma . "enable?folder=" . $muF, 'depends_on' => array('mobile-users/mobile-agent-infrastructure-settings', 'mobile-users/mobile-agent-agent-profiles') ),

            //Prisma Browser (Strata Enterprise Browser) - cursor pagination, draft / publish
            array( 'area' => $pb, 'order' => 1, 'name' => 'user-groups', 'category' => 'dependency', 'scope' => 'tenant', 'pagination' => 'cursor', 'optional' => true, 'url' => $seb . "user-groups", 'depends_on' => array() ),
            array( 'area' => $pb, 'order' => 2, 'name' => 'device-groups', 'category' => 'dependency', 'scope' => 'tenant', 'pagination' => 'cursor', 'optional' => true, 'url' => $seb . "device-groups", 'depends_on' => array() ),
            array( 'area' => $pb, 'order' => 3, 'name' => 'applications', 'category' => 'dependency', 'scope' => 'tenant', 'pagination' => 'cursor', 'optional' => true, 'url' => $seb . "applications", 'depends_on' => array() ),
            array( 'area' => $pb, 'order' => 4, 'name' => 'application-groups', 'category' => 'dependency', 'scope' => 'tenant', 'pagination' => 'cursor', 'optional' => true, 'url' => $seb . "application-groups", 'depends_on' => array('prisma-browser/applications') ),
            array( 'area' => $pb, 'order' => 5, 'name' => 'application-plugins', 'category' => 'dependency', 'scope' => 'tenant', 'pagination' => 'cursor', 'optional' => true, 'url' => $seb . "applications/plugins", 'depends_on' => array('prisma-browser/applications') ),
            array( 'area' => $pb, 'order' => 6, 'name' => 'policy-sign-in', 'category' => 'dependency', 'scope' => 'tenant', 'pagination' => 'cursor', 'optional' => true, 'url' => $seb . "policy/sign-in", 'depends_on' => array('prisma-browser/user-groups', 'prisma-browser/device-groups') ),
            array( 'area' => $pb, 'order' => 7, 'name' => 'policy-access-and-data', 'category' => 'dependency', 'scope' => 'tenant', 'pagination' => 'cursor', 'optional' => true, 'url' => $seb . "policy/access-and-data", 'depends_on' => array('prisma-browser/user-groups', 'prisma-browser/device-groups', 'prisma-browser/applications', 'prisma-browser/application-groups') ),
            array( 'area' => $pb, 'order' => 8, 'name' => 'policy-security', 'category' => 'dependency', 'scope' => 'tenant', 'pagination' => 'cursor', 'optional' => true, 'url' => $seb . "policy/security", 'depends_on' => array('prisma-browser/user-groups', 'prisma-browser/device-groups') ),
            array( 'area' => $pb, 'order' => 9, 'name' => 'policy-customization', 'category' => 'dependency', 'scope' => 'tenant', 'pagination' => 'cursor', 'optional' => true, 'url' => $seb . "policy/customization", 'depends_on' => array('prisma-browser/user-groups', 'prisma-browser/device-groups') ),
            array( 'area' => $pb, 'order' => 90, 'name' => 'pending-changes', 'category' => 'context', 'scope' => 'tenant', 'pagination' => 'cursor', 'optional' => true, 'url' => $seb . "configuration-management/draft/pending-changes", 'depends_on' => array() ),

            //IAM - documentation / compare only (principals, scopes and secrets are tenant specific)
            array( 'area' => $iam, 'order' => 1, 'name' => 'roles', 'category' => 'documentation', 'scope' => 'tenant', 'optional' => true, 'url' => $iamUrl . "roles", 'depends_on' => array() ),
            array( 'area' => $iam, 'order' => 2, 'name' => 'custom-roles', 'category' => 'documentation', 'scope' => 'tenant', 'optional' => true, 'url' => $iamUrl . "custom_roles", 'depends_on' => array() ),
            array( 'area' => $iam, 'order' => 3, 'name' => 'permission-sets', 'category' => 'documentation', 'scope' => 'tenant', 'optional' => true, 'url' => $iamUrl . "permission_sets", 'depends_on' => array() ),
            array( 'area' => $iam, 'order' => 4, 'name' => 'service-accounts', 'category' => 'documentation', 'scope' => 'tenant', 'optional' => true, 'url' => $iamUrl . "service_accounts", 'depends_on' => array() ),
            array( 'area' => $iam, 'order' => 5, 'name' => 'access-policies', 'category' => 'documentation', 'scope' => 'tenant', 'optional' => true, 'url' => $iamUrl . "access_policies", 'depends_on' => array('iam/roles', 'iam/custom-roles', 'iam/service-accounts') ),
            array( 'area' => $iam, 'order' => 90, 'name' => 'permissions', 'category' => 'context', 'scope' => 'tenant', 'optional' => true, 'url' => $iamUrl . "permissions", 'depends_on' => array() ),
        );
    }

    /**
     * endpoints of the selected areas; endpoints of other areas which are needed as context
     * (remote-networks / service-connections -> infra/locations for the IP mapping) are added with 'fetched_as' => 'context'
     */
    public function getEndpoints()
    {
        $needAsContext = array();
        if( count($this->connectionAreas()) > 0 || $this->hasArea(self::AREA_MU) )
            $needAsContext[] = self::AREA_INFRA . '/locations';

        $endpoints = array();
        foreach( $this->getAllEndpoints() as $endpoint )
        {
            if( $this->hasArea($endpoint['area']) )
            {
                $endpoint['fetched_as'] = 'selected';
                $endpoints[] = $endpoint;
            }
            elseif( in_array(self::key($endpoint['area'], $endpoint['name']), $needAsContext, TRUE) )
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

    public static function key( $area, $name )
    {
        return $area . "/" . $name;
    }

    public function prepareDirectory( $timestamp = null )
    {
        if( $timestamp === null )
            $timestamp = date('Ymd-His');

        $this->exportDir = $this->baseDir . "/" . $this->tsg . "/" . $timestamp;
        $subDirs = array("");
        foreach( $this->getEndpoints() as $endpoint )
            $subDirs[] = $endpoint['area'];
        foreach( array_unique($subDirs) as $sub )
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

            if( isset($endpoint['pagination']) && $endpoint['pagination'] == 'cursor' )
                $result = $this->connector->getCursorResourceAll( $endpoint['url'] );
            else
                $result = $this->connector->getSCMResourceAll( $endpoint['url'] );

            $meta = $endpoint;
            $meta['file'] = self::fileName($endpoint);
            $meta['http_code'] = $result['http_code'];
            $meta['fetched_at'] = date('c');

            if( $result['errors'] !== null && !empty($endpoint['optional']) && in_array($result['http_code'], array(401, 403, 404), TRUE) )
            {
                //product not licensed / no permission for this service account
                $meta['status'] = 'unavailable';
                $meta['count'] = null;
                $meta['error'] = self::errorMessage($result['errors']);
                PH::print_stdout( "     - not available (HTTP " . $result['http_code'] . ")" );
            }
            elseif( $result['errors'] !== null )
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
                'area' => $endpoint['area'],
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

            $this->results[self::key($endpoint['area'], $endpoint['name'])] = array( 'meta' => $meta, 'data' => $this->redactSecrets( $endpoint['name'], $result['data'], TRUE ) );
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
        $key = self::key(self::AREA_INFRA, 'egress-ip');

        if( $apiKey === null )
        {
            $meta['status'] = 'skipped';
            $this->results[$key] = array( 'meta' => $meta, 'data' => null );
            return;
        }

        if( !is_dir($this->exportDir . "/" . self::AREA_INFRA) )
            mkdir($this->exportDir . "/" . self::AREA_INFRA, 0700, TRUE);

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
            'endpoint' => 'egress-ip', 'area' => self::AREA_INFRA, 'request' => array( 'serviceType' => 'all', 'addrType' => 'all', 'location' => 'all' ),
            'url' => $meta['url'], 'tsg_id' => $this->tsg, 'fetched_at' => $meta['fetched_at'],
            'http_code' => $meta['http_code'], 'status' => $meta['status'],
            'error' => $result['errors'], 'data' => $data ) );

        $this->results[$key] = array( 'meta' => $meta, 'data' => $data );
    }

    ////////////////////////////////////////////////////////////////////////////////
    // IP mapping (remote-networks, service-connections)

    /**
     * CSV/JSON columns per connection area; order == CSV order
     */
    public static function mappingColumns( $area )
    {
        if( $area == self::AREA_RN )
            return array( 'remote_network', 'region', 'spn_name', 'license_type', 'ipsec_tunnel', 'secondary_ipsec_tunnel',
                'service_ip_address', 'fqdn', 'loopback_ip_address', 'bgp_enabled', 'bgp_peer_ip_address', 'bgp_peer_as',
                'bgp_local_ip_address', 'branch_peer_address', 'location_display', 'egress_ip_addresses', 'egress_match' );

        return array( 'service_connection', 'region', 'onboarding_type', 'ipsec_tunnel', 'secondary_ipsec_tunnel', 'backup_SC',
            'subnets', 'nat_pool', 'source_nat', 'qos_profile', 'no_export_community',
            'bgp_enabled', 'bgp_peer_ip_address', 'bgp_peer_as', 'bgp_local_ip_address',
            'bgp_peer_local_ip_address', 'bgp_peer_peer_ip_address', 'bgp_peer_local_ipv6_address', 'bgp_peer_peer_ipv6_address',
            'peer_address', 'location_display' );
    }

    /**
     * one row per connection (remote network / service connection):
     * Prisma Access side (region, service IP, egress) and peer side (IKE peer address, BGP peer)
     *
     * @param string $area self::AREA_RN (default) or self::AREA_SC
     */
    public function buildIPMapping( $area = self::AREA_RN )
    {
        $def = self::CONNECTION_AREAS[$area];
        $connections = $this->listData($def['endpoint'], $area);
        $tunnels = self::indexByName( $this->listData('ipsec-tunnels', $area) );
        $gateways = self::indexByName( $this->listData('ike-gateways', $area) );
        $locations = $this->listData('locations', self::AREA_INFRA);
        $egress = $this->listData('egress-ip', self::AREA_INFRA);

        //egress result is per zone (display name of a location)
        $egressByZone = array();
        foreach( $egress as $zoneEntry )
        {
            if( isset($zoneEntry['zone']) )
                $egressByZone[$zoneEntry['zone']] = $zoneEntry;
        }

        $rows = array();
        foreach( $connections as $conn )
        {
            $row = array(
                $def['label'] => self::get($conn, 'name'),
                'region' => self::get($conn, 'region'),
                'ipsec_tunnel' => self::get($conn, 'ipsec_tunnel'),
                'secondary_ipsec_tunnel' => self::get($conn, 'secondary_ipsec_tunnel'),
                'bgp_enabled' => self::get($conn, 'protocol.bgp.enable'),
                'bgp_peer_ip_address' => self::get($conn, 'protocol.bgp.peer_ip_address'),
                'bgp_peer_as' => self::get($conn, 'protocol.bgp.peer_as'),
                'bgp_local_ip_address' => self::get($conn, 'protocol.bgp.local_ip_address'),
            );

            if( $area == self::AREA_RN )
            {
                $row['spn_name'] = self::get($conn, 'spn_name');
                $row['license_type'] = self::get($conn, 'license_type');
                $row['service_ip_address'] = self::get($conn, 'details.service_ip_address');
                $row['fqdn'] = self::get($conn, 'details.fqdn');
                $row['loopback_ip_address'] = self::get($conn, 'details.loopback_ip_address');
                $row['egress_ip_addresses'] = array();
                $row['egress_match'] = 'none';
            }
            else
            {
                $row['onboarding_type'] = self::get($conn, 'onboarding_type');
                $row['backup_SC'] = self::get($conn, 'backup_SC');
                $row['subnets'] = self::get($conn, 'subnets', array());
                $row['nat_pool'] = self::get($conn, 'nat_pool');
                $row['source_nat'] = self::get($conn, 'source_nat');
                $row['qos_profile'] = self::get($conn, 'qos.enable') ? self::get($conn, 'qos.qos_profile') : null;
                $row['no_export_community'] = self::get($conn, 'no_export_community');
                $row['bgp_peer_local_ip_address'] = self::get($conn, 'bgp_peer.local_ip_address');
                $row['bgp_peer_peer_ip_address'] = self::get($conn, 'bgp_peer.peer_ip_address');
                $row['bgp_peer_local_ipv6_address'] = self::get($conn, 'bgp_peer.local_ipv6_address');
                $row['bgp_peer_peer_ipv6_address'] = self::get($conn, 'bgp_peer.peer_ipv6_address');
            }

            //peer side: connection -> ipsec tunnel(s) -> ike gateway(s) -> peer_address
            $peerAddresses = array();
            foreach( array($row['ipsec_tunnel'], $row['secondary_ipsec_tunnel']) as $tunnelName )
            {
                if( $tunnelName === null || !isset($tunnels[$tunnelName]) )
                    continue;
                foreach( self::tunnelGatewayNames($tunnels[$tunnelName]) as $gwName )
                {
                    if( !isset($gateways[$gwName]) )
                        continue;
                    foreach( self::peerAddressList($gateways[$gwName]) as $peerText )
                        $peerAddresses[] = $tunnelName . " / " . $gwName . ": " . $peerText;
                }
            }
            $row[ $area == self::AREA_RN ? 'branch_peer_address' : 'peer_address' ] = $peerAddresses;

            $display = self::locationDisplayForRegion( $locations, $row['region'] );
            $row['location_display'] = $display;

            //RN only: Prisma side egress via region -> location display name -> egress zone
            if( $area == self::AREA_RN && $display !== null && isset($egressByZone[$display]) )
            {
                $row['egress_ip_addresses'] = self::egressAddressesForServiceType( $egressByZone[$display], 'remote_network' );
                $row['egress_match'] = 'location';
            }

            //fixed column order
            $ordered = array();
            foreach( self::mappingColumns($area) as $c )
                $ordered[$c] = array_key_exists($c, $row) ? $row[$c] : null;
            $rows[] = $ordered;
        }

        $mapping = array(
            'tsg_id' => $this->tsg,
            'area' => $area,
            'created_at' => date('c'),
        );
        if( $area == self::AREA_RN )
        {
            $mapping['note'] = 'egress_ip_addresses are per Prisma Access location (zone), mapped via remote-network region -> locations[].display; egress_match=none means no automatic match, check infra/92_egress-ip.json manually';
            $mapping['remote_networks'] = $rows;
            $mapping['egress_zones_without_remote_network'] = array_values( array_diff( array_keys($egressByZone), array_filter(array_column($rows, 'location_display')) ) );
        }
        else
        {
            $mapping['note'] = 'peer_address is the data center / CAN side of the IPsec tunnel(s); a new tenant gets new Prisma Access service connection IPs';
            $mapping['service_connections'] = $rows;
        }

        $this->writeJson( $area . '/ip-mapping.json', $mapping );
        $this->writeMappingCSV( $area, $rows );

        return $mapping;
    }

    /** @deprecated use writeMappingCSV() */
    public function writeIPMappingCSV( $rows )
    {
        $this->writeMappingCSV( self::AREA_RN, $rows );
    }

    public function writeMappingCSV( $area, $rows )
    {
        $fh = fopen( $this->exportDir . "/" . $area . "/ip-mapping.csv", "w" );
        $columns = self::mappingColumns($area);
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

    public static function mappingSummary( $area, $mapping )
    {
        if( $mapping === null )
            return null;
        $summary = array( 'files' => array($area . '/ip-mapping.json', $area . '/ip-mapping.csv') );
        if( $area == self::AREA_RN )
        {
            $summary['remote_networks'] = count($mapping['remote_networks']);
            $summary['egress_matched'] = count( array_filter($mapping['remote_networks'], function($r){ return $r['egress_match'] !== 'none'; }) );
        }
        elseif( $area == self::AREA_SC )
            $summary['service_connections'] = count($mapping['service_connections']);
        else
        {
            $summary['locations'] = count($mapping['locations']);
            $summary['egress_matched'] = count( array_filter($mapping['locations'], function($r){ return $r['egress_match'] !== 'none'; }) );
        }
        return $summary;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // import hints / manifest

    /**
     * hints for later import - nothing secret is written, only counts / names
     */
    public function collectImportHints()
    {
        $hints = array();

        foreach( self::SECRET_FIELDS as $endpointName => $paths )
        {
            foreach( self::AREAS as $area )
            {
                $key = self::key($area, $endpointName);
                if( isset($this->results[$key]) && $this->results[$key]['meta']['status'] == 'ok' )
                    $hints[] = array( 'type' => 'redacted', 'area' => $area, 'endpoint' => $endpointName, 'objects' => $paths,
                        'message' => 'secret fields are not written to disk; they are tenant specific and must not be imported' );
            }
        }

        $readOnly = array();
        foreach( array('loopback_ips', 'tunnel_monitor_ip_address', 'captive_portal_redirect_ip_address', 'egress_ip_notification_url') as $field )
        {
            if( self::get( $this->singleData('shared-infrastructure-settings', self::AREA_INFRA), $field ) !== null )
                $readOnly[] = $field;
        }
        if( count($readOnly) > 0 )
            $hints[] = array( 'type' => 'derived_read_only', 'area' => self::AREA_INFRA, 'endpoint' => 'shared-infrastructure-settings', 'objects' => $readOnly,
                'message' => 'values derived by Prisma Access from infrastructure_subnet / tenant - compare only, do not import' );

        foreach( $this->connectionAreas() as $area )
        {
            $def = self::CONNECTION_AREAS[$area];
            $folder = $this->folders[$area];

            $pskGateways = array();
            foreach( $this->listData('ike-gateways', $area) as $gw )
            {
                if( self::get($gw, 'authentication.pre_shared_key') !== null )
                    $pskGateways[] = self::get($gw, 'name');
            }
            if( count($pskGateways) > 0 )
                $hints[] = array( 'type' => 'pre_shared_key', 'area' => $area, 'objects' => $pskGateways,
                    'message' => 'IKE gateways use pre-shared keys (encrypted with the master key) - create ' . $area . '/psk-list.csv (argument psk-list) to provide them for import' );

            $bgpSecrets = array();
            foreach( $this->listData($def['endpoint'], $area) as $conn )
            {
                foreach( self::BGP_SECRET_FIELDS[$def['endpoint']] as $path )
                {
                    $v = self::get($conn, $path);
                    if( $v !== null && $v !== "" )
                        $bgpSecrets[] = self::get($conn, 'name') . " [" . $path . "]";
                }
            }
            if( count($bgpSecrets) > 0 )
                $hints[] = array( 'type' => 'bgp_secret', 'area' => $area, 'objects' => $bgpSecrets,
                    'message' => 'BGP authentication secrets (encrypted with the master key) - create ' . $area . '/bgp-secret-list.csv (argument psk-list) to provide them for import' );

            foreach( array('ike-crypto-profiles', 'ipsec-crypto-profiles', 'ike-gateways', 'ipsec-tunnels', 'qos-profiles') as $type )
            {
                $inherited = array();
                foreach( $this->listData($type, $area) as $entry )
                {
                    $snippet = self::get($entry, 'snippet');
                    $entryFolder = self::get($entry, 'folder');
                    if( $snippet !== null || ( $entryFolder !== null && $entryFolder !== $folder ) )
                        $inherited[] = self::get($entry, 'name') . " [" . ( $snippet !== null ? "snippet=" . $snippet : "folder=" . $entryFolder ) . "]";
                }
                if( count($inherited) > 0 )
                    $hints[] = array( 'type' => 'inherited_or_predefined', 'area' => $area, 'endpoint' => $type, 'objects' => $inherited,
                        'message' => 'entries not defined in folder "' . $folder . '" itself (predefined / snippet / parent folder) - reference only, do not create on import' );
            }
        }

        if( $this->hasArea(self::AREA_MU) )
        {
            $folder = $this->folders[self::AREA_MU];
            foreach( $this->getAllEndpoints() as $endpoint )
            {
                if( $endpoint['area'] !== self::AREA_MU )
                    continue;
                $inherited = array();
                foreach( $this->listData($endpoint['name'], self::AREA_MU) as $entry )
                {
                    $snippet = self::get($entry, 'snippet');
                    $entryFolder = self::get($entry, 'folder');
                    if( $snippet !== null || ( $entryFolder !== null && $entryFolder !== $folder ) )
                        $inherited[] = self::get($entry, 'name') . " [" . ( $snippet !== null ? "snippet=" . $snippet : "folder=" . $entryFolder ) . "]";
                }
                if( count($inherited) > 0 )
                    $hints[] = array( 'type' => 'inherited_or_predefined', 'area' => self::AREA_MU, 'endpoint' => $endpoint['name'], 'objects' => $inherited,
                        'message' => 'entries not defined in folder "' . $folder . '" itself (predefined / snippet / parent folder) - reference only, do not create on import' );
            }

            $certs = array();
            foreach( $this->listData('certificates', self::AREA_MU) as $cert )
            {
                $name = self::get($cert, 'name');
                if( $name !== null && self::get($cert, 'snippet') === null )
                    $certs[] = $name;
            }
            if( count($certs) > 0 )
                $hints[] = array( 'type' => 'certificate_private_key', 'area' => self::AREA_MU, 'endpoint' => 'certificates', 'objects' => $certs,
                    'message' => 'private keys are not exported by the API - certificates (portal/gateway, cookie cert, CA) must be imported manually (PKCS12/PEM with key) on the target tenant before the mobile-agent settings' );

            $secrets = $this->collectSecretFields( self::AREA_MU );
            if( count($secrets) > 0 )
                $hints[] = array( 'type' => 'secret', 'area' => self::AREA_MU,
                    'objects' => array_map( function($s){ return $s['endpoint'] . ": " . $s['object'] . " [" . $s['path'] . "]"; }, $secrets ),
                    'message' => 'passwords / shared secrets (encrypted with the master key, or hashed for local users) - create ' . self::AREA_MU . '/secret-list.csv (argument psk-list) to provide them for import; hashed values need secret_new' );
        }

        if( $this->hasArea(self::AREA_PB) )
        {
            $idpGroups = array();
            foreach( $this->listData('user-groups', self::AREA_PB) as $g )
            {
                $src = strtolower( (string)self::firstOf($g, array('source', 'type', 'origin', 'groupType')) );
                if( $src !== "" && $src !== "local" )
                    $idpGroups[] = self::get($g, 'name', self::get($g, 'id')) . " [" . $src . "]";
            }
            if( count($idpGroups) > 0 )
                $hints[] = array( 'type' => 'idp_synced_groups', 'area' => self::AREA_PB, 'endpoint' => 'user-groups', 'objects' => $idpGroups,
                    'message' => 'user groups synced from an identity provider are not created by import - the IdP integration must exist on the target tenant' );

            $catalog = array();
            foreach( $this->listData('applications', self::AREA_PB) as $app )
            {
                $type = strtolower( (string)self::firstOf($app, array('type', 'applicationType', 'kind')) );
                if( $type === 'catalog' )
                    $catalog[] = self::get($app, 'name', self::get($app, 'id'));
            }
            if( count($catalog) > 0 )
                $hints[] = array( 'type' => 'inherited_or_predefined', 'area' => self::AREA_PB, 'endpoint' => 'applications', 'objects' => $catalog,
                    'message' => 'catalog applications are predefined - reference only, do not create on import' );

            $pending = $this->listData('pending-changes', self::AREA_PB);
            if( count($pending) > 0 )
                $hints[] = array( 'type' => 'unpublished_draft', 'area' => self::AREA_PB, 'endpoint' => 'pending-changes',
                    'objects' => array_map( function($c){ return (string)self::firstOf($c, array('entityType', 'type')) . ": " . (string)self::firstOf($c, array('name', 'entityName', 'id')); }, $pending ),
                    'message' => 'the source tenant has unpublished Prisma Browser changes - the export contains the active configuration' );

            $signIn = self::key(self::AREA_PB, 'policy-sign-in');
            if( isset($this->results[$signIn]) && $this->results[$signIn]['meta']['status'] === 'ok' )
                $hints[] = array( 'type' => 'publish_required', 'area' => self::AREA_PB, 'objects' => array('configuration-management/draft/publish'),
                    'message' => 'Prisma Browser changes are written to a draft - publish after import' );
        }

        if( $this->hasArea(self::AREA_IAM) )
        {
            $sa = array_map( function($a){ return (string)self::firstOf($a, array('name', 'client_id', 'id')); }, $this->listData('service-accounts', self::AREA_IAM) );
            if( count($sa) > 0 )
                $hints[] = array( 'type' => 'service_account_secret', 'area' => self::AREA_IAM, 'endpoint' => 'service-accounts', 'objects' => $sa,
                    'message' => 'service account secrets are only shown at creation - create new service accounts on the target tenant and update all tools (.panconfkeystore, automation)' );
            $policies = $this->listData('access-policies', self::AREA_IAM);
            if( count($policies) > 0 )
                $hints[] = array( 'type' => 'iam_documentation', 'area' => self::AREA_IAM, 'endpoint' => 'access-policies', 'objects' => array( count($policies) . " access policies" ),
                    'message' => 'IAM is exported for documentation / compare only; principals and TSG scopes are tenant specific - see iam/access-policies.csv' );
        }

        //service connection referencing another service connection as backup: create all first, set backup_SC afterwards
        $backup = array();
        foreach( $this->listData('service-connections', self::AREA_SC) as $sc )
        {
            $b = self::get($sc, 'backup_SC');
            if( $b !== null && $b !== "" )
                $backup[] = self::get($sc, 'name') . " -> " . $b;
        }
        if( count($backup) > 0 )
            $hints[] = array( 'type' => 'intra_dependency', 'area' => self::AREA_SC, 'endpoint' => 'service-connections', 'objects' => $backup,
                'message' => 'backup_SC references another service connection - import all service connections without backup_SC first, then set backup_SC' );

        return $hints;
    }

    /**
     * @param array $mappings [area => mapping from buildIPMapping()]
     * @param array $secretStats [area => ['psk' => stats, 'bgp_secret' => stats]]
     */
    public function writeManifest( $frameworkVersion, $mappings = array(), $secretStats = array() )
    {
        //backward compatibility: writeManifest($v, $rnMapping, $pskStats)
        if( is_array($mappings) && isset($mappings['remote_networks']) )
            $mappings = array( self::AREA_RN => $mappings );
        if( is_array($secretStats) && isset($secretStats['gateways']) )
            $secretStats = array( self::AREA_RN => array( 'psk' => $secretStats ) );
        if( $mappings === null )
            $mappings = array();
        if( $secretStats === null )
            $secretStats = array();

        $endpoints = array();
        foreach( $this->results as $r )
            $endpoints[] = $r['meta'];

        $mappingSummary = array();
        foreach( $mappings as $area => $mapping )
            $mappingSummary[$area] = self::mappingSummary($area, $mapping);

        $this->manifest = array(
            'format_version' => self::FORMAT_VERSION,
            'tool' => 'pan-os-php scm_pa_export.php',
            'areas' => $this->areas,
            'pan_os_php_version' => $frameworkVersion,
            'tsg_id' => $this->tsg,
            'api_url' => $this->connector->url_api,
            'folders' => $this->folders,
            'created_at' => date('c'),
            'import_order' => array_values( array_map( function($e){ return self::key($e['area'], $e['name']); },
                array_filter( $this->getEndpoints(), function($e){ return $e['category'] == 'dependency' && $e['fetched_as'] == 'selected'; } ) ) ),
            'endpoints' => $endpoints,
            'infra' => $this->buildInfraSummary(),
            'mobile_users' => $this->buildMobileUsersSummary(),
            'prisma_browser' => $this->buildPrismaBrowserSummary(),
            'iam' => $this->buildIAMSummary(),
            'ip_mapping' => count($mappingSummary) > 0 ? $mappingSummary : null,
            'secret_lists' => count($secretStats) > 0 ? $secretStats : null,
            'import_hints' => $this->collectImportHints(),
            'errors' => count( array_filter($endpoints, function($e){ return isset($e['status']) && $e['status'] == 'error'; }) ),
            'unavailable' => array_values( array_map( function($e){ return self::key($e['area'], $e['name']); },
                array_filter($endpoints, function($e){ return isset($e['status']) && $e['status'] == 'unavailable'; }) ) ),
        );
        $this->manifest['migration_checklist'] = $this->buildMigrationChecklist( $this->manifest );

        $this->writeJson( 'manifest.json', $this->manifest );
        $this->writeMigrationChecklistMarkdown( $this->manifest['migration_checklist'] );

        return $this->manifest;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // secret lists (PSK, BGP secret)

    const PSK_DECRYPT_FAILED = 'DECRYPT_FAILED';
    const PSK_LIST_COLUMNS = array( 'ike_gateway', 'ipsec_tunnel', 'remote_network', 'branch_peer_address', 'psk_current', 'psk_new' );
    const PSK_LIST_COLUMNS_SC = array( 'ike_gateway', 'ipsec_tunnel', 'service_connection', 'peer_address', 'psk_current', 'psk_new' );
    const BGP_SECRET_LIST_COLUMNS = array( 'object', 'field', 'bgp_peer_ip_address', 'secret_current', 'secret_new' );

    /**
     * opens a file with mode 0600 for cleartext secrets
     */
    private function openSecretFile( $file )
    {
        $oldUmask = umask(0077);
        $fh = fopen( $file, "w" );
        umask($oldUmask);
        if( $fh === false )
            derr( "not possible to write " . $file, null, FALSE );
        chmod( $file, 0600 );
        return $fh;
    }

    /**
     * @return string cleartext or self::PSK_DECRYPT_FAILED
     */
    private static function decryptValue( PanosCrypto $crypto, $encrypted, $masterKey, &$stats )
    {
        try
        {
            //PanosCrypto::decrypt() returns "" instead of throwing on wrong master key / invalid format
            $cleartext = $crypto->decrypt( (string)$encrypted, $masterKey );
            if( $cleartext === "" )
                throw new Exception("decrypt failed");
            $stats['decrypted']++;
            return $cleartext;
        }
        catch( Exception $e )
        {
            $stats['decrypt_failed']++;
            return self::PSK_DECRYPT_FAILED;
        }
    }

    /**
     * writes <area>/psk-list.csv (one row per IKE gateway) with the decrypted current PSK and an empty psk_new column
     * file permissions 0600 - contains cleartext secrets, never referenced by name in manifest / ip-mapping
     *
     * @param string|null $masterKey null = PAN-OS default master key
     * @param string $area self::AREA_RN (default) or self::AREA_SC
     * @return array statistics ['gateways' => int, 'decrypted' => int, 'decrypt_failed' => int, 'without_psk' => int]
     */
    public function writePSKList( $masterKey = null, $area = self::AREA_RN )
    {
        $def = self::CONNECTION_AREAS[$area];
        $crypto = new PanosCrypto();

        //reverse references: gateway -> tunnels, tunnel -> connections
        $gatewayTunnels = array();
        foreach( $this->listData('ipsec-tunnels', $area) as $tunnel )
        {
            foreach( self::tunnelGatewayNames($tunnel) as $gwName )
                $gatewayTunnels[$gwName][] = self::get($tunnel, 'name');
        }
        $tunnelConnections = array();
        foreach( $this->listData($def['endpoint'], $area) as $conn )
        {
            foreach( array('ipsec_tunnel', 'secondary_ipsec_tunnel') as $field )
            {
                $tunnelName = self::get($conn, $field);
                if( $tunnelName !== null )
                    $tunnelConnections[$tunnelName][] = self::get($conn, 'name');
            }
        }

        $stats = array( 'gateways' => 0, 'decrypted' => 0, 'decrypt_failed' => 0, 'without_psk' => 0 );

        $fh = $this->openSecretFile( $this->exportDir . "/" . $area . "/psk-list.csv" );
        fputcsv( $fh, $area == self::AREA_RN ? self::PSK_LIST_COLUMNS : self::PSK_LIST_COLUMNS_SC, ',', '"', '' );

        foreach( $this->listData('ike-gateways', $area) as $gw )
        {
            $encrypted = self::get($gw, 'authentication.pre_shared_key.key');
            if( $encrypted === null )
            {
                $stats['without_psk']++;
                continue;
            }
            $stats['gateways']++;

            $cleartext = self::decryptValue( $crypto, $encrypted, $masterKey, $stats );

            $gwName = self::get($gw, 'name');
            $tunnels = isset($gatewayTunnels[$gwName]) ? $gatewayTunnels[$gwName] : array();
            $conns = array();
            foreach( $tunnels as $tunnelName )
            {
                if( isset($tunnelConnections[$tunnelName]) )
                    $conns = array_merge( $conns, $tunnelConnections[$tunnelName] );
            }

            fputcsv( $fh, array( $gwName, implode(" | ", $tunnels), implode(" | ", array_unique($conns)), implode(" | ", self::peerAddressList($gw)), $cleartext, "" ), ',', '"', '' );
        }
        fclose( $fh );

        return $stats;
    }

    /**
     * writes <area>/bgp-secret-list.csv (one row per connection and BGP secret field), mode 0600
     *
     * @return array statistics ['secrets' => int, 'decrypted' => int, 'decrypt_failed' => int]
     */
    public function writeBGPSecretList( $masterKey = null, $area = self::AREA_RN )
    {
        $def = self::CONNECTION_AREAS[$area];
        $crypto = new PanosCrypto();
        $stats = array( 'secrets' => 0, 'decrypted' => 0, 'decrypt_failed' => 0 );

        $fh = $this->openSecretFile( $this->exportDir . "/" . $area . "/bgp-secret-list.csv" );
        fputcsv( $fh, self::BGP_SECRET_LIST_COLUMNS, ',', '"', '' );

        foreach( $this->listData($def['endpoint'], $area) as $conn )
        {
            foreach( self::BGP_SECRET_FIELDS[$def['endpoint']] as $path )
            {
                $encrypted = self::get($conn, $path);
                if( $encrypted === null || $encrypted === "" )
                    continue;
                $stats['secrets']++;

                $peerPath = ( strpos($path, 'bgp_peer.') === 0 ) ? 'bgp_peer.peer_ip_address' : 'protocol.bgp.peer_ip_address';
                fputcsv( $fh, array( self::get($conn, 'name'), $path, self::get($conn, $peerPath),
                    self::decryptValue( $crypto, $encrypted, $masterKey, $stats ), "" ), ',', '"', '' );
            }
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
        $list = self::loadSecretCSV( $file, array('ike_gateway'), 'psk_current', 'psk_new' );
        return array( 'psk' => $list['secret'], 'source' => $list['source'], 'errors' => $list['errors'] );
    }

    /**
     * reads a bgp-secret-list.csv for import: secret_new if filled, otherwise secret_current
     *
     * @return array ['secret' => ["<object>|<field>" => cleartext], 'source' => [...], 'errors' => [...]]
     */
    public static function loadBGPSecretList( $file )
    {
        return self::loadSecretCSV( $file, array('object', 'field'), 'secret_current', 'secret_new' );
    }

    /**
     * generic loader: key columns joined with '|', value = new column if filled, else current column
     */
    public static function loadSecretCSV( $file, $keyColumns, $currentColumn, $newColumn )
    {
        if( !is_readable($file) )
            derr( "secret list not readable: " . $file, null, FALSE );

        $fh = fopen( $file, "r" );
        $header = fgetcsv( $fh, 0, ',', '"', '' );
        if( $header === false )
            derr( "secret list is empty: " . $file, null, FALSE );
        $header = array_map( 'trim', $header );
        foreach( array_merge($keyColumns, array($currentColumn, $newColumn)) as $required )
        {
            if( !in_array($required, $header, TRUE) )
                derr( "secret list " . $file . " has no column '" . $required . "'", null, FALSE );
        }

        $result = array( 'secret' => array(), 'source' => array(), 'errors' => array() );
        $lineNo = 1;
        while( ($line = fgetcsv( $fh, 0, ',', '"', '' )) !== false )
        {
            $lineNo++;
            if( count($line) == 1 && trim((string)$line[0]) === "" )
                continue;
            $row = array();
            foreach( $header as $i => $col )
                $row[$col] = isset($line[$i]) ? $line[$i] : "";

            $keyParts = array();
            foreach( $keyColumns as $c )
                $keyParts[] = trim( $row[$c] );
            $key = implode( "|", $keyParts );
            if( in_array("", $keyParts, TRUE) )
            {
                $result['errors']["line " . $lineNo] = "empty " . implode("/", $keyColumns);
                continue;
            }
            if( isset($result['secret'][$key]) || isset($result['errors'][$key]) )
            {
                $result['errors'][$key] = "duplicate entry (line " . $lineNo . ")";
                unset( $result['secret'][$key], $result['source'][$key] );
                continue;
            }

            //values are used as written - no trim, whitespace may be part of the key
            if( $row[$newColumn] !== "" )
            {
                $result['secret'][$key] = $row[$newColumn];
                $result['source'][$key] = 'new';
            }
            elseif( $row[$currentColumn] !== "" && $row[$currentColumn] !== self::PSK_DECRYPT_FAILED && $row[$currentColumn] !== self::SECRET_HASHED )
            {
                $result['secret'][$key] = $row[$currentColumn];
                $result['source'][$key] = 'current';
            }
            else
                $result['errors'][$key] = $newColumn . " empty and " . $currentColumn . " not available (" . ( $row[$currentColumn] === "" ? "empty" : $row[$currentColumn] ) . ")";
        }
        fclose( $fh );

        return $result;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // mobile users

    const MU_MAPPING_COLUMNS = array( 'deployment_region', 'location', 'location_display',
        'gp_gateway_active', 'gp_gateway_pre_allocated', 'gp_portal_active', 'gp_portal_pre_allocated', 'egress_match' );

    /**
     * MU locations (mobile-agent-infrastructure-settings deployment.region[].locations[], fallback mobile-agent-locations)
     * with their GlobalProtect gateway / portal egress IPs (active / pre-allocated)
     */
    public function buildMobileUsersMapping()
    {
        $infraSettings = $this->singleData('mobile-agent-infrastructure-settings', self::AREA_MU);
        $locations = $this->listData('locations', self::AREA_INFRA);
        $egressByZone = array();
        foreach( $this->listData('egress-ip', self::AREA_INFRA) as $zoneEntry )
        {
            if( isset($zoneEntry['zone']) )
                $egressByZone[$zoneEntry['zone']] = $zoneEntry;
        }

        //region => [location, ...]
        $regions = array();
        $deployment = self::get($infraSettings, 'deployment.region');
        if( is_array($deployment) )
        {
            foreach( $deployment as $region )
                $regions[ (string)self::get($region, 'name') ] = (array)self::get($region, 'locations', array());
        }
        if( count($regions) == 0 )
        {
            //fallback: mobile-agent/locations (structure to be verified against a live tenant)
            foreach( $this->listData('mobile-agent-locations', self::AREA_MU) as $entry )
            {
                $locList = self::get($entry, 'locations');
                if( is_array($locList) )
                    $regions[ (string)self::get($entry, 'name', self::get($entry, 'region', '')) ] = $locList;
            }
        }

        $rows = array();
        foreach( $regions as $regionName => $locList )
        {
            foreach( $locList as $location )
            {
                $location = is_array($location) ? self::get($location, 'name', json_encode($location)) : (string)$location;
                $display = self::locationDisplayForRegion( $locations, $location );
                $row = array(
                    'deployment_region' => $regionName,
                    'location' => $location,
                    'location_display' => $display,
                    'gp_gateway_active' => array(), 'gp_gateway_pre_allocated' => array(),
                    'gp_portal_active' => array(), 'gp_portal_pre_allocated' => array(),
                    'egress_match' => 'none',
                );
                if( $display !== null && isset($egressByZone[$display]) )
                {
                    foreach( array('gp_gateway', 'gp_portal') as $serviceType )
                    {
                        foreach( self::egressDetails( $egressByZone[$display], $serviceType ) as $detail )
                        {
                            $pre = in_array( self::get($detail, 'addressType'), array('pre_allocated', 'pre-allocated'), TRUE );
                            $row[ $serviceType . ( $pre ? '_pre_allocated' : '_active' ) ][] = $detail['address'];
                        }
                    }
                    $row['egress_match'] = 'location';
                }
                $rows[] = $row;
            }
        }

        $mapping = array(
            'tsg_id' => $this->tsg,
            'area' => self::AREA_MU,
            'created_at' => date('c'),
            'portal_hostname' => self::get($infraSettings, 'name'),
            'note' => 'egress IPs per MU location via location value -> infra/90_locations.json display -> egress zone (serviceType gp_gateway / gp_portal); a new tenant gets new IPs - allow lists of SaaS / partners must be updated',
            'locations' => $rows,
        );

        $this->writeJson( self::AREA_MU . '/ip-mapping.json', $mapping );

        $fh = fopen( $this->exportDir . "/" . self::AREA_MU . "/ip-mapping.csv", "w" );
        fputcsv( $fh, self::MU_MAPPING_COLUMNS, ',', '"', '' );
        foreach( $rows as $row )
        {
            $line = array();
            foreach( self::MU_MAPPING_COLUMNS as $c )
                $line[] = is_array($row[$c]) ? implode(" | ", $row[$c]) : $row[$c];
            fputcsv( $fh, $line, ',', '"', '' );
        }
        fclose( $fh );

        return $mapping;
    }

    /**
     * address_details of one zone for one serviceType; fallback to 'addresses' only if no details exist
     */
    public static function egressDetails( $zoneEntry, $serviceType )
    {
        $list = array();
        if( isset($zoneEntry['address_details']) && is_array($zoneEntry['address_details']) )
        {
            foreach( $zoneEntry['address_details'] as $detail )
            {
                if( self::get($detail, 'serviceType') === $serviceType && self::get($detail, 'address') !== null )
                    $list[] = $detail;
            }
        }
        return $list;
    }

    /**
     * short, comparable MU summary (written to manifest.json)
     */
    public function buildMobileUsersSummary()
    {
        if( !$this->hasArea(self::AREA_MU) )
            return null;

        $infraSettings = $this->singleData('mobile-agent-infrastructure-settings', self::AREA_MU);

        $ipPools = array();
        foreach( (array)self::get($infraSettings, 'ip_pools', array()) as $pool )
            $ipPools[ (string)self::get($pool, 'name') ] = self::get($pool, 'ip_pool');

        $regions = array();
        foreach( (array)self::get($infraSettings, 'deployment.region', array()) as $region )
            $regions[ (string)self::get($region, 'name') ] = count( (array)self::get($region, 'locations', array()) );

        $authProfiles = array();
        foreach( $this->listData('mobile-agent-authentication-settings', self::AREA_MU) as $auth )
            $authProfiles[] = self::get($auth, 'authentication_profile');

        $names = function( $endpoint ){
            return array_values( array_filter( array_map( function($e){ return self::get($e, 'name'); }, $this->listData($endpoint, self::AREA_MU) ) ) );
        };

        return array(
            'portal_hostname' => self::get($infraSettings, 'name'),
            'ip_pools' => $ipPools,
            'deployment_regions' => $regions,
            'dns_servers' => count( (array)self::get($infraSettings, 'dns_servers', array()) ),
            'agent_profiles' => $names('mobile-agent-agent-profiles'),
            'tunnel_profiles' => $names('mobile-agent-tunnel-profiles'),
            'authentication_profiles_used' => array_values( array_unique( array_filter($authProfiles) ) ),
            'authentication_profiles' => $names('authentication-profiles'),
            'certificates' => $names('certificates'),
            'local_users' => count( $this->listData('local-users', self::AREA_MU) ),
        );
    }

    ////////////////////////////////////////////////////////////////////////////////
    // generic secret list (mobile-users: server profile passwords / secrets, local user passwords, GP app passwords)

    const SECRET_HASHED = 'HASHED';
    const SECRET_LIST_COLUMNS = array( 'endpoint', 'object', 'path', 'secret_current', 'secret_new' );
    /** field names treated as secret (last path element) */
    const SECRET_KEY_PATTERN = '/(^|_)(secret|password|passwd|passphrase|key)$/i';
    /** field names matching SECRET_KEY_PATTERN which are not secret */
    const SECRET_KEY_EXCLUDE = '/^(public_key|key_type|key_size|key_usage|api_key_header)$/i';
    /** name/value lists (e.g. gp_app_config.config[]) - entry name treated as secret */
    const SECRET_NAME_PATTERN = '/(password|passcode|override-key|secret)/i';

    /**
     * all secret fields of an area: [['endpoint', 'object', 'path', 'value'], ...]
     */
    public function collectSecretFields( $area )
    {
        $found = array();
        foreach( $this->getAllEndpoints() as $endpoint )
        {
            if( $endpoint['area'] !== $area )
                continue;
            $list = $this->listData($endpoint['name'], $area);
            if( count($list) == 0 && ($single = $this->singleData($endpoint['name'], $area)) !== null )
                $list = array( $single );
            foreach( $list as $entry )
            {
                $object = (string)self::get($entry, 'name', '');
                self::scanSecrets( $entry, "", function( $path, $value ) use( &$found, $endpoint, $object ) {
                    $found[] = array( 'endpoint' => $endpoint['name'], 'object' => $object, 'path' => $path, 'value' => $value );
                } );
            }
        }
        return $found;
    }

    private static function scanSecrets( $data, $prefix, $callback )
    {
        if( !is_array($data) )
            return;

        //name/value pair
        if( isset($data['name']) && is_string($data['name']) && array_key_exists('value', $data)
            && preg_match(self::SECRET_NAME_PATTERN, $data['name']) )
        {
            $value = is_array($data['value']) ? ( count($data['value']) == 1 ? reset($data['value']) : json_encode($data['value']) ) : $data['value'];
            if( $value !== null && $value !== "" )
                $callback( ltrim($prefix . ".value", "."), (string)$value );
            return;
        }

        foreach( $data as $k => $v )
        {
            $path = $prefix === "" ? (string)$k : $prefix . "." . $k;
            if( is_array($v) )
                self::scanSecrets( $v, $path, $callback );
            elseif( is_string($k) && preg_match(self::SECRET_KEY_PATTERN, $k) && !preg_match(self::SECRET_KEY_EXCLUDE, $k)
                && $v !== null && $v !== "" && !is_bool($v) )
                $callback( $path, (string)$v );
        }
    }

    /**
     * writes <area>/secret-list.csv (mode 0600): encrypted values ("-...") are decrypted, hashes ("$...") marked HASHED
     *
     * @return array ['secrets' => int, 'decrypted' => int, 'decrypt_failed' => int, 'hashed' => int, 'cleartext' => int]
     */
    public function writeSecretList( $area, $masterKey = null )
    {
        $crypto = new PanosCrypto();
        $stats = array( 'secrets' => 0, 'decrypted' => 0, 'decrypt_failed' => 0, 'hashed' => 0, 'cleartext' => 0 );

        $fh = $this->openSecretFile( $this->exportDir . "/" . $area . "/secret-list.csv" );
        fputcsv( $fh, self::SECRET_LIST_COLUMNS, ',', '"', '' );

        foreach( $this->collectSecretFields($area) as $secret )
        {
            $stats['secrets']++;
            $value = $secret['value'];
            if( strpos($value, '-') === 0 )
                $current = self::decryptValue( $crypto, $value, $masterKey, $stats );
            elseif( strpos($value, '$') === 0 )
            {
                $current = self::SECRET_HASHED;
                $stats['hashed']++;
            }
            else
            {
                $current = $value;
                $stats['cleartext']++;
            }
            fputcsv( $fh, array( $secret['endpoint'], $secret['object'], $secret['path'], $current, "" ), ',', '"', '' );
        }
        fclose( $fh );

        return $stats;
    }

    /**
     * reads a secret-list.csv for import: secret_new if filled, otherwise secret_current (not HASHED / DECRYPT_FAILED)
     *
     * @return array ['secret' => ["<endpoint>|<object>|<path>" => cleartext], 'source' => [...], 'errors' => [...]]
     */
    public static function loadSecretList( $file )
    {
        return self::loadSecretCSV( $file, array('endpoint', 'object', 'path'), 'secret_current', 'secret_new' );
    }

    ////////////////////////////////////////////////////////////////////////////////
    // prisma browser / iam

    public function buildPrismaBrowserSummary()
    {
        if( !$this->hasArea(self::AREA_PB) )
            return null;
        $policy = function( $name ){
            $data = $this->singleData($name, self::AREA_PB);
            if( $data === null )
                return null;
            $rules = self::firstOf($data, array('rules', 'policy.rules'));
            $sections = self::firstOf($data, array('sections', 'policy.sections'));
            return array( 'rules' => is_array($rules) ? count($rules) : null, 'sections' => is_array($sections) ? count($sections) : null );
        };
        return array(
            'user_groups' => count( $this->listData('user-groups', self::AREA_PB) ),
            'device_groups' => count( $this->listData('device-groups', self::AREA_PB) ),
            'applications' => count( $this->listData('applications', self::AREA_PB) ),
            'application_groups' => count( $this->listData('application-groups', self::AREA_PB) ),
            'policy_sign_in' => $policy('policy-sign-in'),
            'policy_access_and_data' => $policy('policy-access-and-data'),
            'policy_security' => $policy('policy-security'),
            'policy_customization' => $policy('policy-customization'),
            'pending_changes' => count( $this->listData('pending-changes', self::AREA_PB) ),
        );
    }

    const IAM_POLICY_COLUMNS = array( 'principal', 'principal_type', 'role', 'resource', 'principal_new', 'resource_new' );

    /**
     * iam/access-policies.csv: one row per access policy, *_new columns to fill in for the target tenant
     */
    public function buildIAMSummary()
    {
        if( !$this->hasArea(self::AREA_IAM) )
            return null;

        $rows = array();
        foreach( $this->listData('access-policies', self::AREA_IAM) as $p )
        {
            $principal = self::firstOf($p, array('principal', 'principal_id', 'email', 'principal_display_name'));
            $role = self::firstOf($p, array('role', 'role_name', 'role.name'));
            $resource = self::firstOf($p, array('resource', 'resource_id', 'scope'));
            $rows[] = array(
                'principal' => is_array($principal) ? json_encode($principal) : $principal,
                'principal_type' => self::firstOf($p, array('principal_type', 'type')),
                'role' => is_array($role) ? json_encode($role) : $role,
                'resource' => is_array($resource) ? json_encode($resource) : $resource,
                'principal_new' => '', 'resource_new' => '',
            );
        }

        if( $this->exportDir !== null && is_dir($this->exportDir . "/" . self::AREA_IAM) )
        {
            $fh = fopen( $this->exportDir . "/" . self::AREA_IAM . "/access-policies.csv", "w" );
            fputcsv( $fh, self::IAM_POLICY_COLUMNS, ',', '"', '' );
            foreach( $rows as $row )
                fputcsv( $fh, array_values($row), ',', '"', '' );
            fclose( $fh );
        }

        $byRole = array();
        foreach( $rows as $row )
        {
            $r = (string)$row['role'];
            $byRole[$r] = ( isset($byRole[$r]) ? $byRole[$r] : 0 ) + 1;
        }
        ksort($byRole);

        $names = function( $endpoint ){
            return array_values( array_filter( array_map( function($e){ return self::firstOf($e, array('name', 'role_name', 'client_id', 'id')); }, $this->listData($endpoint, self::AREA_IAM) ) ) );
        };

        return array(
            'access_policies' => count($rows),
            'access_policies_by_role' => $byRole,
            'custom_roles' => $names('custom-roles'),
            'permission_sets' => $names('permission-sets'),
            'service_accounts' => $names('service-accounts'),
            'files' => array( self::AREA_IAM . '/access-policies.csv' ),
        );
    }

    ////////////////////////////////////////////////////////////////////////////////
    // migration checklist

    /**
     * items to do / check for a migration to a new tenant: from the export (hints, counts) plus fixed items
     * status: action_required | check | info
     */
    public function buildMigrationChecklist( $manifest )
    {
        $items = array();
        $add = function( $id, $status, $area, $title, $detail, $objects = array() ) use( &$items ) {
            $items[] = array( 'id' => $id, 'status' => $status, 'area' => $area, 'title' => $title, 'detail' => $detail, 'objects' => array_values($objects) );
        };
        $hint = function( $type, $area = null ) use( $manifest ) {
            $objects = array();
            foreach( $manifest['import_hints'] as $h )
            {
                if( $h['type'] == $type && ( $area === null || $h['area'] == $area ) )
                    $objects = array_merge( $objects, $h['objects'] );
            }
            return $objects;
        };
        $secretList = function( $area ) use( $manifest ) {
            return isset($manifest['secret_lists'][$area]);
        };

        //licence
        $bandwidth = 0;
        foreach( $this->listData('bandwidth-allocations', self::AREA_RN) as $bw )
            $bandwidth += (int)self::get($bw, 'allocated_bandwidth', 0);
        $add( 'license', 'check', 'tenant', 'Prisma Access license / units on the target tenant',
            'allocate the Prisma Access license (units, MU count, RN bandwidth) to the target TSG before importing'
            . ( $bandwidth > 0 ? '; source RN bandwidth allocated: ' . $bandwidth . ' Mbps' : '' ) );

        if( $manifest['errors'] > 0 )
            $add( 'export_errors', 'action_required', 'export', 'Endpoints failed during export', 'check manifest.json endpoints with status error',
                array_map( function($e){ return self::key($e['area'], $e['name']) . ": " . (isset($e['error']) ? $e['error'] : ''); },
                    array_filter( $manifest['endpoints'], function($e){ return isset($e['status']) && $e['status'] == 'error'; } ) ) );
        if( count($manifest['unavailable']) > 0 )
            $add( 'unavailable', 'check', 'export', 'Endpoints not available', 'product not licensed or the service account has no permission (HTTP 401/403/404)', $manifest['unavailable'] );

        //secrets
        foreach( array( self::AREA_RN, self::AREA_SC ) as $area )
        {
            $psk = $hint('pre_shared_key', $area);
            if( count($psk) > 0 )
                $add( 'psk_' . $area, $secretList($area) ? 'check' : 'action_required', $area, 'IKE pre-shared keys',
                    $secretList($area) ? 'review ' . $area . '/psk-list.csv (psk_new optional)' : 'run the export with psk-list to create ' . $area . '/psk-list.csv', $psk );
            $bgp = $hint('bgp_secret', $area);
            if( count($bgp) > 0 )
                $add( 'bgp_secret_' . $area, $secretList($area) ? 'check' : 'action_required', $area, 'BGP authentication secrets',
                    $secretList($area) ? 'review ' . $area . '/bgp-secret-list.csv' : 'run the export with psk-list to create ' . $area . '/bgp-secret-list.csv', $bgp );
        }
        $muSecrets = $hint('secret', self::AREA_MU);
        if( count($muSecrets) > 0 )
            $add( 'secret_' . self::AREA_MU, 'action_required', self::AREA_MU, 'Passwords / shared secrets (server profiles, local users, GP app)',
                $secretList(self::AREA_MU) ? 'fill secret_new in mobile-users/secret-list.csv for HASHED / DECRYPT_FAILED entries' : 'run the export with psk-list to create mobile-users/secret-list.csv', $muSecrets );

        $certs = $hint('certificate_private_key', self::AREA_MU);
        if( count($certs) > 0 )
            $add( 'certificates', 'action_required', self::AREA_MU, 'Certificates with private key',
                'import the certificates incl. private key (PKCS12 / PEM) on the target tenant before the mobile-agent settings', $certs );

        //new IPs on the target tenant
        if( isset($manifest['ip_mapping'][self::AREA_RN]) && $manifest['ip_mapping'][self::AREA_RN]['remote_networks'] > 0 )
            $add( 'ips_rn', 'action_required', self::AREA_RN, 'Branch firewalls: new Prisma Access IPs',
                'update IKE peer / service IP and allow lists on the branch side - see remote-networks/ip-mapping.csv',
                array( $manifest['ip_mapping'][self::AREA_RN]['remote_networks'] . " remote networks" ) );
        if( isset($manifest['ip_mapping'][self::AREA_SC]) && $manifest['ip_mapping'][self::AREA_SC]['service_connections'] > 0 )
            $add( 'ips_sc', 'action_required', self::AREA_SC, 'Data center / CAN firewalls: new service connection IPs',
                'update IKE peer and BGP on the data center side - see service-connections/ip-mapping.csv',
                array( $manifest['ip_mapping'][self::AREA_SC]['service_connections'] . " service connections" ) );
        if( isset($manifest['ip_mapping'][self::AREA_MU]) && $manifest['ip_mapping'][self::AREA_MU]['locations'] > 0 )
            $add( 'ips_mu', 'action_required', self::AREA_MU, 'Allow lists: new GlobalProtect egress IPs',
                'SaaS / partner allow lists must contain the new gateway / portal egress IPs - see mobile-users/ip-mapping.csv; portal hostname: '
                . json_encode( isset($manifest['mobile_users']['portal_hostname']) ? $manifest['mobile_users']['portal_hostname'] : null ) );

        $intra = $hint('intra_dependency', self::AREA_SC);
        if( count($intra) > 0 )
            $add( 'backup_sc', 'check', self::AREA_SC, 'Service connections with backup_SC', 'create all service connections first, then set backup_SC', $intra );

        $derived = $hint('derived_read_only', self::AREA_INFRA);
        if( count($derived) > 0 )
            $add( 'derived', 'info', self::AREA_INFRA, 'Values derived by Prisma Access', 'loopbacks / tunnel monitor IP etc. are calculated on the target tenant - compare only', $derived );

        if( $this->hasArea(self::AREA_INFRA) )
            $add( 'egress_api_key', 'info', self::AREA_INFRA, 'Egress-IP API key', 'the target tenant has its own egress-IP API key (.panconfkeystore egressip_tsg_id<TSG>)' );

        //not exported
        $sharedInfra = $this->singleData('shared-infrastructure-settings', self::AREA_INFRA);
        $ztna = array();
        foreach( array('connector_connector_blocks', 'connector_application_blocks') as $f )
        {
            $members = self::get($sharedInfra, $f . '.member');
            if( is_array($members) && count($members) > 0 )
                $ztna[] = $f . ": " . implode(", ", $members);
        }
        $add( 'ztna_connector', count($ztna) > 0 ? 'action_required' : 'check', self::AREA_INFRA, 'ZTNA connector (not exported)',
            'ZTNA connector groups / applications use a separate API and are not part of this export', $ztna );
        if( $this->hasArea(self::AREA_MU) )
            $add( 'explicit_proxy', 'check', self::AREA_MU, 'Mobile Users Explicit Proxy (not exported)',
                'no documented public API - configure manually or via the internal SCM API (to be added)' );
        $add( 'identity_logging', 'check', 'tenant', 'Cloud Identity Engine, Strata Logging Service, log forwarding (not exported)',
            'tenant bound services - set up on the target tenant before the configuration that references them' );
        $add( 'objects_policies', 'info', 'tenant', 'Objects and security policy',
            'not part of this export - use pan-os-php in=scm-api://<TSG> for folders / snippets / objects / rules' );

        $pbOk = FALSE;
        foreach( $manifest['endpoints'] as $e )
        {
            if( $e['area'] == self::AREA_PB && isset($e['status']) && $e['status'] == 'ok' )
                $pbOk = TRUE;
        }
        if( $this->hasArea(self::AREA_PB) && $pbOk )
        {
            $idp = $hint('idp_synced_groups', self::AREA_PB);
            if( count($idp) > 0 )
                $add( 'pb_idp_groups', 'check', self::AREA_PB, 'IdP-synced user groups', 'the IdP integration must exist on the target tenant', $idp );
            $draft = $hint('unpublished_draft', self::AREA_PB);
            if( count($draft) > 0 )
                $add( 'pb_draft', 'check', self::AREA_PB, 'Unpublished Prisma Browser changes on the source tenant', 'export contains the active configuration', $draft );
            $add( 'pb_publish', 'info', self::AREA_PB, 'Publish Prisma Browser draft', 'POST /seb-api/v1/configuration-management/draft/publish after import; logos / assets must be uploaded again' );
        }
        if( $this->hasArea(self::AREA_IAM) && isset($manifest['iam'])
            && ( $manifest['iam']['access_policies'] > 0 || count($manifest['iam']['service_accounts']) > 0 ) )
        {
            $sa = $hint('service_account_secret', self::AREA_IAM);
            $add( 'iam', 'action_required', self::AREA_IAM, 'IAM: users, roles, service accounts',
                'create access policies on the target TSG (iam/access-policies.csv: principal_new / resource_new); service account secrets cannot be exported - create new ones', $sa );
        }

        $add( 'push', 'info', 'tenant', 'Push configuration', 'after import push the configuration (config-versions candidate:push) and check the jobs' );

        return $items;
    }

    public function writeMigrationChecklistMarkdown( $items )
    {
        if( $this->exportDir === null )
            return;
        $order = array( 'action_required' => 0, 'check' => 1, 'info' => 2 );
        usort( $items, function($a, $b) use( $order ){ return $order[$a['status']] - $order[$b['status']]; } );

        $md = "# Migration checklist - TSG " . $this->tsg . "\n\n";
        $md .= "Generated by scm_pa_export.php on " . date('c') . " for areas: " . implode(", ", $this->areas) . ".\n\n";
        $md .= "| status | area | item | detail |\n|---|---|---|---|\n";
        foreach( $items as $i )
        {
            $detail = $i['detail'];
            if( count($i['objects']) > 0 )
            {
                $shown = array_slice($i['objects'], 0, 10);
                $detail .= "<br>" . implode(", ", $shown) . ( count($i['objects']) > 10 ? " … (+" . (count($i['objects']) - 10) . ")" : "" );
            }
            $md .= "| " . $i['status'] . " | " . $i['area'] . " | " . str_replace("|", "\\|", $i['title']) . " | " . str_replace(array("|", "\n"), array("\\|", " "), $detail) . " |\n";
        }
        file_put_contents( $this->exportDir . "/MIGRATION_CHECKLIST.md", $md );
    }

    /**
     * first non-null of several dotted paths
     */
    public static function firstOf( $array, $paths )
    {
        foreach( $paths as $path )
        {
            $v = self::get($array, $path);
            if( $v !== null )
                return $v;
        }
        return null;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // infra

    /**
     * short, comparable summary of the infrastructure settings (written to manifest.json)
     */
    public function buildInfraSummary()
    {
        if( !$this->hasArea(self::AREA_INFRA) )
            return null;

        $shared = $this->singleData('shared-infrastructure-settings', self::AREA_INFRA);
        $bgp = $this->singleData('bgp-routing', self::AREA_INFRA);

        $dnsServers = array();
        foreach( $this->listData('internal-dns-servers', self::AREA_INFRA) as $dns )
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
            'locations' => count( $this->listData('locations', self::AREA_INFRA) ),
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

    /**
     * list data of an endpoint; single-object endpoints return an empty list
     */
    public function listData( $name, $area )
    {
        $key = self::key($area, $name);
        if( !isset($this->results[$key]) || !is_array($this->results[$key]['data']) )
            return array();
        $data = $this->results[$key]['data'];
        if( count($data) > 0 && array_keys($data) !== range(0, count($data) - 1) )
            return array();
        return $data;
    }

    /**
     * data of a single-object endpoint (e.g. shared-infrastructure-settings); a list with one entry is unwrapped
     */
    public function singleData( $name, $area )
    {
        $key = self::key($area, $name);
        if( !isset($this->results[$key]) || !is_array($this->results[$key]['data']) )
            return null;
        $data = $this->results[$key]['data'];
        if( count($data) == 0 )
            return null;
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
     * IKE gateway names referenced by an IPsec tunnel (auto_key.ike_gateway[].name)
     */
    public static function tunnelGatewayNames( $tunnel )
    {
        $names = array();
        $gwList = self::get($tunnel, 'auto_key.ike_gateway');
        if( !is_array($gwList) )
            return $names;
        foreach( $gwList as $gwRef )
        {
            $gwName = is_array($gwRef) ? self::get($gwRef, 'name') : $gwRef;
            if( $gwName !== null )
                $names[] = $gwName;
        }
        return $names;
    }

    /**
     * peer_address of an IKE gateway as "type=value" strings (ip / fqdn / dynamic)
     */
    public static function peerAddressList( $gateway )
    {
        $list = array();
        $peer = self::get($gateway, 'peer_address');
        if( is_array($peer) )
        {
            foreach( $peer as $peerType => $peerValue )
                $list[] = $peerType . "=" . ( is_array($peerValue) ? json_encode($peerValue) : (string)$peerValue );
        }
        return $list;
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
