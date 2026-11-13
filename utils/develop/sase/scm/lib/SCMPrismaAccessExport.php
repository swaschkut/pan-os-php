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
 *       config/                                     (folders / snippets, objects, security, zones)
 *           01_folders.json, 02_snippets.json, hierarchy.json, hierarchy.txt
 *           folders/<container>/NN_<type>.json, snippets/<snippet>/NN_<type>.json   (objects owned by that container)
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
    const FORMAT_VERSION = 8;

    const AREA_INFRA = 'infra';
    const AREA_RN = 'remote-networks';
    const AREA_SC = 'service-connections';
    const AREA_MU = 'mobile-users';
    const AREA_PB = 'prisma-browser';
    const AREA_IAM = 'iam';
    const AREA_CONFIG = 'config';
    /** area order == import order (iam: documentation only) */
    const AREAS = array( self::AREA_INFRA, self::AREA_CONFIG, self::AREA_RN, self::AREA_SC, self::AREA_MU, self::AREA_PB, self::AREA_IAM );

    /** config area options, set by the CLI: container / type filter, device folders, predefined snippets */
    public $configOptions = array( 'containers' => null, 'types' => null, 'scope' => null, 'devices' => false, 'predefined_snippets' => false, 'mode' => 'leaf' );

    /** @var array|null config hierarchy (folders, snippets) after exportConfig() */
    public $configHierarchy = null;

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

        if( $this->hasArea(self::AREA_CONFIG) && $this->configStats !== null && count($this->configStats['owners_not_exported']) > 0 )
            $hints[] = array( 'type' => 'owner_not_exported', 'area' => self::AREA_CONFIG,
                'objects' => array_map( function($k, $v){ return $k . " (" . $v . ")"; }, array_keys($this->configStats['owners_not_exported']), $this->configStats['owners_not_exported'] ),
                'message' => 'objects inherited from containers that are not exported (predefined / filtered) - counted only, reference them on import' );

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
            'import_order' => $this->buildImportOrder(),
            'endpoints' => $endpoints,
            'infra' => $this->buildInfraSummary(),
            'mobile_users' => $this->buildMobileUsersSummary(),
            'prisma_browser' => $this->buildPrismaBrowserSummary(),
            'iam' => $this->buildIAMSummary(),
            'config' => $this->buildConfigSummary(),
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
    const PSK_LIST_COLUMNS = array( 'ike_gateway', 'ipsec_tunnel', 'remote_network', 'branch_peer_address', 'psk_current', 'psk_new', 'psk_sha1' );
    const PSK_LIST_COLUMNS_SC = array( 'ike_gateway', 'ipsec_tunnel', 'service_connection', 'peer_address', 'psk_current', 'psk_new', 'psk_sha1' );
    const BGP_SECRET_LIST_COLUMNS = array( 'object', 'field', 'bgp_peer_ip_address', 'secret_current', 'secret_new', 'secret_sha1' );

    /**
     * PAN-OS encrypted value, version 1: "-" + base64(0x01) + base64(sha1(cleartext)) + base64(aes-256-cbc(cleartext))
     * The SHA1 part identifies the cleartext independent of the master key: two tenants with different master keys
     * produce different values for the same secret, but the same SHA1.
     */
    const ENCRYPTED_V1_PATTERN = '#^-AQ==([A-Za-z0-9+/]{27}=)[A-Za-z0-9+/]+={0,2}$#';

    /**
     * base64 SHA1 of the cleartext of a PAN-OS encrypted value, or null
     */
    public static function encryptedSha1( $value )
    {
        if( !is_string($value) || !preg_match(self::ENCRYPTED_V1_PATTERN, $value, $m) )
            return null;
        return $m[1];
    }

    /**
     * base64 SHA1 of a cleartext (same format as encryptedSha1())
     */
    public static function cleartextSha1( $cleartext )
    {
        return base64_encode( sha1( (string)$cleartext, true ) );
    }

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

        $stats = array( 'gateways' => 0, 'decrypted' => 0, 'decrypt_failed' => 0, 'without_psk' => 0, 'sha1_available' => 0 );

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

            $sha1 = self::encryptedSha1( $encrypted );
            if( $sha1 !== null )
                $stats['sha1_available']++;
            fputcsv( $fh, array( $gwName, implode(" | ", $tunnels), implode(" | ", array_unique($conns)), implode(" | ", self::peerAddressList($gw)), $cleartext, "", (string)$sha1 ), ',', '"', '' );
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
                    self::decryptValue( $crypto, $encrypted, $masterKey, $stats ), "", (string)self::encryptedSha1($encrypted) ), ',', '"', '' );
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
        $list = self::loadSecretCSV( $file, array('ike_gateway'), 'psk_current', 'psk_new', 'psk_sha1' );
        return array( 'psk' => $list['secret'], 'source' => $list['source'], 'errors' => $list['errors'], 'verified' => $list['verified'] );
    }

    /**
     * reads a bgp-secret-list.csv for import: secret_new if filled, otherwise secret_current
     *
     * @return array ['secret' => ["<object>|<field>" => cleartext], 'source' => [...], 'errors' => [...]]
     */
    public static function loadBGPSecretList( $file )
    {
        return self::loadSecretCSV( $file, array('object', 'field'), 'secret_current', 'secret_new', 'secret_sha1' );
    }

    /**
     * generic loader: key columns joined with '|', value = new column if filled, else current column
     * 'verified' [key => true|false|null]: the used value has the SHA1 of the exported (encrypted) value -
     * true = same secret as in the source tenant, false = a different secret, null = no SHA1 in the list
     */
    public static function loadSecretCSV( $file, $keyColumns, $currentColumn, $newColumn, $sha1Column = null )
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

        $result = array( 'secret' => array(), 'source' => array(), 'errors' => array(), 'verified' => array() );
        $hasSha1 = $sha1Column !== null && in_array($sha1Column, $header, TRUE);
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
                $result['verified'][$key] = ( $hasSha1 && trim($row[$sha1Column]) !== "" )
                    ? self::cleartextSha1($row[$newColumn]) === trim($row[$sha1Column]) : null;
            }
            elseif( $row[$currentColumn] !== "" && $row[$currentColumn] !== self::PSK_DECRYPT_FAILED && $row[$currentColumn] !== self::SECRET_HASHED )
            {
                $result['secret'][$key] = $row[$currentColumn];
                $result['source'][$key] = 'current';
                $result['verified'][$key] = ( $hasSha1 && trim($row[$sha1Column]) !== "" )
                    ? self::cleartextSha1($row[$currentColumn]) === trim($row[$sha1Column]) : null;
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
    const SECRET_LIST_COLUMNS = array( 'endpoint', 'object', 'path', 'secret_current', 'secret_new', 'secret_sha1' );
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
            fputcsv( $fh, array( $secret['endpoint'], $secret['object'], $secret['path'], $current, "", (string)self::encryptedSha1($value) ), ',', '"', '' );
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
        return self::loadSecretCSV( $file, array('endpoint', 'object', 'path'), 'secret_current', 'secret_new', 'secret_sha1' );
    }

    ////////////////////////////////////////////////////////////////////////////////
    // endpoint metadata for compare / sync

    /**
     * defaults for every endpoint; overridden per "area/endpoint" in ENDPOINT_META
     *  key       fields forming the identity of an entry inside one container (never the tenant specific id)
     *  singleton the endpoint returns one object (compared as a whole, key "_")
     *  ignore    dotted paths removed before compare (derived / read-only / tenant specific)
     *  secret    dotted paths of secrets - compared, but values masked in every output
     *  ordered   true: the order of the entries matters (rule bases); "list.path" entries inside an object
     *  refs      references to other endpoints: dotted path ("[]" = every list element) => "area/endpoint"
     *  write     collection (POST / PUT {id} / DELETE {id}) | singleton (PUT) | none (read-only / documentation)
     *  compare   false: not compared (pure context / runtime data)
     *  keep_owner true: the folder field is data, not the owner (devices: folder assignment) - compared as assigned_folder
     */
    const ENDPOINT_META_DEFAULT = array( 'key' => array('name'), 'singleton' => false, 'ignore' => array(), 'secret' => array(),
        'ordered' => false, 'refs' => array(), 'write' => 'collection', 'compare' => true, 'keep_owner' => false );

    /** fields removed everywhere before compare */
    const COMPARE_IGNORE_ALWAYS = array( 'id', 'folder', 'snippet', 'device' );

    const ENDPOINT_META = array(
        'infra/shared-infrastructure-settings' => array( 'singleton' => true, 'write' => 'singleton',
            'ignore' => array( 'loopback_ips', 'tunnel_monitor_ip_address', 'captive_portal_redirect_ip_address', 'egress_ip_notification_url', 'api_key' ) ),
        'infra/bgp-routing' => array( 'singleton' => true, 'write' => 'singleton' ),
        'infra/locations' => array( 'key' => array('value'), 'write' => 'none' ),
        'infra/egress-ip' => array( 'key' => array('zone'), 'write' => 'none', 'compare' => false ),

        'remote-networks/ike-gateways' => array( 'secret' => array( 'authentication.pre_shared_key.key' ),
            'refs' => array( 'protocol.ikev1.ike_crypto_profile' => 'remote-networks/ike-crypto-profiles', 'protocol.ikev2.ike_crypto_profile' => 'remote-networks/ike-crypto-profiles' ) ),
        'remote-networks/ipsec-tunnels' => array(
            'refs' => array( 'auto_key.ike_gateway[].name' => 'remote-networks/ike-gateways', 'auto_key.ipsec_crypto_profile' => 'remote-networks/ipsec-crypto-profiles' ) ),
        'remote-networks/bandwidth-allocations' => array( 'refs' => array( 'qos.profile' => 'remote-networks/qos-profiles' ) ),
        'remote-networks/remote-networks' => array( 'ignore' => array( 'details' ), 'secret' => array( 'protocol.bgp.secret' ),
            'refs' => array( 'ipsec_tunnel' => 'remote-networks/ipsec-tunnels', 'secondary_ipsec_tunnel' => 'remote-networks/ipsec-tunnels', 'region' => 'remote-networks/bandwidth-allocations' ) ),

        'service-connections/ike-gateways' => array( 'secret' => array( 'authentication.pre_shared_key.key' ),
            'refs' => array( 'protocol.ikev1.ike_crypto_profile' => 'service-connections/ike-crypto-profiles', 'protocol.ikev2.ike_crypto_profile' => 'service-connections/ike-crypto-profiles' ) ),
        'service-connections/ipsec-tunnels' => array(
            'refs' => array( 'auto_key.ike_gateway[].name' => 'service-connections/ike-gateways', 'auto_key.ipsec_crypto_profile' => 'service-connections/ipsec-crypto-profiles' ) ),
        'service-connections/service-connections' => array( 'secret' => array( 'protocol.bgp.secret', 'bgp_peer.secret' ),
            'refs' => array( 'ipsec_tunnel' => 'service-connections/ipsec-tunnels', 'secondary_ipsec_tunnel' => 'service-connections/ipsec-tunnels',
                'qos.qos_profile' => 'service-connections/qos-profiles', 'backup_SC' => 'service-connections/service-connections' ) ),
        'service-connections/service-connection-groups' => array( 'refs' => array( 'target[]' => 'service-connections/service-connections' ) ),
        'service-connections/traffic-steering-rules' => array( 'ordered' => true ),

        'mobile-users/certificates' => array( 'ignore' => array( 'private_key' ) ),
        'mobile-users/ldap-server-profiles' => array( 'secret' => array( 'bind_password' ) ),
        'mobile-users/local-users' => array( 'secret' => array( 'password' ) ),
        'mobile-users/certificate-profiles' => array( 'refs' => array( 'ca_certificates[].name' => 'mobile-users/certificates' ) ),
        'mobile-users/tls-service-profiles' => array( 'refs' => array( 'certificate' => 'mobile-users/certificates' ) ),
        'mobile-users/authentication-profiles' => array( 'refs' => array(
            'method.saml_idp.server_profile' => 'mobile-users/saml-server-profiles', 'method.ldap.server_profile' => 'mobile-users/ldap-server-profiles',
            'method.radius.server_profile' => 'mobile-users/radius-server-profiles', 'method.tacplus.server_profile' => 'mobile-users/tacacs-server-profiles',
            'method.kerberos.server_profile' => 'mobile-users/kerberos-server-profiles', 'certificate_profile' => 'mobile-users/certificate-profiles' ) ),
        'mobile-users/authentication-sequences' => array( 'refs' => array( 'authentication_profiles[]' => 'mobile-users/authentication-profiles' ) ),
        'mobile-users/mobile-agent-infrastructure-settings' => array( 'singleton' => true, 'write' => 'singleton' ),
        'mobile-users/mobile-agent-authentication-settings' => array( 'ordered' => true, 'refs' => array( 'authentication_profile' => 'mobile-users/authentication-profiles' ) ),
        'mobile-users/mobile-agent-agent-profiles' => array( 'ordered' => true,
            'refs' => array( 'authentication_override.cookie_encrypt_decrypt_cert' => 'mobile-users/certificates' ) ),
        'mobile-users/mobile-agent-tunnel-profiles' => array( 'ordered' => true ),
        'mobile-users/mobile-agent-global-settings' => array( 'singleton' => true, 'write' => 'singleton' ),
        'mobile-users/mobile-agent-agent-versions' => array( 'singleton' => true, 'write' => 'none' ),
        'mobile-users/mobile-agent-enable' => array( 'singleton' => true, 'write' => 'singleton' ),

        'prisma-browser/policy-sign-in' => array( 'singleton' => true, 'write' => 'singleton', 'ordered' => array( 'rules', 'sections' ) ),
        'prisma-browser/policy-access-and-data' => array( 'singleton' => true, 'write' => 'singleton', 'ordered' => array( 'rules', 'sections' ) ),
        'prisma-browser/policy-security' => array( 'singleton' => true, 'write' => 'singleton', 'ordered' => array( 'rules', 'sections' ) ),
        'prisma-browser/policy-customization' => array( 'singleton' => true, 'write' => 'singleton', 'ordered' => array( 'rules', 'sections' ) ),
        'prisma-browser/application-groups' => array( 'refs' => array( 'applications[]' => 'prisma-browser/applications' ) ),
        'prisma-browser/pending-changes' => array( 'write' => 'none', 'compare' => false ),

        'iam/roles' => array( 'write' => 'none' ),
        'iam/custom-roles' => array( 'write' => 'none' ),
        'iam/permission-sets' => array( 'write' => 'none' ),
        'iam/service-accounts' => array( 'write' => 'none', 'ignore' => array( 'client_id', 'created_at', 'updated_at' ) ),
        'iam/access-policies' => array( 'key' => array( 'principal', 'role', 'resource' ), 'write' => 'none' ),
        'iam/permissions' => array( 'write' => 'none', 'compare' => false ),

        'config/folders' => array( 'write' => 'collection' ),
        'config/devices' => array( 'key' => array('serial_number'), 'write' => 'none', 'secret' => array(), 'keep_owner' => true,
            'ignore' => array( 'is_connected', 'connected_since', 'last_disconnect_time', 'last_device_update_time', 'last_das_update_time',
                'uptime', 'software_version', 'app_version', 'app_release_date', 'anti_virus_version', 'av_release_date', 'threat_version',
                'threat_release_date', 'wf_ver', 'wf_release_date', 'iot_version', 'iot_release_date', 'gp_client_verion', 'gp_data_version',
                'log_db_version', 'url_db_ver', 'url_db_type', 'ha_state', 'ha_peer_state', 'vm_state', 'dev_cert_detail', 'dev_cert_expiry_date',
                'installed_licenses', 'available_licenses', 'license_match', 'deactivate_wait_hrs', 'deactivated_by', 'to_be_deactivated_at' ) ),
        'config/ike-gateways' => array( 'secret' => array( 'authentication.pre_shared_key.key' ),
            'refs' => array( 'protocol.ikev1.ike_crypto_profile' => 'config/ike-crypto-profiles', 'protocol.ikev2.ike_crypto_profile' => 'config/ike-crypto-profiles' ) ),
        'config/ipsec-tunnels' => array(
            'refs' => array( 'auto_key.ike_gateway[].name' => 'config/ike-gateways', 'auto_key.ipsec_crypto_profile' => 'config/ipsec-crypto-profiles' ) ),
        'config/zones' => array( 'refs' => array( 'zone_protection_profile' => 'config/zone-protection-profiles' ) ),
        'config/tls-service-profiles' => array( 'refs' => array( 'certificate' => 'config/certificates' ) ),
        'config/certificates' => array( 'ignore' => array( 'private_key' ) ),
        'config/ldap-server-profiles' => array( 'secret' => array( 'bind_password' ) ),
        'config/local-users' => array( 'secret' => array( 'password' ) ),
        'config/snippets' => array( 'write' => 'collection' ),
        'config/address-groups' => array( 'refs' => array( 'static[]' => 'config/addresses' ) ),
        'config/service-groups' => array( 'refs' => array( 'members[]' => 'config/services' ) ),
        'config/application-groups' => array( 'refs' => array( 'members[]' => 'config/applications' ) ),
        'config/profile-groups' => array( 'refs' => array(
            'spyware[]' => 'config/anti-spyware-profiles', 'vulnerability[]' => 'config/vulnerability-protection-profiles',
            'virus_and_wildfire_analysis[]' => 'config/wildfire-anti-virus-profiles', 'dns_security[]' => 'config/dns-security-profiles',
            'file_blocking[]' => 'config/file-blocking-profiles', 'url_filtering[]' => 'config/url-access-profiles' ) ),
    );

    /**
     * metadata of one endpoint ("area", "endpoint"); config rule bases (-pre / -post) are ordered and resolve to their type
     */
    public static function endpointMeta( $area, $name )
    {
        $meta = self::ENDPOINT_META_DEFAULT;
        $base = $name;
        if( $area == self::AREA_CONFIG )
        {
            $base = preg_replace( '/-(pre|post)$/', '', $name );
            foreach( self::getConfigTypes() as $t )
                if( $t['name'] == $base && !empty($t['position']) )
                    $meta['ordered'] = true;
        }
        $k = $area . "/" . $base;
        if( isset(self::ENDPOINT_META[$k]) )
            $meta = array_merge( $meta, self::ENDPOINT_META[$k] );
        if( $meta['singleton'] )
            $meta['key'] = array();
        $meta['endpoint'] = $k;
        return $meta;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // config: folders / snippets, objects, security, zones

    /** groups of config types (option config-scope) */
    const CONFIG_GROUPS = array( 'identity', 'objects', 'network', 'policies', 'device' );

    /** Prisma Access folders: network / identity / device types are covered by the areas remote-networks,
     *  service-connections and mobile-users, so only objects and policies are exported there */
    const PA_FOLDERS = array( 'Prisma Access', 'Remote Networks', 'Service Connections', 'Mobile Users',
        'Mobile Users Container', 'Mobile Users Explicit Proxy' );

    /**
     * object types per container in import order (an entry only references lower entries or the hierarchy)
     * 'position' => true: rules, fetched as pre and post; 'group': CONFIG_GROUPS
     */
    public static function getConfigTypes()
    {
        $o = "/config/objects/v1/";
        $sec = "/config/security/v1/";
        $net = "/config/network/v1/";
        $set = "/config/setup/v1/";
        $id = "/config/identity/v1/";
        $dev = "/config/device/v1/";
        $g = function( $group, $list ){
            $out = array();
            foreach( $list as $name => $path )
            {
                $position = false;
                if( substr($name, 0, 1) == "@" )
                {
                    $position = true;
                    $name = substr($name, 1);
                }
                $out[] = array( 'name' => $name, 'path' => $path . $name, 'group' => $group ) + ( $position ? array( 'position' => true ) : array() );
            }
            return $out;
        };
        $t = array_merge(
            array( array( 'name' => 'variables', 'path' => $set . 'variables', 'group' => 'objects' ) ),
            $g( 'identity', array(
                'certificates' => $id, 'trusted-certificate-authorities' => $id, 'certificate-profiles' => $id,
                'ocsp-responders' => $id, 'scep-profiles' => $id, 'tls-service-profiles' => $id,
                'saml-server-profiles' => $id, 'ldap-server-profiles' => $id, 'radius-server-profiles' => $id,
                'tacacs-server-profiles' => $id, 'kerberos-server-profiles' => $id, 'mfa-servers' => $id,
                'local-users' => $id, 'local-user-groups' => $id, 'authentication-profiles' => $id,
                'authentication-sequences' => $id, 'authentication-portals' => $id ) ),
            $g( 'objects', array(
                'tags' => $o, 'addresses' => $o, 'address-groups' => $o, 'regions' => $o, 'services' => $o,
                'service-groups' => $o, 'schedules' => $o, 'external-dynamic-lists' => $o, 'dynamic-user-groups' => $o,
                'applications' => $o, 'application-filters' => $o, 'application-groups' => $o, 'url-categories' => $sec,
                'hip-objects' => $o, 'hip-profiles' => $o, 'http-server-profiles' => $o, 'syslog-server-profiles' => $o,
                'log-forwarding-profiles' => $o, 'auto-tag-actions' => $o ) ),
            $g( 'network', array(
                'interface-management-profiles' => $net, 'link-tags' => $net, 'lldp-profiles' => $net,
                'zone-protection-profiles' => $net,
                'ethernet-interfaces' => $net, 'aggregate-interfaces' => $net, 'layer2-subinterfaces' => $net,
                'layer3-subinterfaces' => $net, 'loopback-interfaces' => $net, 'tunnel-interfaces' => $net,
                'vlan-interfaces' => $net, 'dhcp-interfaces' => $net, 'zones' => $net,
                'route-access-lists' => $net, 'route-prefix-lists' => $net, 'route-community-lists' => $net,
                'route-path-access-lists' => $net, 'bgp-route-maps' => $net, 'bgp-route-map-redistributions' => $net,
                'bgp-address-family-profiles' => $net, 'bgp-authentication-profiles' => $net,
                'bgp-filtering-profiles' => $net, 'bgp-redistribution-profiles' => $net,
                'ospf-auth-profiles' => $net, 'logical-routers' => $net, 'dns-proxies' => $net,
                'ike-crypto-profiles' => $net, 'ipsec-crypto-profiles' => $net, 'ike-gateways' => $net,
                'ipsec-tunnels' => $net, 'qos-profiles' => $net,
                'sdwan-path-quality-profiles' => $net, 'sdwan-saas-quality-profiles' => $net,
                'sdwan-traffic-distribution-profiles' => $net, 'sdwan-error-correction-profiles' => $net ) ),
            $g( 'objects', array(
                'anti-spyware-profiles' => $sec, 'vulnerability-protection-profiles' => $sec,
                'wildfire-anti-virus-profiles' => $sec, 'dns-security-profiles' => $sec, 'file-blocking-profiles' => $sec,
                'url-access-profiles' => $sec, 'decryption-profiles' => $sec, 'saas-security-profiles' => $sec,
                'ai-security-profiles' => $sec, 'profile-groups' => $sec ) ),
            $g( 'policies', array(
                '@security-rules' => $sec, '@decryption-rules' => $sec, '@authentication-rules' => $sec,
                '@app-override-rules' => $sec, '@nat-rules' => $net, '@pbf-rules' => $net, '@qos-policy-rules' => $net,
                '@sdwan-rules' => $net ) ),
            $g( 'device', array(
                'general-settings' => $dev, 'management-interface-settings' => $dev, 'service-settings' => $dev,
                'service-route-settings' => $dev, 'authentication-settings' => $dev, 'session-settings' => $dev,
                'session-timeouts-settings' => $dev, 'tcp-settings' => $dev, 'content-id-settings' => $dev,
                'update-schedule-settings' => $dev, 'vpn-settings' => $dev, 'login-banner-settings' => $dev,
                'system-match-list' => $net, 'config-match-list' => $net, 'userid-match-list' => $net,
                'hipmatch-match-list' => $net, 'globalprotect-match-list' => $net, 'iptag-match-list' => $net ) )
        );
        foreach( $t as $i => &$type )
        {
            $type['order'] = $i + 1;
            $type['heavy'] = in_array( $type['name'], self::CONFIG_HEAVY_TYPES, TRUE );
        }
        return $t;
    }

    /**
     * config types whose answers contain the complete predefined catalog for every queried folder
     * (applications: ~100,000, with SaaS applications ~1,000,000 objects per query) - skipped unless
     * config-heavy-types or named in config-types=
     */
    const CONFIG_HEAVY_TYPES = array( 'applications' );

    /**
     * config types of the given groups (null = all)
     */
    public static function configTypesForScope( $scope )
    {
        return array_values( array_filter( self::getConfigTypes(), function($t) use( $scope ){
            return $scope === null || in_array($t['group'], $scope, TRUE); } ) );
    }

    public static function slug( $name )
    {
        $slug = preg_replace( '/[^A-Za-z0-9._-]+/', '_', (string)$name );
        return trim( $slug, "_" ) === "" ? "_" : $slug;
    }

    /**
     * folders + snippets -> hierarchy: tree, path root..container, attached snippets in API order, DFS order
     */
    public static function buildHierarchy( $folders, $snippets, $devices = array() )
    {
        $deviceBySerial = array();
        foreach( (array)$devices as $d )
        {
            $serial = (string)self::firstOf($d, array('serial_number', 'name'));
            if( $serial !== "" )
                $deviceBySerial[$serial] = $d;
        }
        $byName = array();
        foreach( $folders as $f )
            $byName[(string)self::get($f, 'name')] = $f;

        $children = array();
        $roots = array();
        foreach( $folders as $f )
        {
            $parent = self::get($f, 'parent');
            if( $parent === null || $parent === "" || !isset($byName[$parent]) )
                $roots[] = (string)self::get($f, 'name');
            else
                $children[$parent][] = (string)self::get($f, 'name');
        }

        $ordered = array();
        $walk = function( $name, $path, $depth ) use( &$walk, &$ordered, $byName, $children, $deviceBySerial ) {
            $f = $byName[$name];
            $path[] = $name;
            $ordered[] = array(
                'name' => $name,
                'id' => self::get($f, 'id'),
                'type' => self::get($f, 'type'),
                'parent' => self::get($f, 'parent'),
                'depth' => $depth,
                'path' => $path,
                'snippets' => array_values( (array)self::get($f, 'snippets', array()) ),
                'children' => isset($children[$name]) ? $children[$name] : array(),
            );
            //device folder (name = serial): device facts from /config/setup/v1/devices
            $serial = (string)self::firstOf($f, array('serial_number', 'name'));
            if( isset($deviceBySerial[$serial]) )
            {
                $dv = $deviceBySerial[$serial];
                $ordered[count($ordered) - 1]['device'] = array( 'serial_number' => $serial,
                    'display_name' => self::get($dv, 'display_name'), 'model' => self::get($dv, 'model'),
                    'is_connected' => self::get($dv, 'is_connected'), 'software_version' => self::get($dv, 'software_version'),
                    'ha_peer_serial' => self::get($dv, 'ha_peer_serial') );
            }
            if( isset($children[$name]) )
                foreach( $children[$name] as $child )
                    if( !in_array($child, $path, TRUE) )
                        $walk( $child, $path, $depth + 1 );
        };
        foreach( $roots as $root )
            $walk( $root, array(), 0 );

        $folderIndex = array();
        foreach( $ordered as $f )
            $folderIndex[$f['name']] = $f;

        //effective chain per folder: for every level root..folder the folder itself and its snippets
        foreach( $ordered as &$f )
        {
            $chain = array();
            foreach( $f['path'] as $level )
            {
                $chain[] = array( 'kind' => 'folder', 'name' => $level );
                foreach( $folderIndex[$level]['snippets'] as $sn )
                    $chain[] = array( 'kind' => 'snippet', 'name' => $sn, 'attached_to' => $level );
            }
            $f['inheritance_chain'] = $chain;
        }
        unset($f);

        $snippetList = array();
        foreach( $snippets as $sn )
        {
            $name = (string)self::get($sn, 'name');
            $attached = array();
            foreach( $ordered as $f )
            {
                $pos = array_search($name, $f['snippets'], TRUE);
                if( $pos !== FALSE )
                    $attached[] = array( 'folder' => $f['name'], 'position' => $pos + 1 );
            }
            $snippetList[] = array( 'name' => $name, 'id' => self::get($sn, 'id'), 'type' => self::get($sn, 'type'), 'attached_to' => $attached );
        }

        //devices that are not a folder of the hierarchy, listed per folder field
        $folderSet = array();
        foreach( $ordered as $f )
            $folderSet[$f['name']] = true;
        $unplaced = array();
        foreach( $deviceBySerial as $serial => $dv )
            if( !isset($folderSet[$serial]) )
                $unplaced[] = array( 'serial_number' => $serial, 'folder' => self::get($dv, 'folder'), 'model' => self::get($dv, 'model'),
                    'display_name' => self::get($dv, 'display_name'), 'is_connected' => self::get($dv, 'is_connected') );

        return array( 'folders' => $ordered, 'snippets' => $snippetList, 'roots' => $roots, 'devices_not_in_folders' => $unplaced );
    }

    public static function hierarchyText( $hierarchy )
    {
        $lines = array();
        foreach( $hierarchy['folders'] as $f )
        {
            $line = str_repeat("    ", $f['depth']) . $f['name'] . " [" . $f['type'] . "]";
            if( isset($f['device']) )
                $line .= "  " . trim( (string)$f['device']['display_name'] . " " . (string)$f['device']['model'] . " " . (string)$f['device']['software_version'] )
                    . ( $f['device']['is_connected'] === true ? " connected" : " NOT connected" )
                    . ( !empty($f['device']['ha_peer_serial']) ? " HA peer " . $f['device']['ha_peer_serial'] : "" );
            if( count($f['snippets']) > 0 )
            {
                $sn = array();
                foreach( $f['snippets'] as $i => $name )
                    $sn[] = ($i + 1) . ":" . $name;
                $line .= "  snippets: " . implode(", ", $sn);
            }
            $lines[] = $line;
        }
        $unattached = array();
        foreach( $hierarchy['snippets'] as $sn )
            if( count($sn['attached_to']) == 0 )
                $unattached[] = $sn['name'] . ( $sn['type'] ? " [" . $sn['type'] . "]" : "" );
        if( count($unattached) > 0 )
            $lines[] = "\n(snippets not attached: " . implode(", ", $unattached) . ")";
        if( isset($hierarchy['devices_not_in_folders']) && count($hierarchy['devices_not_in_folders']) > 0 )
        {
            $lines[] = "\ndevices (folder field):";
            foreach( $hierarchy['devices_not_in_folders'] as $d )
                $lines[] = "    " . $d['serial_number'] . " " . trim((string)$d['display_name'] . " " . (string)$d['model']) . " -> " . ( $d['folder'] === null ? "(no folder)" : $d['folder'] )
                    . ( $d['is_connected'] === true ? " connected" : " NOT connected" );
        }
        return implode("\n", $lines) . "\n";
    }

    /**
     * exports the config area: hierarchy + per container (folder / snippet) all config types;
     * a container query also returns the objects of its parents / snippets, so only objects owned by the queried
     * container (field folder / snippet) are stored there; the others are counted per owner
     */
    public function exportConfig()
    {
        $a = self::AREA_CONFIG;
        $opt = $this->configOptions;
        $configStart = microtime(TRUE);
        if( !property_exists($this->connector, 'parallelRequests') )
            $this->connector->parallelRequests = 0;
        $requestsBefore = $this->connector->parallelRequests;
        if( isset($opt['parallel']) )
            $this->configParallel = max( 1, (int)$opt['parallel'] );
        if( isset($opt['page_size']) )
            $this->configPageSize = max( 1, (int)$opt['page_size'] );

        $setup = array(
            array( 'area' => $a, 'order' => 1, 'name' => 'folders', 'category' => 'dependency', 'scope' => 'tenant', 'url' => "/config/setup/v1/folders", 'depends_on' => array(), 'fetched_as' => 'selected' ),
            array( 'area' => $a, 'order' => 2, 'name' => 'snippets', 'category' => 'dependency', 'scope' => 'tenant', 'url' => "/config/setup/v1/snippets", 'depends_on' => array(), 'fetched_as' => 'selected' ),
            array( 'area' => $a, 'order' => 3, 'name' => 'devices', 'category' => 'context', 'scope' => 'tenant', 'optional' => true, 'url' => "/config/setup/v1/devices", 'depends_on' => array(), 'fetched_as' => 'selected' ),
        );
        $raw = array();
        foreach( $setup as $endpoint )
        {
            PH::print_stdout( " - [config " . sprintf("%02d", $endpoint['order']) . "] " . $endpoint['name'] . " ... " );
            $result = $this->connector->getSCMResourceAll( $endpoint['url'] );
            if( $endpoint['name'] == 'devices' && is_array($result['data']) )
                $result['data'] = self::stripDeviceSecrets( $result['data'] );
            $this->storeConfigResult( $endpoint, $endpoint['area'] . "/" . sprintf("%02d", $endpoint['order']) . "_" . $endpoint['name'] . ".json", $result, $result['data'] );
            $raw[$endpoint['name']] = ( $result['errors'] === null && is_array($result['data']) ) ? $result['data'] : array();
        }

        $this->configDevices = $raw['devices'];
        if( count($raw['devices']) > 0 )
            $this->writeDevicesCSV( $raw['devices'] );

        $hierarchy = self::buildHierarchy( $raw['folders'], $raw['snippets'], $raw['devices'] );
        $this->configHierarchy = $hierarchy;
        $this->writeJson( $a . '/hierarchy.json', $hierarchy );
        file_put_contents( $this->exportDir . "/" . $a . "/hierarchy.txt", self::hierarchyText($hierarchy) );

        //containers to query: folders (type container, optionally devices) in DFS order, then snippets
        $containers = array();
        foreach( $hierarchy['folders'] as $f )
        {
            if( $f['type'] !== null && $f['type'] !== 'container' && !$opt['devices'] )
                continue;
            $containers[] = array( 'kind' => 'folder', 'name' => $f['name'], 'device' => $f['type'] !== null && $f['type'] !== 'container' );
        }
        foreach( $hierarchy['snippets'] as $sn )
        {
            if( $sn['type'] === 'predefined' && !$opt['predefined_snippets'] )
                continue;
            $containers[] = array( 'kind' => 'snippet', 'name' => $sn['name'], 'device' => false );
        }
        if( $opt['containers'] !== null )
            $containers = array_values( array_filter( $containers, function($c) use( $opt ){ return in_array($c['name'], $opt['containers'], TRUE); } ) );

        $types = self::configTypesForScope( isset($opt['scope']) ? $opt['scope'] : null );
        if( $opt['types'] !== null )
            $types = array_values( array_filter( $types, function($t) use( $opt ){ return in_array($t['name'], $opt['types'], TRUE); } ) );
        //types with the whole predefined catalog in every answer: only on request
        $skippedHeavy = array();
        if( empty($opt['heavy_types']) )
            foreach( $types as $i => $t )
                if( !empty($t['heavy']) && ( $opt['types'] === null || !in_array($t['name'], $opt['types'], TRUE) ) )
                {
                    $skippedHeavy[] = $t['name'];
                    unset( $types[$i] );
                    PH::print_stdout( " - [config " . sprintf("%03d", $t['order']) . "] " . $t['name'] . " ... skipped (predefined catalog in every answer - config-heavy-types or config-types=" . $t['name'] . " to export)" );
                }
        $types = array_values( $types );

        $exported = array();
        foreach( $containers as $c )
            $exported[$c['kind'] . ":" . $c['name']] = $c;

        $this->configStats = array( 'containers' => array(), 'owned' => array(), 'inherited_by_owner' => array(), 'owners_not_exported' => array(),
            'mode' => null, 'queries' => 0, 'skipped_unavailable' => 0, 'skipped_heavy' => $skippedHeavy );
        foreach( $containers as $c )
            $this->configStats['containers'][$c['kind'] . ":" . $c['name']] = array();

        //query plan: leaf (default) or all; an explicit container filter always queries exactly those containers
        $mode = ( isset($opt['mode']) && $opt['mode'] === 'all' ) || $opt['containers'] !== null ? 'all' : 'leaf';
        $this->configStats['mode'] = $mode;

        $folderInfo = array();
        foreach( $hierarchy['folders'] as $f )
            $folderInfo[$f['name']] = $f;

        $collected = array();      // ckey => name => ['objects' => [], 'seen' => [], 'status' => [], 'queries' => [], 'inherited' => 0, 'errors' => []]
        $notExportedIds = array();   // owner => type => objects (max. per query: every query that includes the owner returns all its objects)
        $unavailable = array();    // type name|class => first container
        $deviceParam = array();    // device container => 'folder' | 'device'

        foreach( $types as $type )
        {
            $eligible = array();
            foreach( $containers as $c )
                if( self::configTypeEligible($c, $type) )
                    $eligible[$c['kind'] . ":" . $c['name']] = $c;
            if( count($eligible) == 0 )
                continue;

            $queries = $mode == 'all' ? self::queryPlanAll($eligible) : self::queryPlanLeaf($eligible, $folderInfo);
            PH::print_stdout( " - [config " . sprintf("%03d", $type['order']) . "] " . $type['name'] . " ... " . count($queries) . " quer" . ( count($queries) == 1 ? "y" : "ies" ) . " for " . count($eligible) . " container(s)" );

            $typeStart = microtime(TRUE);
            $typeObjects = 0;
            foreach( !empty($type['position']) ? array('pre', 'post') : array(null) as $position )
            {
                $name = $type['name'] . ( $position !== null ? "-" . $position : "" );

                //URLs of all queries; fetched in parallel: first one query per container class (to learn
                //whether the type is available for that class), then all others
                $jobs = array();
                foreach( $queries as $i => $q )
                {
                    $c = $q['container'];
                    $class = $c['kind'] == 'snippet' ? 'snippet' : ( $c['device'] ? 'device' : 'folder' );
                    $paramName = $c['kind'] == 'snippet' ? 'snippet' : ( isset($deviceParam[$c['name']]) ? $deviceParam[$c['name']] : 'folder' );
                    $jobs[$i] = array( 'class' => $class,
                        'url' => $type['path'] . "?" . $paramName . "=" . rawurlencode($c['name']) . ( $position !== null ? "&position=" . $position : "" ) );
                }
                $prefetched = array();
                $probe = array();
                foreach( $jobs as $i => $j )
                    if( !isset($unavailable[$type['name'] . "|" . $j['class']]) && !isset($probe[$j['class']]) )
                        $probe[$j['class']] = $i;
                $probeUrls = array();
                foreach( $probe as $i )
                    $probeUrls[$i] = $jobs[$i]['url'];
                $prefetched = $this->fetchConfigQueries( $probeUrls );
                foreach( $probe as $class => $i )
                    if( $class !== 'device' && $prefetched[$i]['errors'] !== null && in_array($prefetched[$i]['http_code'], array(401, 403, 404), TRUE) )
                        $unavailable[$type['name'] . "|" . $class] = $queries[$i]['container']['name'];
                $restUrls = array();
                foreach( $jobs as $i => $j )
                    if( !isset($prefetched[$i]) && !isset($unavailable[$type['name'] . "|" . $j['class']]) )
                        $restUrls[$i] = $j['url'];
                //fetched in chunks while processing: only a few answers in memory at a time
                //(every leaf answer repeats all inherited objects - hundreds of thousands per type)
                $chunkSize = max( 4, $this->configParallel * 2 );

                foreach( $queries as $i => $q )
                {
                    $c = $q['container'];
                    $qkey = $c['kind'] . ":" . $c['name'];
                    $class = $jobs[$i]['class'];

                    if( !isset($prefetched[$i]) && isset($restUrls[$i]) )
                    {
                        $chunk = array_slice( $restUrls, 0, $chunkSize, TRUE );
                        foreach( $chunk as $k => $u )
                            unset( $restUrls[$k] );
                        $prefetched = $prefetched + $this->fetchConfigQueries( $chunk );
                    }

                    //type unavailable for this class of container: no further calls
                    if( !isset($prefetched[$i]) )
                    {
                        $this->configStats['skipped_unavailable']++;
                        foreach( $q['covers'] as $ck )
                            $collected[$ck][$name]['status'][] = 'unavailable';
                        continue;
                    }

                    $url = $jobs[$i]['url'];
                    $result = $prefetched[$i];
                    unset( $prefetched[$i] );
                    $this->configStats['queries']++;

                    //device folders: "folder=<serial>", fallback "device=<serial>"
                    if( $c['device'] && !isset($deviceParam[$c['name']]) && $result['errors'] !== null && in_array($result['http_code'], array(400, 404), TRUE) )
                    {
                        $altUrl = $type['path'] . "?device=" . rawurlencode($c['name']) . ( $position !== null ? "&position=" . $position : "" );
                        $alt = $this->connector->getSCMResourceAll( $altUrl );
                        $this->configStats['queries']++;
                        if( $alt['errors'] === null )
                        {
                            $deviceParam[$c['name']] = 'device';
                            $url = $altUrl;
                            $result = $alt;
                        }
                    }
                    if( $c['device'] && !isset($deviceParam[$c['name']]) && $result['errors'] === null )
                        $deviceParam[$c['name']] = 'folder';

                    if( $result['errors'] !== null )
                    {
                        $status = in_array($result['http_code'], array(401, 403, 404), TRUE) ? 'unavailable' : 'error';
                        if( $status == 'unavailable' )
                            $unavailable[$type['name'] . "|" . $class] = $c['name'];
                        foreach( $q['covers'] as $ck )
                        {
                            $collected[$ck][$name]['status'][] = $status;
                            $collected[$ck][$name]['errors'][] = $url . ": " . self::errorMessage($result['errors']);
                        }
                        if( $status == 'error' )
                            PH::print_stdout( "     x ERROR " . $name . " " . $qkey . ": " . self::errorMessage($result['errors']) );
                        continue;
                    }

                    foreach( $q['covers'] as $ck )
                    {
                        $collected[$ck][$name]['status'][] = 'ok';
                        $collected[$ck][$name]['queries'][] = $url;
                    }
                    if( !$result['is_list'] || !is_array($result['data']) )
                        continue;

                    $typeObjects += count($result['data']);
                    $notExportedQuery = array();
                    foreach( $result['data'] as $obj )
                    {
                        //owner: snippet, folder or device (a device is a folder of type cloud / on-prem)
                        if( isset($obj['snippet']) && $obj['snippet'] !== "" )
                            $ownerKey = "snippet:" . $obj['snippet'];
                        elseif( isset($obj['folder']) && $obj['folder'] !== "" )
                            $ownerKey = "folder:" . $obj['folder'];
                        elseif( isset($obj['device']) && $obj['device'] !== "" )
                            $ownerKey = "folder:" . $obj['device'];
                        else
                        {
                            //no owner field: kept at the queried container (cannot be attributed)
                            $ownerKey = $qkey;
                            if( $mode == 'leaf' )
                                $this->warnings[] = "config " . $name . ": object without folder / snippet field in the answer for " . $qkey . " - stored there";
                        }
                        $id = isset($obj['id']) ? (string)$obj['id'] : md5( json_encode($obj) );

                        if( $ownerKey !== $qkey )
                        {
                            $this->configStats['inherited_by_owner'][$ownerKey][$type['name']] = true;
                            if( !isset($collected[$qkey][$name]['inherited']) )
                                $collected[$qkey][$name]['inherited'] = 0;
                            $collected[$qkey][$name]['inherited']++;
                        }
                        if( !isset($exported[$ownerKey]) )
                        {
                            $notExportedQuery[$ownerKey] = ( isset($notExportedQuery[$ownerKey]) ? $notExportedQuery[$ownerKey] : 0 ) + 1;
                            continue;
                        }
                        if( isset($collected[$ownerKey][$name]['seen'][$id]) )
                            continue;
                        $collected[$ownerKey][$name]['seen'][$id] = true;
                        $collected[$ownerKey][$name]['objects'][] = $obj;
                    }
                    foreach( $notExportedQuery as $owner => $n )
                        if( !isset($notExportedIds[$owner][$name]) || $notExportedIds[$owner][$name] < $n )
                            $notExportedIds[$owner][$name] = $n;
                    unset( $result );
                }
            }

            PH::print_stdout( "     " . $typeObjects . " objects received, " . round( microtime(TRUE) - $typeStart, 1 ) . "s, peak memory " . round( memory_get_peak_usage(TRUE) / 1048576 ) . " MB" );

            //one file per exported container and type
            foreach( $eligible as $ck => $c )
            {
                foreach( !empty($type['position']) ? array('pre', 'post') : array(null) as $position )
                {
                    $name = $type['name'] . ( $position !== null ? "-" . $position : "" );
                    $info = isset($collected[$ck][$name]) ? $collected[$ck][$name] : array();
                    $statuses = isset($info['status']) ? $info['status'] : array();
                    $paramName = $c['kind'] == 'snippet' ? 'snippet' : ( isset($deviceParam[$c['name']]) ? $deviceParam[$c['name']] : 'folder' );
                    $endpoint = array( 'area' => $a, 'order' => $type['order'], 'name' => $name, 'group' => $type['group'], 'container' => $c['name'], 'container_kind' => $c['kind'],
                        'category' => 'dependency', 'scope' => $c['kind'], 'optional' => true,
                        'url' => $type['path'] . "?" . $paramName . "=" . $c['name'] . ( $position !== null ? "&position=" . $position : "" ),
                        'depends_on' => array(), 'fetched_as' => 'selected' );

                    if( in_array('ok', $statuses, TRUE) )
                        $result = array( 'http_code' => 200, 'errors' => null );
                    elseif( count($statuses) > 0 && !in_array('error', $statuses, TRUE) )
                        $result = array( 'http_code' => 404, 'errors' => array( array( 'message' => 'unavailable' . ( isset($unavailable[$type['name'] . "|" . ( $c['kind'] == 'snippet' ? 'snippet' : ( $c['device'] ? 'device' : 'folder' ) )]) ? ' (first answer for ' . $unavailable[$type['name'] . "|" . ( $c['kind'] == 'snippet' ? 'snippet' : ( $c['device'] ? 'device' : 'folder' ) )] . ')' : '' ) ) ) );
                    else
                        $result = array( 'http_code' => 0, 'errors' => array( array( 'message' => count($statuses) == 0 ? 'not covered by a query' : implode("; ", array_slice( isset($info['errors']) ? $info['errors'] : array(), 0, 3 )) ) ) );

                    $owned = $result['errors'] === null ? ( isset($info['objects']) ? $info['objects'] : array() ) : null;
                    $file = $a . "/" . $c['kind'] . "s/" . self::slug($c['name']) . "/" . sprintf("%02d", $type['order']) . "_" . $name . ".json";
                    $this->storeConfigResult( $endpoint, $file, $result, $owned, array( 'container' => $c['name'], 'container_kind' => $c['kind'],
                        'inherited_skipped' => isset($info['inherited']) ? $info['inherited'] : 0,
                        'source_queries' => isset($info['queries']) ? array_values(array_unique($info['queries'])) : array() ), true );

                    if( $owned !== null )
                    {
                        $this->configStats['containers'][$ck][$name] = count($owned);
                        $this->configStats['owned'][$name] = ( isset($this->configStats['owned'][$name]) ? $this->configStats['owned'][$name] : 0 ) + count($owned);
                    }
                }
            }
            unset( $collected );
            $collected = array();
        }

        foreach( $notExportedIds as $owner => $byType )
        {
            $n = 0;
            foreach( $byType as $count )
                $n += $count;
            $this->configStats['owners_not_exported'][$owner] = $n;
        }
        $this->configStats['http_requests'] = $this->connector->parallelRequests - $requestsBefore;
        $this->configStats['parallel'] = $this->configParallel;
        $this->configStats['page_size'] = $this->configPageSize;
        $this->configStats['seconds'] = round( microtime(TRUE) - $configStart, 1 );
        PH::print_stdout( " - [config] " . $this->configStats['queries'] . " API queries (mode " . $mode . ", parallel " . $this->configParallel . ", page size " . $this->configPageSize . "), "
            . $this->configStats['skipped_unavailable'] . " skipped (type unavailable), " . $this->configStats['seconds'] . "s" );
    }

    /** @var int config area: concurrent requests (config-parallel=) */
    public $configParallel = 8;
    /** @var int config area: page size (config-page-size=) */
    public $configPageSize = 1000;

    /**
     * config queries: in parallel (curl_multi) or, with config-parallel=1, one after the other
     * @param string[] $urls key => url
     */
    private function fetchConfigQueries( $urls )
    {
        if( count($urls) == 0 )
            return array();
        if( $this->configParallel > 1 && method_exists($this->connector, 'getSCMResourceAllParallel') )
            return $this->connector->getSCMResourceAllParallel( $urls, $this->configPageSize, $this->configParallel );
        $results = array();
        foreach( $urls as $k => $u )
            $results[$k] = $this->connector->getSCMResourceAll( $u, $this->configPageSize );
        return $results;
    }

    /** @var string[] warnings of exportConfig() */
    public $warnings = array();

    /**
     * Prisma Access folders: network / identity / device types are exported by the PA areas
     */
    public static function configTypeEligible( $container, $type )
    {
        if( $container['kind'] == 'folder' && in_array($container['name'], self::PA_FOLDERS, TRUE)
            && in_array($type['group'], array('network', 'identity', 'device'), TRUE) )
            return false;
        return true;
    }

    /**
     * every container is queried and covers itself
     */
    public static function queryPlanAll( $eligible )
    {
        $plan = array();
        foreach( $eligible as $ck => $c )
            $plan[] = array( 'container' => $c, 'covers' => array( $ck ) );
        return $plan;
    }

    /**
     * the answer for a folder contains the objects of its parent folders and of their attached snippets:
     * query only the deepest eligible (non device) folders - they cover their ancestors and the snippets attached
     * on the way; device folders and snippets that are not covered are queried as well
     */
    public static function queryPlanLeaf( $eligible, $folderInfo )
    {
        $folders = array();
        $devices = array();
        $snippets = array();
        foreach( $eligible as $ck => $c )
        {
            if( $c['kind'] == 'snippet' )
                $snippets[$ck] = $c;
            elseif( $c['device'] )
                $devices[$ck] = $c;
            else
                $folders[$ck] = $c;
        }

        //a folder is a leaf if no other eligible folder has it in its path
        $hasEligibleDescendant = array();
        foreach( $folders as $ck => $c )
        {
            $path = isset($folderInfo[$c['name']]) ? $folderInfo[$c['name']]['path'] : array( $c['name'] );
            foreach( $path as $ancestor )
                if( $ancestor !== $c['name'] )
                    $hasEligibleDescendant[$ancestor] = true;
        }

        $plan = array();
        $covered = array();
        foreach( $folders as $ck => $c )
        {
            if( isset($hasEligibleDescendant[$c['name']]) )
                continue;
            $covers = array();
            $chain = isset($folderInfo[$c['name']]) ? $folderInfo[$c['name']]['inheritance_chain'] : array( array( 'kind' => 'folder', 'name' => $c['name'] ) );
            foreach( $chain as $level )
            {
                $lk = $level['kind'] . ":" . $level['name'];
                if( isset($eligible[$lk]) && !( $level['kind'] == 'folder' && isset($devices[$lk]) ) )
                {
                    $covers[] = $lk;
                    $covered[$lk] = true;
                }
            }
            $plan[] = array( 'container' => $c, 'covers' => array_values(array_unique($covers)) );
        }
        //folders not covered (should not happen) and device folders: own query
        foreach( $folders as $ck => $c )
            if( !isset($covered[$ck]) )
            {
                $plan[] = array( 'container' => $c, 'covers' => array( $ck ) );
                $covered[$ck] = true;
            }
        foreach( $devices as $ck => $c )
            $plan[] = array( 'container' => $c, 'covers' => array( $ck ) );
        foreach( $snippets as $ck => $c )
            if( !isset($covered[$ck]) )
                $plan[] = array( 'container' => $c, 'covers' => array( $ck ) );
        return $plan;
    }

    /** @var array statistics of exportConfig() */
    public $configStats = null;

    private function storeConfigResult( $endpoint, $file, $result, $data, $extra = array(), $quiet = false )
    {
        $meta = $endpoint;
        $meta['file'] = $file;
        $meta['http_code'] = $result['http_code'];
        $meta['fetched_at'] = date('c');
        if( $result['errors'] !== null && !empty($endpoint['optional']) && in_array($result['http_code'], array(401, 403, 404), TRUE) )
        {
            $meta['status'] = 'unavailable';
            $meta['error'] = self::errorMessage($result['errors']);
        }
        elseif( $result['errors'] !== null )
        {
            $meta['status'] = 'error';
            $meta['error'] = self::errorMessage($result['errors']);
            if( !$quiet )
                PH::print_stdout( "     x ERROR " . $endpoint['name'] . ": " . $meta['error'] );
        }
        else
        {
            $meta['status'] = 'ok';
            $meta['count'] = is_array($data) ? count($data) : null;
        }

        $this->writeJson( $file, array_merge( array(
            'endpoint' => $endpoint['name'], 'area' => $endpoint['area'], 'url' => $endpoint['url'], 'tsg_id' => $this->tsg,
            'fetched_at' => $meta['fetched_at'], 'http_code' => $result['http_code'], 'status' => $meta['status'],
            'error' => isset($meta['error']) ? $result['errors'] : null ), $extra, array( 'data' => $data ) ) );

        $key = isset($endpoint['container']) ? $endpoint['area'] . "/" . $endpoint['container_kind'] . ":" . $endpoint['container'] . "/" . $endpoint['name'] : self::key($endpoint['area'], $endpoint['name']);
        $this->results[$key] = array( 'meta' => $meta, 'data' => $data );
    }

    public function buildConfigSummary()
    {
        if( !$this->hasArea(self::AREA_CONFIG) || $this->configHierarchy === null )
            return null;
        $owned = $this->configStats['owned'];
        ksort($owned);
        $unavailableTypes = array();
        foreach( $this->results as $r )
        {
            if( $r['meta']['area'] == self::AREA_CONFIG && isset($r['meta']['container']) && $r['meta']['status'] == 'unavailable' )
                $unavailableTypes[$r['meta']['name']] = true;
        }
        return array(
            'files' => array( self::AREA_CONFIG . '/hierarchy.json', self::AREA_CONFIG . '/hierarchy.txt' ),
            'folders' => count($this->configHierarchy['folders']),
            'snippets' => count($this->configHierarchy['snippets']),
            'containers_exported' => array_keys($this->configStats['containers']),
            'owned_objects_by_type' => $owned,
            'owned_objects_by_container' => $this->configStats['containers'],
            'owners_not_exported' => $this->configStats['owners_not_exported'],
            'types_unavailable' => array_keys($unavailableTypes),
            'types_skipped_heavy' => isset($this->configStats['skipped_heavy']) ? $this->configStats['skipped_heavy'] : array(),
            'devices' => $this->buildDeviceSummary(),
            'mode' => $this->configStats['mode'],
            'api_queries' => $this->configStats['queries'],
            'skipped_unavailable' => $this->configStats['skipped_unavailable'],
            'http_requests' => isset($this->configStats['http_requests']) ? $this->configStats['http_requests'] : null,
            'parallel' => isset($this->configStats['parallel']) ? $this->configStats['parallel'] : null,
            'page_size' => isset($this->configStats['page_size']) ? $this->configStats['page_size'] : null,
            'seconds' => isset($this->configStats['seconds']) ? $this->configStats['seconds'] : null,
            'warnings' => array_values( array_unique($this->warnings) ),
            'options' => $this->configOptions,
        );
    }

    /**
     * area/endpoint list in import order; config: hierarchy, then every type (per container)
     */
    public function buildImportOrder()
    {
        $order = array();
        foreach( $this->getEndpoints() as $e )
        {
            if( $e['area'] == self::AREA_CONFIG )
                continue;
            if( $e['category'] == 'dependency' && $e['fetched_as'] == 'selected' )
                $order[] = self::key($e['area'], $e['name']);
        }
        if( $this->hasArea(self::AREA_CONFIG) )
        {
            $config = array( 'config/folders', 'config/snippets' );
            $types = self::configTypesForScope( isset($this->configOptions['scope']) ? $this->configOptions['scope'] : null );
            if( $this->configOptions['types'] !== null )
                $types = array_filter( $types, function($t){ return in_array($t['name'], $this->configOptions['types'], TRUE); } );
            foreach( $types as $t )
            {
                if( !empty($t['position']) )
                {
                    $config[] = 'config/' . $t['name'] . '-pre';
                    $config[] = 'config/' . $t['name'] . '-post';
                }
                else
                    $config[] = 'config/' . $t['name'];
            }
            //config right after infra
            $pos = 0;
            foreach( $order as $i => $k )
                if( strpos($k, self::AREA_INFRA . '/') === 0 )
                    $pos = $i + 1;
            array_splice( $order, $pos, 0, $config );
        }
        return array_values($order);
    }

    ////////////////////////////////////////////////////////////////////////////////
    // devices (/config/setup/v1/devices)

    /** @var array devices of the last exportConfig() */
    public $configDevices = array();

    const DEVICE_CSV_COLUMNS = array( 'serial_number', 'name', 'display_name', 'hostname', 'model', 'family', 'type', 'folder',
        'snippets', 'labels', 'is_connected', 'connected_since', 'last_disconnect_time', 'ip_address', 'ipV6_address',
        'mac_address', 'software_version', 'app_version', 'threat_version', 'anti_virus_version', 'wf_ver', 'url_db_ver',
        'ha_state', 'ha_peer_serial', 'ha_peer_state', 'license_match', 'device_only', 'description' );

    /**
     * license authcodes are not written to disk
     */
    public static function stripDeviceSecrets( $devices )
    {
        foreach( $devices as &$d )
        {
            foreach( array('installed_licenses', 'available_licenses') as $f )
            {
                if( !isset($d[$f]) || !is_array($d[$f]) )
                    continue;
                foreach( $d[$f] as &$lic )
                    if( is_array($lic) && array_key_exists('authcode', $lic) && $lic['authcode'] !== null && $lic['authcode'] !== "" )
                        $lic['authcode'] = self::REDACTED;
                unset($lic);
            }
        }
        unset($d);
        return $devices;
    }

    public function writeDevicesCSV( $devices )
    {
        $fh = fopen( $this->exportDir . "/" . self::AREA_CONFIG . "/devices.csv", "w" );
        fputcsv( $fh, self::DEVICE_CSV_COLUMNS, ',', '"', '' );
        foreach( $devices as $d )
        {
            $line = array();
            foreach( self::DEVICE_CSV_COLUMNS as $c )
            {
                $v = self::get($d, $c);
                if( is_array($v) )
                    $v = implode(" | ", array_map( function($x){ return is_array($x) ? json_encode($x) : (string)$x; }, $v ));
                elseif( is_bool($v) )
                    $v = $v ? "true" : "false";
                $line[] = $v;
            }
            fputcsv( $fh, $line, ',', '"', '' );
        }
        fclose( $fh );
    }

    public function buildDeviceSummary()
    {
        $devices = $this->configDevices;
        if( count($devices) == 0 )
            return null;
        $byModel = array();
        $byFolder = array();
        $connected = array();
        $disconnected = array();
        $ha = array();
        $withoutFolder = array();
        $folderNames = array();
        foreach( (array)( $this->configHierarchy !== null ? $this->configHierarchy['folders'] : array() ) as $f )
            $folderNames[$f['name']] = true;
        foreach( $devices as $d )
        {
            $serial = (string)self::firstOf($d, array('serial_number', 'name'));
            $model = (string)self::get($d, 'model', '?');
            $folder = self::get($d, 'folder');
            $byModel[$model] = ( isset($byModel[$model]) ? $byModel[$model] : 0 ) + 1;
            $fk = $folder === null || $folder === "" ? '(none)' : (string)$folder;
            $byFolder[$fk][] = $serial;
            if( self::get($d, 'is_connected') === true )
                $connected[] = $serial;
            else
                $disconnected[] = $serial;
            $peer = self::get($d, 'ha_peer_serial');
            if( $peer !== null && $peer !== "" )
            {
                $pair = array( $serial, (string)$peer );
                sort($pair);
                $ha[ implode(" / ", $pair) ] = true;
            }
            if( $folder === null || $folder === "" || ( count($folderNames) > 0 && !isset($folderNames[$folder]) && !isset($folderNames[$serial]) ) )
                $withoutFolder[] = $serial;
        }
        ksort($byModel);
        ksort($byFolder);
        return array(
            'files' => array( self::AREA_CONFIG . '/03_devices.json', self::AREA_CONFIG . '/devices.csv' ),
            'total' => count($devices),
            'connected' => count($connected),
            'disconnected' => $disconnected,
            'by_model' => $byModel,
            'by_folder' => $byFolder,
            'ha_pairs' => array_keys($ha),
            'without_folder' => $withoutFolder,
        );
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
    /**
     * principal_type of the access policy; if the API does not return one: derived from the principal
     * (service accounts end with .iam.panserviceaccount.com)
     */
    public static function iamPrincipalType( $policy, $principal )
    {
        $t = self::firstOf($policy, array('principal_type', 'type'));
        if( is_string($t) && $t !== '' )
            return $t;
        if( !is_string($principal) || $principal === '' )
            return '';
        if( substr($principal, -strlen('.iam.panserviceaccount.com')) === '.iam.panserviceaccount.com' )
            return 'service_account';
        if( strpos($principal, '@') !== FALSE )
            return 'user';
        return '';
    }

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
                'principal_type' => self::iamPrincipalType( $p, $principal ),
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
        $byType = array();
        foreach( $rows as $row )
        {
            $r = (string)$row['role'];
            $byRole[$r] = ( isset($byRole[$r]) ? $byRole[$r] : 0 ) + 1;
            $t = (string)$row['principal_type'] !== '' ? (string)$row['principal_type'] : 'unknown';
            $byType[$t] = ( isset($byType[$t]) ? $byType[$t] : 0 ) + 1;
        }
        ksort($byRole);
        ksort($byType);

        $names = function( $endpoint ){
            return array_values( array_filter( array_map( function($e){ return self::firstOf($e, array('name', 'role_name', 'client_id', 'id')); }, $this->listData($endpoint, self::AREA_IAM) ) ) );
        };

        return array(
            'access_policies' => count($rows),
            'access_policies_by_role' => $byRole,
            'access_policies_by_principal_type' => $byType,
            'roles' => count( $this->listData('roles', self::AREA_IAM) ),
            'custom_roles' => $names('custom-roles'),
            //names are in iam/03_permission-sets.json - hundreds of entries, only counted here
            'permission_sets' => count( $this->listData('permission-sets', self::AREA_IAM) ),
            'permissions' => count( $this->listData('permissions', self::AREA_IAM) ),
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
            $pskStats = isset($manifest['secret_lists'][$area]['psk']) ? $manifest['secret_lists'][$area]['psk'] : null;
            if( count($psk) > 0 && $pskStats !== null && $pskStats['decrypt_failed'] > 0 )
                $add( 'psk_' . $area, 'action_required', $area, 'IKE pre-shared keys not decryptable',
                    $pskStats['decrypt_failed'] . ' of ' . $pskStats['gateways'] . ' PSKs are not encrypted with the master key used (default or master-key=) - '
                    . 'fill psk_new in ' . $area . '/psk-list.csv (e.g. from the peer firewalls); check the values with scm_pa_secret_check.php '
                    . '(SHA1 of the exported value: psk_sha1)', $psk );
            elseif( count($psk) > 0 )
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
        if( $this->hasArea(self::AREA_INFRA) )
            $add( 'ztna_connector', count($ztna) > 0 ? 'action_required' : 'check', self::AREA_INFRA, 'ZTNA connector (not exported)',
                'ZTNA connector groups / applications use a separate API and are not part of this export', $ztna );
        if( $this->hasArea(self::AREA_MU) )
            $add( 'explicit_proxy', 'check', self::AREA_MU, 'Mobile Users Explicit Proxy (not exported)',
                'no documented public API - configure manually or via the internal SCM API (to be added)' );
        $add( 'identity_logging', 'check', 'tenant', 'Cloud Identity Engine, Strata Logging Service, log forwarding (not exported)',
            'tenant bound services - set up on the target tenant before the configuration that references them' );
        if( $this->hasArea(self::AREA_CONFIG) && isset($manifest['config']['devices']) && $manifest['config']['devices'] !== null )
        {
            $dv = $manifest['config']['devices'];
            $add( 'devices', 'action_required', self::AREA_CONFIG, 'Devices (NGFW serials)',
                $dv['total'] . ' device(s) - onboarding / license transfer of the serials to the target tenant and the folder assignment are not part of the config sync; see config/devices.csv',
                array_map( function($f, $serials){ return $f . ": " . implode(", ", $serials); }, array_keys($dv['by_folder']), $dv['by_folder'] ) );
            if( count($dv['disconnected']) > 0 )
                $add( 'devices_disconnected', 'check', self::AREA_CONFIG, 'Devices not connected', 'not connected to Strata Cloud Manager at export time', $dv['disconnected'] );
            if( count($dv['ha_pairs']) > 0 )
                $add( 'devices_ha', 'info', self::AREA_CONFIG, 'HA pairs', 'move HA peers together', $dv['ha_pairs'] );
        }
        if( $this->hasArea(self::AREA_CONFIG) && $this->configHierarchy !== null )
        {
            $add( 'objects_policies', 'check', self::AREA_CONFIG, 'Folders, snippets, objects and security policy',
                'exported in config/ (owned objects per container, hierarchy.json with snippet order); import / verify with pan-os-php in=scm-api://<TSG>' );
            if( !empty($manifest['config']['types_skipped_heavy']) )
                $add( 'config_heavy', 'check', self::AREA_CONFIG, 'Custom applications not exported',
                    'the applications API returns the complete predefined catalog for every folder - skipped by default; export custom applications with config-types=applications (optionally container=<folders with custom applications>) or config-heavy-types',
                    $manifest['config']['types_skipped_heavy'] );
            $notExported = isset($manifest['config']['owners_not_exported']) ? $manifest['config']['owners_not_exported'] : array();
            if( count($notExported) > 0 )
                $add( 'config_owners', 'info', self::AREA_CONFIG, 'Objects owned by containers not exported',
                    'inherited objects whose owner is predefined or filtered out (container= / config-devices / config-predefined-snippets) - counted only',
                    array_map( function($k, $v){ return $k . " (" . $v . ")"; }, array_keys($notExported), $notExported ) );
        }
        else
            $add( 'objects_policies', 'info', 'tenant', 'Objects and security policy',
                'not part of this export - export them with area=config (config-scope=objects,policies,...)' );

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
            $roles = array();
            foreach( $manifest['iam']['access_policies_by_role'] as $r => $c )
                $roles[] = $r . " " . $c;
            $add( 'iam', 'action_required', self::AREA_IAM, 'IAM: users, roles, service accounts',
                $manifest['iam']['access_policies'] . ' access policies (' . implode(", ", $roles) . ') - create them on the target TSG (iam/access-policies.csv: principal_new / resource_new); review superuser assignments; service account secrets cannot be exported - create new ones', $sa );
            if( count($manifest['iam']['custom_roles']) > 0 )
                $add( 'iam_custom_roles', 'action_required', self::AREA_IAM, 'IAM custom roles',
                    'create the custom roles before the access policies that use them (iam/02_custom-roles.json)', $manifest['iam']['custom_roles'] );
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
        $dir = dirname( $this->exportDir . "/" . $file );
        if( !is_dir($dir) )
            mkdir( $dir, 0700, TRUE );
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
