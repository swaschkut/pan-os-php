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
 * As-built documentation of a Prisma Access / SCM tenant from a scm_pa_export.php folder
 * (CONCEPT_prisma_access_lifecycle.md 4.1, step A):
 *
 *   report.md        Markdown (convert to Word / PDF with pandoc or similar)
 *   report.html      self-contained HTML (print to PDF)
 *   prisma-access.drawio   network plans (pages: overview, service connections, remote networks, mobile users) -
 *                          opens in draw.io / diagrams.net, imports into Lucidchart (File > Import > draw.io)
 *
 * Offline: only the export files are read. Secrets are never printed (the export redacts them, the report skips
 * every secret field in addition).
 */
class SCMPrismaAccessReport
{
    public $dir;
    public $manifest = array();
    /** @var array area|name => manifest endpoint entry */
    private $endpoints = array();
    /** @var array[] sections: id, title, blocks */
    public $sections = array();
    /** @var array drawio pages: name => array( cells ) */
    public $pages = array();
    public $warnings = array();

    const SECRET_KEYS = '/(secret|password|passwd|pre_shared_key|psk|api_key|private_key|passphrase|token|client_secret)/i';

    public function __construct( $dir )
    {
        $dir = PanSCMExportConnector::resolveDir( $dir );
        if( !is_file($dir . "/manifest.json") )
            derr( "'" . $dir . "' is no scm_pa_export.php folder (manifest.json missing)", null, FALSE );
        $this->dir = $dir;
        $this->manifest = json_decode( file_get_contents($dir . "/manifest.json"), TRUE );
        if( !is_array($this->manifest) )
            derr( "manifest.json of '" . $dir . "' is not readable", null, FALSE );
        foreach( isset($this->manifest['endpoints']) ? $this->manifest['endpoints'] : array() as $ep )
            if( isset($ep['area']) && isset($ep['name']) && !isset($ep['container']) )
                $this->endpoints[$ep['area'] . "|" . $ep['name']] = $ep;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // data access

    /** data of an endpoint (area level), null when not exported / error */
    public function data( $area, $name )
    {
        $k = $area . "|" . $name;
        if( !isset($this->endpoints[$k]) || !isset($this->endpoints[$k]['file']) )
            return null;
        $j = $this->json( $this->endpoints[$k]['file'] );
        return is_array($j) && array_key_exists('data', $j) ? $j['data'] : null;
    }

    public function status( $area, $name )
    {
        $k = $area . "|" . $name;
        return isset($this->endpoints[$k]['status']) ? $this->endpoints[$k]['status'] : 'not exported';
    }

    /** list data (always an array of entries) */
    public function rows( $area, $name )
    {
        $d = $this->data( $area, $name );
        if( !is_array($d) )
            return array();
        if( $d !== array() && array_keys($d) !== range(0, count($d) - 1) )
            return array( $d );
        return $d;
    }

    public function json( $rel )
    {
        $f = $this->dir . "/" . $rel;
        if( !is_file($f) )
            return null;
        $j = json_decode( file_get_contents($f), TRUE );
        return is_array($j) ? $j : null;
    }

    public function hasArea( $area )
    {
        return isset($this->manifest['areas']) && in_array($area, $this->manifest['areas'], TRUE);
    }

    public static function get( $a, $path, $default = null )
    {
        foreach( explode(".", $path) as $p )
        {
            if( !is_array($a) || !array_key_exists($p, $a) )
                return $default;
            $a = $a[$p];
        }
        return $a;
    }

    /** value for a table cell: lists joined, booleans yes / no, secrets masked */
    public static function fmt( $v )
    {
        if( $v === null || $v === '' || $v === array() )
            return "–";
        if( is_bool($v) )
            return $v ? "yes" : "no";
        if( is_array($v) )
        {
            if( array_keys($v) === range(0, count($v) - 1) )
            {
                $parts = array();
                foreach( $v as $x )
                    $parts[] = is_array($x) ? ( isset($x['name']) ? $x['name'] : json_encode($x, JSON_UNESCAPED_SLASHES) ) : self::fmt($x);
                return implode(", ", $parts);
            }
            if( isset($v['member']) && is_array($v['member']) )
                return self::fmt( $v['member'] );
            $parts = array();
            foreach( $v as $k => $x )
                $parts[] = $k . ( is_string($k) && preg_match(self::SECRET_KEYS, $k) ? ": (secret)" : ( $x === array() ? "" : ": " . self::fmt($x) ) );
            return implode("; ", $parts);
        }
        $s = (string)$v;
        if( preg_match('/^-AQ==|REDACTED/', $s) )
            return "(secret)";
        return $s;
    }

    public static function stripSecrets( $v )
    {
        if( !is_array($v) )
            return $v;
        $out = array();
        foreach( $v as $k => $x )
        {
            if( is_string($k) && preg_match(self::SECRET_KEYS, $k) )
            {
                $out[$k] = "(secret)";
                continue;
            }
            $out[$k] = self::stripSecrets($x);
        }
        return $out;
    }

    /** flat key / value rows of an object (nested keys with dots), secrets masked */
    public static function flatten( $v, $prefix = "", &$out = array(), $depth = 0 )
    {
        if( is_array($v) && $v !== array() && $depth <= 4 && array_keys($v) === range(0, count($v) - 1) && is_array($v[0]) && isset($v[0]['name']) )
        {
            //list of named objects: one block per entry
            foreach( $v as $x )
            {
                $n = is_array($x) && isset($x['name']) ? $x['name'] : '?';
                if( is_array($x) )
                    unset( $x['name'] );
                self::flatten( $x, $prefix . "[" . $n . "]", $out, $depth + 1 );
            }
            return $out;
        }
        if( !is_array($v) || $depth > 4 || ( $v !== array() && array_keys($v) === range(0, count($v) - 1) ) )
        {
            $out[] = array( $prefix, self::fmt($v) );
            return $out;
        }
        foreach( $v as $k => $x )
        {
            if( in_array($k, array('id', 'folder', 'snippet'), TRUE) )
                continue;
            $key = $prefix === "" ? (string)$k : $prefix . "." . $k;
            if( is_string($k) && preg_match(self::SECRET_KEYS, $k) )
            {
                $out[] = array( $key, "(secret)" );
                continue;
            }
            self::flatten( $x, $key, $out, $depth + 1 );
        }
        return $out;
    }

    public static function names( $rows )
    {
        $n = array();
        foreach( $rows as $r )
            if( is_array($r) && isset($r['name']) )
                $n[] = $r['name'];
        return $n;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // sections

    private function section( $id, $title, $blocks )
    {
        $this->sections[] = array( 'id' => $id, 'title' => $title, 'blocks' => $blocks );
    }

    private static function p( $text ) { return array( 'type' => 'p', 'text' => $text ); }
    private static function h( $text ) { return array( 'type' => 'h', 'text' => $text ); }
    private static function kv( $rows ) { return array( 'type' => 'table', 'head' => array( 'setting', 'value' ), 'rows' => $rows ); }
    private static function table( $head, $rows ) { return array( 'type' => 'table', 'head' => $head, 'rows' => $rows ); }
    private static function pre( $text ) { return array( 'type' => 'pre', 'text' => $text ); }

    public function build()
    {
        $this->sectionSummary();
        $this->sectionInfra();
        $this->sectionConnections( SCMPrismaAccessExport::AREA_SC );
        $this->sectionConnections( SCMPrismaAccessExport::AREA_RN );
        $this->sectionMobileUsers();
        $this->sectionExplicitProxy();
        $this->sectionPrismaBrowser();
        $this->sectionConfig();
        $this->sectionIam();
        $this->sectionChecklist();
        $this->sectionFindings();
        $this->buildDiagrams();
        //numbering: summary, findings, rest
        foreach( $this->sections as $i => $sec )
            $this->sections[$i]['title'] = ( $i + 1 ) . ". " . preg_replace('/^\d+\.\s*/', '', $sec['title']);
    }

    /** security rule statistics of the config area (sectionConfig) */
    public $ruleStats = array( 'total' => 0, 'disabled' => 0, 'allow' => 0, 'no_profile' => array(), 'any_any' => array() );

    /** @var array[] findings: severity, area, finding, recommendation */
    public $findings = array();

    private function finding( $severity, $area, $text, $recommendation )
    {
        $this->findings[] = array( $severity, $area, $text, $recommendation );
    }

    const WEAK_ENC = '/^(des|3des|aes-128-cbc|null)$/i';
    const WEAK_HASH = '/^(md5|sha1|non-auth)$/i';
    const WEAK_DH = '/^group(1|2|5)$/i';

    /**
     * maturity style checks of the as-built state (design / operations, not the security profile best practice -
     * that is the playbook / exportsptohtml part)
     */
    private function sectionFindings()
    {
        $sc = $this->scRows();
        $rn = $this->rnRows();
        if( $this->hasArea(SCMPrismaAccessExport::AREA_SC) )
        {
            if( count($sc) == 1 )
                $this->finding( 'medium', 'service connections', "only one service connection (" . $sc[0]['service_connection'] . ")", "second service connection in another location as backup_SC / for redundancy of the data center access" );
            $backupOf = array();
            foreach( $sc as $c )
                if( !empty($c['backup_SC']) )
                    $backupOf[$c['backup_SC']][] = $c['service_connection'];
            foreach( $sc as $c )
                if( empty($c['secondary_ipsec_tunnel']) && empty($c['backup_SC']) && count($sc) > 1 )
                {
                    if( isset($backupOf[$c['service_connection']]) )
                        $this->finding( 'low', 'service connections', $c['service_connection'] . " (backup SC of " . implode(", ", $backupOf[$c['service_connection']]) . "): single tunnel", "secondary IPsec tunnel when the backup path itself needs redundancy" );
                    else
                        $this->finding( 'medium', 'service connections', $c['service_connection'] . ": no secondary tunnel and no backup SC", "secondary IPsec tunnel to a second data center firewall / ISP, or backup_SC" );
                }
                elseif( empty($c['secondary_ipsec_tunnel']) && count($sc) == 1 )
                    $this->finding( 'high', 'service connections', $c['service_connection'] . ": single tunnel, single service connection", "secondary IPsec tunnel and a second service connection" );
            foreach( $sc as $c )
                if( empty($c['bgp_enabled']) )
                    $this->finding( 'low', 'service connections', $c['service_connection'] . ": static routing", "BGP for dynamic failover between primary / secondary tunnel and service connections" );
        }
        foreach( $rn as $c )
        {
            if( empty($c['secondary_ipsec_tunnel']) )
                $this->finding( 'low', 'remote networks', $c['remote_network'] . ": no secondary tunnel", "secondary IPsec tunnel (second ISP / branch firewall) or ECMP for sites with availability requirements" );
            if( empty($c['bgp_enabled']) && !empty($c['secondary_ipsec_tunnel']) )
                $this->finding( 'low', 'remote networks', $c['remote_network'] . ": secondary tunnel with static routing", "BGP for a deterministic failover" );
        }
        foreach( array( SCMPrismaAccessExport::AREA_SC, SCMPrismaAccessExport::AREA_RN ) as $area )
        {
            $label = $area == SCMPrismaAccessExport::AREA_SC ? 'service connections' : 'remote networks';
            foreach( $this->rows( $area, 'ike-crypto-profiles' ) as $p )
            {
                $weak = array_merge( preg_grep(self::WEAK_ENC, (array)self::get($p, 'encryption', array())), preg_grep(self::WEAK_HASH, (array)self::get($p, 'hash', array())), preg_grep(self::WEAK_DH, (array)self::get($p, 'dh_group', array())) );
                if( count($weak) )
                    $this->finding( 'high', $label, "IKE crypto profile " . self::get($p, 'name') . ": weak algorithms " . implode(", ", $weak), "AES-256 (GCM / CBC), SHA-256 or better, DH group 14 / 19 / 20" );
            }
            foreach( $this->rows( $area, 'ipsec-crypto-profiles' ) as $p )
            {
                $weak = array_merge( preg_grep(self::WEAK_ENC, (array)self::get($p, 'esp.encryption', array())), preg_grep(self::WEAK_HASH, (array)self::get($p, 'esp.authentication', array())), preg_grep(self::WEAK_DH, (array)self::get($p, 'dh_group', array())) );
                if( count($weak) )
                    $this->finding( 'high', $label, "IPsec crypto profile " . self::get($p, 'name') . ": weak algorithms " . implode(", ", $weak), "AES-256-GCM, SHA-256 or better, PFS with DH group 14 / 19 / 20" );
            }
            foreach( $this->rows( $area, 'ike-gateways' ) as $g )
                if( self::get($g, 'protocol.version') == 'ikev1' || ( self::get($g, 'protocol.ikev1') !== null && self::get($g, 'protocol.ikev2') === null && self::get($g, 'protocol.version') === null ) )
                    $this->finding( 'medium', $label, "IKE gateway " . self::get($g, 'name') . ": IKEv1", "IKEv2 when the peer supports it" );
            foreach( $this->rows( $area, 'ipsec-tunnels' ) as $t )
                if( !self::get($t, 'tunnel_monitor.enable') )
                    $this->finding( 'low', $label, "IPsec tunnel " . self::get($t, 'name') . ": tunnel monitor disabled", "tunnel monitor for a faster failover (static routing)" );
        }
        $MU = SCMPrismaAccessExport::AREA_MU;
        if( $this->hasArea($MU) )
        {
            foreach( $this->rows( $MU, 'authentication-profiles' ) as $a )
            {
                $method = is_array(self::get($a, 'method')) ? array_keys(self::get($a, 'method')) : array();
                if( !in_array('saml_idp', $method, TRUE) && !self::get($a, 'multi_factor_auth.mfa_enable') )
                    $this->finding( 'medium', 'mobile users', "authentication profile " . self::get($a, 'name') . " (" . implode(", ", $method) . "): no MFA", "SAML with MFA at the IdP (Cloud Identity Engine) or MFA in the authentication profile" );
            }
            foreach( $this->rows( $MU, 'mobile-agent-agent-profiles' ) as $p )
            {
                $cm = self::get($p, 'gp_app_config.connect_method', self::get($p, 'connect_method'));
                if( $cm !== null && !in_array($cm, array('user-logon', 'pre-logon'), TRUE) )
                    $this->finding( 'medium', 'mobile users', "agent profile " . self::get($p, 'name') . ": connect method " . $cm, "always-on (user-logon / pre-logon) for consistent protection" );
            }
            if( count($this->rows( $MU, 'local-users' )) > 0 )
                $this->finding( 'low', 'mobile users', count($this->rows($MU, 'local-users')) . " local user(s)", "identities from the IdP; local users only as break glass" );
        }
        if( $this->hasArea(SCMPrismaAccessExport::AREA_INFRA) && count($this->rows(SCMPrismaAccessExport::AREA_INFRA, 'internal-dns-servers')) == 0 && count($sc) > 0 )
            $this->finding( 'low', 'infrastructure', "no internal DNS servers configured", "internal DNS servers for the internal domains (resolution of private applications through the service connections)" );
        if( $this->hasArea(SCMPrismaAccessExport::AREA_INFRA) && count($this->rows(SCMPrismaAccessExport::AREA_INFRA, 'egress-ip')) == 0 )
            $this->finding( 'info', 'infrastructure', "egress IP addresses not exported", "export with egress-api-key= for the allow list documentation" );
        $IAM = SCMPrismaAccessExport::AREA_IAM;
        if( $this->hasArea($IAM) )
        {
            $super = 0;
            $saSuper = array();
            foreach( $this->rows( $IAM, 'access-policies' ) as $p )
                if( self::get($p, 'role') == 'superuser' )
                {
                    $super++;
                    if( strpos((string)self::get($p, 'principal'), 'iam.panserviceaccount.com') !== FALSE )
                        $saSuper[] = self::get($p, 'principal');
                }
            if( $super - count($saSuper) > 3 )
                $this->finding( 'medium', 'administration', ( $super - count($saSuper) ) . " users with role superuser", "least privilege: role based access (network / security / view only administrator) per task" );
            if( count($saSuper) )
                $this->finding( 'low', 'administration', count($saSuper) . " service account(s) with role superuser", "service accounts with the minimal role for their automation (e.g. read only for exports)" );
        }
        $rs = $this->ruleStats;
        if( count($rs['no_profile']) )
            $this->finding( 'medium', 'security policy', count($rs['no_profile']) . " of " . $rs['allow'] . " allow rule(s) without profile group: " . self::fmt(array_slice($rs['no_profile'], 0, 10)) . ( count($rs['no_profile']) > 10 ? ", …" : "" ),
                "profile group (at least visibility / alert only) on every allow rule - visibility playbook (WORKFLOW_scm_visibility.md)" );
        if( count($rs['any_any']) )
            $this->finding( 'low', 'security policy', count($rs['any_any']) . " allow rule(s) with application any and service any: " . self::fmt(array_slice($rs['any_any'], 0, 10)) . ( count($rs['any_any']) > 10 ? ", …" : "" ),
                "App-ID based rules (application / service application-default)" );
        if( $rs['disabled'] > 0 )
            $this->finding( 'info', 'security policy', $rs['disabled'] . " disabled security rule(s)", "remove rules that are no longer needed" );
        if( count($this->rows( SCMPrismaAccessExport::AREA_PB, 'pending-changes' )) )
            $this->finding( 'low', 'Prisma Browser', count($this->rows(SCMPrismaAccessExport::AREA_PB, 'pending-changes')) . " unpublished change(s)", "publish or discard the draft" );

        $order = array( 'high' => 0, 'medium' => 1, 'low' => 2, 'info' => 3 );
        usort( $this->findings, function( $a, $b ) use ( $order ) { return $order[$a[0]] - $order[$b[0]]; } );
        $count = array( 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0 );
        foreach( $this->findings as $f )
            $count[$f[0]]++;
        $sec = array( 'id' => 'findings', 'title' => 'Findings', 'blocks' => array(
            self::p( "Design and operations checks of the as-built state (redundancy, routing, crypto, authentication, administration). "
                . "Security profile best practice / visibility: section \"Configuration and security posture\"." ),
            self::table( array( 'severity', 'count' ), array( array( 'high', (string)$count['high'] ), array( 'medium', (string)$count['medium'] ), array( 'low', (string)$count['low'] ), array( 'info', (string)$count['info'] ) ) ),
            count($this->findings) ? self::table( array( 'severity', 'area', 'finding', 'recommendation' ), $this->findings ) : self::p( "no findings" ) ) );
        array_splice( $this->sections, 1, 0, array( $sec ) );
        //summary row
        $this->sections[0]['blocks'][1]['rows'][] = array( 'findings (high / medium / low / info)', $count['high'] . " / " . $count['medium'] . " / " . $count['low'] . " / " . $count['info'] );
    }

    private function scRows()
    {
        $m = $this->json( SCMPrismaAccessExport::AREA_SC . "/ip-mapping.json" );
        return isset($m['service_connections']) ? $m['service_connections'] : array();
    }

    private function rnRows()
    {
        $m = $this->json( SCMPrismaAccessExport::AREA_RN . "/ip-mapping.json" );
        return isset($m['remote_networks']) ? $m['remote_networks'] : array();
    }

    private function muMapping()
    {
        $m = $this->json( SCMPrismaAccessExport::AREA_MU . "/ip-mapping.json" );
        return is_array($m) ? $m : array();
    }

    private function sectionSummary()
    {
        $m = $this->manifest;
        $mu = $this->muMapping();
        $rows = array(
            array( 'tenant (TSG)', self::fmt( isset($m['tsg_id']) ? $m['tsg_id'] : null ) ),
            array( 'export created', self::fmt( isset($m['created_at']) ? $m['created_at'] : null ) ),
            array( 'export tool', self::fmt( ( isset($m['tool']) ? $m['tool'] : '' ) . ( isset($m['pan_os_php_version']) ? " (pan-os-php " . $m['pan_os_php_version'] . ")" : '' ) ) ),
            array( 'exported areas', self::fmt( isset($m['areas']) ? $m['areas'] : null ) ),
            array( 'infrastructure subnet', self::fmt( self::get($m, 'infra.infrastructure_subnet') ) ),
            array( 'infrastructure BGP AS', self::fmt( self::get($m, 'infra.infra_bgp_as') ) ),
            array( 'service connections', (string)count($this->scRows()) ),
            array( 'remote networks', (string)count($this->rnRows()) ),
            array( 'mobile users locations', (string)( isset($mu['locations']) ? count($mu['locations']) : 0 ) ),
            array( 'mobile users portal', self::fmt( isset($mu['portal_hostname']) ? $mu['portal_hostname'] : self::get($m, 'mobile_users.portal_hostname') ) ),
            array( 'explicit proxy', $this->hasArea(SCMPrismaAccessExport::AREA_EP) ? ( count($this->rows(SCMPrismaAccessExport::AREA_EP, 'ep-settings')) ? 'configured' : 'exported, no settings' ) : 'not exported' ),
            array( 'Prisma Browser', $this->hasArea(SCMPrismaAccessExport::AREA_PB) ? count($this->rows(SCMPrismaAccessExport::AREA_PB, 'applications')) . " application(s), " . count($this->rows(SCMPrismaAccessExport::AREA_PB, 'user-groups')) . " user group(s)" : 'not exported' ),
        );
        $errors = 0;
        foreach( $this->endpoints as $ep )
            if( isset($ep['status']) && $ep['status'] == 'error' )
                $errors++;
        $rows[] = array( 'endpoints with export errors', (string)$errors );
        $this->section( 'summary', '1. Summary', array(
            self::p( "As-built documentation generated from the export folder `" . basename(dirname($this->dir)) . "/" . basename($this->dir) . "` (read only, offline). Network plans: `prisma-access.drawio` (draw.io / Lucidchart)." ),
            self::kv( $rows ) ) );
    }

    private function sectionInfra()
    {
        $A = SCMPrismaAccessExport::AREA_INFRA;
        if( !$this->hasArea($A) )
        {
            $this->section( 'infra', '2. Infrastructure', array( self::p( "not exported (area infra)" ) ) );
            return;
        }
        $blocks = array();
        $infra = $this->data( $A, 'shared-infrastructure-settings' );
        $blocks[] = self::h( "Shared infrastructure settings" );
        $blocks[] = is_array($infra) && $infra !== array() ? self::kv( self::flatten($infra) ) : self::p( "not exported (" . $this->status($A, 'shared-infrastructure-settings') . ")" );
        $bgp = $this->data( $A, 'bgp-routing' );
        $blocks[] = self::h( "BGP routing" );
        $blocks[] = is_array($bgp) && $bgp !== array() ? self::kv( self::flatten($bgp) ) : self::p( "defaults / not exported" );
        $dns = $this->rows( $A, 'internal-dns-servers' );
        $blocks[] = self::h( "Internal DNS servers" );
        if( count($dns) )
        {
            $rows = array();
            foreach( $dns as $d )
                $rows[] = array( self::fmt(self::get($d, 'name')), self::fmt(self::get($d, 'domain_name')), self::fmt(self::get($d, 'primary')), self::fmt(self::get($d, 'secondary')) );
            $blocks[] = self::table( array( 'name', 'domains', 'primary', 'secondary' ), $rows );
        }
        else
            $blocks[] = self::p( "none" );

        $egress = $this->rows( $A, 'egress-ip' );
        $blocks[] = self::h( "Egress IP addresses per location (allow lists of SaaS / partners)" );
        if( count($egress) )
        {
            $rows = array();
            foreach( $egress as $z )
            {
                $by = array();
                foreach( isset($z['address_details']) ? $z['address_details'] : array() as $a )
                    $by[ ( isset($a['serviceType']) ? $a['serviceType'] : '?' ) . ( isset($a['addressType']) && $a['addressType'] != 'active' ? " (" . $a['addressType'] . ")" : '' ) ][] = isset($a['address']) ? $a['address'] : '?';
                foreach( $by as $svc => $addrs )
                    $rows[] = array( self::fmt(self::get($z, 'zone')), $svc, implode(", ", $addrs) );
            }
            $blocks[] = self::table( array( 'location', 'service', 'addresses' ), $rows );
        }
        else
            $blocks[] = self::p( "not exported (egress IP API key: `egress-api-key=` of scm_pa_export.php)" );
        $this->section( 'infra', '2. Infrastructure', $blocks );
    }

    /** IKE / IPsec objects of a connection area */
    private function cryptoBlocks( $area )
    {
        $blocks = array();
        $gws = $this->rows( $area, 'ike-gateways' );
        if( count($gws) )
        {
            $rows = array();
            foreach( $gws as $g )
            {
                $peer = self::get($g, 'peer_address.ip', self::get($g, 'peer_address.fqdn', self::get($g, 'peer_address.dynamic') !== null ? 'dynamic' : null));
                $ver = self::get($g, 'protocol.version');
                $prof = self::get($g, 'protocol.ikev2.ike_crypto_profile', self::get($g, 'protocol.ikev1.ike_crypto_profile'));
                if( $ver === null )
                    $ver = self::get($g, 'protocol.ikev2') !== null ? ( self::get($g, 'protocol.ikev1') !== null ? 'ikev2-preferred' : 'ikev2' ) : ( self::get($g, 'protocol.ikev1') !== null ? 'ikev1' : null );
                $auth = self::get($g, 'authentication.pre_shared_key') !== null ? 'pre-shared key' : ( self::get($g, 'authentication.certificate') !== null ? 'certificate' : null );
                $rows[] = array( self::fmt(self::get($g, 'name')), self::fmt($peer), self::fmt($ver), self::fmt($prof), self::fmt($auth),
                    self::fmt(self::get($g, 'local_id.id')), self::fmt(self::get($g, 'peer_id.id')), self::fmt(self::get($g, 'protocol_common.passive_mode')) );
            }
            $blocks[] = self::h( "IKE gateways (peer side)" );
            $blocks[] = self::table( array( 'name', 'peer address', 'IKE', 'IKE crypto profile', 'authentication', 'local id', 'peer id', 'passive' ), $rows );
        }
        $tun = $this->rows( $area, 'ipsec-tunnels' );
        if( count($tun) )
        {
            $rows = array();
            foreach( $tun as $t )
                $rows[] = array( self::fmt(self::get($t, 'name')), self::fmt( self::names( (array)self::get($t, 'auto_key.ike_gateway', array()) ) ),
                    self::fmt(self::get($t, 'auto_key.ipsec_crypto_profile')), self::fmt(self::get($t, 'tunnel_monitor.enable')), self::fmt(self::get($t, 'tunnel_monitor.destination_ip')),
                    self::fmt(self::get($t, 'anti_replay')) );
            $blocks[] = self::h( "IPsec tunnels" );
            $blocks[] = self::table( array( 'name', 'IKE gateway(s)', 'IPsec crypto profile', 'tunnel monitor', 'monitor IP', 'anti replay' ), $rows );
        }
        $rows = array();
        foreach( $this->rows( $area, 'ike-crypto-profiles' ) as $p )
            $rows[] = array( 'IKE', self::fmt(self::get($p, 'name')), self::fmt(self::get($p, 'encryption')), self::fmt(self::get($p, 'hash')), self::fmt(self::get($p, 'dh_group')),
                self::fmt( self::lifetime(self::get($p, 'lifetime')) ) );
        foreach( $this->rows( $area, 'ipsec-crypto-profiles' ) as $p )
            $rows[] = array( 'IPsec', self::fmt(self::get($p, 'name')), self::fmt(self::get($p, 'esp.encryption')), self::fmt(self::get($p, 'esp.authentication')), self::fmt(self::get($p, 'dh_group')),
                self::fmt( self::lifetime(self::get($p, 'lifetime')) ) );
        if( count($rows) )
        {
            $blocks[] = self::h( "Crypto profiles" );
            $blocks[] = self::table( array( 'type', 'name', 'encryption', 'hash / authentication', 'DH group', 'lifetime' ), $rows );
        }
        return $blocks;
    }

    private static function lifetime( $l )
    {
        if( !is_array($l) )
            return $l;
        foreach( $l as $unit => $v )
            return $v . " " . ( $v == 1 ? rtrim($unit, "s") : $unit );
        return null;
    }

    private function sectionConnections( $area )
    {
        $isSC = $area == SCMPrismaAccessExport::AREA_SC;
        $blocks = array();
        $mapRows = $isSC ? $this->scRows() : $this->rnRows();
        $raw = array();
        foreach( $this->rows( $area, $isSC ? 'service-connections' : 'remote-networks' ) as $r )
            if( isset($r['name']) )
                $raw[$r['name']] = $r;
        if( !$this->hasArea($area) )
        {
            $this->section( $isSC ? 'sc' : 'rn', $isSC ? '3. Service connections' : '4. Remote networks', array( self::p( "not exported" ) ) );
            return;
        }
        if( count($mapRows) == 0 )
            $blocks[] = self::p( "none configured" );
        else
        {
            $rows = array();
            foreach( $mapRows as $c )
            {
                $name = $isSC ? $c['service_connection'] : $c['remote_network'];
                $r = isset($raw[$name]) ? $raw[$name] : array();
                $routing = !empty($c['bgp_enabled']) ? "BGP peer AS " . self::fmt($c['bgp_peer_as']) . " (" . self::fmt($c['bgp_peer_ip_address']) . " ↔ " . self::fmt($c['bgp_local_ip_address']) . ")"
                    : "static" . ( self::get($r, 'subnets') ? ": " . self::fmt(self::get($r, 'subnets')) : "" );
                $tunnels = self::fmt($c['ipsec_tunnel']) . ( !empty($c['secondary_ipsec_tunnel']) ? " (active) / " . $c['secondary_ipsec_tunnel'] . " (backup)" : "" );
                if( !$isSC && self::get($r, 'ecmp_load_balancing') == 'enable' )
                    $tunnels = "ECMP: " . self::fmt( self::names( (array)self::get($r, 'ecmp_tunnels', array()) ) );
                if( $isSC )
                    $rows[] = array( $name, self::fmt($c['location_display'] ?: $c['region']), $tunnels, self::fmt($c['backup_SC']), $routing,
                        self::fmt($c['subnets']), self::fmt($c['peer_address']), self::fmt($c['qos_profile']), self::fmt($c['onboarding_type']) );
                else
                    $rows[] = array( $name, self::fmt($c['location_display'] ?: $c['region']), self::fmt($c['spn_name']), self::fmt($c['license_type']), $tunnels, $routing,
                        self::fmt($c['branch_peer_address']), self::fmt($c['service_ip_address']), self::fmt($c['egress_ip_addresses']) );
            }
            $blocks[] = self::table( $isSC
                ? array( 'service connection', 'location', 'tunnels', 'backup SC', 'routing', 'subnets', 'peer endpoint(s)', 'QoS', 'onboarding' )
                : array( 'remote network', 'location', 'SPN', 'licence', 'tunnels', 'routing', 'branch endpoint(s)', 'service IP', 'egress IP' ), $rows );
        }
        if( !$isSC )
        {
            $bw = $this->rows( $area, 'bandwidth-allocations' );
            if( count($bw) )
            {
                $rows = array();
                foreach( $bw as $b )
                    $rows[] = array( self::fmt(self::get($b, 'name')), self::fmt(self::get($b, 'allocated_bandwidth')), self::fmt(self::get($b, 'spn_name_list')),
                        self::fmt(self::get($b, 'qos.enabled')) . ( self::get($b, 'qos.profile') ? " (" . self::get($b, 'qos.profile') . ")" : "" ) );
                $blocks[] = self::h( "Bandwidth allocations" );
                $blocks[] = self::table( array( 'region', 'allocated bandwidth (Mbps)', 'SPNs', 'QoS' ), $rows );
            }
        }
        else
        {
            $grp = $this->rows( $area, 'service-connection-groups' );
            if( count($grp) )
            {
                $rows = array();
                foreach( $grp as $g )
                    $rows[] = array( self::fmt(self::get($g, 'name')), self::fmt(self::get($g, 'target')), self::fmt(self::get($g, 'disable_snat')), self::fmt(self::get($g, 'pbf_only')) );
                $blocks[] = self::h( "Service connection groups" );
                $blocks[] = self::table( array( 'name', 'service connections', 'SNAT disabled', 'PBF only' ), $rows );
            }
            $ts = $this->rows( $area, 'traffic-steering-rules' );
            if( count($ts) )
            {
                $rows = array();
                foreach( $ts as $t )
                    $rows[] = array( self::fmt(self::get($t, 'name')), self::fmt(self::get($t, 'source')), self::fmt(self::get($t, 'destination')), self::fmt(self::get($t, 'service')), self::fmt(self::get($t, 'action')) );
                $blocks[] = self::h( "Traffic steering rules" );
                $blocks[] = self::table( array( 'name', 'source', 'destination', 'service', 'action' ), $rows );
            }
        }
        $blocks = array_merge( $blocks, $this->cryptoBlocks($area) );
        $blocks[] = self::p( "Network plan: `prisma-access.drawio`, page \"" . ( $isSC ? "Service connections" : "Remote networks" ) . "\"." );
        $this->section( $isSC ? 'sc' : 'rn', $isSC ? '3. Service connections' : '4. Remote networks', $blocks );
    }

    private function sectionMobileUsers()
    {
        $A = SCMPrismaAccessExport::AREA_MU;
        if( !$this->hasArea($A) )
        {
            $this->section( 'mu', '5. Mobile users', array( self::p( "not exported" ) ) );
            return;
        }
        $blocks = array();
        $mu = $this->muMapping();
        $sum = isset($this->manifest['mobile_users']) ? $this->manifest['mobile_users'] : array();
        $blocks[] = self::kv( array(
            array( 'portal hostname', self::fmt( isset($mu['portal_hostname']) ? $mu['portal_hostname'] : self::get($sum, 'portal_hostname') ) ),
            array( 'deployment regions', self::fmt( array_keys( (array)self::get($sum, 'deployment_regions', array()) ) ) ),
            array( 'IP pools', self::fmt( self::get($sum, 'ip_pools') ) ),
            array( 'DNS servers (entries)', self::fmt( self::get($sum, 'dns_servers') ) ),
            array( 'authentication profiles used', self::fmt( self::get($sum, 'authentication_profiles_used') ) ),
            array( 'certificates', self::fmt( self::get($sum, 'certificates') ) ),
            array( 'local users', self::fmt( self::get($sum, 'local_users') ) ),
            array( 'mobile agent enabled', self::fmt( $this->data($A, 'mobile-agent-enable') ) ),
        ) );
        if( isset($mu['locations']) && count($mu['locations']) )
        {
            $cols = array();
            foreach( $mu['locations'] as $l )
                foreach( array_keys($l) as $k )
                    $cols[$k] = TRUE;
            $cols = array_keys($cols);
            $rows = array();
            foreach( $mu['locations'] as $l )
            {
                $r = array();
                foreach( $cols as $k )
                    $r[] = self::fmt( isset($l[$k]) ? $l[$k] : null );
                $rows[] = $r;
            }
            $blocks[] = self::h( "Locations and egress / gateway addresses" );
            $blocks[] = self::table( $cols, $rows );
        }
        $infra = $this->rows( $A, 'mobile-agent-infrastructure-settings' );
        if( count($infra) )
        {
            $blocks[] = self::h( "Infrastructure settings (IP pools, DNS, portal)" );
            foreach( $infra as $i )
                $blocks[] = self::kv( self::flatten($i) );
        }
        $auth = $this->rows( $A, 'authentication-profiles' );
        if( count($auth) )
        {
            $rows = array();
            foreach( $auth as $a )
            {
                $method = is_array(self::get($a, 'method')) ? implode(", ", array_keys(self::get($a, 'method'))) : null;
                $rows[] = array( self::fmt(self::get($a, 'name')), self::fmt($method), self::fmt(self::get($a, 'method.saml_idp.server_profile', self::get($a, 'method.ldap.server_profile'))), self::fmt(self::get($a, 'multi_factor_auth.mfa_enable')) );
            }
            $blocks[] = self::h( "Authentication profiles" );
            $blocks[] = self::table( array( 'name', 'method', 'server profile', 'MFA' ), $rows );
        }
        // 5a GlobalProtect
        $blocks[] = self::h( "5a. GlobalProtect (GPA)" );
        $rows = array();
        foreach( array( 'mobile-agent-agent-profiles' => 'agent profiles (app settings)', 'mobile-agent-tunnel-profiles' => 'tunnel profiles', 'mobile-agent-agent-versions' => 'agent versions',
                     'mobile-agent-authentication-settings' => 'authentication settings', 'gp-portals' => 'portals', 'gp-clientless-apps' => 'clientless apps', 'gp-trusted-zones' => 'trusted zones' ) as $ep => $label )
        {
            $r = $this->rows( $A, $ep );
            $rows[] = array( $label, $this->status($A, $ep), (string)count($r), self::fmt( array_slice( self::names($r) ?: array_map(function($x){ return is_array($x) ? ( isset($x['version']) ? $x['version'] : '' ) : (string)$x; }, array_slice($r, 0, 8)), 0, 12 ) ) );
        }
        $blocks[] = self::table( array( 'item', 'export status', 'entries', 'names (first 12)' ), $rows );
        foreach( $this->rows( $A, 'mobile-agent-agent-profiles' ) as $p )
        {
            $kv = array();
            foreach( array( 'connect_method', 'gp_app_config.connect_method', 'gp_app_config.always_on', 'tunnel_profile', 'os', 'match.os', 'authentication_override' ) as $k )
                if( self::get($p, $k) !== null )
                    $kv[] = array( $k, self::fmt(self::get($p, $k)) );
            if( count($kv) )
            {
                $blocks[] = self::p( "Agent profile **" . self::fmt(self::get($p, 'name')) . "**" );
                $blocks[] = self::kv( $kv );
            }
        }
        // 5b Prisma Access Agent
        $blocks[] = self::h( "5b. Prisma Access Agent (PAA)" );
        $rows = array();
        foreach( array( 'pa-agent-tenant-settings' => 'tenant settings', 'pa-agent-global-settings' => 'global settings', 'pa-agent-app-settings' => 'app settings',
                     'pa-agent-client-auth' => 'client authentication', 'pa-agent-token-lifetime' => 'token lifetime', 'pa-agent-staged-rollout' => 'staged rollout',
                     'pa-agent-project-based-access' => 'project based access' ) as $ep => $label )
        {
            $r = $this->rows( $A, $ep );
            $rows[] = array( $label, $this->status($A, $ep), (string)count($r), self::fmt( array_slice(self::names($r), 0, 12) ) );
        }
        $blocks[] = self::table( array( 'item', 'export status', 'entries', 'names (first 12)' ), $rows );
        $fp = $this->rows( SCMPrismaAccessExport::AREA_EP, 'forwarding-profiles' );
        if( count($fp) )
            $blocks[] = self::p( "Forwarding profiles (PAA / Explicit Proxy): " . self::fmt(self::names($fp)) );
        $this->section( 'mu', '5. Mobile users', $blocks );
    }

    private function sectionExplicitProxy()
    {
        $A = SCMPrismaAccessExport::AREA_EP;
        if( !$this->hasArea($A) )
        {
            $this->section( 'ep', '6. Explicit Proxy', array( self::p( "not exported (area explicit-proxy, internal UI API, ui-api-host=)" ) ) );
            return;
        }
        $blocks = array();
        $set = $this->rows( $A, 'ep-settings' );
        $blocks[] = self::h( "Settings" );
        $blocks[] = count($set) ? self::kv( self::flatten($set[0]) ) : self::p( "none" );
        $rows = array();
        foreach( array( 'ep-auth-settings' => 'authentication settings', 'ep-auth-ip-access' => 'IP based access', 'ep-block-settings' => 'block settings', 'ep-users' => 'users',
                     'proxy-server-profiles' => 'proxy server profiles', 'upstream-proxy-rules' => 'upstream proxy rules', 'forwarding-destinations' => 'forwarding destinations',
                     'forwarding-proxies' => 'forwarding proxies', 'forwarding-user-locations' => 'forwarding user locations', 'forwarding-source-applications' => 'forwarding source applications',
                     'forwarding-profiles' => 'forwarding profiles' ) as $ep => $label )
        {
            $r = $this->rows( $A, $ep );
            $rows[] = array( $label, $this->status($A, $ep), (string)count($r), self::fmt( array_slice(self::names($r), 0, 12) ) );
        }
        $blocks[] = self::h( "Components" );
        $blocks[] = self::table( array( 'item', 'export status', 'entries', 'names (first 12)' ), $rows );
        $this->section( 'ep', '6. Explicit Proxy', $blocks );
    }

    private function sectionPrismaBrowser()
    {
        $A = SCMPrismaAccessExport::AREA_PB;
        if( !$this->hasArea($A) )
        {
            $this->section( 'pb', '7. Prisma Browser', array( self::p( "not exported" ) ) );
            return;
        }
        $rows = array();
        foreach( array( 'user-groups' => 'user groups', 'device-groups' => 'device groups', 'applications' => 'applications', 'application-groups' => 'application groups',
                     'application-plugins' => 'application plugins', 'pending-changes' => 'pending (not published) changes' ) as $ep => $label )
        {
            $r = $this->rows( $A, $ep );
            $rows[] = array( $label, $this->status($A, $ep), (string)count($r), self::fmt( array_slice(self::names($r), 0, 12) ) );
        }
        $pol = array();
        foreach( array( 'policy-sign-in' => 'sign-in', 'policy-access-and-data' => 'access & data', 'policy-security' => 'security', 'policy-customization' => 'customization' ) as $ep => $label )
        {
            $d = $this->data( $A, $ep );
            $pol[] = array( $label, $this->status($A, $ep), (string)count((array)self::get($d, 'rules', array())), (string)count((array)self::get($d, 'sections', array())) );
        }
        $this->section( 'pb', '7. Prisma Browser', array( self::table( array( 'item', 'export status', 'entries', 'names (first 12)' ), $rows ),
            self::h( "Policies" ), self::table( array( 'policy', 'export status', 'rules', 'sections' ), $pol ) ) );
    }

    private function sectionConfig()
    {
        $blocks = array();
        if( !$this->hasArea(SCMPrismaAccessExport::AREA_CONFIG) )
        {
            $this->section( 'config', '8. Configuration and security posture', array( self::p( "config area not exported" ) ) );
            return;
        }
        if( is_file($this->dir . "/config/hierarchy.txt") )
        {
            $blocks[] = self::h( "Folder / snippet hierarchy" );
            $blocks[] = self::pre( trim(file_get_contents($this->dir . "/config/hierarchy.txt")) );
        }
        $counts = array();
        $types = array();
        foreach( array( 'folders', 'snippets' ) as $kind )
            foreach( glob($this->dir . "/config/" . $kind . "/*/*.json") as $f )
            {
                $t = preg_replace(array('/^\d+_/', '/-(pre|post)$/'), '', basename($f, ".json"));
                $j = json_decode(file_get_contents($f), TRUE);
                $n = isset($j['data']) && is_array($j['data']) ? count($j['data']) : 0;
                if( $n == 0 )
                    continue;
                $c = rtrim($kind, "s") . " " . basename(dirname($f));
                $counts[$c][$t] = ( isset($counts[$c][$t]) ? $counts[$c][$t] : 0 ) + $n;
                $types[$t] = TRUE;
                if( $t == 'security-rules' )
                    foreach( $j['data'] as $r )
                    {
                        if( !is_array($r) )
                            continue;
                        $this->ruleStats['total']++;
                        if( !empty($r['disabled']) )
                        {
                            $this->ruleStats['disabled']++;
                            continue;
                        }
                        if( self::get($r, 'action') != 'allow' )
                            continue;
                        $this->ruleStats['allow']++;
                        $name = $c . " / " . self::get($r, 'name', '?');
                        if( count((array)self::get($r, 'profile_setting.group', array())) == 0 )
                            $this->ruleStats['no_profile'][] = $name;
                        if( (array)self::get($r, 'application', array()) == array('any') && (array)self::get($r, 'service', array()) == array('any') )
                            $this->ruleStats['any_any'][] = $name;
                    }
            }
        $focus = array( 'addresses', 'address-groups', 'services', 'applications', 'url-categories', 'profile-groups', 'anti-spyware-profiles', 'vulnerability-protection-profiles',
            'wildfire-anti-virus-profiles', 'dns-security-profiles', 'url-access-profiles', 'file-blocking-profiles', 'decryption-profiles', 'zones', 'security-rules', 'nat-rules', 'decryption-rules' );
        $cols = array_values( array_intersect( $focus, array_keys($types) ) );
        if( count($counts) && count($cols) )
        {
            $rows = array();
            foreach( $counts as $c => $byType )
            {
                $r = array( $c );
                foreach( $cols as $t )
                    $r[] = isset($byType[$t]) ? (string)$byType[$t] : "";
                $rows[] = $r;
            }
            $blocks[] = self::h( "Objects per container (owned objects)" );
            $blocks[] = self::table( array_merge( array( 'container' ), $cols ), $rows );
        }
        if( $this->ruleStats['total'] > 0 )
            $blocks[] = self::p( "Security rules: " . $this->ruleStats['total'] . " (allow " . $this->ruleStats['allow'] . ", disabled " . $this->ruleStats['disabled'] . ", allow without profile group " . count($this->ruleStats['no_profile']) . ") - see section Findings." );
        $blocks[] = self::p( "Best practice / visibility of the security profiles: `pan-os-php type=scm-export-xml in=scm-export://<export> out=scm.xml`, then "
            . "`pan-os-php type=securityprofile in=scm.xml location=any actions=exportsptohtml:sp.html` (see WORKFLOW_scm_visibility.md)." );
        $this->section( 'config', '8. Configuration and security posture', $blocks );
    }

    private function sectionIam()
    {
        $A = SCMPrismaAccessExport::AREA_IAM;
        if( !$this->hasArea($A) )
        {
            $this->section( 'iam', '9. Administration', array( self::p( "not exported" ) ) );
            return;
        }
        $pol = $this->rows( $A, 'access-policies' );
        $byRole = array();
        foreach( $pol as $p )
            $byRole[ self::fmt(self::get($p, 'role')) ] = ( isset($byRole[self::fmt(self::get($p, 'role'))]) ? $byRole[self::fmt(self::get($p, 'role'))] : 0 ) + 1;
        $rows = array();
        foreach( $byRole as $r => $n )
            $rows[] = array( $r, (string)$n );
        $this->section( 'iam', '9. Administration', array(
            self::kv( array(
                array( 'roles', self::fmt( self::names($this->rows($A, 'roles')) ) ),
                array( 'custom roles', self::fmt( self::names($this->rows($A, 'custom-roles')) ) . ( $this->status($A, 'custom-roles') != 'ok' ? " (" . $this->status($A, 'custom-roles') . ")" : "" ) ),
                array( 'service accounts', (string)count($this->rows($A, 'service-accounts')) ),
                array( 'access policies', (string)count($pol) ) ) ),
            self::h( "Access policies per role" ),
            count($rows) ? self::table( array( 'role', 'principals' ), $rows ) : self::p( "none" ) ) );
    }

    private function sectionChecklist()
    {
        $blocks = array();
        $rows = array();
        foreach( $this->endpoints as $ep )
            if( isset($ep['status']) && $ep['status'] != 'ok' )
                $rows[] = array( $ep['area'], $ep['name'], $ep['status'], self::fmt( isset($ep['error']) ? ( is_array($ep['error']) ? json_encode($ep['error']) : $ep['error'] ) : null ) );
        $blocks[] = self::h( "Endpoints not exported completely" );
        $blocks[] = count($rows) ? self::table( array( 'area', 'endpoint', 'status', 'detail' ), $rows ) : self::p( "none" );
        if( is_file($this->dir . "/MIGRATION_CHECKLIST.md") )
        {
            $blocks[] = self::h( "Manual items (MIGRATION_CHECKLIST.md of the export)" );
            $blocks[] = array( 'type' => 'md', 'text' => preg_replace('/^#\s.*\R/', '', trim(file_get_contents($this->dir . "/MIGRATION_CHECKLIST.md"))) );
        }
        $this->section( 'checklist', '10. Checklist / open points', $blocks );
    }

    ////////////////////////////////////////////////////////////////////////////////
    // draw.io

    private $cellId = 2;

    private function vertex( $page, $label, $x, $y, $w, $h, $style )
    {
        $id = "c" . ( $this->cellId++ );
        $this->pages[$page][] = '<mxCell id="' . $id . '" value="' . self::xmlLabel($label) . '" style="' . $style . '" vertex="1" parent="1"><mxGeometry x="' . $x . '" y="' . $y . '" width="' . $w . '" height="' . $h . '" as="geometry"/></mxCell>';
        return $id;
    }

    private function edge( $page, $src, $tgt, $label, $style )
    {
        $id = "c" . ( $this->cellId++ );
        $this->pages[$page][] = '<mxCell id="' . $id . '" value="' . self::xmlLabel($label) . '" style="' . $style . '" edge="1" parent="1" source="' . $src . '" target="' . $tgt . '"><mxGeometry relative="1" as="geometry"/></mxCell>';
        return $id;
    }

    private static function xmlLabel( $s )
    {
        return str_replace( "\n", "&#xa;", htmlspecialchars( (string)$s, ENT_QUOTES | ENT_XML1, 'UTF-8' ) );
    }

    const ST_PA = 'ellipse;shape=cloud;whiteSpace=wrap;html=0;fillColor=#dae8fc;strokeColor=#6c8ebf;fontStyle=1;';
    const ST_DC = 'rounded=1;whiteSpace=wrap;html=0;fillColor=#fff2cc;strokeColor=#d6b656;align=left;spacingLeft=6;';
    const ST_BR = 'rounded=1;whiteSpace=wrap;html=0;fillColor=#d5e8d4;strokeColor=#82b366;align=left;spacingLeft=6;';
    const ST_PANODE = 'rounded=1;whiteSpace=wrap;html=0;fillColor=#dae8fc;strokeColor=#6c8ebf;align=left;spacingLeft=6;';
    const ST_MU = 'rounded=1;whiteSpace=wrap;html=0;fillColor=#e1d5e7;strokeColor=#9673a6;align=left;spacingLeft=6;';
    const ST_ZONE = 'rounded=0;whiteSpace=wrap;html=0;fillColor=none;dashed=1;strokeColor=#666666;verticalAlign=top;align=left;spacingLeft=8;fontStyle=2;';
    const ST_E1 = 'endArrow=none;html=0;strokeWidth=2;strokeColor=#333333;';
    const ST_E2 = 'endArrow=none;html=0;strokeWidth=1;dashed=1;strokeColor=#333333;';

    private function buildDiagrams()
    {
        $m = $this->manifest;
        $infraLabel = "Prisma Access\ninfra " . self::fmt(self::get($m, 'infra.infrastructure_subnet')) . "\nAS " . self::fmt(self::get($m, 'infra.infra_bgp_as'));
        $sc = $this->scRows();
        $rn = $this->rnRows();
        $mu = $this->muMapping();
        $muLoc = isset($mu['locations']) ? $mu['locations'] : array();

        // overview
        $P = "Overview";
        $this->pages[$P] = array();
        $rowsH = max( count($sc), count($rn), 3 ) * 90;
        $pa = $this->vertex( $P, $infraLabel, 470, max( 60, $rowsH / 2 - 40 ), 260, 150, self::ST_PA );
        foreach( array_values($sc) as $i => $c )
        {
            $dc = $this->vertex( $P, "DC / " . $c['service_connection'] . "\n" . self::fmt($c['location_display'] ?: $c['region']) . ( !empty($c['bgp_peer_as']) ? "\nBGP AS " . $c['bgp_peer_as'] : "\nstatic" ), 40, 40 + $i * 90, 220, 70, self::ST_DC );
            $this->edge( $P, $dc, $pa, "SC" . ( !empty($c['secondary_ipsec_tunnel']) ? " (2 tunnels)" : "" ), self::ST_E1 );
        }
        foreach( array_values($rn) as $i => $c )
        {
            $br = $this->vertex( $P, "Branch / " . $c['remote_network'] . "\n" . self::fmt($c['location_display'] ?: $c['region']) . ( !empty($c['bgp_peer_as']) ? "\nBGP AS " . $c['bgp_peer_as'] : "" ), 940, 40 + $i * 90, 220, 70, self::ST_BR );
            $this->edge( $P, $pa, $br, "RN", self::ST_E1 );
        }
        if( count($muLoc) || !empty($mu['portal_hostname']) )
        {
            $regions = array();
            foreach( $muLoc as $l )
                $regions[ isset($l['deployment_region']) ? $l['deployment_region'] : '?' ][] = isset($l['location_display']) ? $l['location_display'] : ( isset($l['location']) ? $l['location'] : '?' );
            $txt = "Mobile users\nportal " . self::fmt( isset($mu['portal_hostname']) ? $mu['portal_hostname'] : null );
            foreach( $regions as $r => $locs )
                $txt .= "\n" . $r . ": " . implode(", ", $locs);
            $muId = $this->vertex( $P, $txt, 470, max( 60, $rowsH / 2 - 40 ) + 200, 260, 40 + 18 * ( count($regions) + 1 ), self::ST_MU );
            $this->edge( $P, $pa, $muId, "GlobalProtect / PAA", self::ST_E2 );
        }

        // service connections
        foreach( array( 'Service connections' => array( $sc, 'service_connection', 'peer_address', self::ST_DC, 'Customer data center routing domain' ),
                     'Remote networks' => array( $rn, 'remote_network', 'branch_peer_address', self::ST_BR, 'Branch routing domain' ) ) as $P => $def )
        {
            list( $list, $key, $peerKey, $peerStyle, $zoneLabel ) = $def;
            $this->pages[$P] = array();
            $n = max( 1, count($list) );
            $this->vertex( $P, $zoneLabel, 20, 20, 330, 60 + $n * 130, self::ST_ZONE );
            $this->vertex( $P, "Prisma Access backbone (infra AS " . self::fmt(self::get($m, 'infra.infra_bgp_as')) . ", " . self::fmt(self::get($m, 'infra.infrastructure_subnet')) . ")", 560, 20, 360, 60 + $n * 130, self::ST_ZONE );
            foreach( array_values($list) as $i => $c )
            {
                $y = 60 + $i * 130;
                $peerIPs = array();
                foreach( (array)$c[$peerKey] as $pa )
                    $peerIPs[] = preg_replace( '/^(ip|fqdn)=/', '', substr( (string)$pa, strrpos((string)$pa, ": ") === FALSE ? 0 : strrpos((string)$pa, ": ") + 2 ) );
                $peer = $this->vertex( $P, ( $key == 'service_connection' ? "DC peer" : "Branch peer" ) . "\n" . self::fmt(array_values(array_unique($peerIPs)))
                    . ( !empty($c['bgp_enabled']) ? "\nBGP AS " . self::fmt($c['bgp_peer_as']) . " / " . self::fmt($c['bgp_peer_ip_address']) : "" )
                    . ( $key == 'service_connection' && !empty($c['subnets']) ? "\nsubnets " . self::fmt($c['subnets']) : "" ), 40, $y, 290, 100, $peerStyle );
                $node = $this->vertex( $P, $c[$key] . "\n" . self::fmt($c['location_display'] ?: $c['region'])
                    . ( !empty($c['bgp_local_ip_address']) ? "\nlocal BGP " . $c['bgp_local_ip_address'] : "" )
                    . ( $key == 'remote_network' && !empty($c['service_ip_address']) ? "\nservice IP " . $c['service_ip_address'] : "" )
                    . ( $key == 'service_connection' && !empty($c['backup_SC']) ? "\nbackup SC " . $c['backup_SC'] : "" ), 590, $y, 300, 100, self::ST_PANODE );
                $two = !empty($c['secondary_ipsec_tunnel']);
                $this->edge( $P, $peer, $node, self::fmt($c['ipsec_tunnel']) . ( $two ? " (active)" : "" ), self::ST_E1 . ( $two ? 'exitX=1;exitY=0.3;entryX=0;entryY=0.3;' : 'exitX=1;exitY=0.5;entryX=0;entryY=0.5;' ) );
                if( $two )
                    $this->edge( $P, $peer, $node, $c['secondary_ipsec_tunnel'] . " (backup)", self::ST_E2 . 'exitX=1;exitY=0.7;entryX=0;entryY=0.7;' );
            }
        }

        // mobile users
        $P = "Mobile users";
        $this->pages[$P] = array();
        $regions = array();
        foreach( $muLoc as $l )
            $regions[ isset($l['deployment_region']) ? $l['deployment_region'] : '?' ][] = $l;
        $x = 20;
        foreach( $regions as $r => $locs )
        {
            $this->vertex( $P, "region " . $r, $x, 20, 280, 50 + count($locs) * 90, self::ST_ZONE );
            foreach( $locs as $i => $l )
            {
                $ips = array();
                foreach( $l as $k => $v )
                    if( strpos($k, 'gp_') === 0 && !empty($v) )
                        $ips[] = $k . ": " . self::fmt($v);
                $this->vertex( $P, ( isset($l['location_display']) ? $l['location_display'] : self::fmt( isset($l['location']) ? $l['location'] : null ) ) . ( count($ips) ? "\n" . implode("\n", $ips) : "" ), $x + 15, 55 + $i * 90, 250, 75, self::ST_MU );
            }
            $x += 310;
        }
        if( count($regions) == 0 )
            $this->vertex( $P, "no mobile users locations exported", 20, 20, 300, 60, self::ST_MU );
    }

    public function renderDrawio()
    {
        $out = '<mxfile host="pan-os-php" type="device">' . "\n";
        $i = 0;
        foreach( $this->pages as $name => $cells )
        {
            $out .= '  <diagram name="' . self::xmlLabel($name) . '" id="page' . ( $i++ ) . '"><mxGraphModel dx="1200" dy="800" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1169" pageHeight="827"><root><mxCell id="0"/><mxCell id="1" parent="0"/>'
                . "\n    " . implode("\n    ", $cells) . "\n  </root></mxGraphModel></diagram>\n";
        }
        return $out . "</mxfile>\n";
    }

    ////////////////////////////////////////////////////////////////////////////////
    // Markdown / HTML

    public function title()
    {
        return "Prisma Access – as-built documentation – tenant " . ( isset($this->manifest['tsg_id']) ? $this->manifest['tsg_id'] : '?' );
    }

    private static function mdCell( $s )
    {
        return str_replace( array( "|", "\n" ), array( "\\|", "<br>" ), (string)$s );
    }

    public function renderMarkdown()
    {
        $md = "# " . $this->title() . "\n\n";
        $md .= "Generated " . date('Y-m-d H:i') . " by pan-os-php (scm_pa_report.php) from the export of " . self::fmt( isset($this->manifest['created_at']) ? $this->manifest['created_at'] : null ) . ".\n\n";
        foreach( $this->sections as $s )
            $md .= "- [" . $s['title'] . "](#" . $s['id'] . ")\n";
        $md .= "\n";
        foreach( $this->sections as $s )
        {
            $md .= '<a id="' . $s['id'] . '"></a>' . "\n\n## " . $s['title'] . "\n\n";
            foreach( $s['blocks'] as $b )
            {
                if( $b['type'] == 'p' )
                    $md .= $b['text'] . "\n\n";
                elseif( $b['type'] == 'h' )
                    $md .= "### " . $b['text'] . "\n\n";
                elseif( $b['type'] == 'pre' )
                    $md .= "```\n" . $b['text'] . "\n```\n\n";
                elseif( $b['type'] == 'md' )
                    $md .= preg_replace('/^(#+)\s/m', '$1## ', $b['text']) . "\n\n";
                elseif( $b['type'] == 'table' )
                {
                    $md .= "| " . implode(" | ", array_map(array(__CLASS__, 'mdCell'), $b['head'])) . " |\n|" . str_repeat("---|", count($b['head'])) . "\n";
                    foreach( $b['rows'] as $r )
                        $md .= "| " . implode(" | ", array_map(array(__CLASS__, 'mdCell'), $r)) . " |\n";
                    $md .= "\n";
                }
            }
        }
        return $md;
    }

    private static function inline( $s )
    {
        $s = htmlspecialchars( (string)$s, ENT_QUOTES, 'UTF-8' );
        $s = preg_replace('/`([^`]+)`/', '<code>$1</code>', $s);
        return preg_replace('/\*\*([^*]+)\*\*/', '<strong>$1</strong>', $s);
    }

    public function renderHtml()
    {
        $h = "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>"
            . htmlspecialchars($this->title()) . "</title>\n<style>\n"
            . ":root{--fg:#1f2328;--muted:#59636e;--line:#d1d9e0;--head:#f6f8fa;--accent:#0b5cad}\n"
            . "body{font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:var(--fg);margin:0 auto;max-width:1200px;padding:24px 16px;line-height:1.45;font-size:14px}\n"
            . "h1{font-size:24px;border-bottom:2px solid var(--accent);padding-bottom:8px}h2{font-size:19px;margin-top:36px;border-bottom:1px solid var(--line);padding-bottom:4px;color:var(--accent)}h3{font-size:15px;margin-top:22px}\n"
            . "table{border-collapse:collapse;width:100%;margin:8px 0 16px;font-size:13px}th,td{border:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top;word-break:break-word}th{background:var(--head)}\n"
            . "pre{background:var(--head);border:1px solid var(--line);padding:10px;overflow-x:auto;font-size:12px}code{background:var(--head);padding:1px 4px;border-radius:3px}\n"
            . ".meta{color:var(--muted)}nav ol{columns:2}@media print{nav{display:none}h2{page-break-before:always}table{page-break-inside:auto}tr{page-break-inside:avoid}}\n"
            . ".wrap{overflow-x:auto}\n</style></head><body>\n";
        $h .= "<h1>" . htmlspecialchars($this->title()) . "</h1>\n<p class=\"meta\">Generated " . date('Y-m-d H:i') . " by pan-os-php (scm_pa_report.php) from the export of "
            . htmlspecialchars(self::fmt( isset($this->manifest['created_at']) ? $this->manifest['created_at'] : null )) . ". Network plans: <code>prisma-access.drawio</code> (draw.io / Lucidchart).</p>\n<nav><ol>";
        foreach( $this->sections as $s )
            $h .= "<li><a href=\"#" . $s['id'] . "\">" . htmlspecialchars(preg_replace('/^\d+\.\s*/', '', $s['title'])) . "</a></li>";
        $h .= "</ol></nav>\n";
        foreach( $this->sections as $s )
        {
            $h .= "<h2 id=\"" . $s['id'] . "\">" . htmlspecialchars($s['title']) . "</h2>\n";
            foreach( $s['blocks'] as $b )
            {
                if( $b['type'] == 'p' )
                    $h .= "<p>" . self::inline($b['text']) . "</p>\n";
                elseif( $b['type'] == 'h' )
                    $h .= "<h3>" . self::inline($b['text']) . "</h3>\n";
                elseif( $b['type'] == 'pre' || $b['type'] == 'md' )
                    $h .= "<pre>" . htmlspecialchars($b['text']) . "</pre>\n";
                elseif( $b['type'] == 'table' )
                {
                    $h .= "<div class=\"wrap\"><table><thead><tr>";
                    foreach( $b['head'] as $c )
                        $h .= "<th>" . htmlspecialchars($c) . "</th>";
                    $h .= "</tr></thead><tbody>";
                    foreach( $b['rows'] as $r )
                    {
                        $h .= "<tr>";
                        foreach( $r as $c )
                            $h .= "<td>" . nl2br(htmlspecialchars((string)$c)) . "</td>";
                        $h .= "</tr>";
                    }
                    $h .= "</tbody></table></div>\n";
                }
            }
        }
        return $h . "</body></html>\n";
    }

    /** writes report.md, report.html, prisma-access.drawio into $outDir */
    public function write( $outDir )
    {
        if( !is_dir($outDir) )
            mkdir( $outDir, 0700, TRUE );
        file_put_contents( $outDir . "/report.md", $this->renderMarkdown() );
        file_put_contents( $outDir . "/report.html", $this->renderHtml() );
        file_put_contents( $outDir . "/prisma-access.drawio", $this->renderDrawio() );
        return array( $outDir . "/report.md", $outDir . "/report.html", $outDir . "/prisma-access.drawio" );
    }
}
