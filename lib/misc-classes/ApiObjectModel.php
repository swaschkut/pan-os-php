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
 * JSON object model of the API (todo/json-object-model.md): an object in the shape of the SCM API resource
 * (lib/resources/scm/scm-ngfw-config-schema.json), built from its XML with SCMChangeGenerator::toBody().
 *
 * What the SCM API does not have is defined here in the same style, until PANW defines it:
 *  - location of a Panorama / firewall object: device_group (shared: "shared"), vsys, template, template_stack;
 *    an SCM object keeps the SCM fields folder / snippet / device
 *  - a top-level XML element the SCM schema does not know: its element name in snake_case, converted generically
 *  - anything else that could not be converted is listed in _panosphp.not_converted (nothing is dropped silently)
 *
 * Order of the resources = their dependencies: tags, addresses, address-groups, services, service-groups,
 * schedules, url-categories, external-dynamic-lists, log-forwarding-profiles; then security profiles, profile-groups,
 * zones, rules.
 */
class ApiObjectModel
{
    const MODEL = 'scm-v1';

    /** object class => SCM resource */
    public static $classResource = array(
        'Tag' => 'tags',
        'Address' => 'addresses',
        'AddressGroup' => 'address-groups',
        'Service' => 'services',
        'ServiceGroup' => 'service-groups',
        'Schedule' => 'schedules',
        'customURLProfile' => 'url-categories',
        'EDL' => 'external-dynamic-lists',
        'LogProfile' => 'log-forwarding-profiles',
        'AntiSpywareProfile' => 'anti-spyware-profiles',
        'VulnerabilityProfile' => 'vulnerability-protection-profiles',
        'URLProfile' => 'url-access-profiles',
        'FileBlockingProfile' => 'file-blocking-profiles',
        'DNSSecurityProfile' => 'dns-security-profiles',
        'VirusAndWildfireProfile' => 'wildfire-anti-virus-profiles',
        'AntiVirusProfile' => 'antivirus-profiles',
        'WildfireProfile' => 'wildfire-analysis-profiles',
        'SecurityProfileGroup' => 'profile-groups',
        'ZoneProtectionProfile' => 'zone-protection-profiles',
        'Zone' => 'zones',
        'SecurityRule' => 'security-rules',
        'NatRule' => 'nat-rules',
        'DecryptionRule' => 'decryption-rules',
        'AppOverrideRule' => 'app-override-rules',
        'AuthenticationRule' => 'authentication-rules',
        'PbfRule' => 'pbf-rules',
        'QoSRule' => 'qos-policy-rules',
        'DoSRule' => 'dos-rules',
        'TunnelInspectionRule' => 'tunnel-inspection-rules',
        'CaptivePortalRule' => 'captive-portal-rules',
        'DefaultSecurityRule' => 'default-security-rules',
        'SDWanRule' => 'sdwan-rules',
        'NetworkPacketBrokerRule' => 'network-packet-broker-rules',
        // network (IKE / IPsec, interfaces, routing, GlobalProtect, …) - the first ones with the SCM schema
        'IkeCryptoProfil' => 'ike-crypto-profiles',
        'IPSecCryptoProfil' => 'ipsec-crypto-profiles',
        'IKEGateway' => 'ike-gateways',
        'IPsecTunnel' => 'ipsec-tunnels',
        'VirtualRouter' => 'virtual-routers',
        'LogicalRouter' => 'logical-routers',
        'GreTunnel' => 'gre-tunnels',
        'GPGateway' => 'globalprotect-gateways',
        'GPPortal' => 'globalprotect-portals',
        'GPGatewayTunnel' => 'globalprotect-gateway-tunnels',
        'InterfaceManagementProfile' => 'interface-management-profiles',
        'EthernetInterface' => 'ethernet-interfaces',
        'AggregateEthernetInterface' => 'aggregate-interfaces',
        'LoopbackInterface' => 'loopback-interfaces',
        'TunnelInterface' => 'tunnel-interfaces',
        'VlanInterface' => 'vlan-interfaces',
        'VirtualWire' => 'virtual-wires',
        'StaticRoute' => 'static-routes',
        'DHCP' => 'dhcp',
    );

    /**
     * own resources: the SCM API has none (todo/json-object-model.md). The item is the XML of the object in snake_case.
     * Panorama / firewall keep antivirus and WildFire analysis apart; SCM has them in wildfire-anti-virus-profiles.
     */
    public static $ownResources = array( 'antivirus-profiles', 'wildfire-analysis-profiles',
        'dos-rules', 'tunnel-inspection-rules', 'captive-portal-rules', 'default-security-rules', 'sdwan-rules', 'network-packet-broker-rules',
        // network: the XML of the object (the SCM schema has no such resource, or another shape - interfaces of a firewall
        // keep their sub-interfaces, zones and IPs in one entry)
        'gre-tunnels', 'globalprotect-gateways', 'globalprotect-portals', 'globalprotect-gateway-tunnels', 'interface-management-profiles',
        'ethernet-interfaces', 'aggregate-interfaces', 'loopback-interfaces', 'tunnel-interfaces', 'vlan-interfaces', 'virtual-wires',
        'static-routes', 'dhcp' );

    /**
     * TRUE: item() adds the computed values (never configuration) as _panosphp: references, ip_count, visibility,
     * best_practice and the single checks. Off by default - the item is then the plain SCM shape.
     */
    public static $withComputed = FALSE;

    /** single checks per class: name in _panosphp.checks => method prefix ("<prefix>_visibility" / "<prefix>_best_practice") */
    public static $checks = array(
        'AntiSpywareProfile' => array( 'rules' => 'spyware_rules', 'inline' => 'cloud_inline_analysis', 'dns_lists' => 'spyware_dnslist',
            'dns_security' => 'spyware_dns_security', 'advanced_dns_security' => 'spyware_advanced_dns_security' ),
        'VulnerabilityProfile' => array( 'rules' => 'vulnerability_rules', 'inline' => 'cloud_inline_analysis' ),
        'AntiVirusProfile' => array( 'actions' => 'av_actions', 'inline' => 'cloud_inline_analysis' ),
        'WildfireProfile' => array( 'rules' => 'wildfire_rules', 'inline' => 'cloud_inline_analysis' ),
        'FileBlockingProfile' => array( 'rules' => 'fileblocking_rules' ),
        'URLProfile' => array( 'site_access' => 'url_siteaccess', 'credential' => 'url_usercredentialsubmission', 'inline' => 'url_mica_engine' ),
    );

    /** @var SCMChangeGenerator|null */
    private static $generator = null;

    public static function resourceOf( $object ): ?string
    {
        return is_object( $object ) ? ( self::$classResource[get_class( $object )] ?? null ) : null;
    }

    /** the location fields of the object's owner (store owner) */
    public static function location( $object ): array
    {
        $sub = isset( $object->owner ) && is_object( $object->owner ) && isset( $object->owner->owner ) ? $object->owner->owner : null;
        if( !is_object( $sub ) )
            return array();
        $class = get_class( $sub );
        if( $class == 'PanoramaConf' )
            return array( 'device_group' => 'shared' );
        if( $class == 'PANConf' )
            return array( 'vsys' => 'shared' );
        if( $class == 'DeviceGroup' )
            return array( 'device_group' => $sub->name() );
        if( $class == 'VirtualSystem' )
        {
            // a vsys inside a Panorama template / template stack: the template is the location, the vsys is kept
            $conf = isset( $sub->owner ) && is_object( $sub->owner ) ? $sub->owner : null;
            $tpl = $conf !== null && isset( $conf->owner ) && is_object( $conf->owner ) ? $conf->owner : null;
            if( $tpl !== null && get_class( $tpl ) == 'Template' )
                return array( 'template' => $tpl->name(), 'vsys' => $sub->name() );
            if( $tpl !== null && get_class( $tpl ) == 'TemplateStack' )
                return array( 'template_stack' => $tpl->name(), 'vsys' => $sub->name() );
            return array( 'vsys' => $sub->name() );
        }
        if( $class == 'Template' )
            return array( 'template' => $sub->name() );
        if( $class == 'TemplateStack' )
            return array( 'template_stack' => $sub->name() );
        if( $class == 'Container' )
            return array( 'folder' => $sub->name() );
        if( $class == 'Snippet' )
            return array( 'snippet' => $sub->name() );
        if( $class == 'DeviceCloud' || $class == 'DeviceOnPrem' )
            return array( 'device' => $sub->name() );
        return array();
    }

    /**
     * @return array|null array( 'resource' => SCM resource, 'item' => object in the SCM shape + location );
     *                    null: no model for this class yet, or an object without XML (tmp object)
     */
    public static function item( $object ): ?array
    {
        $resource = self::resourceOf( $object );
        if( $resource === null || !isset( $object->xmlroot ) || !( $object->xmlroot instanceof DOMElement ) )
            return null;
        if( self::$generator === null )
            self::$generator = new SCMChangeGenerator();

        if( in_array( $resource, self::$ownResources, TRUE ) )
        {
            $own = self::generic( $object->xmlroot );
            $item = array( 'name' => $object->name() ) + ( is_array( $own ) ? $own : array() ) + self::ruleFields( $object ) + self::location( $object );
            if( self::$withComputed && count( $c = self::computed( $object ) ) > 0 )
                $item['_panosphp'] = $c;
            return array( 'resource' => $resource, 'item' => $item );
        }

        $dropped = array();
        $body = self::$generator->toBody( array( 'resource' => $resource, 'node' => $object->xmlroot, 'name' => $object->name() ), $dropped );

        // XML elements the SCM schema does not know: PAN-OS has them, so they stay - same name in snake_case, at the
        // same place in the item. Only what can not be placed is listed in _panosphp.not_converted.
        $notConverted = array();
        $xp = new DOMXPath( $object->xmlroot->ownerDocument );
        foreach( array_unique( $dropped ) as $path )
        {
            $placed = FALSE;
            $nodes = @$xp->query( $path, $object->xmlroot );
            foreach( $nodes ?: array() as $node )
                if( self::place( $body, $object->xmlroot, $node ) )
                    $placed = TRUE;
            if( !$placed )
                $notConverted[] = $path;
        }
        $item = $body + self::ruleFields( $object ) + self::location( $object );
        $extra = self::$withComputed ? self::computed( $object ) : array();
        if( count( $notConverted ) > 0 )
            $extra['not_converted'] = $notConverted;
        if( count( $extra ) > 0 )
            $item['_panosphp'] = $extra;
        return array( 'resource' => $resource, 'item' => $item );
    }

    /** TRUE / FALSE / null (N/A: the BP JSON has no check, or the PAN-OS version not the setting) */
    private static function verdict( $v ): ?bool
    {
        return $v === null ? null : (bool)$v;
    }

    /**
     * values pan-os-php calculates for an object (todo/json-object-model.md, decision 3):
     * references, ip_count (address), visibility / best_practice (security profiles, profile groups) with the
     * single checks, profiles_visibility / profiles_best_practice (security rules: the profiles of the rule)
     */
    public static function computed( $object ): array
    {
        $out = array();
        if( method_exists( $object, 'countReferences' ) )
            $out['references'] = (int)$object->countReferences();
        $class = get_class( $object );
        if( $class == 'Address' && method_exists( $object, 'getIPcount' ) )
            $out['ip_count'] = $object->getIPcount();
        if( $object instanceof Rule )
        {
            if( $object->isSecurityRule() || $object->isDefaultSecurityRule() )
            {
                $out['profiles_visibility'] = self::verdict( $object->SP_isVisibility() );
                $out['profiles_best_practice'] = self::verdict( $object->SP_isBestPractice() );
            }
            return $out;
        }
        if( method_exists( $object, 'is_visibility' ) && method_exists( $object, 'is_best_practice' ) )
        {
            $out['visibility'] = self::verdict( $object->is_visibility() );
            $out['best_practice'] = self::verdict( $object->is_best_practice() );
            foreach( self::$checks[$class] ?? array() as $name => $prefix )
            {
                $check = array();
                foreach( array( 'visibility', 'best_practice' ) as $section )
                    if( method_exists( $object, $prefix . '_' . $section ) )
                        $check[$section] = self::verdict( $object->{$prefix . '_' . $section}() );
                if( count( $check ) > 0 )
                    $out['checks'][$name] = $check;
            }
        }
        return $out;
    }

    /**
     * own fields of a rule (the SCM API has the position only as a query of the request and no uuid in the body):
     * uuid, rulebase 'pre' / 'post' (Panorama, SCM) or 'local' (firewall), position (1 = first rule of its rulebase)
     */
    public static function ruleFields( $object ): array
    {
        if( !( $object instanceof Rule ) )
            return array();
        $out = array();
        if( $object->xmlroot->hasAttribute( 'uuid' ) )
            $out['uuid'] = $object->xmlroot->getAttribute( 'uuid' );
        if( get_class( $object ) == 'DefaultSecurityRule' )
            return $out;
        $out['rulebase'] = $object->isPreRule() ? 'pre' : ( $object->isPostRule() ? 'post' : 'local' );
        $position = 1;
        for( $n = $object->xmlroot->previousSibling; $n !== null; $n = $n->previousSibling )
            if( $n->nodeType == XML_ELEMENT_NODE )
                $position++;
        $out['position'] = $position;
        return $out;
    }

    /** puts the generic conversion of $node into $body at the place of its XML path below $root; FALSE: no such place */
    private static function place( array &$body, DOMElement $root, DOMElement $node ): bool
    {
        $chain = array();
        for( $n = $node; $n !== null && !$n->isSameNode( $root ); $n = $n->parentNode )
            array_unshift( $chain, $n );
        $ref = &$body;
        foreach( $chain as $i => $n )
        {
            $last = $i == count( $chain ) - 1;
            if( $n->tagName == 'entry' )
            {
                // a list of entries in the body: the one with this name
                $found = null;
                if( is_array( $ref ) )
                    foreach( $ref as $k => $e )
                        if( is_array( $e ) && isset( $e['name'] ) && $e['name'] === $n->getAttribute( 'name' ) )
                        {
                            $found = $k;
                            break;
                        }
                if( $found === null || $last )
                    return FALSE;
                $ref = &$ref[$found];
                continue;
            }
            $key = str_replace( '-', '_', $n->tagName );
            if( $last )
            {
                if( !is_array( $ref ) || isset( $ref[$key] ) )
                    return FALSE;
                $ref[$key] = self::generic( $n );
                return TRUE;
            }
            if( !is_array( $ref ) || !isset( $ref[$key] ) )
                return FALSE;
            // an empty object of the SCM conversion ({}): the PAN-OS only element goes into it
            if( $ref[$key] instanceof stdClass )
                $ref[$key] = (array)$ref[$key];
            if( !is_array( $ref[$key] ) )
                return FALSE;
            $ref = &$ref[$key];
        }
        return FALSE;
    }

    /** an XML element without SCM schema: member list -> string[], entry list -> objects with "name", leaf -> string */
    public static function generic( DOMElement $node )
    {
        $children = array();
        foreach( $node->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE )
                $children[] = $c;
        if( count( $children ) == 0 )
        {
            // <default/> -> {} (as the SCM API writes a choice), text -> string
            $text = trim( $node->textContent );
            return $text === '' ? new stdClass() : $text;
        }
        $tags = array();
        foreach( $children as $c )
            $tags[$c->tagName][] = $c;
        if( count( $tags ) == 1 && isset( $tags['member'] ) )
            return array_map( function( $c ) { return trim( $c->textContent ); }, $children );
        if( count( $tags ) == 1 && isset( $tags['entry'] ) )
        {
            $out = array();
            foreach( $children as $c )
            {
                $v = self::generic( $c );
                $out[] = array( 'name' => $c->getAttribute( 'name' ) ) + ( is_array( $v ) ? $v : array() );
            }
            return $out;
        }
        $out = array();
        foreach( $tags as $tag => $list )
            $out[str_replace( '-', '_', $tag )] = self::generic( $list[0] );
        return $out;
    }
}
