<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
 * Copyright (c) 2019, Palo Alto Networks Inc.
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
 * The objects an object can refer to: for a kind (address, service, tag, zone, interface, …) the names in the
 * location of the object and in the locations above it - the same levels pan-os-php resolves a name in:
 *  objects: PH::firewallResolutionLevels (vsys -> shared; device group -> parent device groups -> shared;
 *           SCM folder -> its snippets -> parent folders -> All)
 *  network: PH::networkScope (own configuration, template stack, SCM levels)
 * Panorama device group: zones of the templates (a rule of a device group names the zones of the firewalls).
 * Used by the config viewer (drop down of a field) - the actions accept what is offered here.
 */
class ObjectCandidates
{
    /** kind => store of a location (objects) */
    const OBJECT_KINDS = array(
        'address' => array( 'addressStore' ),
        'service' => array( 'serviceStore' ),
        'tag' => array( 'tagStore' ),
        'schedule' => array( 'scheduleStore' ),
        'securityprofilegroup' => array( 'securityProfileGroupStore' ),
        'log-profile' => array( 'LogProfileStore' ),
        'application' => array( 'appStore' ),
        'url-category' => array( 'customURLProfileStore', 'EDLStore' ),
    );

    /** kind => store of a network configuration (NetworkPropertiesContainer) */
    const NETWORK_KINDS = array(
        'ike-crypto-profile' => 'ikeCryptoProfileStore',
        'ipsec-crypto-profile' => 'ipsecCryptoProfileStore',
        'ike-gateway' => 'ikeGatewayStore',
        'interface-management-profile' => 'interfaceManagementProfileStore',
        'zone-protection-profile' => 'zoneProtectionProfileStore',
        'virtual-router' => 'virtualRouterStore',
    );

    const LOCATION_CLASSES = array( 'VirtualSystem', 'DeviceGroup', 'PanoramaConf', 'PANConf', 'Container', 'Snippet', 'DeviceCloud', 'DeviceOnPrem', 'FawkesConf', 'BuckbeakConf' );

    static public function kinds(): array
    {
        return array_merge( array_keys( self::OBJECT_KINDS ), array_keys( self::NETWORK_KINDS ), array( 'zone', 'interface', 'tunnel-interface' ) );
    }

    /**
     * @return array list of array( 'location' => label, 'names' => string[] ), nearest location first; a name only
     *               at its nearest location (the one a reference resolves to)
     */
    static public function forObject( $object, string $kind ): array
    {
        $loc = self::locationOf( $object );
        if( $loc === null )
            return array();
        if( isset( self::OBJECT_KINDS[$kind] ) )
            $groups = self::objectKind( $loc, $kind );
        elseif( isset( self::NETWORK_KINDS[$kind] ) )
            $groups = self::networkStores( $loc, self::NETWORK_KINDS[$kind] );
        elseif( $kind === 'zone' )
            $groups = self::zones( $loc );
        elseif( $kind === 'interface' || $kind === 'tunnel-interface' )
            $groups = self::interfaces( $loc, $kind === 'tunnel-interface' );
        else
            throw new Exception( "unknown kind '" . $kind . "' - " . implode( ', ', self::kinds() ) );

        // only what the object can take - the same rules as its actions refuse
        $drop = self::notUsable( $object, $kind );
        if( $drop !== array() )
            foreach( $groups as &$g )
                $g['names'] = array_values( array_filter( $g['names'], function( $n ) use ( $drop ) { return !isset( $drop[$n] ); } ) );
        unset( $g );

        // a name only once: at the nearest location
        $seen = array();
        $out = array();
        foreach( $groups as $g )
        {
            $names = array();
            foreach( $g['names'] as $n )
                if( is_string( $n ) && $n !== '' && !isset( $seen[$n] ) )
                {
                    $seen[$n] = TRUE;
                    $names[] = $n;
                }
            if( $names !== array() )
            {
                natcasesort( $names );
                $out[] = array( 'location' => $g['location'], 'names' => array_values( $names ) );
            }
        }
        return $out;
    }

    /** the location (vsys, device group, shared, SCM folder / snippet / device) of an object: the owner of its store */
    static public function locationOf( $object )
    {
        $cur = $object;
        for( $i = 0; $i < 8 && is_object( $cur ); $i++ )
        {
            if( in_array( get_class( $cur ), self::LOCATION_CLASSES, TRUE ) )
                return $cur;
            $cur = $cur->owner ?? null;
        }
        return null;
    }

    /**
     * names the object can not take (refused by its action): a group - itself and the groups that hold it (loop), a
     * wildcard address; a zone - interfaces of another zone or of another type; a router - interfaces of another router
     * @return array name => TRUE
     */
    static public function notUsable( $object, string $kind ): array
    {
        $drop = array();
        if( ( $object instanceof AddressGroup && $kind === 'address' ) || ( $object instanceof ServiceGroup && $kind === 'service' ) )
        {
            $drop[$object->name()] = TRUE;
            // every group that holds this one (directly or below) - adding it would be a loop
            $holders = array( $object );
            for( $i = 0; $i < count( $holders ) && $i < 1000; $i++ )
                foreach( $holders[$i]->getReferences() as $ref )
                    if( ( $ref instanceof AddressGroup || $ref instanceof ServiceGroup ) && !in_array( $ref, $holders, TRUE ) )
                    {
                        $holders[] = $ref;
                        $drop[$ref->name()] = TRUE;
                    }
            if( $object instanceof AddressGroup )
                foreach( PH::firewallResolutionLevels( self::locationOf( $object ) ) as $level )
                    if( isset( $level->addressStore ) )
                        foreach( $level->addressStore->all() as $a )
                            if( method_exists( $a, 'isType_ipWildcard' ) && !$a->isGroup() && $a->isType_ipWildcard() )
                                $drop[$a->name()] = TRUE;
        }
        if( $object instanceof Zone && $kind === 'interface' )
        {
            foreach( $object->owner->getAll() as $zone )
                if( $zone !== $object )
                    foreach( $zone->interfaceNames() as $n )
                        $drop[$n] = TRUE;
            foreach( self::networkLocations( self::locationOf( $object ) ) as $nl )
                foreach( PH::networkScope( $nl ) as $network )
                    foreach( $network->getAllInterfaces() as $if )
                    {
                        $t = Zone::interfaceZoneType( $if );
                        if( $t !== null && $t !== $object->type() )
                            $drop[$if->name()] = TRUE;
                    }
        }
        if( isset( $object->attachedInterfaces ) && ( $object instanceof VirtualRouter ) && $kind === 'interface' && method_exists( $object->owner, 'getAll' ) )
            foreach( $object->owner->getAll() as $router )
                if( $router !== $object && isset( $router->attachedInterfaces ) )
                    foreach( $router->attachedInterfaces->interfaces() as $if )
                        $drop[$if->name()] = TRUE;
        return $drop;
    }

    static public function label( $loc ): string
    {
        if( $loc instanceof PANConf && isset( $loc->owner ) && ( $loc->owner instanceof Template || $loc->owner instanceof TemplateStack ) )
            return 'template ' . $loc->owner->name();
        if( $loc instanceof PANConf || $loc instanceof PanoramaConf )
            return 'shared';
        if( $loc instanceof NetworkPropertiesContainer )
            return $loc->owner instanceof PANConf && !( isset( $loc->owner->owner ) && ( $loc->owner->owner instanceof Template || $loc->owner->owner instanceof TemplateStack ) )
                ? 'firewall' : self::label( $loc->owner );
        return method_exists( $loc, 'name' ) ? (string)$loc->name() : get_class( $loc );
    }

    /** the names of the objects of a store - no temporary objects (names pan-os-php created for an unknown reference) */
    static public function names( $store, bool $skipTmp = TRUE ): array
    {
        if( !is_object( $store ) )
            return array();
        $all = method_exists( $store, 'all' ) ? $store->all() : ( method_exists( $store, 'getAll' ) ? $store->getAll() : array() );
        $out = array();
        foreach( $all as $o )
        {
            if( !is_object( $o ) || !method_exists( $o, 'name' ) )
                continue;
            if( $skipTmp )
                foreach( array( 'isTmp', 'isTmpAddr', 'isTmpSrv' ) as $m )
                    if( method_exists( $o, $m ) && $o->$m() )
                        continue 2;
            $out[] = $o->name();
        }
        return $out;
    }

    static private function objectKind( $loc, string $kind ): array
    {
        $groups = array();
        foreach( PH::firewallResolutionLevels( $loc ) as $level )
        {
            $names = array();
            foreach( self::OBJECT_KINDS[$kind] as $prop )
                if( isset( $level->$prop ) )
                {
                    $store = $level->$prop;
                    if( $prop === 'EDLStore' )
                    {
                        // a URL category: only an EDL of type url
                        foreach( $store->getAll() as $edl )
                            if( method_exists( $edl, 'type' ) && $edl->type() === 'url' )
                                $names[] = $edl->name();
                    }
                    else
                        $names = array_merge( $names, self::names( $store ) );
                }
            $groups[] = array( 'location' => self::label( $level ), 'names' => $names );
        }
        // predefined: applications, URL categories
        if( $kind === 'application' && isset( $loc->appStore ) )
        {
            $pre = AppStore::getPredefinedStore( PH::findRootObjectOrDie( $loc ) );
            if( is_object( $pre ) )
                $groups[] = array( 'location' => 'predefined', 'names' => self::names( $pre, FALSE ) );
        }
        if( $kind === 'url-category' )
        {
            $root = PH::findRootObjectOrDie( $loc );
            if( isset( $root->urlStore ) )
            {
                $groups[] = array( 'location' => 'predefined', 'names' => self::names( SecurityProfileStore::getURLPredefinedStore( $root->urlStore ), FALSE ) );
            }
        }
        return $groups;
    }

    /** the network configurations of a location: a vsys -> its firewall / template, a device group -> the templates */
    static private function networkLocations( $loc ): array
    {
        if( $loc instanceof VirtualSystem )
            return array( $loc->owner );
        if( $loc instanceof DeviceGroup || $loc instanceof PanoramaConf )
        {
            $pan = $loc instanceof PanoramaConf ? $loc : $loc->owner;
            $out = array();
            foreach( $pan->getTemplates() as $t )
                $out[] = $t->deviceConfiguration;
            return $out;
        }
        return array( $loc );
    }

    static private function networkStores( $loc, string $prop ): array
    {
        $groups = array();
        foreach( self::networkLocations( $loc ) as $nl )
            foreach( PH::networkScope( $nl ) as $network )
                $groups[] = array( 'location' => self::label( $network ), 'names' => isset( $network->$prop ) ? self::names( $network->$prop ) : array() );
        return $groups;
    }

    static private function zones( $loc ): array
    {
        if( $loc instanceof VirtualSystem || $loc instanceof Container || $loc instanceof Snippet || $loc instanceof DeviceCloud || $loc instanceof DeviceOnPrem )
        {
            $levels = $loc instanceof VirtualSystem ? array( $loc ) : PH::scmObjectLevels( $loc );
            $groups = array();
            foreach( $levels as $level )
                $groups[] = array( 'location' => self::label( $level ), 'names' => isset( $level->zoneStore ) ? self::names( $level->zoneStore ) : array() );
            // SCM: zones are often not defined (Prisma Access: trust / untrust) - the names the rules use
            if( !( $loc instanceof VirtualSystem ) )
                foreach( $levels as $level )
                    $groups[] = array( 'location' => self::label( $level ) . ' (used in rules)', 'names' => isset( $level->zoneStore ) ? self::names( $level->zoneStore, FALSE ) : array() );
            return $groups;
        }
        // Panorama: the zones of the vsys of every template (and the ones a device group has)
        $groups = array();
        foreach( self::networkLocations( $loc ) as $conf )
            if( $conf instanceof PANConf )
                foreach( $conf->getVirtualSystems() as $vsys )
                    $groups[] = array( 'location' => self::label( $conf ) . ' / ' . $vsys->name(), 'names' => self::names( $vsys->zoneStore ) );
        if( isset( $loc->zoneStore ) )
            $groups[] = array( 'location' => self::label( $loc ) . ' (used in rules)', 'names' => self::names( $loc->zoneStore, FALSE ) );
        return $groups;
    }

    static private function interfaces( $loc, bool $tunnelOnly ): array
    {
        $groups = array();
        foreach( self::networkLocations( $loc ) as $nl )
            foreach( PH::networkScope( $nl ) as $network )
            {
                $names = array();
                foreach( $network->getAllInterfaces() as $if )
                {
                    if( $if instanceof IPsecTunnel || $if instanceof GreTunnel || $if instanceof GPGatewayTunnel || ( method_exists( $if, 'isTmp' ) && $if->isTmp() )
                        || ( method_exists( $if, 'type' ) && $if->type() === 'aggregate-group' ) )
                        continue;
                    if( $tunnelOnly && !( $if instanceof TunnelInterface ) )
                        continue;
                    $names[] = $if->name();
                }
                // a vsys: only the interfaces imported into it (when it lists them)
                if( $loc instanceof VirtualSystem && isset( $loc->importedInterfaces ) && count( $loc->importedInterfaces->interfaces() ) > 0 )
                    $names = array_values( array_filter( $names, function( $n ) use ( $loc ) { return $loc->importedInterfaces->hasInterfaceNamed( $n ); } ) );
                $groups[] = array( 'location' => self::label( $network ), 'names' => $names );
            }
        return $groups;
    }
}
