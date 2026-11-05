<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
 * Copyright (c) 2019, Palo Alto Networks Inc.
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
 * Effective-policy check for the mergers.
 *
 * Before a merge operation is executed, it is simulated and every name use it touches is resolved
 * the way Panorama pushes it to the firewalls (same-name copies across the device-group hierarchy,
 * 'ancestor-objects-take-precedence', group members resolved again by name in the firewall's
 * device group). The operation is allowed only if, for every firewall device group reached by an
 * affected referencer, the content behind the name is the same before and after
 * (allowaddingmissingobjects: the content may grow, it must never shrink).
 *
 * Content is compared by coverage: addresses as IP ranges (IPv4 and IPv6) (FQDN, EDL, dynamic groups and
 * unresolved names as tokens), services as destination-port ranges per
 * protocol / source port / timeouts.
 *
 * Nothing in the configuration is changed by this class.
 *
 * Simulated changes ("overlay"):
 *   removed      [spl_object_id(object)]          => TRUE    object no longer exists where it is
 *   placed       [spl_object_id(store)][name]     => object  object exists (also) in this store
 *   memberRename [spl_object_id(group)][oldName]  => newName
 *   memberAdd    [spl_object_id(group)][]         => name
 *   memberRemove [spl_object_id(group)][name]     => TRUE
 *   content      [spl_object_id(object)]          => content array (object gets another value)
 *
 * A unit is one name use: array( 'loc' => referencer location, 'before' => names, 'after' => names,
 *   'via' => group referencer or null, 'ref' => referencer, 'only' => [spl_object_id(F)] or null )
 */
class MergeSafety
{
    /** @var PanoramaConf|PANConf|mixed */
    private $root;
    private $storeProp;
    private $allowWiden;
    private $precedence = FALSE;

    /** content cache of the real configuration, cleared by changed() */
    private $cache = array();

    /** set by the last failed check */
    public $lastReason = null;

    public function __construct( $root, string $storeProp, bool $allowWiden )
    {
        $this->root = $root;
        $this->storeProp = $storeProp;
        $this->allowWiden = $allowWiden;
        if( $root instanceof PanoramaConf )
            $this->precedence = $root->ancestorObjectsTakePrecedence();
    }

    /** whether this check applies (address / service objects and groups) */
    public static function supports( string $storeProp ): bool
    {
        return $storeProp === 'addressStore' || $storeProp === 'serviceStore';
    }

    /** the configuration was changed: drop cached contents */
    public function changed()
    {
        $this->cache = array();
    }

    // ------------------------------------------------------------------------------------------
    // operations
    // ------------------------------------------------------------------------------------------

    /**
     * $old is replaced by $new everywhere it is used and deleted afterwards.
     * $extraOverlay: further simulated changes (e.g. $new does not exist yet, see placeOverlay()).
     * @return string|null  null: allowed, otherwise the reason
     */
    public function checkReplace( $old, $new, array $extraOverlay = array() )
    {
        $overlay = $extraOverlay;
        self::markRemoved( $overlay, $old );

        $units = array();
        foreach( $this->referencers( $old ) as $ref )
        {
            $isGroup = $this->isGroupObject( $ref );
            if( $isGroup )
                $overlay['memberRename'][spl_object_id($ref)][$old->name()] = $new->name();
            $units[] = array( 'loc' => $this->locationOf( $ref ), 'before' => array( $old->name() ), 'after' => array( $new->name() ),
                'via' => $isGroup ? $ref : null, 'ref' => $ref, 'only' => null );
        }

        return $this->check( $overlay, $units );
    }

    /**
     * $object is created as a copy in $targetStore (child device group -> parent).
     * @return string|null
     */
    public function checkPlace( $object, $targetStore )
    {
        $overlay = self::placeOverlay( $object, $targetStore );
        return $this->check( $overlay, array() );
    }

    /**
     * $object is moved to $targetStore.
     * @return string|null
     */
    public function checkMove( $object, $targetStore )
    {
        $overlay = self::placeOverlay( $object, $targetStore );
        self::markRemoved( $overlay, $object );
        return $this->check( $overlay, array() );
    }

    /**
     * dupAlgorithm=whereused for groups: the members of $old are added to $new, $old is removed
     * from every place where it is used and deleted.
     * @return string|null
     */
    public function checkWhereUsedGroupMerge( $old, $new )
    {
        $overlay = array();
        self::markRemoved( $overlay, $old );
        foreach( $old->members() as $member )
            $overlay['memberAdd'][spl_object_id($new)][] = $member->name();

        $units = array();
        foreach( $this->referencers( $old ) as $ref )
        {
            $isGroup = $this->isGroupObject( $ref );
            if( $isGroup )
                $overlay['memberRemove'][spl_object_id($ref)][$old->name()] = TRUE;
            $units[] = array( 'loc' => $this->locationOf( $ref ), 'before' => array( $old->name(), $new->name() ), 'after' => array( $new->name() ),
                'via' => $isGroup ? $ref : null, 'ref' => $ref, 'only' => null );
        }
        // every other user of $new sees the added members
        foreach( $this->referencers( $new ) as $ref )
            $units[] = array( 'loc' => $this->locationOf( $ref ), 'before' => array( $new->name() ), 'after' => array( $new->name() ),
                'via' => $this->isGroupObject( $ref ) ? $ref : null, 'ref' => $ref, 'only' => null );

        return $this->check( $overlay, $units );
    }

    /**
     * dupAlgorithm=whereused for services: the destination ports of $old are added to $new
     * ($new keeps its protocol, source port and timeouts), $old is removed where used and deleted.
     * @return string|null
     */
    public function checkWhereUsedServiceMerge( $old, $new )
    {
        $merged = $this->leafContent( $new );
        $oldContent = $this->leafContent( $old );
        $key = array_key_first( $merged['ports'] );
        foreach( $oldContent['ports'] as $ranges )
            foreach( $ranges as $range )
                $merged['ports'][$key][] = $range;
        if( $key !== null )
            $merged['ports'][$key] = self::mergeRanges( $merged['ports'][$key] );

        $overlay = array();
        self::markRemoved( $overlay, $old );
        $overlay['content'][spl_object_id($new)] = $merged;

        $units = array();
        foreach( $this->referencers( $old ) as $ref )
        {
            $isGroup = $this->isGroupObject( $ref );
            if( $isGroup )
                $overlay['memberRemove'][spl_object_id($ref)][$old->name()] = TRUE;
            $units[] = array( 'loc' => $this->locationOf( $ref ), 'before' => array( $old->name(), $new->name() ), 'after' => array( $new->name() ),
                'via' => $isGroup ? $ref : null, 'ref' => $ref, 'only' => null );
        }
        foreach( $this->referencers( $new ) as $ref )
            $units[] = array( 'loc' => $this->locationOf( $ref ), 'before' => array( $new->name() ), 'after' => array( $new->name() ),
                'via' => $this->isGroupObject( $ref ) ? $ref : null, 'ref' => $ref, 'only' => null );

        return $this->check( $overlay, $units );
    }

    private static function markRemoved( array &$overlay, $object )
    {
        $overlay['removed'][spl_object_id($object)] = TRUE;
        $overlay['removedObjects'][spl_object_id($object)] = $object;
    }

    public static function placeOverlay( $object, $targetStore ): array
    {
        $overlay = array();
        $overlay['placed'][spl_object_id($targetStore)][$object->name()] = $object;
        return $overlay;
    }

    // ------------------------------------------------------------------------------------------
    // check
    // ------------------------------------------------------------------------------------------

    private function check( array $overlay, array $units )
    {
        // users of a placed or removed name that may now resolve differently (other copies of the name)
        foreach( $this->placementUnits( $overlay ) as $unit )
            $units[] = $unit;
        foreach( $this->removalUnits( $overlay ) as $unit )
            $units[] = $unit;

        $this->lastReason = null;
        // the configuration may have changed since the last check
        $this->cache = array();
        $afterCache = array();

        foreach( $units as $unit )
        {
            if( $unit['loc'] === null )
                continue;

            foreach( $this->reach( $unit['loc'] ) as $fw )
            {
                if( $unit['only'] !== null && !isset($unit['only'][spl_object_id($fw)]) )
                    continue;

                // a group referencer only matters where its name resolves to this group
                if( $unit['via'] !== null && $this->resolve( $unit['via']->name(), $fw, array() ) !== $unit['via'] )
                    continue;

                $before = $this->namesContent( $unit['before'], $fw, array(), $this->cache );
                $after = $this->namesContent( $unit['after'], $fw, $overlay, $afterCache );

                if( $this->sameContent( $before, $after ) )
                    continue;
                if( $this->allowWiden && $this->contentIncludes( $after, $before ) )
                    continue;

                $refText = is_object($unit['ref']) && method_exists($unit['ref'], 'toString') ? $unit['ref']->toString() : '';
                $this->lastReason = "effective policy would change for firewalls of '" . self::locationName( $fw ) . "'"
                    . " (name '" . implode("','", $unit['before']) . "'" . ( $refText !== '' ? " used by " . $refText : "" ) . ")"
                    . ": before [" . self::contentText( $before ) . "] after [" . self::contentText( $after ) . "]";
                return $this->lastReason;
            }
        }

        return null;
    }

    /** units for every user of a placed name below the placement */
    private function placementUnits( array $overlay ): array
    {
        $units = array();
        if( !isset($overlay['placed']) )
            return $units;
        foreach( $overlay['placed'] as $storeId => $byName )
            foreach( $byName as $name => $object )
            {
                $targetLoc = $this->storeLocation( $storeId, $object );
                $only = array();
                foreach( $this->reach( $targetLoc ) as $fw )
                    $only[spl_object_id($fw)] = TRUE;

                foreach( $this->copiesOfName( $name ) as $copy )
                    foreach( $this->referencers( $copy ) as $ref )
                        $units[] = array( 'loc' => $this->locationOf( $ref ), 'before' => array( $name ), 'after' => array( $name ),
                            'via' => $this->isGroupObject( $ref ) ? $ref : null, 'ref' => $ref, 'only' => $only );
            }
        return $units;
    }

    /** units for every user of a removed object's name below the object's location */
    private function removalUnits( array $overlay ): array
    {
        $units = array();
        if( !isset($overlay['removedObjects']) )
            return $units;
        foreach( $overlay['removedObjects'] as $object )
        {
            $loc = $this->locationOf( $object );
            if( $loc === null )
                continue;
            $only = array();
            foreach( $this->reach( $loc ) as $fw )
                $only[spl_object_id($fw)] = TRUE;

            foreach( $this->copiesOfName( $object->name() ) as $copy )
            {
                if( $copy === $object )
                    continue;
                foreach( $this->referencers( $copy ) as $ref )
                    $units[] = array( 'loc' => $this->locationOf( $ref ), 'before' => array( $object->name() ), 'after' => array( $object->name() ),
                        'via' => $this->isGroupObject( $ref ) ? $ref : null, 'ref' => $ref, 'only' => $only );
            }
        }
        return $units;
    }

    private $storeLocations = array();

    private function storeLocation( $storeId, $object )
    {
        if( isset($this->storeLocations[$storeId]) )
            return $this->storeLocations[$storeId];
        foreach( $this->allLocations() as $loc )
        {
            $prop = $this->storeProp;
            if( isset($loc->$prop) && $loc->$prop !== null && spl_object_id($loc->$prop) === $storeId )
                return $this->storeLocations[$storeId] = $loc;
        }
        return $this->storeLocations[$storeId] = null;
    }

    // ------------------------------------------------------------------------------------------
    // hierarchy
    // ------------------------------------------------------------------------------------------

    private $allLocationsList = null;

    private function allLocations(): array
    {
        if( $this->allLocationsList !== null )
            return $this->allLocationsList;

        $list = array( $this->root );
        if( $this->root instanceof PanoramaConf )
            foreach( $this->root->getDeviceGroups() as $dg )
                $list[] = $dg;
        elseif( $this->root instanceof PANConf )
            foreach( $this->root->getVirtualSystems() as $vsys )
                $list[] = $vsys;

        return $this->allLocationsList = $list;
    }

    /** firewall locations that receive what is configured at $loc */
    private $reachCache = array();

    private function reach( $loc ): array
    {
        $id = spl_object_id($loc);
        if( isset($this->reachCache[$id]) )
            return $this->reachCache[$id];

        if( $loc instanceof PanoramaConf )
            $ret = array_values( $loc->getDeviceGroups() );
        elseif( $loc instanceof DeviceGroup )
            $ret = array_merge( array( $loc ), array_values( $loc->childDeviceGroups(TRUE) ) );
        elseif( $loc instanceof PANConf )
            $ret = array_values( $loc->getVirtualSystems() );
        else
            $ret = array( $loc );

        return $this->reachCache[$id] = $ret;
    }

    private static function locationName( $loc ): string
    {
        if( $loc instanceof PanoramaConf || $loc instanceof PANConf )
            return 'shared';
        return $loc->name();
    }

    private function locationOf( $ref )
    {
        return ReferenceableObject::findLocationOwner( $ref );
    }

    private function isGroupObject( $ref ): bool
    {
        return ( $ref instanceof AddressGroup ) || ( $ref instanceof ServiceGroup );
    }

    private function referencers( $object ): array
    {
        if( !method_exists($object, 'getReferences') )
            return array();
        return array_values( $object->getReferences() );
    }

    /** every object named $name in the hierarchy */
    private function copiesOfName( $name ): array
    {
        $ret = array();
        $prop = $this->storeProp;
        foreach( $this->allLocations() as $loc )
        {
            if( !isset($loc->$prop) || $loc->$prop === null )
                continue;
            $found = $loc->$prop->find( $name, null, FALSE );
            if( $found !== null )
                $ret[spl_object_id($found)] = $found;
        }
        return array_values( $ret );
    }

    // ------------------------------------------------------------------------------------------
    // resolution with overlay
    // ------------------------------------------------------------------------------------------

    /** the object the firewalls of $fw receive for $name */
    private function resolve( $name, $fw, array $overlay )
    {
        $prop = $this->storeProp;
        $copies = array();
        $seen = array();
        $levels = PH::firewallResolutionLevels( $fw );
        foreach( $levels as $level )
        {
            if( !isset($level->$prop) || $level->$prop === null )
                continue;
            $store = $level->$prop;
            $sid = spl_object_id($store);
            if( isset($seen[$sid]) )
                continue;
            $seen[$sid] = TRUE;

            if( isset($overlay['placed'][$sid][$name]) )
            {
                $copies[] = $overlay['placed'][$sid][$name];
                continue;
            }
            $found = $store->find( $name, null, FALSE );
            if( $found !== null && !isset($overlay['removed'][spl_object_id($found)]) )
                $copies[] = $found;
        }

        if( count($copies) == 0 )
        {
            // predefined / outside the hierarchy
            $first = $levels[0];
            if( isset($first->$prop) && $first->$prop !== null )
            {
                $found = $first->$prop->find( $name );
                if( $found !== null && !isset($overlay['removed'][spl_object_id($found)]) )
                    return $found;
            }
            return null;
        }

        return $this->precedence ? end($copies) : $copies[0];
    }

    // ------------------------------------------------------------------------------------------
    // content
    // ------------------------------------------------------------------------------------------

    private static function emptyContent(): array
    {
        return array( 'ip4' => new IP4Map(), 'ip6' => new IP6Map(), 'other' => array(), 'ports' => array() );
    }

    private function namesContent( array $names, $fw, array $overlay, array &$cache ): array
    {
        $content = self::emptyContent();
        foreach( $names as $name )
        {
            $key = spl_object_id($fw) . '|' . $name;
            if( !isset($cache[$key]) )
            {
                $object = $this->resolve( $name, $fw, $overlay );
                if( $object === null )
                {
                    $c = self::emptyContent();
                    $c['other']['unresolved:' . $name] = TRUE;
                }
                else
                {
                    $visited = array();
                    $c = $this->objectContent( $object, $fw, $overlay, $visited );
                }
                $cache[$key] = $c;
            }
            self::addContent( $content, $cache[$key] );
        }
        $content['ip4']->sortAndRecalculate();
        $content['ip6']->sortAndRecalculate();
        return $content;
    }

    private function objectContent( $object, $fw, array $overlay, array &$visited ): array
    {
        $id = spl_object_id($object);
        if( isset($overlay['content'][$id]) )
            return $overlay['content'][$id];

        $isGroup = $this->isGroupObject( $object );
        if( !$isGroup || ( $object instanceof AddressGroup && $object->isDynamic() ) )
            return $this->leafContent( $object );

        $content = self::emptyContent();
        if( isset($visited[$id]) )
            return $content;
        $visited[$id] = TRUE;

        $names = array();
        foreach( $object->members() as $member )
        {
            $name = $member->name();
            if( isset($overlay['memberRemove'][$id][$name]) )
                continue;
            if( isset($overlay['memberRename'][$id][$name]) )
                $name = $overlay['memberRename'][$id][$name];
            $names[$name] = $name;
        }
        if( isset($overlay['memberAdd'][$id]) )
            foreach( $overlay['memberAdd'][$id] as $name )
                $names[$name] = $name;

        foreach( $names as $name )
        {
            $resolved = $this->resolve( $name, $fw, $overlay );
            if( $resolved === null )
            {
                $content['other']['unresolved:' . $name] = TRUE;
                continue;
            }
            self::addContent( $content, $this->objectContent( $resolved, $fw, $overlay, $visited ) );
        }

        return $content;
    }

    /** content of one non-group object */
    public function leafContent( $object ): array
    {
        $c = self::emptyContent();

        if( $object instanceof AddressGroup )
        {
            // dynamic group: its own identity (tag based membership is not evaluated)
            $c['other']['dag:' . spl_object_id($object)] = TRUE;
            return $c;
        }
        if( $object instanceof EDL )
        {
            $c['other']['edl:' . $object->name()] = TRUE;
            return $c;
        }
        // the IP maps of pan-os-php hold IPv4 and IPv6 entries alike: one map ('ip4') is used for both
        if( $object instanceof Region )
        {
            $c['ip4']->addMap( $object->getIP4Mapping(), TRUE );
            return $c;
        }
        if( $object instanceof Address )
        {
            if( $object->isTmpAddr() && !$object->nameIsValidRuleIPEntry() )
            {
                $c['other']['unresolved:' . $object->name()] = TRUE;
                return $c;
            }
            $type = $object->isTmpAddr() ? 'tmp' : $object->type();
            if( $type == 'fqdn' )
                $c['other']['fqdn:' . $object->value()] = TRUE;
            elseif( $type == 'ip-wildcard' )
                $c['other']['wildcard:' . $object->value()] = TRUE;
            else
                $c['ip4']->addMap( $object->getIP4Mapping(), TRUE );
            return $c;
        }
        if( $object instanceof Service )
        {
            if( $object->isTmpSrv() )
            {
                if( $object->name() == 'service-http' )
                    $c['ports']['tcp||||'] = array( array( 80, 80 ) );
                elseif( $object->name() == 'service-https' )
                    $c['ports']['tcp||||'] = array( array( 443, 443 ) );
                else
                    $c['other']['service:' . $object->name()] = TRUE;
                return $c;
            }
            $key = $object->protocol() . '|' . $object->getSourcePort() . '|' . $object->getTimeout() . '|'
                . $object->getHalfcloseTimeout() . '|' . $object->getTimewaitTimeout();
            $c['ports'][$key] = self::parsePorts( $object->getDestPort() );
            return $c;
        }

        $c['other']['object:' . get_class($object) . ':' . $object->name()] = TRUE;
        return $c;
    }

    private static function parsePorts( $text ): array
    {
        $ranges = array();
        foreach( explode(',', (string)$text) as $part )
        {
            $part = trim($part);
            if( $part === '' )
                continue;
            $p = explode('-', $part);
            $ranges[] = array( (int)$p[0], (int)( isset($p[1]) ? $p[1] : $p[0] ) );
        }
        return self::mergeRanges( $ranges );
    }

    private static function mergeRanges( array $ranges ): array
    {
        usort( $ranges, function( $a, $b ) { return $a[0] <=> $b[0]; } );
        $ret = array();
        foreach( $ranges as $r )
        {
            $n = count($ret);
            if( $n > 0 && $r[0] <= $ret[$n - 1][1] + 1 )
                $ret[$n - 1][1] = max( $ret[$n - 1][1], $r[1] );
            else
                $ret[] = $r;
        }
        return $ret;
    }

    private static function addContent( array &$content, array $add )
    {
        $content['ip4']->addMap( $add['ip4'], TRUE );
        $content['ip6']->addMap( $add['ip6'], TRUE );
        foreach( $add['other'] as $k => $v )
            $content['other'][$k] = TRUE;
        foreach( $add['ports'] as $k => $ranges )
            $content['ports'][$k] = isset($content['ports'][$k]) ? self::mergeRanges( array_merge( $content['ports'][$k], $ranges ) ) : $ranges;
    }

    private function sameContent( array $a, array $b ): bool
    {
        if( !$a['ip4']->equals( $b['ip4'] ) || !$a['ip6']->equals( $b['ip6'] ) )
            return FALSE;
        $ao = $a['other']; $bo = $b['other'];
        ksort($ao); ksort($bo);
        if( array_keys($ao) !== array_keys($bo) )
            return FALSE;
        $ap = $a['ports']; $bp = $b['ports'];
        ksort($ap); ksort($bp);
        return $ap == $bp;
    }

    /** $a covers everything of $b */
    private function contentIncludes( array $a, array $b ): bool
    {
        if( $b['ip4']->count() > 0 && !$a['ip4']->includesOtherMap( $b['ip4'] ) )
            return FALSE;
        if( $b['ip6']->count() > 0 && !$a['ip6']->includesOtherMap( $b['ip6'] ) )
            return FALSE;
        foreach( $b['other'] as $k => $v )
            if( !isset($a['other'][$k]) )
                return FALSE;
        foreach( $b['ports'] as $k => $ranges )
        {
            if( !isset($a['ports'][$k]) )
                return FALSE;
            foreach( $ranges as $r )
            {
                $covered = FALSE;
                foreach( $a['ports'][$k] as $ar )
                    if( $ar[0] <= $r[0] && $ar[1] >= $r[1] )
                        $covered = TRUE;
                if( !$covered )
                    return FALSE;
            }
        }
        return TRUE;
    }

    private static function contentText( array $c ): string
    {
        $parts = array();
        $t = $c['ip4']->dumpToString();
        if( $t !== '' ) $parts[] = $t;
        $t = $c['ip6']->dumpToString();
        if( $t !== '' ) $parts[] = $t;
        foreach( $c['ports'] as $k => $ranges )
        {
            $r = array();
            foreach( $ranges as $range )
                $r[] = $range[0] == $range[1] ? $range[0] : $range[0] . '-' . $range[1];
            $kp = explode('|', $k);
            $parts[] = $kp[0] . '/' . implode(',', $r) . ( $kp[1] !== '' ? ' sport:' . $kp[1] : '' ) . ( ( $kp[2] . $kp[3] . $kp[4] ) !== '' ? ' timeouts:' . $kp[2] . '/' . $kp[3] . '/' . $kp[4] : '' );
        }
        foreach( $c['other'] as $k => $v )
            $parts[] = $k;
        return implode(', ', $parts);
    }
}
