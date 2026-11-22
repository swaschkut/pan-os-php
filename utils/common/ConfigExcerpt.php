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
 * A small configuration with only what a problem with some object names needs (support file, todo/support-file.md):
 * the hierarchy (every device group with its parent / every vsys - empty unless it holds something), and for the
 * names:
 *   - every copy of a name in every location (shared, device groups, vsys) - names of addresses, groups, services,
 *     tags, ... share one name space, so every object store is searched;
 *   - the groups that contain a name, up to the top (and their groups);
 *   - the members of every group taken, down to the leaves (in every location - the firewall of a device group
 *     resolves them there);
 *   - optionally the rules that use one of the names or groups (pre / post / vsys rulebase, every rule type).
 * The result is a configuration pan-os-php and the config viewer load - the same merger run on it shows the same
 * problem. Works on the XML (DOM), not on the objects of pan-os-php: fast, and the same for every PAN-OS version.
 */
class ConfigExcerpt
{
    /** object stores below a location (shared, device group, vsys) */
    const STORES = array( 'address', 'address-group', 'service', 'service-group', 'tag', 'application-group', 'application-filter',
        'application', 'schedule', 'external-list', 'profile-group', 'region', 'dynamic-user-group' );
    /** stores of groups and how their members are written */
    const GROUP_MEMBERS = array( 'address-group' => 'static/member', 'service-group' => 'members/member', 'application-group' => 'members/member',
        'profile-group' => '*/member', 'dynamic-user-group' => 'tag/member' );
    /** rulebases below a location */
    const RULEBASES = array( 'pre-rulebase', 'post-rulebase', 'rulebase' );
    /** at most this many entries (a limit against a configuration of one big nest) */
    const MAX_ENTRIES = 20000;

    /** @var DOMDocument */
    private $doc;
    /** @var DOMXPath */
    private $x;
    /** location name => element (shared, device group, vsys) */
    public $locations = array();
    /** device group => parent device group (Panorama) */
    public $parents = array();
    public $panorama = FALSE;
    public $truncated = FALSE;

    public function __construct( DOMDocument $doc )
    {
        $this->doc = $doc;
        $this->x = new DOMXPath( $doc );
        $shared = $this->x->query( '/config/shared' )->item( 0 );
        if( $shared !== null )
            $this->locations['shared'] = $shared;
        foreach( $this->x->query( '/config/devices/entry/device-group/entry' ) as $dg )
        {
            $this->panorama = TRUE;
            $this->locations[$dg->getAttribute( 'name' )] = $dg;
        }
        foreach( $this->x->query( '/config/devices/entry/vsys/entry' ) as $v )
            $this->locations[$v->getAttribute( 'name' )] = $v;
        foreach( $this->x->query( '/config/readonly/devices/entry/device-group/entry' ) as $e )
        {
            $p = $this->x->query( 'parent-dg', $e )->item( 0 );
            $this->parents[$e->getAttribute( 'name' )] = $p !== null ? trim( $p->textContent ) : 'shared';
        }
        foreach( array_keys( $this->locations ) as $l )
            if( $l !== 'shared' && $this->panorama && !isset( $this->parents[$l] ) )
                $this->parents[$l] = 'shared';
    }

    /** the hierarchy: device groups with parent and child, templates / template stacks (names, members), firewalls per device group (count) */
    public function hierarchy(): array
    {
        $h = array( 'kind' => $this->panorama ? 'panorama' : ( count( $this->locations ) > 1 ? 'firewall' : 'unknown' ), 'locations' => array_keys( $this->locations ) );
        if( $this->panorama )
        {
            $h['deviceGroups'] = array();
            foreach( $this->parents as $dg => $parent )
            {
                $e = $this->locations[$dg] ?? null;
                $h['deviceGroups'][$dg] = array( 'parent' => $parent, 'firewalls' => $e !== null ? $this->x->query( 'devices/entry', $e )->length : 0 );
            }
            $h['templates'] = array();
            foreach( $this->x->query( '/config/devices/entry/template/entry' ) as $t )
                $h['templates'][] = $t->getAttribute( 'name' );
            $h['templateStacks'] = array();
            foreach( $this->x->query( '/config/devices/entry/template-stack/entry' ) as $t )
            {
                $m = array();
                foreach( $this->x->query( 'templates/member', $t ) as $mm )
                    $m[] = trim( $mm->textContent );
                $h['templateStacks'][$t->getAttribute( 'name' )] = array( 'templates' => $m, 'firewalls' => $this->x->query( 'devices/entry', $t )->length );
            }
        }
        return $h;
    }

    /** the entries of a name in every location: list of array( location, store, element ) */
    public function copies( string $name ): array
    {
        $out = array();
        foreach( $this->locations as $loc => $e )
            foreach( self::STORES as $s )
                foreach( $this->x->query( $s . '/entry[@name=' . self::lit( $name ) . ']', $e ) as $o )
                    $out[] = array( 'location' => $loc, 'store' => $s, 'element' => $o );
        return $out;
    }

    /**
     * what the excerpt holds for these names: names (with the groups up and the members down), the entries per
     * location, the rules
     */
    public function select( array $names, bool $rules ): array
    {
        $want = array();
        foreach( $names as $n )
            if( is_string( $n ) && $n !== '' )
                $want[$n] = TRUE;
        $entries = array();
        $count = 0;
        $take = function( string $loc, string $store, DOMElement $o ) use ( &$entries, &$count ) {
            $id = spl_object_id( $o );
            if( isset( $entries[$id] ) )
                return FALSE;
            if( $count >= self::MAX_ENTRIES )
            {
                $this->truncated = TRUE;
                return FALSE;
            }
            $count++;
            $entries[$id] = array( 'location' => $loc, 'store' => $store, 'element' => $o );
            return TRUE;
        };
        // up: the groups that hold a name, until nothing new
        $up = $want;
        $queue = array_keys( $want );
        while( $queue && !$this->truncated )
        {
            $next = array();
            foreach( $this->locations as $loc => $e )
                foreach( self::GROUP_MEMBERS as $store => $path )
                    foreach( $this->x->query( $store . '/entry', $e ) as $g )
                    {
                        $gn = $g->getAttribute( 'name' );
                        if( isset( $up[$gn] ) )
                            continue;
                        foreach( $this->x->query( $path, $g ) as $m )
                            if( in_array( trim( $m->textContent ), $queue, TRUE ) )
                            {
                                $up[$gn] = TRUE;
                                $next[] = $gn;
                                break;
                            }
                    }
            $queue = $next;
        }
        // down: every copy of a name of "up", the members of its groups, until nothing new
        $all = $up;
        $queue = array_keys( $up );
        while( $queue && !$this->truncated )
        {
            $next = array();
            foreach( $queue as $n )
                foreach( $this->copies( (string)$n ) as $c )
                {
                    $take( $c['location'], $c['store'], $c['element'] );
                    if( isset( self::GROUP_MEMBERS[$c['store']] ) )
                        foreach( $this->x->query( self::GROUP_MEMBERS[$c['store']], $c['element'] ) as $m )
                        {
                            $mn = trim( $m->textContent );
                            if( $mn !== '' && !isset( $all[$mn] ) )
                            {
                                $all[$mn] = TRUE;
                                $next[] = $mn;
                            }
                        }
                }
            $queue = $next;
        }
        // rules that use a name of "up" (the names and the groups above them)
        $ruleList = array();
        if( $rules )
            foreach( $this->locations as $loc => $e )
                foreach( self::RULEBASES as $rb )
                    foreach( $this->x->query( $rb . '/*/rules/entry', $e ) as $r )
                    {
                        foreach( $this->x->query( './/member', $r ) as $m )
                            if( isset( $up[trim( $m->textContent )] ) )
                            {
                                if( $take( $loc, $rb . '/' . $r->parentNode->parentNode->nodeName, $r ) )
                                    $ruleList[] = array( 'location' => $loc, 'rulebase' => $rb, 'type' => $r->parentNode->parentNode->nodeName, 'name' => $r->getAttribute( 'name' ) );
                                break;
                            }
                    }
        return array( 'names' => array_keys( $want ), 'up' => array_keys( $up ), 'all' => array_keys( $all ), 'entries' => array_values( $entries ), 'rules' => $ruleList );
    }

    /**
     * the small configuration: the root element with its attributes, the hierarchy (device groups / vsys, the
     * device-group part of readonly), and the entries of select() at their place (in the order of the original)
     */
    public function build( array $selection ): DOMDocument
    {
        $out = new DOMDocument( '1.0', 'UTF-8' );
        $out->formatOutput = TRUE;
        $root = $out->importNode( $this->doc->documentElement, FALSE );
        $out->appendChild( $root );
        $keep = array();
        foreach( $selection['entries'] as $e )
            $keep[spl_object_id( $e['element'] )] = TRUE;
        // the path from the root to a kept entry, with only the elements on the way (and the name attributes)
        $copyPath = function( DOMElement $el ) use ( $out, $root ) {
            $chain = array();
            for( $p = $el->parentNode; $p instanceof DOMElement && $p !== $this->doc->documentElement; $p = $p->parentNode )
                $chain[] = $p;
            $parent = $root;
            foreach( array_reverse( $chain ) as $p )
            {
                $found = null;
                foreach( $parent->childNodes as $c )
                    if( $c instanceof DOMElement && $c->nodeName === $p->nodeName && $c->getAttribute( 'name' ) === $p->getAttribute( 'name' ) )
                    {
                        $found = $c;
                        break;
                    }
                if( $found === null )
                {
                    $found = $out->importNode( $p, FALSE );
                    $parent->appendChild( $found );
                }
                $parent = $found;
            }
            $parent->appendChild( $out->importNode( $el, TRUE ) );
        };
        // the hierarchy first (also the device groups / vsys without an entry), then the entries in document order
        foreach( array( 'mgt-config' ) as $t )
            $root->appendChild( $out->createElement( $t ) );
        foreach( $this->locations as $loc => $e )
        {
            // the location element itself, empty (a stand-in next to it, copied with its path, removed again)
            $tmp = $this->doc->createElement( $e->nodeName );
            if( $e->hasAttribute( 'name' ) )
                $tmp->setAttribute( 'name', $e->getAttribute( 'name' ) );
            $e->parentNode->insertBefore( $tmp, $e );
            $copyPath( $tmp );
            $tmp->parentNode->removeChild( $tmp );
        }
        foreach( $this->x->query( '//entry' ) as $el )
            if( isset( $keep[spl_object_id( $el )] ) )
                $copyPath( $el );
        // device group hierarchy of readonly: name, id, parent-dg
        $ro = $this->x->query( '/config/readonly/devices/entry/device-group/entry' );
        foreach( $ro as $e )
        {
            $copy = $this->doc->createElement( 'entry' );
            $copy->setAttribute( 'name', $e->getAttribute( 'name' ) );
            foreach( array( 'id', 'parent-dg' ) as $t )
            {
                $v = $this->x->query( $t, $e )->item( 0 );
                if( $v !== null )
                    $copy->appendChild( $this->doc->createElement( $t, $v->textContent ) );
            }
            $e->parentNode->insertBefore( $copy, $e );
            $copyPath( $copy );
            $copy->parentNode->removeChild( $copy );
        }
        return $out;
    }

    /** an XPath string literal */
    private static function lit( string $s ): string
    {
        if( strpos( $s, "'" ) === FALSE )
            return "'" . $s . "'";
        if( strpos( $s, '"' ) === FALSE )
            return '"' . $s . '"';
        return "concat('" . str_replace( "'", "',\"'\",'", $s ) . "')";
    }
}
