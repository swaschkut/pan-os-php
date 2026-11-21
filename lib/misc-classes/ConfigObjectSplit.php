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
 * A configuration as one entry per object (git on object level, step 1: split and join) - see
 * todo/config-viewer-panos-style-edit.md "Changes with git, on object level".
 *
 * split(): the XML of a PAN-OS / Panorama / SCM configuration → array( path => text ):
 *
 *   devices/localhost.localdomain/device-group/DG-Berlin/address/web01.xml     one object (canonical XML)
 *   devices/localhost.localdomain/device-group/DG-Berlin/address/_order        the order of the entries (one key per line)
 *   devices/localhost.localdomain/device-group/DG-Berlin/pre-rulebase/security/rules/<uuid>.xml   a rule (by its UUID)
 *   shared/address/web01.xml
 *   _rest.xml                                                                  everything else (the split entries taken out)
 *
 * The path is the XML path from <config>: element names, and the name of every <entry> on the way. Split are the
 * entries of the object stores and rule bases (STORES) of a location: /config/shared and every entry of a device
 * group, vsys, SCM snippet / container (folder) / device. Templates and template stacks stay in _rest.xml (later).
 * A store is only split when it holds nothing but named <entry> elements (otherwise it stays whole in _rest.xml).
 *
 * Names in paths: "%" "/" control characters and a leading "." are written as %XX (rawurldecode gives them back).
 * Two entries with the same key in one store (an invalid configuration): the second gets "~2", ….
 *
 * Canonical XML: whitespace between elements is dropped and written again as an indentation of 2 per level; text
 * (a description, a value) is kept as it is; the order of the elements and attributes is kept. join( split( x ) )
 * gives the same document as x up to the whitespace between elements (canonical( x ) === canonical( join( split( x ) ) )).
 */
class ConfigObjectSplit
{
    const REST = '_rest.xml';
    const ORDER = '_order';

    /** the stores of a location, relative to it ('*' = every child element) */
    const STORES = array(
        'address', 'address-group', 'service', 'service-group', 'tag', 'schedule', 'external-list', 'region',
        'application', 'application-group', 'application-filter', 'dynamic-user-group', 'profile-group',
        'profiles/*', 'threats/*', 'log-settings/profiles',
        'pre-rulebase/*/rules', 'post-rulebase/*/rules', 'rulebase/*/rules',
    );
    /** an <entry> below one of these elements is a location */
    const LOCATIONS = array( 'device-group', 'vsys', 'snippet', 'container', 'device' );
    /** nothing below these is split (yet) */
    const SKIP_BELOW = array( 'template', 'template-stack' );

    /**
     * @param DOMDocument $doc the configuration (not changed: split works on a copy)
     * @return string[] path => text, sorted by path
     */
    public static function split( DOMDocument $doc ): array
    {
        $copy = new DOMDocument();
        $copy->appendChild( $copy->importNode( $doc->documentElement, TRUE ) );
        self::stripBlanks( $copy->documentElement );

        $files = array();
        foreach( self::collect( $copy ) as $dir => $store )
        {
            foreach( $store['entries'] as $key => $e )
            {
                $files[$dir . '/' . $key . '.xml'] = self::canonical( $e );
                $store['node']->removeChild( $e );
            }
            $files[$dir . '/' . self::ORDER] = self::orderText( $store['entries'] );
        }
        $files[self::REST] = self::canonical( $copy );
        ksort( $files, SORT_STRING );
        return $files;
    }

    /**
     * The state of a configuration in memory (the DOM pan-os-php works on; not changed): a hash of every entry as it
     * is in the DOM now, the order of each store and a hash of the rest - cheap enough to take after every change.
     * changes( $before, $after ) gives the entries of the repository that differ (canonical text, like split()).
     *
     * @return array( 'entries' => path => array( 'hash' => md5, 'node' => DOMElement ), 'orders' => path => text,
     *                'rest' => md5, 'doc' => DOMDocument )
     */
    public static function state( DOMDocument $doc ): array
    {
        $state = array( 'entries' => array(), 'orders' => array(), 'rest' => '', 'doc' => $doc );
        $stores = self::collect( $doc );
        foreach( $stores as $dir => $store )
        {
            foreach( $store['entries'] as $key => $e )
                $state['entries'][$dir . '/' . $key . '.xml'] = array( 'hash' => md5( $doc->saveXML( $e ) ), 'node' => $e );
            $state['orders'][$dir . '/' . self::ORDER] = self::orderText( $store['entries'] );
        }
        $state['rest'] = md5( self::withoutEntries( $doc, $stores, function() use ( $doc ) { return $doc->saveXML(); } ) );
        return $state;
    }

    /**
     * the entries of the repository that differ between two states: array( 'put' => path => text, 'delete' => paths )
     * ('put' as split() would write them; an entry whose text did not change only by its whitespace is also in it -
     * git keeps the same blob then)
     */
    public static function changes( array $before, array $after ): array
    {
        $put = array();
        $delete = array();
        foreach( $after['entries'] as $path => $e )
            if( !isset( $before['entries'][$path] ) || $before['entries'][$path]['hash'] !== $e['hash'] )
                $put[$path] = self::canonical( $e['node'] );
        foreach( $before['entries'] as $path => $e )
            if( !isset( $after['entries'][$path] ) )
                $delete[] = $path;
        foreach( $after['orders'] as $path => $text )
            if( ( $before['orders'][$path] ?? null ) !== $text )
                $put[$path] = $text;
        foreach( $before['orders'] as $path => $text )
            if( !isset( $after['orders'][$path] ) )
                $delete[] = $path;
        if( $before['rest'] !== $after['rest'] )
        {
            $doc = $after['doc'];
            $put[self::REST] = self::withoutEntries( $doc, self::collect( $doc ), function() use ( $doc ) { return self::canonical( $doc ); } );
        }
        ksort( $put, SORT_STRING );
        sort( $delete, SORT_STRING );
        return array( 'put' => $put, 'delete' => $delete );
    }

    /** all files of a state, as split() gives them (the first commit of a version from the DOM in memory) */
    public static function files( array $state ): array
    {
        $empty = array( 'entries' => array(), 'orders' => array(), 'rest' => '' );
        return self::changes( $empty, $state )['put'];
    }

    /**
     * @param string[] $files path => text (as split() gives them)
     * @return DOMDocument
     */
    public static function join( array $files ): DOMDocument
    {
        if( !isset($files[self::REST]) )
            throw new Exception( "the entry " . self::REST . " is missing" );
        $doc = self::load( $files[self::REST], self::REST );

        // the entries of each store, in the order of its _order; entries not in it (added without) after them, sorted
        $dirs = array();
        foreach( $files as $path => $text )
        {
            if( $path === self::REST )
                continue;
            $slash = strrpos( $path, '/' );
            if( $slash === FALSE )
                throw new Exception( "unexpected entry '" . $path . "'" );
            $dir = substr( $path, 0, $slash );
            $base = substr( $path, $slash + 1 );
            if( $base === self::ORDER )
                $dirs[$dir]['order'] = $text;
            elseif( substr( $base, -4 ) === '.xml' )
                $dirs[$dir]['entries'][substr( $base, 0, -4 )] = $text;
            else
                throw new Exception( "unexpected entry '" . $path . "'" );
        }
        ksort( $dirs, SORT_STRING );
        foreach( $dirs as $dir => $d )
        {
            $entries = $d['entries'] ?? array();
            $keys = array();
            foreach( explode( "\n", $d['order'] ?? '' ) as $k )
                if( $k !== '' && isset($entries[$k]) && !in_array( $k, $keys, TRUE ) )
                    $keys[] = $k;
            $rest = array_diff( array_keys( $entries ), $keys );
            sort( $rest, SORT_STRING );
            $keys = array_merge( $keys, $rest );
            if( !$keys )
                continue;
            $store = self::find( $doc, $dir );
            foreach( $keys as $k )
            {
                $e = self::load( $entries[$k], $dir . '/' . $k . '.xml' );
                $store->appendChild( $doc->importNode( $e->documentElement, TRUE ) );
            }
        }
        return $doc;
    }

    /** the text of a node or document: whitespace between elements as an indentation of 2 per level */
    public static function canonical( DOMNode $node ): string
    {
        $doc = new DOMDocument( '1.0', 'UTF-8' );
        $doc->formatOutput = TRUE;
        $root = $node instanceof DOMDocument ? $node->documentElement : $node;
        $doc->appendChild( $doc->importNode( $root, TRUE ) );
        self::stripBlanks( $doc->documentElement );
        if( $node instanceof DOMDocument )
            return $doc->saveXML();
        return $doc->saveXML( $doc->documentElement ) . "\n";
    }

    /** the path of a store / entry in the repository: the XML path from <config> (element names, names of entries) */
    public static function path( DOMElement $node ): string
    {
        $parts = array();
        for( $n = $node; $n !== null && $n->parentNode instanceof DOMElement; $n = $n->parentNode )
            $parts[] = $n->nodeName === 'entry' ? self::enc( $n->getAttribute( 'name' ) ) : $n->nodeName;
        return implode( '/', array_reverse( $parts ) );
    }

    public static function enc( string $s ): string
    {
        $s = preg_replace_callback( '/[%\/\x00-\x1f\x7f]/', function( $m ) {
            return sprintf( '%%%02X', ord( $m[0] ) );
        }, $s );
        if( $s === '' || $s[0] === '.' )
            $s = '%2E' . ( $s === '' ? '' : substr( $s, 1 ) );
        return $s;
    }

    // ------------------------------------------------------------------------------------------------------------

    /**
     * the stores to split of a configuration: dir => array( 'node' => store, 'entries' => key => entry )
     * (the same for a DOM as pan-os-php loaded it - whitespace between the elements - and for the copy of split())
     */
    private static function collect( DOMDocument $doc ): array
    {
        $list = array();
        foreach( self::locations( $doc->documentElement ) as $loc )
            foreach( self::stores( $loc ) as $store )
            {
                if( !self::splittable( $store ) )
                    continue;
                $entries = array();
                foreach( $store->childNodes as $c )
                    if( $c instanceof DOMElement )
                    {
                        $key = self::key( $c );
                        if( isset( $entries[$key] ) )
                        {
                            $i = 2;
                            while( isset( $entries[$key . '~' . $i] ) )
                                $i++;
                            $key .= '~' . $i;
                        }
                        $entries[$key] = $c;
                    }
                $list[self::path( $store )] = array( 'node' => $store, 'entries' => $entries );
            }
        return $list;
    }

    private static function orderText( array $entries ): string
    {
        return implode( "\n", array_keys( $entries ) ) . "\n";
    }

    /**
     * $fn while the children of the split stores are out of the document (they are put back in their order, the
     * same nodes - pan-os-php keeps its references to them)
     */
    private static function withoutEntries( DOMDocument $doc, array $stores, callable $fn )
    {
        $out = array();
        foreach( $stores as $dir => $store )
        {
            $kids = array();
            while( $store['node']->firstChild !== null )
                $kids[] = $store['node']->removeChild( $store['node']->firstChild );
            $out[$dir] = $kids;
        }
        try
        {
            return $fn();
        }
        finally
        {
            foreach( $stores as $dir => $store )
                foreach( $out[$dir] as $k )
                    $store['node']->appendChild( $k );
        }
    }

    /** the key of an entry in its store: a rule by its UUID (when it has one), every other entry by its name */
    private static function key( DOMElement $e ): string
    {
        $uuid = $e->getAttribute( 'uuid' );
        if( $uuid !== '' && $e->parentNode !== null && $e->parentNode->nodeName === 'rules' )
            return self::enc( $uuid );
        return self::enc( $e->getAttribute( 'name' ) );
    }

    /** @return DOMElement[] */
    private static function locations( DOMElement $config ): array
    {
        $list = array();
        foreach( $config->childNodes as $c )
            if( $c instanceof DOMElement && $c->nodeName === 'shared' )
                $list[] = $c;
        $walk = function( DOMElement $n ) use ( &$walk, &$list ) {
            foreach( $n->childNodes as $c )
            {
                if( !$c instanceof DOMElement || in_array( $c->nodeName, self::SKIP_BELOW, TRUE ) )
                    continue;
                if( $c->nodeName === 'entry' && in_array( $n->nodeName, self::LOCATIONS, TRUE ) && $c->hasAttribute( 'name' ) )
                    $list[] = $c;
                // the stores of a location are not walked again (a rule base has no locations)
                if( $c->nodeName === 'entry' || in_array( $c->nodeName, array( 'devices', 'device-group', 'vsys', 'snippet', 'container', 'device' ), TRUE ) )
                    $walk( $c );
            }
        };
        foreach( $config->childNodes as $c )
            if( $c instanceof DOMElement && $c->nodeName === 'devices' )
                $walk( $c );
        return $list;
    }

    /** @return DOMElement[] the stores of a location that exist */
    private static function stores( DOMElement $loc ): array
    {
        $list = array();
        foreach( self::STORES as $spec )
        {
            $nodes = array( $loc );
            foreach( explode( '/', $spec ) as $part )
            {
                $next = array();
                foreach( $nodes as $n )
                    foreach( $n->childNodes as $c )
                        if( $c instanceof DOMElement && $c->nodeName !== 'entry' && ( $part === '*' || $c->nodeName === $part ) )
                            $next[] = $c;
                $nodes = $next;
            }
            foreach( $nodes as $n )
                $list[] = $n;
        }
        return $list;
    }

    /** only named <entry> elements in it (and whitespace between them) */
    private static function splittable( DOMElement $store ): bool
    {
        if( !$store->hasChildNodes() )
            return FALSE;
        $any = FALSE;
        foreach( $store->childNodes as $c )
        {
            if( $c->nodeType === XML_TEXT_NODE && trim( $c->nodeValue, " \t\r\n" ) === '' )
                continue;
            if( !$c instanceof DOMElement || $c->nodeName !== 'entry' || !$c->hasAttribute( 'name' ) )
                return FALSE;
            $any = TRUE;
        }
        return $any;
    }

    /** whitespace-only text between elements out (an element with element children); text of a leaf element stays */
    private static function stripBlanks( DOMElement $el ): void
    {
        $hasElement = FALSE;
        foreach( $el->childNodes as $c )
            if( $c->nodeType === XML_ELEMENT_NODE )
            {
                $hasElement = TRUE;
                break;
            }
        $remove = array();
        foreach( $el->childNodes as $c )
        {
            if( $c instanceof DOMElement )
                self::stripBlanks( $c );
            elseif( $hasElement && $c->nodeType === XML_TEXT_NODE && trim( $c->nodeValue, " \t\r\n" ) === '' )
                $remove[] = $c;
        }
        foreach( $remove as $c )
            $el->removeChild( $c );
    }

    private static function load( string $text, string $what ): DOMDocument
    {
        $doc = new DOMDocument();
        $prev = libxml_use_internal_errors( TRUE );
        $ok = $doc->loadXML( $text, LIBXML_PARSEHUGE );
        libxml_clear_errors();
        libxml_use_internal_errors( $prev );
        if( !$ok || $doc->documentElement === null )
            throw new Exception( "the entry '" . $what . "' is no valid XML" );
        self::stripBlanks( $doc->documentElement );
        return $doc;
    }

    /** a location or an element of it (not an entry of a store) */
    private static function insideLocation( DOMElement $n ): bool
    {
        for( ; $n instanceof DOMElement; $n = $n->parentNode )
        {
            if( $n->nodeName === 'shared' && $n->parentNode === $n->ownerDocument->documentElement )
                return TRUE;
            if( $n->nodeName === 'entry' )
                return $n->parentNode instanceof DOMElement && in_array( $n->parentNode->nodeName, self::LOCATIONS, TRUE );
        }
        return FALSE;
    }

    /** the store of a path in the rest; elements missing at its end are created (a store added after the split) */
    private static function find( DOMDocument $doc, string $dir ): DOMElement
    {
        $n = $doc->documentElement;
        $parts = explode( '/', $dir );
        foreach( $parts as $i => $part )
        {
            $name = rawurldecode( $part );
            $next = null;
            foreach( $n->childNodes as $c )
                if( $c instanceof DOMElement && $c->nodeName === $part && $c->nodeName !== 'entry' )
                {
                    $next = $c;
                    break;
                }
            if( $next === null )
                foreach( $n->childNodes as $c )
                    if( $c instanceof DOMElement && $c->nodeName === 'entry' && $c->getAttribute( 'name' ) === $name )
                    {
                        $next = $c;
                        break;
                    }
            if( $next === null )
            {
                // only the store itself (and the elements above it inside the location) can be created
                if( !preg_match( '/^[A-Za-z][A-Za-z0-9_.-]*$/', $part ) || !self::insideLocation( $n ) )
                    throw new Exception( "the location of '" . $dir . "' is not in " . self::REST );
                $next = $n->appendChild( $doc->createElement( $part ) );
            }
            $n = $next;
        }
        return $n;
    }
}
