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
 * Generic access to device / Panorama settings that pan-os-php does not model as objects (sections with named
 * entries below the device entry, e.g. deviceconfig/system/deployment-update-schedule).
 *
 * The sections are declared in config_sections.json (path, scope, references) - a new section needs no code.
 * Works on the XML as it is: read (flattened fields), set / add-member / remove-member / delete, set commands.
 * Used by pan-os-php type=config-section (utils/lib/CONFIG_SECTION__.php) and type=panorama-move.
 */
class ConfigSection
{
    const DEVICE_ENTRY = "/config/devices/entry[@name='localhost.localdomain']";

    /** prefix of values encrypted with the master key - never displayed */
    const SECRET_PREFIX = '-AQ==';

    private static $registry = null;

    /** section name => definition (description, path, scope, references) */
    public static function registry( $file = null )
    {
        if( self::$registry === null || $file !== null )
        {
            if( $file === null )
                $file = dirname(__FILE__) . '/config_sections.json';
            $json = json_decode( file_get_contents($file), TRUE );
            if( !is_array($json) || !isset($json['sections']) )
                derr( "invalid config section registry '" . $file . "'", null, FALSE );
            self::$registry = $json['sections'];
        }
        return self::$registry;
    }

    public static function section( $name )
    {
        $r = self::registry();
        if( !isset($r[$name]) )
            derr( "config section '" . $name . "' is not known - available: " . implode(', ', array_keys($r)), null, FALSE );
        return $r[$name] + array( 'name' => $name );
    }

    /** XPath of the device entry of Panorama / firewall, or of a template (Panorama) */
    public static function deviceXpath( $template = null )
    {
        if( $template === null )
            return self::DEVICE_ENTRY;
        return self::DEVICE_ENTRY . "/template/entry[@name='" . $template . "']/config/devices/entry[@name='localhost.localdomain']";
    }

    /**
     * the kind of configuration a section is read in: 'template' (Panorama, template=), 'panorama', 'firewall' or 'scm'
     * (a folder / snippet / device of SCM - its entry is the base of the path)
     */
    public static function scopeOf( $isPanorama, $template = null, $isScm = FALSE )
    {
        if( $isScm )
            return 'scm';
        return $template !== null ? 'template' : ( $isPanorama ? 'panorama' : 'firewall' );
    }

    /**
     * the path of a section in a scope: 'paths' => scope => path (e.g. authentication profiles: panorama/… on Panorama,
     * shared/… on a firewall), else 'path'
     */
    public static function pathOf( array $section, $scope )
    {
        if( isset($section['paths'][$scope]) )
            return $section['paths'][$scope];
        // a template holds the configuration of a firewall
        if( $scope === 'template' && isset($section['paths']['firewall']) )
            return $section['paths']['firewall'];
        return $section['path'];
    }

    /**
     * XPath of the section container. 'base' of the section: 'device' (default, below the device entry
     * localhost.localdomain) or 'config' (below <config>: mgt-config, shared, panorama); a template: inside its
     * <config>. SCM has no XPath (the folder / snippet / device entry is the base) - see container()
     */
    public static function xpath( array $section, $template = null, $scope = null )
    {
        if( $scope === null )
            $scope = $template !== null ? 'template' : 'panorama';
        $path = self::pathOf( $section, $scope );
        if( ( $section['base'] ?? 'device' ) === 'config' )
            return ( $template === null ? '/config' : self::DEVICE_ENTRY . "/template/entry[@name='" . $template . "']/config" ) . '/' . $path;
        return self::deviceXpath( $template ) . '/' . $path;
    }

    /** a section is "settings": one container of fields (shown as one entry with the name of the section) */
    public static function isSettings( array $section )
    {
        return ( $section['kind'] ?? 'entries' ) === 'settings';
    }

    /** check that the section exists for this kind of configuration */
    public static function checkScope( array $section, $isPanorama, $template = null, $isScm = FALSE )
    {
        $scope = self::scopeOf( $isPanorama, $template, $isScm );
        if( !in_array($scope, $section['scope'], TRUE) )
            derr( "config section '" . $section['name'] . "' is not available for " . $scope . " (scope: " . implode(', ', $section['scope']) . ")", null, FALSE );
    }

    /**
     * section container node, null when missing (created along the path with $create). $scope: as scopeOf() - for
     * 'scm' $scmRoot is the entry of the folder / snippet / device
     */
    public static function container( DOMDocument $doc, array $section, $template = null, $create = FALSE, $scope = null, ?DOMElement $scmRoot = null )
    {
        if( $scope === 'scm' )
        {
            if( $scmRoot === null )
                return null;
            $node = $scmRoot;
            foreach( explode('/', self::pathOf( $section, 'scm' )) as $name )
            {
                $next = null;
                foreach( $node->childNodes as $c )
                    if( $c->nodeType == XML_ELEMENT_NODE && $c->nodeName == $name )
                        $next = $c;
                if( $next === null )
                {
                    if( !$create )
                        return null;
                    $next = self::childOrCreate( $node, $name );
                }
                $node = $next;
            }
            return $node;
        }
        $x = new DOMXPath( $doc );
        $n = $x->query( self::xpath($section, $template, $scope) );
        if( $n->length )
            return $n->item(0);
        if( !$create )
            return null;

        $config = ( $section['base'] ?? 'device' ) === 'config';
        if( $template === null )
        {
            $base = $x->query( $config ? '/config' : self::DEVICE_ENTRY );
            if( $base->length == 0 )
                derr( "device entry not found in the configuration", null, FALSE );
            $node = $base->item(0);
        }
        else
        {
            $t = $x->query( self::DEVICE_ENTRY . "/template/entry[@name='" . $template . "']" );
            if( $t->length == 0 )
                derr( "template '" . $template . "' not found", null, FALSE );
            $node = self::childOrCreate( $t->item(0), 'config' );
            if( !$config )
                $node = self::childOrCreate( self::childOrCreate( $node, 'devices' ), 'entry', 'localhost.localdomain' );
        }
        foreach( explode('/', self::pathOf( $section, $scope ?? ( $template !== null ? 'template' : 'panorama' ) )) as $name )
            $node = self::childOrCreate( $node, $name );
        return $node;
    }

    /**
     * the entries of a section to show: named entries; a "settings" section: the container itself (one entry with the
     * name of the section) - child elements listed in 'exclude' (sections of their own) left out
     */
    public static function sectionEntries( array $section, $container, $forDisplay = TRUE )
    {
        if( !self::isSettings( $section ) )
            return self::entries( $container );
        if( $container === null )
            return array();
        if( $forDisplay && !empty($section['exclude']) )
        {
            $copy = $container->cloneNode( TRUE );
            foreach( iterator_to_array( $copy->childNodes ) as $c )
                if( $c->nodeType == XML_ELEMENT_NODE && in_array( $c->nodeName, $section['exclude'], TRUE ) )
                    $copy->removeChild( $c );
            // the copy is only read (display); a change works on the container itself ($forDisplay = FALSE); nothing
            // left (only sections of their own): not set
            foreach( $copy->childNodes as $c )
                if( $c->nodeType == XML_ELEMENT_NODE )
                    return array( $section['name'] => $copy );
            return array();
        }
        return array( $section['name'] => $container );
    }

    private static function childOrCreate( DOMElement $node, $name, $entryName = null )
    {
        foreach( $node->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE && $c->nodeName == $name && ( $entryName === null || $c->getAttribute('name') === $entryName ) )
                return $c;
        $e = $node->ownerDocument->createElement( $name );
        if( $entryName !== null )
            $e->setAttribute( 'name', $entryName );
        $node->appendChild( $e );
        return $e;
    }

    /** named entries of a section container: name => DOMElement */
    public static function entries( $container )
    {
        $out = array();
        if( $container === null )
            return $out;
        foreach( $container->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE && $c->nodeName == 'entry' && $c->hasAttribute('name') )
                $out[$c->getAttribute('name')] = $c;
        return $out;
    }

    /** entry of a section container, created on request */
    public static function entry( DOMElement $container, $name, $create = FALSE )
    {
        $e = self::entries( $container );
        if( isset($e[$name]) )
            return $e[$name];
        return $create ? self::childOrCreate( $container, 'entry', $name ) : null;
    }

    /** field names whose value is never shown (password hashes, keys, secrets), also when not encrypted */
    const SECRET_FIELDS = '/(^|\.)(?!public-key$)([a-z0-9-]*-key|key|authkey|phash|password|passwd|[a-z0-9-]*-password|secret|[a-z0-9-]*-secret|psk|community|passphrase|token)$/i';

    public static function isSecret( $value, $path = null )
    {
        if( $path !== null && preg_match( self::SECRET_FIELDS, (string)$path ) )
            return TRUE;
        return strpos( (string)$value, self::SECRET_PREFIX ) === 0;
    }

    /**
     * fields of an entry: relative path (elements joined by '.', named entries as name[entry]) => value;
     * member lists joined by ', ', empty elements as '(set)', encrypted values masked
     */
    public static function flatten( DOMElement $node, $prefix = '', &$out = array() )
    {
        $elements = array();
        foreach( $node->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE )
                $elements[] = $c;

        if( count($elements) == 0 )
        {
            if( $prefix !== '' )
            {
                $v = trim( $node->textContent );
                $out[$prefix] = $v === '' ? '(set)' : ( self::isSecret($v) ? '*** encrypted ***' : ( self::isSecret($v, $prefix) ? '*** hidden ***' : $v ) );
            }
            return $out;
        }

        $members = array();
        foreach( $elements as $c )
        {
            if( $c->nodeName == 'member' )
            {
                $members[] = trim( $c->textContent );
                continue;
            }
            $name = $c->nodeName == 'entry' && $c->hasAttribute('name') ? '[' . $c->getAttribute('name') . ']' : $c->nodeName;
            $p = $prefix === '' ? $name : ( $c->nodeName == 'entry' ? $prefix . $name : $prefix . '.' . $name );
            self::flatten( $c, $p, $out );
        }
        if( count($members) )
            $out[$prefix === '' ? 'member' : $prefix] = implode( ', ', $members );
        return $out;
    }

    /** the fields of an entry (as flatten() names them) that are member lists (<member>…) - changed with add-member / remove-member */
    public static function memberPaths( DOMElement $node, $prefix = '', &$out = array() )
    {
        $hasMember = FALSE;
        foreach( $node->childNodes as $c )
        {
            if( $c->nodeType != XML_ELEMENT_NODE )
                continue;
            if( $c->nodeName == 'member' )
            {
                $hasMember = TRUE;
                continue;
            }
            $name = $c->nodeName == 'entry' && $c->hasAttribute('name') ? '[' . $c->getAttribute('name') . ']' : $c->nodeName;
            $p = $prefix === '' ? $name : ( $c->nodeName == 'entry' ? $prefix . $name : $prefix . '.' . $name );
            self::memberPaths( $c, $p, $out );
        }
        if( $hasMember )
            $out[] = $prefix === '' ? 'member' : $prefix;
        return $out;
    }

    /**
     * text values of an entry that are device group / template / template stack names or serials of $names
     * (kind => [name => TRUE]): list of "kind name"
     */
    public static function references( DOMElement $entry, array $names )
    {
        $out = array();
        $x = new DOMXPath( $entry->ownerDocument );
        foreach( $x->query( './/text()', $entry ) as $t )
        {
            $v = trim( $t->nodeValue );
            if( $v === '' )
                continue;
            foreach( $names as $kind => $list )
                if( isset($list[$v]) )
                    $out[$kind . ' ' . $v] = array( 'kind' => $kind, 'name' => $v, 'path' => self::relPath( $t->parentNode, $entry ) );
        }
        foreach( $x->query( './/entry/@name', $entry ) as $a )
            foreach( $names as $kind => $list )
                if( isset($list[$a->value]) )
                    $out[$kind . ' ' . $a->value] = array( 'kind' => $kind, 'name' => $a->value, 'path' => self::relPath( $a->ownerElement, $entry ) );
        return array_values( $out );
    }

    private static function relPath( DOMNode $node, DOMElement $root )
    {
        $p = array();
        for( $n = $node; $n !== null && !$n->isSameNode($root); $n = $n->parentNode )
            $p[] = $n->nodeName == 'entry' ? '[' . $n->getAttribute('name') . ']' : $n->nodeName;
        return implode( '.', array_reverse($p) );
    }

    /**
     * device groups, templates, template stacks and managed firewalls of a Panorama configuration (XML as stored):
     * kind => [name => TRUE] - input for references()
     */
    public static function panoramaNames( DOMDocument $doc )
    {
        $x = new DOMXPath( $doc );
        $out = array( 'device group' => array(), 'template' => array(), 'template stack' => array(), 'firewall' => array() );
        foreach( array( 'device group' => 'device-group', 'template' => 'template', 'template stack' => 'template-stack' ) as $k => $el )
            foreach( $x->query( self::DEVICE_ENTRY . '/' . $el . '/entry/@name' ) as $a )
                $out[$k][$a->value] = TRUE;
        foreach( $x->query( '/config/mgt-config/devices/entry/@name' ) as $a )
            $out['firewall'][$a->value] = TRUE;
        return $out;
    }

    /** element path inside an entry: "a.b.c" (named entries "a.[name].b") => DOMElement, created on request */
    public static function node( DOMElement $entry, $path, $create = FALSE )
    {
        $node = $entry;
        foreach( self::splitPath($path) as $part )
        {
            $entryName = null;
            $name = $part;
            if( preg_match('/^\[(.*)\]$/', $part, $m) )
            {
                $name = 'entry';
                $entryName = $m[1];
            }
            $found = null;
            foreach( $node->childNodes as $c )
                if( $c->nodeType == XML_ELEMENT_NODE && $c->nodeName == $name && ( $entryName === null || $c->getAttribute('name') === $entryName ) )
                {
                    $found = $c;
                    break;
                }
            if( $found === null )
            {
                if( !$create )
                    return null;
                $found = self::childOrCreate( $node, $name, $entryName );
            }
            $node = $found;
        }
        return $node;
    }

    private static function splitPath( $path )
    {
        $parts = array();
        preg_match_all( '/\[[^\]]*\]|[^.\[\]]+/', $path, $m );
        foreach( $m[0] as $p )
            if( $p !== '' )
                $parts[] = $p;
        if( count($parts) == 0 )
            derr( "empty field path", null, FALSE );
        return $parts;
    }

    /** set a field to a text value (elements created when missing); TRUE when changed */
    public static function setValue( DOMElement $entry, $path, $value )
    {
        $n = self::node( $entry, $path, TRUE );
        foreach( $n->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE )
                derr( "field '" . $path . "' is not a single value (has child elements)", null, FALSE );
        if( $n->textContent === (string)$value )
            return FALSE;
        $n->nodeValue = '';
        $n->appendChild( $n->ownerDocument->createTextNode( (string)$value ) );
        return TRUE;
    }

    /** add a member to a member list field; TRUE when changed */
    public static function addMember( DOMElement $entry, $path, $value )
    {
        $n = self::node( $entry, $path, TRUE );
        foreach( $n->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE && $c->nodeName == 'member' && trim($c->textContent) === $value )
                return FALSE;
        $m = $n->ownerDocument->createElement( 'member' );
        $m->appendChild( $n->ownerDocument->createTextNode( $value ) );
        $n->appendChild( $m );
        return TRUE;
    }

    /** remove a member from a member list field; TRUE when changed */
    public static function removeMember( DOMElement $entry, $path, $value )
    {
        $n = self::node( $entry, $path );
        if( $n === null )
            return FALSE;
        $changed = FALSE;
        foreach( iterator_to_array( $n->childNodes ) as $c )
            if( $c->nodeType == XML_ELEMENT_NODE && $c->nodeName == 'member' && trim($c->textContent) === $value )
            {
                $n->removeChild( $c );
                $changed = TRUE;
            }
        return $changed;
    }

    /** remove a field (element) of an entry; TRUE when changed */
    public static function removeField( DOMElement $entry, $path )
    {
        $n = self::node( $entry, $path );
        if( $n === null )
            return FALSE;
        $n->parentNode->removeChild( $n );
        return TRUE;
    }

    /**
     * set commands that create the entry: "set deviceconfig system <section> <entry> <path...> <value>";
     * with a template: "set template <name> config deviceconfig ..."; encrypted values are written as <encrypted>
     */
    public static function setCommands( array $section, DOMElement $entry, $template = null )
    {
        $prefix = 'set ' . ( $template !== null ? 'template ' . self::quote($template) . ' config ' : '' )
            . implode( ' ', explode('/', $section['path']) ) . ' ' . self::quote( $entry->getAttribute('name') );
        $out = array();
        self::setLines( $entry, $prefix, $out );
        if( count($out) == 0 )
            $out[] = $prefix;
        return $out;
    }

    private static function setLines( DOMElement $node, $prefix, array &$out )
    {
        $elements = array(); $members = array();
        foreach( $node->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE )
            {
                if( $c->nodeName == 'member' )
                    $members[] = self::quote( trim($c->textContent) );
                else
                    $elements[] = $c;
            }
        if( count($members) )
            $out[] = $prefix . ' [ ' . implode( ' ', $members ) . ' ]';
        foreach( $elements as $c )
        {
            $p = $prefix . ' ' . ( $c->nodeName == 'entry' && $c->hasAttribute('name') ? self::quote($c->getAttribute('name')) : $c->nodeName );
            $hasChild = FALSE;
            foreach( $c->childNodes as $cc )
                if( $cc->nodeType == XML_ELEMENT_NODE ) { $hasChild = TRUE; break; }
            if( $hasChild )
                self::setLines( $c, $p, $out );
            else
            {
                $v = trim( $c->textContent );
                $out[] = $v === '' ? $p : $p . ' ' . ( self::isSecret($v) ? '<encrypted>' : self::quote($v) );
            }
        }
    }

    private static function quote( $v )
    {
        return preg_match('/[\s"\'\[\];]/', $v) || $v === '' ? '"' . str_replace('"', '\"', $v) . '"' : $v;
    }
}
