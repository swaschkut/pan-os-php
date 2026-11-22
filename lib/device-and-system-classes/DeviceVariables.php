<?php
/**
 * ISC License
 *
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
 * Variables of Panorama and SCM - as PAN-OS keeps them:
 *   <variable><entry name="$x"><type><ip-netmask>10.0.0.1/24</ip-netmask></type><description>…</description></entry></variable>
 *
 * Where they are:
 *   Panorama  template                      template/entry/variable
 *             template stack                template-stack/entry/variable
 *             one firewall of a stack       template-stack/entry/devices/entry[@name=serial]/variable  (override)
 *   SCM       folder / snippet / device     the entry of the container / snippet / cloud / on-prem device
 *             (loaded from /config/setup/v1/variables - PanSCMAPIConnector::SCM_API_variable_import)
 *
 * Which value a firewall gets (effective()): Panorama - its own override in the stack, the stack, then the templates
 * of the stack in their order (the first wins); SCM - the device, its snippets, then each folder up to "All" with its
 * snippets (the nearest wins).
 */
class DeviceVariables
{
    /** the element that holds the <variable> of an object; $serial: the firewall of a template stack (override) */
    public static function holder( $object, $serial = null, bool $create = FALSE ): ?DOMElement
    {
        if( $object instanceof ManagedDevice )
        {
            $stack = self::stackOf( $object );
            return $stack === null ? null : self::holder( $stack, $object->name(), $create );
        }
        if( !isset( $object->xmlroot ) || !$object->xmlroot instanceof DOMElement )
            return null;
        if( $object instanceof TemplateStack && $serial !== null && $serial !== '' )
        {
            $devices = $create ? DH::findFirstElementOrCreate( 'devices', $object->xmlroot ) : DH::findFirstElement( 'devices', $object->xmlroot );
            if( $devices === FALSE )
                return null;
            $entry = DH::findFirstElementByNameAttr( 'entry', $serial, $devices );
            if( $entry === null && $create )
            {
                $entry = $object->xmlroot->ownerDocument->createElement( 'entry' );
                $entry->setAttribute( 'name', $serial );
                $devices->appendChild( $entry );
            }
            return $entry;
        }
        return $object->xmlroot;
    }

    /** @return array name => array( 'type', 'value', 'description' ) */
    public static function listOf( ?DOMElement $holder ): array
    {
        $list = array();
        $root = $holder !== null ? DH::findFirstElement( 'variable', $holder ) : FALSE;
        if( $root === FALSE )
            return $list;
        foreach( $root->childNodes as $entry )
        {
            if( !$entry instanceof DOMElement || $entry->nodeName !== 'entry' )
                continue;
            $type = DH::findFirstElement( 'type', $entry );
            $value = $type !== FALSE ? DH::firstChildElement( $type ) : FALSE;
            $desc = DH::findFirstElement( 'description', $entry );
            $list[$entry->getAttribute( 'name' )] = array( 'type' => $value !== FALSE ? $value->nodeName : '',
                'value' => $value !== FALSE ? $value->textContent : '', 'description' => $desc !== FALSE ? $desc->textContent : '' );
        }
        return $list;
    }

    /** a variable set (added or its type / value replaced) */
    public static function set( DOMElement $holder, string $name, string $type, string $value, ?string $description = null ): void
    {
        if( !preg_match( '/^\$[A-Za-z0-9_.\-]{1,62}$/', $name ) )
            throw new Exception( "variable name '" . $name . "': \$ followed by letters, digits, _ . - (at most 63 characters)" );
        if( !preg_match( '/^[a-z][a-z0-9-]{0,40}$/', $type ) )
            throw new Exception( "variable type '" . $type . "' is not valid" );
        $doc = $holder->ownerDocument;
        $root = DH::findFirstElementOrCreate( 'variable', $holder );
        $entry = DH::findFirstElementByNameAttr( 'entry', $name, $root );
        if( $entry === null )
        {
            $entry = $doc->createElement( 'entry' );
            $entry->setAttribute( 'name', $name );
            $root->appendChild( $entry );
        }
        $typeNode = DH::findFirstElementOrCreate( 'type', $entry );
        DH::clearDomNodeChilds( $typeNode );
        $v = $doc->createElement( $type );
        $v->appendChild( $doc->createTextNode( $value ) );
        $typeNode->appendChild( $v );
        if( $description !== null )
        {
            $d = DH::findFirstElement( 'description', $entry );
            if( $description === '' && $d !== FALSE )
                $entry->removeChild( $d );
            elseif( $description !== '' )
            {
                $d = DH::findFirstElementOrCreate( 'description', $entry );
                $d->textContent = $description;
            }
        }
    }

    /** a variable removed; TRUE when it was there */
    public static function remove( DOMElement $holder, string $name ): bool
    {
        $root = DH::findFirstElement( 'variable', $holder );
        if( $root === FALSE )
            return FALSE;
        $entry = DH::findFirstElementByNameAttr( 'entry', $name, $root );
        if( $entry === null )
            return FALSE;
        $root->removeChild( $entry );
        return TRUE;
    }

    /** the template stack of a firewall of Panorama */
    public static function stackOf( ManagedDevice $device ): ?TemplateStack
    {
        $name = $device->getTemplateStack();
        $pan = $device->owner->owner ?? null;
        if( !is_string( $name ) || $name === '' || !is_object( $pan ) || !method_exists( $pan, 'findTemplateStack' ) )
            return null;
        return $pan->findTemplateStack( $name );
    }

    /**
     * the levels a value can come from, nearest first: array( array( 'kind' => devicetype, 'name' => …, 'label' => …,
     * 'vars' => listOf() ), … ) - the first level is the object itself (where a change is written)
     */
    public static function levels( $object ): array
    {
        $levels = array();
        $add = function( $kind, $name, $label, $holder ) use ( &$levels ) {
            $levels[] = array( 'kind' => $kind, 'name' => $name, 'label' => $label, 'vars' => self::listOf( $holder ) );
        };
        $templates = function( TemplateStack $stack ) use ( $add ) {
            foreach( array_values( $stack->templates ) as $i => $t )
                if( is_object( $t ) )
                    $add( 'template', $t->name(), 'template ' . $t->name() . ' (' . ( $i + 1 ) . ')', $t->xmlroot );
        };
        if( $object instanceof ManagedDevice )
        {
            $stack = self::stackOf( $object );
            $add( 'manageddevice', $object->name(), 'this firewall (template stack ' . ( $stack !== null ? $stack->name() : '-' ) . ')', self::holder( $object ) );
            if( $stack !== null )
            {
                $add( 'templatestack', $stack->name(), 'template stack ' . $stack->name(), $stack->xmlroot );
                $templates( $stack );
            }
        }
        elseif( $object instanceof TemplateStack )
        {
            $add( 'templatestack', $object->name(), 'this template stack', $object->xmlroot );
            $templates( $object );
        }
        elseif( $object instanceof Template )
            $add( 'template', $object->name(), 'this template', $object->xmlroot );
        elseif( $object instanceof Container || $object instanceof DeviceCloud || $object instanceof DeviceOnPrem || $object instanceof Snippet )
        {
            $kinds = array( 'Container' => 'container', 'DeviceCloud' => 'devicecloud', 'DeviceOnPrem' => 'deviceonprem', 'Snippet' => 'snippet' );
            $seen = array();
            for( $cur = $object, $first = TRUE, $i = 0; is_object( $cur ) && $i < 30; $i++, $first = FALSE )
            {
                if( isset( $seen[spl_object_id( $cur )] ) )
                    break;
                $seen[spl_object_id( $cur )] = TRUE;
                $kind = $kinds[get_class( $cur )] ?? 'container';
                $add( $kind, $cur->name(), $first ? 'this ' . ( $kind === 'container' ? 'folder' : $kind ) : 'folder ' . $cur->name(), $cur->xmlroot );
                foreach( $cur->attachedSnippets ?? array() as $sn )
                    if( is_object( $sn ) )
                        $add( 'snippet', $sn->name(), 'snippet ' . $sn->name() . ( $first ? '' : ' (of ' . $cur->name() . ')' ), $sn->xmlroot );
                $parent = $cur->parentContainer ?? null;
                if( is_string( $parent ) && method_exists( $cur->owner, 'findContainer' ) )
                    $parent = $cur->owner->findContainer( $parent );
                $cur = is_object( $parent ) ? $parent : null;
            }
        }
        return $levels;
    }

    /**
     * the value of each variable for the object: name => array( 'type', 'value', 'description', 'from' (label of the
     * level), 'fromkind', 'fromname', 'own' (set on the object itself), 'shadowed' (labels of the levels it hides) )
     */
    public static function effective( $object ): array
    {
        $out = array();
        foreach( self::levels( $object ) as $i => $l )
            foreach( $l['vars'] as $name => $v )
            {
                if( isset( $out[$name] ) )
                {
                    $out[$name]['shadowed'][] = $l['label'] . ': ' . $v['value'];
                    continue;
                }
                $out[$name] = $v + array( 'from' => $l['label'], 'fromkind' => $l['kind'], 'fromname' => $l['name'], 'own' => $i === 0, 'shadowed' => array() );
            }
        ksort( $out, SORT_NATURAL );
        return $out;
    }
}
