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
 * Order of the resources = their dependencies: tags, addresses, address-groups, services, service-groups; then
 * the next ones (schedules, profiles, profile-groups, zones, rules).
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
            return array( 'vsys' => $sub->name() );
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

        $dropped = array();
        $body = self::$generator->toBody( array( 'resource' => $resource, 'node' => $object->xmlroot, 'name' => $object->name() ), $dropped );

        $notConverted = array();
        foreach( array_unique( $dropped ) as $path )
        {
            $child = strpos( $path, '/' ) === FALSE ? DH::findFirstElement( $path, $object->xmlroot ) : FALSE;
            $key = str_replace( '-', '_', $path );
            if( $child !== FALSE && !isset( $body[$key] ) )
                $body[$key] = self::generic( $child );
            else
                $notConverted[] = $path;
        }
        $item = $body + self::location( $object );
        if( count( $notConverted ) > 0 )
            $item['_panosphp'] = array( 'not_converted' => $notConverted );
        return array( 'resource' => $resource, 'item' => $item );
    }

    /** an XML element without SCM schema: member list -> string[], entry list -> objects with "name", leaf -> string */
    public static function generic( DOMElement $node )
    {
        $children = array();
        foreach( $node->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE )
                $children[] = $c;
        if( count( $children ) == 0 )
            return trim( $node->textContent );
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
