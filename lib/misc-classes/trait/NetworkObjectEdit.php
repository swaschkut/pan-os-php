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
 * Changes of the XML of a network object (IKE gateway, IKE / IPsec crypto profile, IPsec tunnel): elements below its
 * entry by a path, a choice of one child, a member list - and the references to the objects it names. Used by the
 * set methods of these classes (actions ike-gateway / ike-profile / ipsec-profile / ipsec-tunnel …-set).
 */
trait NetworkObjectEdit
{
    /** the element at $path below the entry (created) */
    protected function editNode( array $path ): DOMElement
    {
        $node = $this->xmlroot;
        foreach( $path as $tag )
            $node = DH::findFirstElementOrCreate( $tag, $node );
        return $node;
    }

    /** the element at $path, FALSE: not there */
    protected function editFind( array $path )
    {
        $node = $this->xmlroot;
        foreach( $path as $tag )
        {
            $node = DH::findFirstElement( $tag, $node );
            if( $node === FALSE || $node === null )
                return FALSE;
        }
        return $node;
    }

    protected function editText( array $path, string $value ): void
    {
        DH::setDomNodeText( $this->editNode( $path ), $value );
    }

    /** removes the element at $path and parents that are empty afterwards (not the entry itself) */
    protected function editRemove( array $path ): void
    {
        $node = $this->editFind( $path );
        if( $node === FALSE )
            return;
        $parent = $node->parentNode;
        $parent->removeChild( $node );
        while( $parent !== $this->xmlroot && $parent instanceof DOMElement && !$parent->hasChildNodes() )
        {
            $up = $parent->parentNode;
            $up->removeChild( $parent );
            $parent = $up;
        }
    }

    /** one child of the element at $path: the others removed; $value null: an empty element (<dynamic/>) */
    protected function editChoice( array $path, string $choice, ?string $value ): void
    {
        $node = $this->editNode( $path );
        foreach( iterator_to_array( $node->childNodes ) as $c )
            $node->removeChild( $c );
        $el = $node->ownerDocument->createElement( $choice );
        if( $value !== null )
            $el->appendChild( $node->ownerDocument->createTextNode( $value ) );
        $node->appendChild( $el );
    }

    /** the members of the element at $path */
    protected function editMembers( array $path, array $values ): void
    {
        $node = $this->editNode( $path );
        foreach( iterator_to_array( $node->childNodes ) as $c )
            $node->removeChild( $c );
        foreach( $values as $v )
        {
            $m = $node->ownerDocument->createElement( 'member' );
            $m->appendChild( $node->ownerDocument->createTextNode( (string)$v ) );
            $node->appendChild( $m );
        }
    }

    /** the members of the element at $path (empty: none) */
    protected function editMembersOf( array $path ): array
    {
        $node = $this->editFind( $path );
        $out = array();
        if( $node !== FALSE )
            foreach( $node->childNodes as $c )
                if( $c instanceof DOMElement && $c->nodeName === 'member' )
                    $out[] = trim( $c->textContent );
        return $out;
    }

    protected function editTextOf( array $path ): string
    {
        $node = $this->editFind( $path );
        return $node === FALSE ? '' : trim( $node->textContent );
    }

    /** the object of $name this one refers to, in its network scope (own location, template stack, SCM hierarchy) */
    protected function editLookup( ?string $storeProperty, string $name, string $findMethod )
    {
        return PH::findInNetworkScope( $this->owner->owner, $storeProperty, $name, $findMethod );
    }

    /** this object refers to $new instead of $old (each may be null) */
    protected function editSwapReference( $old, $new ): void
    {
        if( is_object( $old ) && $old !== $new )
            $old->removeReference( $this );
        if( is_object( $new ) )
            $new->addReference( $this );
    }

    /** a name of a profile / gateway / interface: no control characters, not empty */
    protected static function editName( string $name, string $what ): string
    {
        $name = trim( $name );
        if( $name === '' || strlen( $name ) > 63 || preg_match( '/[\x00-\x1F\x7F<>]/', $name ) )
            throw new Exception( $what . ": '" . $name . "' is not a valid name" );
        return $name;
    }

    /** a keyword (algorithm, DH group, …): lower case letters, digits, - */
    protected static function editKeyword( string $value, string $what ): string
    {
        $value = strtolower( trim( $value ) );
        if( !preg_match( '/^[a-z0-9][a-z0-9.-]{0,40}$/', $value ) )
            throw new Exception( $what . ": '" . $value . "' is not valid" );
        return $value;
    }

    /** a list of keywords separated by | or , (at least one) */
    protected static function editKeywords( $values, string $what ): array
    {
        $list = is_array( $values ) ? $values : preg_split( '/[|,]/', (string)$values );
        $out = array();
        foreach( $list as $v )
            if( trim( (string)$v ) !== '' )
                $out[] = self::editKeyword( (string)$v, $what );
        if( count( $out ) === 0 )
            throw new Exception( $what . ": at least one value" );
        return array_values( array_unique( $out ) );
    }

    protected static function editYesNo( $bool ): string
    {
        return $bool ? 'yes' : 'no';
    }

    /** lifetime / lifesize: one unit, a number in its range */
    protected function editAmount( array $path, string $unit, string $value, array $units, string $what ): void
    {
        $unit = strtolower( trim( $unit ) );
        if( !isset( $units[$unit] ) )
            throw new Exception( $what . ": unit one of " . implode( ', ', array_keys( $units ) ) );
        if( !preg_match( '/^[0-9]{1,8}$/', trim( $value ) ) || (int)$value < $units[$unit][0] || (int)$value > $units[$unit][1] )
            throw new Exception( $what . ": " . $unit . " " . $units[$unit][0] . "-" . $units[$unit][1] );
        $this->editChoice( $path, $unit, (string)(int)$value );
    }
}
