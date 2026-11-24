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

    // ---- name-rename (common action): the object, its store and every user (referencedObjectRenamed)

    /**
     * which users name an object of a class: class => array( XML tags below the user that hold the name, properties
     * of the user that keep it in memory )
     */
    static public function editRenameMap(): array
    {
        return array(
            'IkeCryptoProfil' => array( array( 'ike-crypto-profile' ), array( 'proposal' ) ),
            'IPSecCryptoProfil' => array( array( 'ipsec-crypto-profile' ), array( 'proposal' ) ),
            'IKEGateway' => array( array( 'ike-gateway' ), array( 'gateway' ) ),
            'InterfaceManagementProfile' => array( array( 'interface-management-profile' ), array( 'intMgmtProfile' ) ),
            'ZoneProtectionProfile' => array( array( 'zone-protection-profile' ), array( 'zoneProtectionProfile' ) ),
            'VirtualRouter' => array( array( 'next-vr' ), array( '_nexthopVR' ) ),
        );
    }

    /** the longest name PAN-OS takes for the object */
    protected function editNameMax(): int
    {
        foreach( array( 'IkeCryptoProfil', 'IPSecCryptoProfil', 'InterfaceManagementProfile', 'ZoneProtectionProfile', 'VirtualRouter', 'LogicalRouter',
                     'VirtualWire', 'GPPortal', 'GPGateway' ) as $c )
            if( $this instanceof $c )
                return 31;
        return 63;
    }

    /**
     * renames the object: its XML, the index of its store and every user that names it (XML and memory). Refused:
     * an invalid name, a name of another object of the same store.
     */
    public function editRename( string $new ): void
    {
        $new = trim( $new );
        $max = $this->editNameMax();
        // IKE gateway / IPsec tunnel: no space (PAN-OS)
        $space = ( $this instanceof IKEGateway || $this instanceof IPsecTunnel ) ? '' : ' ';
        if( !preg_match( '/^[0-9a-zA-Z][0-9a-zA-Z_.' . $space . '-]{0,' . ( $max - 1 ) . '}$/', $new ) )
            throw new Exception( "name '" . $new . "': up to " . $max . " characters - letters, digits, _ - ." . ( $space ? " and space" : "" ) . ", starting with a letter or digit" );
        if( $new === $this->name() )
            throw new Exception( "the name is " . $new . " already" );
        $siblings = array();
        if( isset( $this->owner ) && is_object( $this->owner ) )
        {
            if( method_exists( $this->owner, 'getAll' ) )
                $siblings = $this->owner->getAll();
            elseif( method_exists( $this->owner, 'staticRoutes' ) )
                $siblings = $this->owner->staticRoutes();
        }
        foreach( $siblings as $o )
            if( $o !== $this && is_object( $o ) && method_exists( $o, 'name' ) && $o->name() === $new )
                throw new Exception( "'" . $new . "' is the name of another " . get_class( $o ) . " here" );

        $old = $this->name();
        // pan-os-php: the store (index) and every referencing object are told (broadcastMyNameChange)
        $this->setRefName( $new );
        if( $this->xmlroot !== null )
            $this->xmlroot->setAttribute( 'name', $new );
        // a virtual router as next hop: also in the static routes of the other routers (not every one is a reference)
        if( $this instanceof VirtualRouter && $siblings !== array() )
            foreach( $siblings as $vr )
                if( method_exists( $vr, 'staticRoutes' ) )
                    foreach( $vr->staticRoutes() as $route )
                        if( method_exists( $route, 'editReferenceRenamed' ) )
                            $route->editReferenceRenamed( $this, $old );
    }

    /**
     * a referenced object of another class was renamed ($h, old name $old): the name in this object's XML (the tags
     * of editRenameMap: text, <member>, <entry name="">) and in its properties
     */
    public function editReferenceRenamed( $h, $old ): void
    {
        $map = null;
        foreach( self::editRenameMap() as $class => $m )
            if( $h instanceof $class )
                $map = $m;
        if( $map === null || !is_string( $old ) || $old === '' || $this->xmlroot === null )
            return;
        $new = $h->name();
        foreach( $map[0] as $tag )
            foreach( iterator_to_array( $this->xmlroot->getElementsByTagName( $tag ) ) as $node )
            {
                $children = 0;
                foreach( $node->childNodes as $c )
                    if( $c instanceof DOMElement )
                    {
                        $children++;
                        if( $c->nodeName === 'entry' && $c->getAttribute( 'name' ) === $old )
                            $c->setAttribute( 'name', $new );
                        elseif( $c->nodeName === 'member' && trim( $c->textContent ) === $old )
                            $c->textContent = $new;
                    }
                if( $children === 0 && trim( $node->textContent ) === $old )
                    $node->textContent = $new;
            }
        foreach( $map[1] as $prop )
            if( property_exists( $this, $prop ) && $this->$prop === $old )
                $this->$prop = $new;
    }
}
