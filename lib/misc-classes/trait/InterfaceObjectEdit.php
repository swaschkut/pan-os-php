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
 * Changes of an interface (ethernet / aggregate - layer3 and their sub-interfaces -, loopback, tunnel, VLAN): comment,
 * IPv4 addresses, MTU, interface management profile, adjust TCP MSS, link state, VLAN tag. XML, object and references
 * together (actions type=interface …-set / ip-add / ip-remove).
 */
trait InterfaceObjectEdit
{
    use NetworkObjectEdit;

    /** ethernet / aggregate main interface: the settings are below <layer3>; every other one: below its entry */
    protected function editL3Path(): array
    {
        if( $this instanceof EthernetInterface && !$this->isSubInterface() )
        {
            if( $this->type() !== 'layer3' )
                throw new Exception( "the interface is " . $this->type() . " - only a layer3 interface has these settings" );
            return array( 'layer3' );
        }
        return array();
    }

    /** the IPv4 list of the object (ethernet / aggregate: l3ipv4Addresses, the others: _ipv4Addresses) */
    private function &editIpList(): array
    {
        if( property_exists( $this, 'l3ipv4Addresses' ) && $this instanceof EthernetInterface )
        {
            if( !is_array( $this->l3ipv4Addresses ) )
                $this->l3ipv4Addresses = array();
            return $this->l3ipv4Addresses;
        }
        if( !is_array( $this->_ipv4Addresses ) )
            $this->_ipv4Addresses = array();
        return $this->_ipv4Addresses;
    }

    public function editComment( string $comment ): void
    {
        $comment = trim( $comment );
        if( strlen( $comment ) > 1023 || preg_match( '/[\x00-\x08\x0B-\x1F]/', $comment ) )
            throw new Exception( "comment: up to 1023 characters" );
        if( $comment === '' )
            $this->editRemove( array( 'comment' ) );
        else
            $this->editText( array( 'comment' ), $comment );
        if( property_exists( $this, '_description' ) )
            $this->_description = $comment;
    }

    /** an IPv4 address with mask (or an address object) */
    public function editIpAdd( string $ip ): void
    {
        $ip = trim( $ip );
        if( $ip === '' || strlen( $ip ) > 255 || preg_match( '/[\s<>]/', $ip ) )
            throw new Exception( "IP: an IPv4 address with mask (or an address object)" );
        $node = $this->editNode( array_merge( $this->editL3Path(), array( 'ip' ) ) );
        foreach( $node->childNodes as $c )
            if( $c instanceof DOMElement && $c->getAttribute( 'name' ) === $ip )
                throw new Exception( "IP " . $ip . " is set already" );
        $e = $node->ownerDocument->createElement( 'entry' );
        $e->setAttribute( 'name', $ip );
        $node->appendChild( $e );
        $list = &$this->editIpList();
        $list[] = $ip;
    }

    public function editIpRemove( string $ip ): void
    {
        $ip = trim( $ip );
        $node = $this->editFind( array_merge( $this->editL3Path(), array( 'ip' ) ) );
        if( $node !== FALSE )
            foreach( $node->childNodes as $c )
                if( $c instanceof DOMElement && $c->getAttribute( 'name' ) === $ip )
                {
                    $node->removeChild( $c );
                    if( !$node->hasChildNodes() )
                        $node->parentNode->removeChild( $node );
                    $list = &$this->editIpList();
                    $list = array_values( array_filter( $list, function( $x ) use ( $ip ) { return $x !== $ip; } ) );
                    return;
                }
        throw new Exception( "IP " . $ip . " is not set" );
    }

    /** MTU 576-9216; '' removes it (default) */
    public function editMtu( string $mtu ): void
    {
        $mtu = trim( $mtu );
        $path = array_merge( $this->editL3Path(), array( 'mtu' ) );
        if( $mtu === '' )
        {
            $this->editRemove( $path );
            return;
        }
        if( !preg_match( '/^[0-9]{3,4}$/', $mtu ) || (int)$mtu < 576 || (int)$mtu > 9216 )
            throw new Exception( "MTU: 576-9216" );
        $this->editText( $path, (string)(int)$mtu );
    }

    /** the interface management profile - it must exist in the location / its scope; '' removes it */
    public function editManagementProfile( string $profile ): void
    {
        $profile = trim( $profile );
        $path = array_merge( $this->editL3Path(), array( 'interface-management-profile' ) );
        $oldName = $this->editTextOf( $path );
        $old = $oldName !== '' ? $this->editLookup( 'interfaceManagementProfileStore', $oldName, 'find' ) : null;
        $new = null;
        if( $profile === '' )
            $this->editRemove( $path );
        else
        {
            $profile = self::editName( $profile, 'interface management profile' );
            $new = $this->editLookup( 'interfaceManagementProfileStore', $profile, 'find' );
            if( $new === null )
                throw new Exception( "interface management profile '" . $profile . "' not found in the location of the interface or above it" );
            $this->editText( $path, $profile );
        }
        $this->editSwapReference( $old, $new );
        if( property_exists( $this, 'intMgmtProfile' ) )
        {
            $this->intMgmtProfile = $profile === '' ? null : $profile;
            $this->intMgmtProfileObj = $new;
        }
    }

    public function editAdjustTcpMss( bool $enable ): void
    {
        $this->editText( array_merge( $this->editL3Path(), array( 'adjust-tcp-mss', 'enable' ) ), self::editYesNo( $enable ) );
    }

    /** link state of an ethernet / aggregate main interface: auto, up, down */
    public function editLinkState( string $state ): void
    {
        $state = strtolower( trim( $state ) );
        if( !( $this instanceof EthernetInterface ) || $this->isSubInterface() )
            throw new Exception( "link state: only an ethernet / aggregate interface (not a sub-interface)" );
        if( !in_array( $state, array( 'auto', 'up', 'down' ), TRUE ) )
            throw new Exception( "link state: auto, up or down" );
        $this->editText( array( 'link-state' ), $state );
        $this->linkstate = $state;
    }

    /** VLAN tag of a sub-interface: 1-4094 */
    public function editTag( string $tag ): void
    {
        $tag = trim( $tag );
        if( !( $this instanceof EthernetInterface ) || !$this->isSubInterface() )
            throw new Exception( "tag: only a sub-interface" );
        if( !preg_match( '/^[0-9]{1,4}$/', $tag ) || (int)$tag < 1 || (int)$tag > 4094 )
            throw new Exception( "tag: 1-4094" );
        $this->editText( array( 'tag' ), (string)(int)$tag );
        $this->tag = (string)(int)$tag;
    }
}
