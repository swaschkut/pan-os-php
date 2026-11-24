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
 * Changes of a tunnel object with a local interface and a tunnel interface (GRE tunnel, GlobalProtect gateway
 * tunnel): XML, the interface containers and the references together. An invalid value: Exception.
 * The class has $localInterface and $tunnelInterface (InterfaceContainer).
 */
trait TunnelObjectEdit
{
    use NetworkObjectEdit;

    /** an interface of the location / its scope (it must exist) */
    protected function editTunnelLookupInterface( string $interface, string $what )
    {
        $interface = self::editName( $interface, $what );
        $if = $this->editLookup( null, $interface, 'findInterface' );
        if( $if === null || $if === FALSE )
            throw new Exception( $what . " '" . $interface . "' not found in the location of the tunnel or above it" );
        return $if;
    }

    /** the container (local / tunnel interface) holds only $if */
    protected function editTunnelContainer( InterfaceContainer $c, $if ): void
    {
        foreach( $c->interfaces() as $old )
            $c->removeInterface( $old );
        $c->addInterface( $if );
    }

    public function editLocalInterface( string $interface ): void
    {
        $if = $this->editTunnelLookupInterface( $interface, 'local interface' );
        $this->editText( array( 'local-address', 'interface' ), $if->name() );
        $this->editTunnelContainer( $this->localInterface, $if );
    }

    public function editTunnelInterface( string $interface ): void
    {
        $if = $this->editTunnelLookupInterface( $interface, 'tunnel interface' );
        if( !( $if instanceof TunnelInterface ) )
            throw new Exception( "tunnel interface: '" . $if->name() . "' is not a tunnel interface" );
        $this->editText( array( 'tunnel-interface' ), $if->name() );
        $this->editTunnelContainer( $this->tunnelInterface, $if );
    }
}
