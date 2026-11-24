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
 * Changes of a GlobalProtect portal / gateway (vsys): local interface, local IPv4 address, SSL/TLS service profile.
 * XML, object and references together; an invalid value: Exception.
 * The class has locationInterfaces(), $localAddress_interface, $localAddress_ipv4 and gpEditBase() (the path of
 * local-address / ssl-tls-service-profile below the entry: portal-config for a portal, the entry for a gateway).
 */
trait GlobalProtectObjectEdit
{
    use NetworkObjectEdit;

    /** an object of a store of the vsys, or of shared */
    protected function gpEditFind( string $store, string $name )
    {
        $vsys = $this->owner->owner;
        foreach( array( $vsys, isset( $vsys->owner ) ? $vsys->owner : null ) as $loc )
            if( is_object( $loc ) && isset( $loc->$store ) && is_object( $loc->$store ) )
            {
                $o = $loc->$store->find( $name );
                if( $o !== null && $o !== FALSE )
                    return $o;
            }
        return null;
    }

    public function editLocalInterface( string $interface ): void
    {
        $interface = self::editName( $interface, 'local interface' );
        $new = null;
        foreach( $this->locationInterfaces() as $if )
            if( $if->name() === $interface )
                $new = $if;
        if( $new === null )
            throw new Exception( "local interface '" . $interface . "' is not an interface of " . $this->owner->owner->name() );
        $old = null;
        foreach( $this->locationInterfaces() as $if )
            if( $if->name() === $this->localAddress_interface )
                $old = $if;
        $this->editText( array_merge( $this->gpEditBase(), array( 'local-address', 'interface' ) ), $interface );
        $this->editSwapReference( $old, $new );
        $this->localAddress_interface = $interface;
    }

    /** the local IPv4 address (address with mask or an address object); '' removes it */
    public function editLocalIp( string $ip ): void
    {
        $ip = trim( $ip );
        $path = array_merge( $this->gpEditBase(), array( 'local-address', 'ip', 'ipv4' ) );
        $old = $this->localAddress_ipv4 !== null ? $this->gpEditFind( 'addressStore', $this->localAddress_ipv4 ) : null;
        if( $ip === '' )
        {
            $this->editRemove( $path );
            $this->editSwapReference( $old, null );
            $this->localAddress_ipv4 = null;
            return;
        }
        if( strlen( $ip ) > 63 || preg_match( '/[\s<>:]/', $ip ) )
            throw new Exception( "local IP: an IPv4 address with mask, or an address object" );
        $this->editText( array_merge( $this->gpEditBase(), array( 'local-address', 'ip-address-family' ) ), 'ipv4' );
        $this->editText( $path, $ip );
        $this->editSwapReference( $old, $this->gpEditFind( 'addressStore', $ip ) );
        $this->localAddress_ipv4 = $ip;
    }

    /** the SSL/TLS service profile (of the vsys or shared, it must exist); '' removes it. No reference: as when loaded,
     *  the users of an SSL/TLS service profile are read from the XML (CertificateUsage) */
    public function editSslTlsProfile( string $profile ): void
    {
        $path = array_merge( $this->gpEditBase(), array( 'ssl-tls-service-profile' ) );
        if( trim( $profile ) === '' )
        {
            $this->editRemove( $path );
            return;
        }
        $profile = self::editName( $profile, 'SSL/TLS service profile' );
        if( $this->gpEditFind( 'SSL_TLSServiceProfileStore', $profile ) === null )
            throw new Exception( "SSL/TLS service profile '" . $profile . "' not found in " . $this->owner->owner->name() . " or shared" );
        $this->editText( $path, $profile );
    }
}
