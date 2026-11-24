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
 * Changes of a virtual router / logical router (its VRF "default"): interfaces, ECMP, administrative distances, a new
 * static route. XML, object and references together (actions type=routing …).
 */
trait RouterObjectEdit
{
    use NetworkObjectEdit;

    /** the administrative distances PAN-OS keeps (admin-dists/<name>) */
    public static $ADMIN_DISTS = array( 'static', 'static-ipv6', 'ospf-int', 'ospf-ext', 'ospfv3-int', 'ospfv3-ext', 'ibgp', 'ebgp', 'rip' );

    /** a virtual router: its entry; a logical router: vrf/entry[@name='default'] */
    protected function routerBase(): DOMElement
    {
        if( $this instanceof LogicalRouter )
        {
            $vrf = DH::findFirstElementOrCreate( 'vrf', $this->xmlroot );
            return DH::findFirstElementByNameAttrOrCreate( 'entry', 'default', $vrf, $this->xmlroot->ownerDocument );
        }
        return $this->xmlroot;
    }

    public function editInterfaceAdd( string $interface ): void
    {
        $interface = self::editName( $interface, 'interface' );
        $if = $this->editLookup( null, $interface, 'findInterface' );
        if( $if === null )
            throw new Exception( "interface '" . $interface . "' not found in the location of the router or above it" );
        if( $this->attachedInterfaces->hasInterfaceNamed( $interface ) )
            throw new Exception( "interface " . $interface . " is in the router already" );
        if( isset( $this->owner ) && is_object( $this->owner ) && method_exists( $this->owner, 'getAll' ) )
            foreach( $this->owner->getAll() as $other )
                if( $other !== $this && isset( $other->attachedInterfaces ) && $other->attachedInterfaces->hasInterfaceNamed( $interface ) )
                    throw new Exception( "interface " . $interface . " is in router " . $other->name() . " - an interface is in one router" );
        if( $this->attachedInterfaces->xmlroot === null )
            $this->attachedInterfaces->load_from_domxml( DH::findFirstElementOrCreate( 'interface', $this->routerBase() ) );
        if( !$this->attachedInterfaces->addInterface( $if ) )
            throw new Exception( "interface " . $interface . " can not be added (aggregate group member?)" );
    }

    public function editInterfaceRemove( string $interface ): void
    {
        $interface = trim( $interface );
        foreach( $this->attachedInterfaces->interfaces() as $if )
            if( $if->name() === $interface )
            {
                $this->attachedInterfaces->removeInterface( $if );
                return;
            }
        throw new Exception( "interface " . $interface . " is not in the router" );
    }

    public function editEcmp( bool $enable ): void
    {
        $base = $this->routerBase();
        $node = DH::findFirstElementOrCreate( 'enable', DH::findFirstElementOrCreate( 'ecmp', $base ) );
        DH::setDomNodeText( $node, self::editYesNo( $enable ) );
    }

    /** administrative distance of a route type: 10-240 ('' removes it: default) */
    public function editAdminDistance( string $type, string $value ): void
    {
        $type = strtolower( trim( $type ) );
        if( !in_array( $type, self::$ADMIN_DISTS, TRUE ) )
            throw new Exception( "route type: one of " . implode( ', ', self::$ADMIN_DISTS ) );
        $base = $this->routerBase();
        $dists = DH::findFirstElementOrCreate( 'admin-dists', $base );
        $node = DH::findFirstElement( $type, $dists );
        if( trim( $value ) === '' )
        {
            if( $node !== FALSE )
                $dists->removeChild( $node );
            return;
        }
        if( !preg_match( '/^[0-9]{1,3}$/', trim( $value ) ) || (int)$value < 10 || (int)$value > 240 )
            throw new Exception( "administrative distance: 10-240" );
        DH::setDomNodeText( $node !== FALSE ? $node : DH::findFirstElementOrCreate( $type, $dists ), (string)(int)$value );
    }

    /** a new IPv4 static route: name, destination, next hop (ip-address / next-vr / discard / none), interface, metric */
    public function editStaticRouteAdd( string $name, string $destination, string $nexthopType, string $nexthop = '', string $interface = '', string $metric = '' ): StaticRoute
    {
        $name = self::editName( $name, 'static route' );
        foreach( $this->staticRoutes() as $r )
            if( $r->name() === $name )
                throw new Exception( "static route '" . $name . "' exists" );
        // built apart, then added by addstaticRoute() at the place of the router (logical router: below its VRF)
        $entry = $this->xmlroot->ownerDocument->createElement( 'entry' );
        $entry->setAttribute( 'name', $name );
        $route = new StaticRoute( $name, $this );
        $route->xmlroot = $entry;
        $route->editDestination( $destination );
        $route->editNexthop( $nexthopType, $nexthop );
        if( trim( $interface ) !== '' )
            $route->editInterface( $interface );
        $route->editMetric( trim( $metric ) === '' ? '10' : $metric );
        $route->load_from_xml( $entry );
        $this->addstaticRoute( $route );
        return $route;
    }
}
