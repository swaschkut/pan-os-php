<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
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

class DHCP
{
    use XmlConvertible;
    use PathableName;
    use ReferenceableObject;
    use NetworkObjectEdit;

    /** @var DHCPStore */
    public $owner;
    public $server_leases = array();
    public $server_ip_pool = array();
    public $relay_ipv4 = array();
    public $relay_ipv6 = array();
    public $relay_ipv4_status = false;
    public $relay_ipv6_status = false;

    /**
     * @param $name string
     * @param $owner DHCPStore
     */
    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
    }

    /**
     * @param DOMElement $xml
     */
    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("DHCP name not found\n");

        #$interface = $this->owner->owner->network->findInterface( $this->name );
        $interface = $this->owner->owner->network->findInterfaceOrCreateTmp( $this->name );
        if( $interface !==  null )
            $interface->addReference( $this );
        else
            mwarning( "interface with name: ".$this->name." can not be found for DHCP: ".$this->name." | ".$this->owner->owner->_PANC_shortName(), null, FALSE );

        ///todo: update interface list - to correctly show all interfaces

        $tmp_server = DH::findFirstElement("server", $xml);
        if( $tmp_server !== false )
        {
            $tmp_reserved = DH::findFirstElement("reserved", $tmp_server);
            if( $tmp_reserved !== false )
            {
                foreach( $tmp_reserved->childNodes as $entry )
                {
                    if( $entry->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_IP = DH::findAttribute('name', $entry);
                    $tmp_mac_xml = DH::findFirstElement("mac", $entry);
                    if( $tmp_mac_xml !== False )
                    {
                        $tmp_mac = $tmp_mac_xml->textContent;

                        $this->server_leases[] = array( 'ip' => $tmp_IP, 'mac' => $tmp_mac );
                    }
                }
            }

            $tmp_ip_pool = DH::findFirstElement("ip-pool", $tmp_server);
            if( $tmp_ip_pool !== false )
            {
                foreach( $tmp_ip_pool->childNodes as $entry )
                {
                    if( $entry->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $this->server_ip_pool[] = $entry->textContent;
                }
            }
                /*
              <option>
               <lease>
                <unlimited/>
               </lease>
              </option>
              <mode>auto</mode>
             */
        }
        $tmp_relay = DH::findFirstElement("relay", $xml);
        if( $tmp_relay !== false )
        {
            $tmp_relay_ipv4 = DH::findFirstElement("ip", $tmp_relay);
            if( $tmp_relay_ipv4 !== false )
            {
                $tmp_enabled = DH::findFirstElement("enabled", $tmp_relay_ipv4);
                if( $tmp_enabled->textContent == "yes" )
                    $this->relay_ipv4_status = true;

                $tmp_server = DH::findFirstElement("server", $tmp_relay_ipv4);
                if( $tmp_server !== false )
                {
                    foreach( $tmp_server->childNodes as $entry )
                    {
                        if( $entry->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $this->relay_ipv4[] = $entry->textContent;
                    }
                }
            }
            $tmp_relay_ipv6 = DH::findFirstElement("ipv6", $tmp_relay);
            if( $tmp_relay_ipv6 !== false )
            {
                $tmp_enabled = DH::findFirstElement("enabled", $tmp_relay_ipv6);
                if( $tmp_enabled->textContent == "yes" )
                    $this->relay_ipv6_status = true;

                $tmp_server = DH::findFirstElement("server", $tmp_relay_ipv6);
                if( $tmp_server !== false )
                {
                    foreach( $tmp_server->childNodes as $entry )
                    {
                        if( $entry->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $this->relay_ipv6[] = $entry->textContent;
                    }
                }
            }
        }
    }

    /**
     * return true if change was successful false if not
     * @param string $name new name for the VirtualRouter
     * @return bool
     */
    // ---- changes of the actions (dhcp …-set): XML and object together; an invalid value: Exception

    /** an IPv4 address (or a network / range for an IP pool) - no spaces, no ":" */
    private static function editDhcpValue( string $v, string $what ): string
    {
        $v = trim( $v );
        if( $v === '' || strlen( $v ) > 63 || preg_match( '/[\s<>:]/', $v ) )
            throw new Exception( $what . ": an IPv4 value" );
        return $v;
    }

    /** DHCP server mode: auto, enabled, disabled */
    public function editServerMode( string $mode ): void
    {
        $mode = strtolower( trim( $mode ) );
        if( !in_array( $mode, array( 'auto', 'enabled', 'disabled' ), TRUE ) )
            throw new Exception( "mode: auto, enabled or disabled" );
        if( $this->editFind( array( 'relay' ) ) !== FALSE )
            throw new Exception( "the interface is a DHCP relay - not a server" );
        $this->editText( array( 'server', 'mode' ), $mode );
    }

    public function editIpPoolAdd( string $pool ): void
    {
        $pool = self::editDhcpValue( $pool, 'IP pool' );
        $members = $this->editMembersOf( array( 'server', 'ip-pool' ) );
        if( in_array( $pool, $members, TRUE ) )
            throw new Exception( "IP pool " . $pool . " is there already" );
        $members[] = $pool;
        $this->editMembers( array( 'server', 'ip-pool' ), $members );
        $this->server_ip_pool = $members;
    }

    public function editIpPoolRemove( string $pool ): void
    {
        $pool = trim( $pool );
        $members = $this->editMembersOf( array( 'server', 'ip-pool' ) );
        if( !in_array( $pool, $members, TRUE ) )
            throw new Exception( "IP pool " . $pool . " is not there" );
        $members = array_values( array_diff( $members, array( $pool ) ) );
        if( count( $members ) === 0 )
            $this->editRemove( array( 'server', 'ip-pool' ) );
        else
            $this->editMembers( array( 'server', 'ip-pool' ), $members );
        $this->server_ip_pool = $members;
    }

    /** an option: gateway, subnet-mask ('' removes it) */
    public function editOption( string $option, string $value ): void
    {
        if( !in_array( $option, array( 'gateway', 'subnet-mask' ), TRUE ) )
            throw new Exception( "option: gateway or subnet-mask" );
        if( trim( $value ) === '' )
            $this->editRemove( array( 'server', 'option', $option ) );
        else
            $this->editText( array( 'server', 'option', $option ), self::editDhcpValue( $value, $option ) );
    }

    /** DNS servers: primary, secondary ('' removes one) */
    public function editDns( string $primary, string $secondary = '' ): void
    {
        foreach( array( 'primary' => $primary, 'secondary' => $secondary ) as $k => $v )
            if( trim( $v ) === '' )
                $this->editRemove( array( 'server', 'option', 'dns', $k ) );
            else
                $this->editText( array( 'server', 'option', 'dns', $k ), self::editDhcpValue( $v, 'DNS ' . $k ) );
    }

    /** lease: unlimited, or timeout in minutes (0-1000000) */
    public function editLease( string $type, string $minutes = '' ): void
    {
        $type = strtolower( trim( $type ) );
        if( $type === 'unlimited' )
            $this->editChoice( array( 'server', 'option', 'lease' ), 'unlimited', null );
        elseif( $type === 'timeout' )
        {
            if( !preg_match( '/^[0-9]{1,7}$/', trim( $minutes ) ) || (int)$minutes > 1000000 )
                throw new Exception( "lease timeout: minutes 0-1000000" );
            $this->editChoice( array( 'server', 'option', 'lease' ), 'timeout', (string)(int)$minutes );
        }
        else
            throw new Exception( "lease: unlimited or timeout" );
    }

    /** a reserved address: IP and MAC */
    public function editReservationAdd( string $ip, string $mac, string $description = '' ): void
    {
        $ip = self::editDhcpValue( $ip, 'reserved IP' );
        $mac = strtolower( trim( $mac ) );
        if( !preg_match( '/^([0-9a-f]{2}[.-]){5}[0-9a-f]{2}$/', $mac ) )
            throw new Exception( "MAC: e.g. 00-11-22-33-44-55 (- or . between the bytes; \":\" can not be used in an action argument)" );
        $mac = str_replace( array( '-', '.' ), ':', $mac );
        $node = $this->editNode( array( 'server', 'reserved' ) );
        if( DH::findFirstElementByNameAttr( 'entry', $ip, $node ) !== null )
            throw new Exception( "reserved IP " . $ip . " is there already" );
        $e = $node->ownerDocument->createElement( 'entry' );
        $e->setAttribute( 'name', $ip );
        $node->appendChild( $e );
        DH::createElement( $e, 'mac', $mac );
        if( trim( $description ) !== '' )
            DH::createElement( $e, 'description', trim( $description ) );
        $this->server_leases[] = array( 'ip' => $ip, 'mac' => $mac );
    }

    public function editReservationRemove( string $ip ): void
    {
        $ip = trim( $ip );
        $node = $this->editFind( array( 'server', 'reserved' ) );
        $e = $node !== FALSE ? DH::findFirstElementByNameAttr( 'entry', $ip, $node ) : null;
        if( $e === null )
            throw new Exception( "reserved IP " . $ip . " is not there" );
        $node->removeChild( $e );
        if( !$node->hasChildNodes() )
            $node->parentNode->removeChild( $node );
        $this->server_leases = array_values( array_filter( $this->server_leases, function( $l ) use ( $ip ) { return $l['ip'] !== $ip; } ) );
    }

    /** DHCP relay (IPv4): on / off */
    public function editRelay( bool $enable ): void
    {
        if( $this->editFind( array( 'server' ) ) !== FALSE )
            throw new Exception( "the interface is a DHCP server - not a relay" );
        $this->editText( array( 'relay', 'ip', 'enabled' ), self::editYesNo( $enable ) );
        $this->relay_ipv4_status = $enable;
    }

    public function editRelayServerAdd( string $server ): void
    {
        if( $this->editFind( array( 'server' ) ) !== FALSE )
            throw new Exception( "the interface is a DHCP server - not a relay" );
        $server = self::editDhcpValue( $server, 'relay server' );
        $members = $this->editMembersOf( array( 'relay', 'ip', 'server' ) );
        if( in_array( $server, $members, TRUE ) )
            throw new Exception( "relay server " . $server . " is there already" );
        $members[] = $server;
        $this->editMembers( array( 'relay', 'ip', 'server' ), $members );
        $this->relay_ipv4 = $members;
    }

    public function editRelayServerRemove( string $server ): void
    {
        $server = trim( $server );
        $members = $this->editMembersOf( array( 'relay', 'ip', 'server' ) );
        if( !in_array( $server, $members, TRUE ) )
            throw new Exception( "relay server " . $server . " is not there" );
        $members = array_values( array_diff( $members, array( $server ) ) );
        $this->editMembers( array( 'relay', 'ip', 'server' ), $members );
        $this->relay_ipv4 = $members;
    }

    public function setName($name)
    {
        if( $this->name == $name )
            return TRUE;

        if( $this->name != "**temporarynamechangeme**" )
            $this->setRefName($name);

        $this->name = $name;

        $this->xmlroot->setAttribute('name', $name);

        return TRUE;
    }


    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getDHCPStoreXPath() . "/entry[@name='" . $this->name . "']";

        if( $this->owner->owner->owner !== null && get_class( $this->owner->owner->owner ) == "Template" )
        {
            $templateXpath = $this->owner->owner->owner->getXPath();
            $str = $templateXpath.$str;
        }


        return $str;
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**"><relay></relay></entry>';

}