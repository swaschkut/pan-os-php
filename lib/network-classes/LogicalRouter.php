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

class LogicalRouter
{
    use XmlConvertible;
    use PathableName;
    use ReferenceableObject;

    /** @var LogicalRouterStore */
    public $owner;

    /** @var StaticRoute[] */
    protected $_staticRoutes = array();

    /** @var InterfaceContainer */
    public $attachedInterfaces;

    public $routingProtocols = array();

    protected $xmlroot_protocol = false;

    protected $xmlroot_vrf = false;

    protected $fastMemToIndex;
    protected $fastNameToIndex;

    /**
     * @param $name string
     * @param $owner LogicalRouterStore
     */
    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;

        $this->attachedInterfaces = new InterfaceContainer($this, $owner->owner->network);
    }

    /**
     * @param DOMElement $xml
     */
    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("logical-router name not found\n");

        $this->xmlroot_vrf = DH::findFirstElement('vrf', $xml);
        if(  $this->xmlroot_vrf !== False )
        {
            $entry_default = DH::findFirstElementByNameAttr( "entry", "default", $this->xmlroot_vrf);

            $node = FALSE;
            $tmp_routing_table = DH::findFirstElement('routing-table', $entry_default);
            if( $tmp_routing_table !== FALSE )
            {
                $tmp_ip = DH::findFirstElement('ip', $tmp_routing_table);
                if( $tmp_ip !== FALSE )
                {
                    $tmp_static_route = DH::findFirstElement('static-route', $tmp_ip);
                    if( $tmp_static_route !== FALSE )
                        $node = DH::findXPath('/entry', $tmp_static_route);

                    if( $node !== FALSE )
                    {
                        for( $i = 0; $i < $node->length; $i++ )
                        {
                            $newRoute = new StaticRoute('***tmp**', $this);
                            $newRoute->load_from_xml($node->item($i));
                            $this->_staticRoutes[] = $newRoute;

                            $ser = spl_object_hash($newRoute);

                            $this->fastMemToIndex[$ser] = $newRoute;
                            $this->fastNameToIndex[$newRoute->name()] = $newRoute;
                        }
                    }
                }

                $tmp_ipv6 = DH::findFirstElement('ipv6', $tmp_routing_table);
                if( $tmp_ipv6 !== FALSE )
                {
                    $tmp_static_route = DH::findFirstElement('static-route', $tmp_ipv6);
                    if( $tmp_static_route !== FALSE )
                        $node = DH::findXPath('/entry', $tmp_static_route);

                    if( $node !== FALSE )
                    {
                        for( $i = 0; $i < $node->length; $i++ )
                        {
                            $newRoute = new StaticRoute('***tmp**', $this);
                            $newRoute->load_from_xml($node->item($i));
                            $this->_staticRoutes[] = $newRoute;
                        }
                    }
                }
            }

            $node = DH::findFirstElementOrCreate('interface', $entry_default);

            $this->attachedInterfaces->load_from_domxml($node);


            $tmp_routing_protocolls = array("multicast", "ecmp", "bgp", "ospfv3", "rip", "ospf" );
            foreach( $tmp_routing_protocolls as $protocoll )
            {
                $node = DH::findFirstElement( $protocoll, $entry_default);
                if( $node !== FALSE )
                {
                    $tmpProtocolName = $node->nodeName;
                    $this->routingProtocols[$tmpProtocolName] = array();

                    $protocolEnabled = DH::findFirstElement("enable", $node);
                    if( $protocolEnabled !== FALSE )
                        $this->routingProtocols[$tmpProtocolName]['enabled'] = $protocolEnabled->textContent;


                    if( $protocoll == "bgp" )
                    {
                        $tmp_peer_group = DH::findFirstElement('peer-group', $node);
                        if(  $tmp_peer_group !== False )
                        {
                            foreach( $tmp_peer_group->childNodes as $node )
                            {
                                if ($node->nodeType != XML_ELEMENT_NODE)
                                    continue;

                                $tmp_peer_node = DH::findFirstElement('peer', $node);
                                if(  $tmp_peer_node !== False )
                                {
                                    foreach ($tmp_peer_node->childNodes as $node2)
                                    {
                                        if ($node2->nodeType != XML_ELEMENT_NODE)
                                            continue;

                                        $tmp_peer_address_node = DH::findFirstElement('peer-address', $node2);
                                        if ($tmp_peer_address_node != null)
                                        {
                                            $peerAddressNode = DH::findFirstElement('ip', $tmp_peer_address_node);
                                            if ($peerAddressNode != null) {
                                                #$this->peerAddress = $peerAddressNode->textContent;
                                                $this->validateIPorObject($peerAddressNode->textContent, $type = 'peer-address');
                                            }
                                        }

                                        $tmp_local_address_node = DH::findFirstElement('local-address', $node2);
                                        if ($tmp_local_address_node != null)
                                        {
                                            $localAddressNode = DH::findFirstElement('ip', $tmp_local_address_node);
                                            if ($localAddressNode != null)
                                            {
                                                #$this->localAddress = $localAddressNode->textContent;
                                                $this->validateIPorObject($localAddressNode->textContent, $type = 'local-address');
                                            }
                                            $localInterfaceNode = DH::findFirstElement('interface', $tmp_local_address_node);
                                            if ($localInterfaceNode != null)
                                            {
                                                $tmp_interface = $this->owner->owner->network->findInterfaceOrCreateTmp($localInterfaceNode->textContent);
                                                $tmp_interface->addReference($this);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    elseif( $protocoll == "rip" )
                    {
                        $tmp_interface_node = DH::findFirstElement('interface', $node);
                        if( $tmp_interface_node !== False )
                        {
                            foreach( $tmp_interface_node->childNodes as $interface_entry )
                            {
                                if ($interface_entry->nodeType != XML_ELEMENT_NODE)
                                    continue;

                                $interface_name = DH::findAttribute('name', $interface_entry);
                                $tmp_interface = $this->owner->owner->network->findInterfaceOrCreateTmp($interface_name);
                                $tmp_interface->addReference($this);
                            }
                        }
                    }
                    elseif( $protocoll == "ospf" || $protocoll == "ospfv3" )
                    {
                        $tmp_area = DH::findFirstElement('area', $node);
                        if( $tmp_area !== False )
                        {
                            foreach( $tmp_area->childNodes as $area_entry )
                            {
                                if ($area_entry->nodeType != XML_ELEMENT_NODE)
                                    continue;

                                $tmp_interface_node = DH::findFirstElement('interface', $area_entry);
                                if( $tmp_interface_node !== False )
                                {
                                    foreach ($tmp_interface_node->childNodes as $interface_entry)
                                    {
                                        if ($interface_entry->nodeType != XML_ELEMENT_NODE)
                                            continue;

                                        $interface_name = DH::findAttribute('name', $interface_entry);
                                        $tmp_interface = $this->owner->owner->network->findInterfaceOrCreateTmp($interface_name);
                                        $tmp_interface->addReference($this);
                                    }
                                }
                            }
                        }
                    }

                    elseif( $protocoll == "multicast")
                    {

                        foreach( $node->childNodes as $multicast_type_node )
                        {
                            if ($multicast_type_node->nodeType != XML_ELEMENT_NODE)
                                continue;

                            $nodeName = $multicast_type_node->nodeName;
                            if( $nodeName == "pim" )
                            {
                                $tmp_interface_node = DH::findFirstElement('interface', $multicast_type_node);
                                if($tmp_interface_node !== False )
                                {
                                    foreach( $tmp_interface_node->childNodes as $interface_entry )
                                    {
                                        if ($interface_entry->nodeType != XML_ELEMENT_NODE)
                                            continue;

                                        $interface_name = DH::findAttribute('name', $interface_entry);
                                        $tmp_interface = $this->owner->owner->network->findInterfaceOrCreateTmp($interface_name);
                                        $tmp_interface->addReference($this);
                                    }
                                }
                            }
                            elseif( $nodeName == "igmp" )
                            {
                                $tmp_dynamic_node = DH::findFirstElement('dynamic', $multicast_type_node);
                                if( $tmp_dynamic_node !== False )
                                {
                                    $tmp_interface_node = DH::findFirstElement('interface', $tmp_dynamic_node);
                                    if( $tmp_interface_node !== False )
                                    {
                                        foreach ($tmp_interface_node->childNodes as $interface_entry)
                                        {
                                            if ($interface_entry->nodeType != XML_ELEMENT_NODE)
                                                continue;

                                            $interface_name = DH::findAttribute('name', $interface_entry);
                                            $tmp_interface = $this->owner->owner->network->findInterfaceOrCreateTmp($interface_name);
                                            $tmp_interface->addReference($this);
                                        }
                                    }
                                }
                            }
                            elseif( $nodeName == "static-route" )
                            {
                                foreach ($multicast_type_node->childNodes as $static_route_entry)
                                {
                                    if ($static_route_entry->nodeType != XML_ELEMENT_NODE)
                                        continue;

                                    $tmp_interface_node = DH::findFirstElement('interface', $static_route_entry);
                                    if( $tmp_interface_node !== False )
                                    {
                                        $interface_name = $tmp_interface_node->textContent;
                                        $tmp_interface = $this->owner->owner->network->findInterfaceOrCreateTmp($interface_name);
                                        $tmp_interface->addReference($this);
                                    }
                                    $tmp_destination_node = DH::findFirstElement('destination', $static_route_entry);
                                    if( $tmp_destination_node !== False )
                                    {
                                        $this->validateIPorObject($tmp_destination_node->textContent, $type = 'destination');
                                    }
                                }
                            }
                        }
                    }
                    elseif( $protocoll == "ecmp" )
                    {

                    }
                }
            }
        }
    }

    /**
     * return true if change was successful false if not
     * @param string $name new name for the LogicalRouter
     * @return bool
     */
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
     * @return StaticRoute[]
     */
    public function staticRoutes()
    {
        return $this->_staticRoutes;
    }

    /**
     * @return int
     */
    public function count()
    {
        return count($this->_staticRoutes);
    }

    public function addstaticRoute($staticRoute, $version = 'ip')
    {
        if( !is_object($staticRoute) )
            derr('this function only accepts staticRoute class objects');

        /** @var StaticRoute $staticRoute*/
        $destination = $staticRoute->destination();
        //Todo: nexthop would be also good, but it could be that nexthop is "" than $interface ip-address must be used for IP check
        $checkIP = explode( "/", $destination);
        if(filter_var($checkIP[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))
            $version = 'ip';
        elseif(filter_var($checkIP[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
            $version = 'ipv6';


        #if( $staticRoute->owner !== null )
        #    derr('Trying to add a logicalRouter that has a owner already !');

        $this->_staticRoutes[] = $staticRoute;

        $ser = spl_object_hash($staticRoute);

        if( !isset($this->fastMemToIndex[$ser]) )
        {
            $staticRoute->owner = $this;

            $this->fastMemToIndex[$ser] = $staticRoute;
            $this->fastNameToIndex[$staticRoute->name()] = $staticRoute;

            if( $this->xmlroot === null )
                $this->createXmlRoot();

            $tmp_routing_table = DH::findFirstElementOrCreate('routing-table', $this->xmlroot);
            if( $tmp_routing_table !== FALSE )
            {
                $tmp_ip = DH::findFirstElementOrCreate($version, $tmp_routing_table);
                if( $tmp_ip !== FALSE )
                {
                    $tmp_static_route = DH::findFirstElementOrCreate('static-route', $tmp_ip);
                    if( $tmp_static_route !== FALSE )
                        #$node = DH::findXPath('/entry', $tmp_static_route );//find routing/table -> static route
                        $tmp_static_route->appendChild($staticRoute->xmlroot);
                }
            }


            return TRUE;
        }
        else
            derr('You cannot add a logicalRouter that is already here :)');

        return FALSE;
    }

    /**
     * @param StaticRoute $s
     * @param bool $cleanInMemory
     * @return bool
     */
    public function removeStaticRoute($staticRoute, $cleanInMemory = FALSE)
    {
        $class = get_class($staticRoute);

        $objectName = $staticRoute->name();


        if( !isset($this->fastNameToIndex[$staticRoute->name()]) )
        {
            mwarning('Tried to remove an object that is not part of this store', null, false);
            return FALSE;
        }

        unset($this->fastNameToIndex[$staticRoute->name()]);

        $staticRoute->owner = null;

        $version = "ip";

        $tmp_routing_table = DH::findFirstElementOrCreate('routing-table', $this->xmlroot);
        if( $tmp_routing_table !== FALSE )
        {
            $tmp_ip = DH::findFirstElementOrCreate($version, $tmp_routing_table);
            if( $tmp_ip !== FALSE )
            {
                $tmp_static_route = DH::findFirstElementOrCreate('static-route', $tmp_ip);
                if( $tmp_static_route !== FALSE )
                    $tmp_static_route->removeChild($staticRoute->xmlroot);
            }
        }


        if( $cleanInMemory )
            $staticRoute->xmlroot = null;

        return TRUE;
    }

    /**
     * @return LogicalSystem[]
     */
    public function &findConcernedVsys()
    {
        $vsysList = array();
        foreach( $this->attachedInterfaces->interfaces() as $if )
        {
            $vsys = $this->owner->owner->network->findVsysInterfaceOwner($if->name());
            if( $vsys !== null )
                $vsysList[$vsys->name()] = $vsys;
        }

        return $vsysList;
    }


    /**
     * @param $contextVSYS LogicalSystem
     * @param $orderByNarrowest bool
     * @return array
     */
    public function getIPtoZoneRouteMapping($contextVSYS, $orderByNarrowest = TRUE, $loopFilter = null)
    {
        $ipv4 = array();
        $ipv6 = array();

        $ipv4sort = array();

        if( $loopFilter === null )
        {
            $loopFilter = array();
        }

        $loopFilter[$this->name()][$contextVSYS->name()] = TRUE;


        foreach( $this->attachedInterfaces->interfaces() as $if )
        {
            if( !$contextVSYS->importedInterfaces->hasInterfaceNamed($if->name()) )
                continue;

            if( ($if->isEthernetType() || $if->isAggregateType()) && $if->type() == 'layer3' )
            {
                $findZone = $contextVSYS->zoneStore->findZoneMatchingInterfaceName($if->name());
                if( $findZone === null )
                    continue;

                #$ipAddresses = $if->getLayer3IPv4Addresses();
                $ipAddresses = $if->getLayer3IPAddresses();

                foreach( $ipAddresses as $interfaceIP )
                {
                    $address_object = $contextVSYS->addressStore->find($interfaceIP);
                    if( $address_object != null )
                        $interfaceIP = $address_object->value();

                    $ipv4Mapping = cidr::stringToStartEnd($interfaceIP);
                    $record = array('network' => $interfaceIP, 'start' => $ipv4Mapping['start'], 'end' => $ipv4Mapping['end'], 'zone' => $findZone->name(), 'origin' => 'connected', 'priority' => 1);
                    //Todo: int working well for IPv4; IPv6 is float
                    #$ipv4sort[$record['end'] - $record['start']][$record['start']][] = &$record;
                    $this->IPvalidation64bit( $ipv4sort, $record );
                    unset($record);
                }
            }
            elseif( $if->isLoopbackType() || $if->isTunnelType() || $if->isVlanType() )
            {
                $findZone = $contextVSYS->zoneStore->findZoneMatchingInterfaceName($if->name());
                if( $findZone === null )
                    continue;

                //should be already IPv4 and IPv6
                $ipAddresses = $if->getIPv4Addresses();

                foreach( $ipAddresses as $interfaceIP )
                {
                    if( strpos($interfaceIP, "/") === FALSE )
                    {
                        $object = $contextVSYS->addressStore->find($interfaceIP);
                        if( $object != null )
                            $interfaceIP = $object->value();
                    }

                    $ipv4Mapping = cidr::stringToStartEnd($interfaceIP);
                    $record = array('network' => $interfaceIP, 'start' => $ipv4Mapping['start'], 'end' => $ipv4Mapping['end'], 'zone' => $findZone->name(), 'origin' => 'connected', 'priority' => 1);
                    //Todo: int working well for IPv4; IPv6 is float
                    #$ipv4sort[$record['end'] - $record['start']][$record['start']][] = &$record;
                    $this->IPvalidation64bit( $ipv4sort, $record );
                    unset($record);
                }
            }
        }

        foreach( $this->staticRoutes() as $route )
        {
            #$ipv4Mapping = $route->destinationIP4Mapping();
            $ipv4Mapping = $route->destinationIPMapping();

            $nexthopIf = $route->nexthopInterface();
            if( $nexthopIf !== null )
            {
                if( !$this->attachedInterfaces->hasInterfaceNamed($nexthopIf->name()) )
                {
                    mwarning("route {$route->name()}/{$route->destination()} ignored because its attached to interface {$nexthopIf->name()} but this interface does not belong to this logical router'", null, FALSE);
                    continue;
                }
                if( $contextVSYS->importedInterfaces->hasInterfaceNamed($nexthopIf->name()) )
                {
                    $findZone = $contextVSYS->zoneStore->findZoneMatchingInterfaceName($nexthopIf->name());
                    if( $findZone === null )
                    {
                        mwarning("route {$route->name()}/{$route->destination()} ignored because its attached to interface {$nexthopIf->name()} but this interface is not attached to a Zone in vsys {$contextVSYS->name()}'", null, FALSE);
                        continue;
                    }
                    else
                    {

                        $record = array('network' => $route->destination(), 'start' => $ipv4Mapping['start'], 'end' => $ipv4Mapping['end'], 'zone' => $findZone->name(), 'origin' => 'static', 'priority' => 2);
                        //Todo: int working well for IPv4; IPv6 is float
                        #$ipv4sort[$record['end'] - $record['start']][$record['start']][] = &$record;
                        $this->IPvalidation64bit( $ipv4sort, $record );
                        unset($record);
                    }
                }
                else
                {
                    $findVsys = $contextVSYS->owner->network->findVsysInterfaceOwner($nexthopIf->name());

                    if( $findVsys === null )
                    {
                        mwarning("route {$route->name()}/{$route->destination()} ignored because its attached to interface {$nexthopIf->name()} but this interface is attached to no VSYS", null, FALSE);
                        continue;
                    }
                    $externalZone = $contextVSYS->zoneStore->findZoneWithExternalVsys($findVsys);

                    if( $externalZone == null )
                    {
                        mwarning("route {$route->name()}/{$route->destination()} ignored because its attached to interface {$nexthopIf->name()} but this interface is attached to wrong vsys '{$findVsys->name()}' and no external zone could be found", null, FALSE);
                        continue;
                    }

                    $record = array('network' => $route->destination(), 'start' => $ipv4Mapping['start'], 'end' => $ipv4Mapping['end'], 'zone' => $externalZone->name(), 'origin' => 'static', 'priority' => 2);
                    //Todo: int working well for IPv4; IPv6 is float
                    #$ipv4sort[$record['end'] - $record['start']][$record['start']][] = &$record;
                    $this->IPvalidation64bit( $ipv4sort, $record );
                    unset($record);
                }

            }
            else if( $route->nexthopType() == 'ip-address' )
            {
                $nextHopType = $route->nexthopType();
                $nexthopIP = $route->nexthopIP();
                $findZone = null;
                foreach( $this->attachedInterfaces->interfaces() as $if )
                {
                    if( ($if->isEthernetType() || $if->isAggregateType()) && $if->type() == 'layer3' || $if->isLoopbackType() )
                    {
                        if( !$contextVSYS->importedInterfaces->hasInterfaceNamed($if->name()) )
                            continue;

                        if( $if->isLoopbackType() )
                            $ips = $if->getIPv4Addresses();
                        else
                        {
                            #$ips = $if->getLayer3IPv4Addresses();
                            $ips = $if->getLayer3IPAddresses();
                        }


                        foreach( $ips as &$interfaceIP )
                        {
                            if( cidr::netMatch($nexthopIP, $interfaceIP) > 0 )
                            {
                                $findZone = $contextVSYS->zoneStore->findZoneMatchingInterfaceName($if->name());
                                if( $findZone === null )
                                {
                                    mwarning("route {$route->name()}/{$route->destination()} ignored because its attached to interface {$if->name()} but this interface is not attached to a Zone in vsys {$contextVSYS->name()}'", null, FALSE);
                                    continue;
                                }

                                break;
                            }
                        }
                        if( $findZone !== null )
                        {
                            break;
                        }
                    }
                    else
                    {
                        continue;
                    }
                }
                if( $findZone === null )
                {
                    //Todo: check for some template config this is triggered
                    mwarning("route {$route->name()}/{$route->destination()} ignored because no matching interface was found for nexthop={$nexthopIP}", null, FALSE);
                    continue;
                }

                $record = array('network' => $route->destination(), 'start' => $ipv4Mapping['start'], 'end' => $ipv4Mapping['end'], 'zone' => $findZone->name(), 'origin' => 'static', 'priority' => 2);
                //Todo: int working well for IPv4; IPv6 is float
                #$ipv4sort[$record['end'] - $record['start']][$record['start']][] = &$record;
                $this->IPvalidation64bit( $ipv4sort, $record );
                unset($record);
            }
            else if( $route->nexthopType() == 'next-vr' )
            {

                $nextVR = $route->nexthopVR();
                if( $nextVR === null )
                {
                    mwarning("route {$route->name()}/{$route->destination()} ignored because nextVR is blank or invalid '", $route->xmlroot, null, FALSE);
                    continue;
                }
                $nextvrObject = $this->owner->findVirtualRouter($nextVR);
                if( $nextvrObject === null )
                {
                    mwarning("route {$route->name()}/{$route->destination()} ignored because nextVR '{$nextVR}' was not found", null, FALSE);
                    continue;
                }

                // prevent routes looping
                if( isset($loopFilter[$nextVR]) && isset($loopFilter[$nextVR][$contextVSYS->name()]) )
                    continue;

                $obj = $nextvrObject->getIPtoZoneRouteMapping($contextVSYS, $orderByNarrowest, $loopFilter);
                $currentRouteRemains = IP4Map::mapFromText($route->destination());

                foreach( $obj['ipv4'] as &$v4recordFromOtherVr )
                {
                    $ex = explode('/', $v4recordFromOtherVr['network']);
                    if( filter_var($ex[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE )
                        $intersection = $currentRouteRemains->intersection(IP4Map::mapFromText(long2ip($v4recordFromOtherVr['start']) . '-' . long2ip($v4recordFromOtherVr['end'])));
                    else
                    {
                        //IPv6
                        $intersection = $currentRouteRemains->intersection(IP4Map::mapFromText(cidr::inet_itop($v4recordFromOtherVr['start']) . '-' . cidr::inet_itop($v4recordFromOtherVr['end'])));
                    }




                    $foundMatches = $currentRouteRemains->substractSingleIP4Entry($v4recordFromOtherVr);
                    if( $intersection->count() > 0 )
                    {
                        foreach( $intersection->getMapArray() as $mapEntry )
                        {
                            $ex = explode('/', $mapEntry['network']);
                            if( filter_var($ex[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE )
                            {
                                $network = long2ip($mapEntry['start']) . '-' . long2ip($mapEntry['end']);

                                $record = array('network' => $network,
                                    'start' => $mapEntry['start'],
                                    'end' => $mapEntry['end'],
                                    'zone' => $v4recordFromOtherVr['zone'],
                                    'origin' => 'static',
                                    'priority' => 2);
                            }

                            else
                            {
                                #$network = cidr::inet_itop($mapEntry['start']) . '-' . cidr::inet_itop($mapEntry['end']);

                                $network = cidr::inet_itop($mapEntry['start']);
                                $record = array();
                                $record = array('network' => $network,
                                    'start' => $mapEntry['start'],
                                    'end' => $mapEntry['end'],
                                    'zone' => $v4recordFromOtherVr['zone'],
                                    'origin' => 'static',
                                    'priority' => 2);
                            }

                            if( !empty( $record ) )
                            {
                                //Todo: int working well for IPv4; IPv6 is float
                                #$ipv4sort[$record['end'] - $record['start']][$record['start']][] = &$record;
                                $this->IPvalidation64bit( $ipv4sort, $record );
                            }

                            unset($record);
                        }
                    }

                    if( $currentRouteRemains->count() == 0 )
                        break;
                }
            }
            else
            {
                mwarning("route {$route->name()}/{$route->destination()} ignored because of unknown type '{$route->nexthopType()}'", null, FALSE);
                continue;
            }
        }

        ksort($ipv4sort);

        foreach( $ipv4sort as &$record )
        {
            ksort($record);
            foreach( $record as &$subRecord )
            {
                foreach( $subRecord as &$subSubRecord )
                {
                    //only IPv4
                    if( isset($subSubRecord['network']) && strpos( $subSubRecord['network'], ":" ) !== FALSE )
                    {
                        $ipv6[] = &$subSubRecord;
                        continue;
                    }
                    else
                        $ipv4[] = &$subSubRecord;
                }
            }
        }

        $result = array('ipv4' => &$ipv4);

        return $result;
    }


    private function IPvalidation64bit( &$ipv4sort, $record )
    {
        if( $record['end'] > 9223372036854775807 )
        {
            #print "DEBUG output IPv6 related:\n";
            #print "start: ".$record['start']."\n";
            #print "end: ".$record['end']."\n";
            #(int)$test = $record['end'] - $record['start'];
            #print "end-start".intval($test)."\n";
        }
        else
            $ipv4sort[$record['end'] - $record['start']][$record['start']][] = &$record;
    }

    function validateIPorObject($nexthopIP, $type = 'local-address')
    {
        $pan_object = $this->owner->owner;
        if( isset( $pan_object->owner ) )
        {
            if( get_class($pan_object->owner) == "Template" )
            {
                $template_object = $pan_object->owner;
                $panorama_object = $template_object->owner;
                $shared_object = $panorama_object->addressStore->find($nexthopIP);
                if( $shared_object != null )
                {
                    $shared_object->addReference($this);

                    if( $type == "local-address" )
                    {
                        #$this->_destination = $shared_object->value();
                        #$this->_destinationObject = $shared_object;
                    }
                    elseif( $type == "peer-address" )
                    {
                        #$this->_nexthopIP = $shared_object->value();
                        #$this->_nexthopIPObject = $shared_object;
                    }
                }
            }
        }
        else
        {
            $all_vsys = $pan_object->getVirtualSystems();

            foreach( $all_vsys as $vsys )
            {
                $ngfw_object = $vsys->addressStore->find($nexthopIP);
                if( $ngfw_object != null && !$ngfw_object->isTmpAddr() )
                {
                    $ngfw_object->addReference($this);

                    if( $type == "local-address" )
                    {
                        #$this->_destination = $ngfw_object->value();
                        #$this->_destinationObject = $ngfw_object;
                    }
                    elseif( $type == "peer-address" )
                    {
                        #$this->_nexthopIP = $ngfw_object->value();
                        #$this->_nexthopIPObject = $ngfw_object;
                    }
                }
            }
        }
    }

    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getlogicalRouterStoreXPath() . "/entry[@name='" . $this->name . "']";

        if( $this->owner->owner->owner !== null && get_class( $this->owner->owner->owner ) == "Template" )
        {
            $templateXpath = $this->owner->owner->owner->getXPath();
            $str = $templateXpath.$str;
        }


        return $str;
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**"><routing-table></routing-table></entry>';
    #static public $templatexml = '<entry name="**temporarynamechangeme**"><routing-table><ip><static-route><entry></entry></static-route></ip></routing-table></entry>';

}