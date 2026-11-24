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


class StaticRoute
{
    use XmlConvertible;
    use PathableName;
    use ReferenceableObject;
    use NetworkObjectEdit;

    //Todo:
    //set interface
    //set metric
    //set nexthop


    /** @var string */
    protected $_destination;
    protected $_destinationObject;
    protected $_nexthopType = 'none';

    protected $_nexthopIP = null;

    protected $_nexthopIPObject = null;

    protected $_metric = null;

    /** @var null|string */
    protected $_nexthopVR = null;

    /** @var VirtualRouter */
    public $owner;

    /** @var null|EthernetInterface|AggregateEthernetInterface|TmpInterface */
    protected $_interface = null;


    /**
     * StaticRoute constructor.
     * @param string $name
     * @param VirtualRouter $owner
     */
    function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
    }

    /**
     * @param $xml DOMElement
     */
    function load_from_xml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("static-route name not found\n");

        #print "NAME: ".$this->name."\n";

        $dstNode = DH::findFirstElement('destination', $xml);

        if( $dstNode !== FALSE )
        {
            #print "DST: ".$dstNode->textContent."\n";
            #var_dump( $dstNode );

            if( strpos( $dstNode->textContent, "/" ) !== false )
            {
                $this->_destination = $dstNode->textContent;
            }
            else
            {
                $this->validateIPorObject($dstNode->textContent, 'destination');
            }
        }


        $ifNode = DH::findFirstElement('interface', $xml);
        if( $ifNode !== FALSE )
        {
            #print "INTERFACE: ".$ifNode->textContent."\n";
            #var_dump( $ifNode );
            $tmp_interface = $this->owner->owner->owner->network->findInterfaceOrCreateTmp($ifNode->textContent);
            $this->_interface = $tmp_interface;
            $tmp_interface->addReference($this);
        }

        $metricNode = DH::findFirstElement('metric', $xml);
        if( $metricNode !== FALSE )
        {
            $this->_metric = $metricNode->textContent;
        }

        $fhNode = DH::findFirstElement('nexthop', $xml);
        if( $fhNode !== FALSE )
        {
            $fhTypeNode = DH::findFirstElement('discard', $fhNode);
            if( $fhTypeNode !== FALSE )
            {
                $this->_nexthopType = 'discard';
            }

            $fhTypeNode = DH::findFirstElement('ip-address', $fhNode);
            if( $fhTypeNode !== FALSE )
            {
                $this->_nexthopType = 'ip-address';
                $this->_nexthopIP = $fhTypeNode->textContent;
                $this->validateIPorObject($this->_nexthopIP, 'nexthop');
                return;
            }
            $fhTypeNode = DH::findFirstElement('ipv6-address', $fhNode);
            if( $fhTypeNode !== FALSE )
            {
                $this->_nexthopType = 'ipv6-address';
                $this->_nexthopIP = $fhTypeNode->textContent;
                $this->validateIPorObject($this->_nexthopIP, 'nexthop');
                return;
            }
            $fhTypeNode = DH::findFirstElement('next-vr', $fhNode);
            if( $fhTypeNode !== FALSE )
            {
                $this->_nexthopType = 'next-vr';
                $this->_nexthopVR = $fhTypeNode->textContent;
                return;
            }

        }
    }

    function validateIPorObject($nexthopIP, $type = 'destination')
    {
        $pan_object = $this->owner->owner->owner;
        if( isset( $pan_object->owner ) )
        {
            #if( get_class($pan_object->owner) == "Template" )
            if( get_class($pan_object->owner) == "Template" || get_class($pan_object->owner) == "TemplateStack" )
            {
                $template_object = $pan_object->owner;
                $panorama_object = $template_object->owner;
                $shared_object = $panorama_object->addressStore->find($nexthopIP);
                if( $shared_object != null )
                {
                    $shared_object->addReference($this);

                    if( $type == "destination" )
                    {
                        $this->_destination = $shared_object->value();
                        $this->_destinationObject = $shared_object;
                    }
                    elseif( $type == "nexthop" )
                    {
                        $this->_nexthopIP = $shared_object->value();
                        $this->_nexthopIPObject = $shared_object;
                    }
                }
            }
        }
        else
        {
            //Todo: NGFW not easy to handle
            //print "it is a firewall\n";
            //it is directly a NGFW
            $all_vsys = $pan_object->getVirtualSystems();

            //vsys information not available at the time for reading config
            //

            #print "count vsys: ".count($all_vsys)."\n";

            foreach( $all_vsys as $vsys )
            {
                #not correct because you need to find correct vsys;
                #static route per interface???
                #if( $nexthopIP == "" )
                #    mwarning("empty name");
                $ngfw_object = $vsys->addressStore->find($nexthopIP);
                if( $ngfw_object != null && !$ngfw_object->isTmpAddr() )
                {
                    #print "add Reference for :".$ngfw_object->name()."\n";
                    $ngfw_object->addReference($this);

                    if( $type == "destination" )
                    {
                        $this->_destination = $ngfw_object->value();
                        $this->_destinationObject = $ngfw_object;
                    }
                    elseif( $type == "nexthop" )
                    {
                        $this->_nexthopIP = $ngfw_object->value();
                        $this->_nexthopIPObject = $ngfw_object;
                    }
                }
            }

            if( count($all_vsys) == 0 )
            {
                if( $type == "destination" )
                    $this->_destination = $nexthopIP;
                elseif( $type == "nexthop" )
                    $this->_nexthopIP = $nexthopIP;
            }
        }
    }

    function create_staticroute_from_xml($xmlString)
    {
        #print $xmlString."\n";
        $xmlElement = DH::importXmlStringOrDie($this->owner->owner->xmlroot->ownerDocument, $xmlString);
        $this->load_from_xml($xmlElement);

        return $this;
    }

    function create_staticroute_from_variables( $routename, $destination, $nexthop, $metric, $interface)
    {
        $xml_interface = "";
        if( $interface !== "" )
            $xml_interface = "<interface>" . $interface . "</interface>";

        //Todo: nexthop would be also good, but it could be that nexthop is "" than $interface ip-address must be used for IP check
        $checkIP = explode( "/", $destination);

        if(filter_var($checkIP[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))
            $ipType = "ip-address";
        elseif(filter_var($checkIP[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
            $ipType = "ipv6-address";

        $xmlString = "<entry name=\"" . $routename . "\"><nexthop><".$ipType.">" . $nexthop . "</".$ipType."></nexthop><metric>" . $metric . "</metric>" . $xml_interface . "<destination>" . $destination . "</destination></entry>";

        $tmpRoute = $this->create_staticroute_from_xml($xmlString);

        return $tmpRoute;
    }

    function remove()
    {
        $this->owner->removeStaticRoute($this, true);
    }

    /**
     * @return string
     */
    // ---- changes of the actions (static-route …-set): XML and object together; an invalid value: Exception

    /** a static route belongs to a router: names are looked up from the configuration of the router */
    protected function editLookup( ?string $storeProperty, string $name, string $findMethod )
    {
        return PH::findInNetworkScope( $this->owner->owner->owner, $storeProperty, $name, $findMethod );
    }

    /** destination: an IPv4 network (a.b.c.d/n) or an address object */
    public function editDestination( string $destination ): void
    {
        $destination = trim( $destination );
        $cidr = explode( '/', $destination );
        if( $destination === '' || strlen( $destination ) > 63 || preg_match( '/[\s<>:]/', $destination )
            || ( count( $cidr ) > 1 && ( count( $cidr ) !== 2 || filter_var( $cidr[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) === FALSE
                || !preg_match( '/^[0-9]{1,2}$/', $cidr[1] ) || (int)$cidr[1] > 32 ) ) )
            throw new Exception( "destination: an IPv4 network (e.g. 10.0.0.0/8) or an address object" );
        $this->editText( array( 'destination' ), $destination );
        $this->_destination = $destination;
    }

    /** next hop: ip-address (an address or address object), next-vr (a virtual router), discard, none */
    public function editNexthop( string $type, string $value = '' ): void
    {
        $type = strtolower( trim( $type ) );
        $value = trim( $value );
        if( !in_array( $type, array( 'ip-address', 'next-vr', 'discard', 'none' ), TRUE ) )
            throw new Exception( "next hop: ip-address, next-vr, discard or none" );
        if( $type === 'none' )
        {
            $this->editRemove( array( 'nexthop' ) );
            $this->_nexthopType = 'none';
            $this->_nexthopIP = null;
            $this->_nexthopVR = null;
            return;
        }
        if( $type === 'ip-address' && ( $value === '' || strlen( $value ) > 63 || preg_match( '/[\s<>:]/', $value ) ) )
            throw new Exception( "next hop ip-address: an IPv4 address or an address object" );
        if( $type === 'next-vr' )
        {
            $value = self::editName( $value, 'next virtual router' );
            if( $this->editLookup( 'virtualRouterStore', $value, 'findVirtualRouter' ) === null )
                throw new Exception( "virtual router '" . $value . "' not found" );
        }
        $this->editChoice( array( 'nexthop' ), $type, $type === 'discard' ? null : $value );
        $this->_nexthopType = $type;
        $this->_nexthopIP = $type === 'ip-address' ? $value : null;
        $this->_nexthopVR = $type === 'next-vr' ? $value : null;
    }

    /** the interface; '' removes it */
    public function editInterface( string $interface ): void
    {
        $interface = trim( $interface );
        $old = is_object( $this->_interface ) ? $this->_interface : null;
        if( $interface === '' )
        {
            $this->editRemove( array( 'interface' ) );
            $this->editSwapReference( $old, null );
            $this->_interface = null;
            return;
        }
        $interface = self::editName( $interface, 'interface' );
        $new = $this->editLookup( null, $interface, 'findInterface' );
        if( $new === null )
            throw new Exception( "interface '" . $interface . "' not found in the location of the router or above it" );
        $this->editText( array( 'interface' ), $interface );
        $this->editSwapReference( $old, $new );
        $this->_interface = $new;
    }

    /** metric 1-65535 */
    public function editMetric( string $metric ): void
    {
        if( !preg_match( '/^[0-9]{1,5}$/', trim( $metric ) ) || (int)$metric < 1 || (int)$metric > 65535 )
            throw new Exception( "metric: 1-65535" );
        $this->editText( array( 'metric' ), (string)(int)$metric );
        $this->_metric = (string)(int)$metric;
    }

    /** administrative distance 10-240; '' removes it (default of the router) */
    public function editAdminDistance( string $value ): void
    {
        if( trim( $value ) === '' )
        {
            $this->editRemove( array( 'admin-dist' ) );
            return;
        }
        if( !preg_match( '/^[0-9]{1,3}$/', trim( $value ) ) || (int)$value < 10 || (int)$value > 240 )
            throw new Exception( "administrative distance: 10-240" );
        $this->editText( array( 'admin-dist' ), (string)(int)$value );
    }

    /** route table: unicast, multicast, both, no-install */
    public function editRouteTable( string $table ): void
    {
        $table = strtolower( trim( $table ) );
        if( !in_array( $table, array( 'unicast', 'multicast', 'both', 'no-install' ), TRUE ) )
            throw new Exception( "route table: unicast, multicast, both or no-install" );
        $this->editChoice( array( 'route-table' ), $table, null );
    }

    public function destination()
    {
        return $this->_destination;
    }

    public function destinationObject()
    {
        return $this->_destinationObject;
    }

    /**
     * @return bool|string
     */
    public function destinationIP4Mapping()
    {
        return self::destinationIPMapping();
    }

    /**
     * @return bool|string
     */
    public function destinationIPMapping()
    {
        return cidr::stringToStartEnd($this->_destination);
    }

    /**
     * @return IP4Map
     */
    public function destinationIP4Map()
    {
        return IP4Map::mapFromText($this->_destination);
    }

    public function nexthopIP()
    {
        return $this->_nexthopIP;
    }

    public function nexthopIPobject()
    {
        return $this->_nexthopIPObject;
    }

    /**
     * @return null|string
     */
    public function nexthopVR()
    {
        return $this->_nexthopVR;
    }

    public function nexthopInterface()
    {
        return $this->_interface;
    }

    public function metric()
    {
        return $this->_metric;
    }

    /**
     * @return string   'none','ip-address'
     */
    public function nexthopType()
    {
        return $this->_nexthopType;
    }

    public function referencedObjectRenamed($h, $old)
    {
        if( get_class($h) == "EthernetInterface" || get_class($h) == "AggregateEthernetInterface" )
        {
            if( $this->_interface !== $h )
            {
                //why set it again????
                $this->_interface = $h;

                $this->rewriteInterface_XML();

                return;
            }

            if( $this->_interface === $h )
            {
                //already set
                $this->rewriteInterface_XML();
                return;
            }

            $this->owner->attachedInterfaces->removeInterface($old);
            $this->owner->attachedInterfaces->addInterface($h);
        }
        elseif( get_class($h) == "Address" )
        {
            //Text replace
            $qualifiedNodeName = '//*[text()="'.$old.'"]';
            $xpathResult = DH::findXPath( $qualifiedNodeName, $this->xmlroot);
            foreach( $xpathResult as $node )
                $node->textContent = $h->name();


            //attribute replace
            $nameattribute = $old;
            $qualifiedNodeName = "entry";
            $nodeList = $this->xmlroot->getElementsByTagName($qualifiedNodeName);
            $nodeArray = iterator_to_array($nodeList);
            foreach( $nodeArray as $item )
            {
                if ($nameattribute !== null)
                {
                    $XMLnameAttribute = DH::findAttribute("name", $item);
                    if ($XMLnameAttribute === FALSE)
                        continue;

                    if ($XMLnameAttribute !== $nameattribute)
                        continue;
                }
                $item->setAttribute('name', $h->name());
            }

            return;
        }

        print get_class($h)."\n";
        mwarning("object is not part of this static route : {$h->toString()}", null, false);
    }

    public function rewriteInterface_XML()
    {
        DH::createOrResetElement($this->xmlroot, 'interface', $this->_interface->name());
    }


    public function display($virtualRouter, $includingName = false)
    {
        $text = "";

        if( $includingName )
            $text .= "       - '" . PH::boldText($this->name())."'".str_pad(" ", 30 - strlen($this->name()) );
        else
            $text .= "       ";

        $tmpArray[$this->name()]['name'] = $this->name();

        if($this->destination() !== null)
        {
            $string_destination = $this->destination();
            if( $this->destinationObject() !== "" && $this->destinationObject() !== null )
                $string_destination .= " [".$this->destinationObject()->name()."]";

            $text .= " - DEST: " . str_pad($string_destination, 20);
            $tmpArray[$this->name()]['destination'] = $this->destination();
            if( $this->destinationObject() !== "" && $this->destinationObject() !== null )
                $tmpArray[$this->name()]['destinationObject'] = $this->destinationObject()->name();
        }
        else
            $text .= str_pad( " ", 30 );


        if( $this->nexthopIP() !== null )
        {
            $string_nexthopIP = $this->nexthopIP();
            if( $this->nexthopIPobject() !== "" && $this->nexthopIPobject() !== null )
                $string_nexthopIP .= " [".$this->nexthopIPobject()->name()."]";

            $text .= " - NEXTHOP: " . str_pad($string_nexthopIP, 20);
            $tmpArray[$this->name()]['nexthop'] = $this->nexthopIP();
            if( $this->nexthopIPobject() !== "" && $this->nexthopIPobject() !== null )
                $tmpArray[$this->name()]['nexthopObject'] = $this->nexthopIPobject()->name();
        }
        else
            $text .= str_pad( " ", 30 );

        if( $this->nexthopVR() != null )
        {
            $text .= "  - NEXT VR: " . str_pad($this->nexthopVR(), 20);
            $tmpArray[$this->name()]['nexthopvr'] = $this->nexthopVR();
        }
        else
            $text .= str_pad( " ", 20 );

        if( $this->metric() !== null )
        {
            $text .= " - metric: " . str_pad($this->metric(), 20);
            $tmpArray[$this->name()]['metric'] = $this->metric();
        }

        if( $this->nexthopType() == "discard" )
        {
            $text .= "  - DISCARD ";
            $tmpArray[$this->name()]['nexthop'] = "discard";
        }

        if( $this->nexthopInterface() != null )
        {
            $text .= "\n           - NEXT INTERFACE: " . str_pad($this->nexthopInterface()->toString(), 20);
            $tmpArray[$this->name()]['nexthopinterface'] = $this->nexthopInterface()->name();
        }
        
        if( $includingName )
            PH::$JSON_TMP['sub']['object'][$virtualRouter->name()]['staticroute'] = $tmpArray;
        else
            PH::$JSON_TMP['sub']['object'] = $tmpArray;

        return $text;
    }

    public function replaceReferencedObject($old, $new)
    {
        $this->referencedObjectRenamed($new, $old->name());
        return true;
    }

    public function API_replaceReferencedObject($old, $new)
    {
        $ret = $this->replaceReferencedObject($old, $new);

        if( $ret )
        {
            $this->API_sync();
        }

        return $ret;
    }
}