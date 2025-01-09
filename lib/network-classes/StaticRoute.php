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

        //<entry name="Route 161">
            //<nexthop><ip-address>10.34.111.1</ip-address></nexthop>
            //<metric>10</metric>
            //<interface>Port-channel22.511</interface>
            //<destination>192.168.220.70/32</destination>
        //</entry>

        /*
        <entry name="test">
          <nexthop><ip-address>Route_6.7.8.9</ip-address></nexthop>
          <bfd><profile>None</profile></bfd>
          <metric>10</metric>
          <destination>Route_DST_192.168.10.0m24</destination>
          <route-table><unicast/></route-table>
        </entry>
         */

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
            if( get_class($pan_object->owner) == "Template" )
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
        if( get_class($h) == "EthernetInterface" )
        {
            if( $this->_interface !== $h )
            {
                //why set it again????
                $this->_interface = $h;

                $this->rewriteInterface_XML();

                return;
            }
        }
        elseif( get_class($h) == "Address" )
        {
            return;
        }

        mwarning("object is not part of this static route : {$h->toString()}");
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
}