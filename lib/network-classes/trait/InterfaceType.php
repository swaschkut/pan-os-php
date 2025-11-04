<?php

trait InterfaceType
{
    public function isEthernetType()
    {
        return FALSE;
    }

    public function isIPsecTunnelType()
    {
        return FALSE;
    }

    public function isAggregateType()
    {
        return FALSE;
    }

    public function isTmpType()
    {
        return FALSE;
    }

    public function isLoopbackType()
    {
        return FALSE;
    }

    public function isTunnelType()
    {
        return FALSE;
    }

    public function isVlanType()
    {
        return FALSE;
    }

    public $importedByVSYS = null;


    /**
     * return true if change was successful false if not (duplicate ipaddress?)
     * @param string $ip
     * @return bool
     */
    public function addIPv4Address($ip)
    {
        foreach( $this->getIPv4Addresses() as $IPv4Address )
        {
            if( $IPv4Address == $ip )
                return TRUE;
        }

        if( strpos($ip, ".") === FALSE )
        {
            $tmp_vsys = $this->owner->owner->network->findVsysInterfaceOwner($this->name());

            if( is_object($tmp_vsys) )
                $object = $tmp_vsys->addressStore->find($ip);
            else
                return FALSE;

            if( is_object($object) )
                $object->addReference($this);
            else
                derr("objectname: " . $ip . " not found. Can not be added to interface.\n", $this);
        }


        $this->_ipv4Addresses[] = $ip;

        $tmp_xmlroot = $this->xmlroot;

        $ipNode = DH::findFirstElementOrCreate('ip', $tmp_xmlroot);

        $tmp_ipaddress = DH::createElement($ipNode, 'entry', "");
        $tmp_ipaddress->setAttribute('name', $ip);

        $ipNode->appendChild($tmp_ipaddress);

        return TRUE;
    }

    /**
     * Add a ip to this interface, it must be passed as an object or string
     * @param Address $ip Object to be added, or String
     * @return bool
     */
    public function API_addIPv4Address($ip)
    {
        $ret = $this->addIPv4Address($ip);

        if( $ret )
        {
            $con = findConnector($this);
            $xpath = $this->getXPath();

            $xpath .= '/ip';

            $con->sendSetRequest($xpath, "<entry name='{$ip}'/>");
        }

        return $ret;
    }

    /**
     * return true if change was successful false if not (duplicate ipaddress?)
     * @param string $ip
     * @return bool
     */
    public function removeIPv4Address($ip)
    {
        $tmp_IPv4 = array();
        foreach( $this->getIPv4Addresses() as $key => $IPv4Address )
        {
            $tmp_IPv4[$IPv4Address] = $IPv4Address;
            if( $IPv4Address == $ip )
                unset($this->_ipv4Addresses[$key]);
        }

        if( !array_key_exists($ip, $tmp_IPv4) )
        {
            PH::print_stdout(  " ** skipped ** IP Address: " . $ip . " is not set on interface: " . $this->name() );
            return FALSE;
        }

        if( strpos($ip, "/") === FALSE )
        {
            $tmp_vsys = $this->owner->owner->network->findVsysInterfaceOwner($this->name());

            if( is_object($tmp_vsys) )
                $object = $tmp_vsys->addressStore->find($ip);
            else
                return FALSE;

            if( is_object($object) )
                $object->removeReference($this);
            else
                mwarning("objectname: " . $ip . " not found. Can not be removed from interface.\n", $this);
        }

        $tmp_xmlroot = $this->xmlroot;

        $ipNode = DH::findFirstElementOrCreate('ip', $tmp_xmlroot);

        $tmp_ipaddress = DH::findFirstElementByNameAttrOrDie('entry', $ip, $ipNode);
        if( $tmp_ipaddress !== False )
            $ipNode->removeChild($tmp_ipaddress);

        return TRUE;
    }

    /**
     * remove a ip address to this interface, it must be passed as an object or string
     * @param Address $ip Object to be added, or String
     * @return bool
     */
    public function API_removeIPv4Address($ip)
    {
        $ret = $this->removeIPv4Address($ip);

        if( $ret )
        {
            $con = findConnector($this);
            $xpath = $this->getXPath();

            $xpath .= '/ip';

            $con->sendDeleteRequest($xpath . "/entry[@name='{$ip}']");
        }

        return $ret;
    }

    /**
     * return true if change was successful false if not (duplicate ipaddress?)
     * @param string $ip
     * @return bool
     */
    public function addIPv6Address($ip)
    {
        foreach( $this->getIPv6Addresses() as $IPv6Address )
        {
            if( $IPv6Address == $ip )
                return TRUE;
        }

        if( strpos($ip, ":") === FALSE )
        {
            $tmp_vsys = $this->owner->owner->network->findVsysInterfaceOwner($this->name());

            if( is_object($tmp_vsys) )
                $object = $tmp_vsys->addressStore->find($ip);
            else
                return FALSE;

            if( is_object($object) )
                $object->addReference($this);
            else
                derr("objectname: " . $ip . " not found. Can not be added to interface.\n", $this);
        }


        $this->_ipv6Addresses[] = $ip;

        $tmp_xmlroot = $this->xmlroot;

        $ipv6Node = DH::findFirstElementOrCreate('ipv6', $tmp_xmlroot);
        $ipNode = DH::findFirstElementOrCreate('address', $ipv6Node);

        $tmp_ipaddress = DH::createElement($ipNode, 'entry', "");
        $tmp_ipaddress->setAttribute('name', $ip);

        $ipNode->appendChild($tmp_ipaddress);

        return TRUE;
    }

    /**
     * Add a ip to this interface, it must be passed as an object or string
     * @param Address $ip Object to be added, or String
     * @return bool
     */
    public function API_addIPv6Address($ip)
    {
        $ret = $this->addIPv6Address($ip);

        if( $ret )
        {
            $con = findConnector($this);
            $xpath = $this->getXPath();

            $xpath .= '/ipv6/address';

            $con->sendSetRequest($xpath, "<entry name='{$ip}'/>");
        }

        return $ret;
    }

    /**
     * return true if change was successful false if not (duplicate ipaddress?)
     * @param string $ip
     * @return bool
     */
    public function removeIPv6Address($ip)
    {
        $tmp_IPv4 = array();
        foreach( $this->getIPv6Addresses() as $key => $IPv6Address )
        {
            $tmp_IPv6[$IPv6Address] = $IPv6Address;
            if( $IPv6Address == $ip )
                unset($this->_ipv6Addresses[$key]);
        }

        if( !array_key_exists($ip, $tmp_IPv6) )
        {
            PH::print_stdout(  " ** skipped ** IPv6 Address: " . $ip . " is not set on interface: " . $this->name() );
            return FALSE;
        }

        if( strpos($ip, "/") === FALSE )
        {
            $tmp_vsys = $this->owner->owner->network->findVsysInterfaceOwner($this->name());

            if( is_object($tmp_vsys) )
                $object = $tmp_vsys->addressStore->find($ip);
            else
                return FALSE;

            if( is_object($object) )
                $object->removeReference($this);
            else
                mwarning("objectname: " . $ip . " not found. Can not be removed from interface.\n", $this);
        }

        $tmp_xmlroot = $this->xmlroot;

        $ipv6Node = DH::findFirstElementOrCreate('ipv6', $tmp_xmlroot);
        $ipNode = DH::findFirstElementOrCreate('address', $ipv6Node);

        $tmp_ipaddress = DH::findFirstElementByNameAttrOrDie('entry', $ip, $ipNode);
        if( $tmp_ipaddress !== False )
            $ipNode->removeChild($tmp_ipaddress);

        return TRUE;
    }

    /**
     * remove a ip address to this interface, it must be passed as an object or string
     * @param Address $ip Object to be added, or String
     * @return bool
     */
    public function API_removeIPv6Address($ip)
    {
        $ret = $this->removeIPv6Address($ip);

        if( $ret )
        {
            $con = findConnector($this);
            $xpath = $this->getXPath();

            $xpath .= '/ipv6/address';

            $con->sendDeleteRequest($xpath . "/entry[@name='{$ip}']");
        }

        return $ret;
    }

    public function replaceIPv4ObjectByValue( $context, $address_obj )
    {
        if( strpos( $address_obj->value(), ":" ) !== FALSE )
        {
            PH::print_stdout( "      - value: ".$address_obj->value() );
            PH::print_stdout( "      - only IPv4 Address can be added with this function" );
        }
        elseif( strpos( $address_obj->value(), "." ) !== FALSE )
        {
            PH::print_stdout( "      - remove object: ".$address_obj->name() );
            PH::print_stdout( "      - add value: ".$address_obj->value() );

            $this->removeIPv4Address($address_obj->name());
            $this->addIPv4Address($address_obj->value());

            PH::print_stdout("-----------------------------------");
            //Todo: interface reference are better to work on | validation needed
            foreach( $address_obj->refrules as $o )
            {
                if( $o->name() !== $this->name() )
                {
                    PH::print_stdout( '  - ' . $o->toString() );

                    $o->referencedObjectRenamed($address_obj, $address_obj->name(), "value");
                }
            }
            PH::print_stdout("-----------------------------------");

            if( $context->isAPI )
            {
                //Todo: API sync
                mwarning( "      - API sync not yet implemented", null, false );
            }
        }
        else
            mwarning( "      - unknown address ".$address_obj->value() );
    }

    public function replaceIPv6ObjectByValue( $context, $address_obj )
    {
        if( strpos( $address_obj->value(), "." ) !== FALSE )
        {
            PH::print_stdout( "      - value: ".$address_obj->value() );
            PH::print_stdout( "      - only IPv6 Address can be added with this function" );
        }
        elseif( strpos( $address_obj->value(), ":" ) !== FALSE )
        {
            PH::print_stdout( "      - remove object: ".$address_obj->name() );
            PH::print_stdout( "      - add value: ".$address_obj->value() );

            #mwarning( "      - not yet implemented", null, false );

            $this->removeIPv6Address($address_obj->name());
            $this->addIPv6Address($address_obj->value());

            PH::print_stdout("-----------------------------------");
            //Todo: interface reference are better to work on | validation needed
            foreach( $address_obj->refrules as $o )
            {
                if( $o->name() !== $this->name() )
                {
                    PH::print_stdout( '  - ' . $o->toString() );

                    $o->referencedObjectRenamed($address_obj, $address_obj->name(), "value");
                }
            }
            PH::print_stdout("-----------------------------------");


            if( $context->isAPI )
            {
                //Todo: API sync
                mwarning( "      - API sync not yet implemented", null, false );
            }
        }
        else
            mwarning( "      - unknown address ".$address_obj->value() );
    }

    public function display()
    {
        $object = $this;

        PH::print_stdout("     * ".get_class($object)." '{$object->name()}'" );
        PH::$JSON_TMP['sub']['object'][$object->name()]['name'] = $object->name();
        PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object);

        //Todo: optimization needed, same process as for other utiles

        $text = "       - " . $object->type . " - ";

        if( $object->type == "layer3" || $object->type == "virtual-wire" || $object->type == "layer2" )
        {
            if( $object->isSubInterface() )
            {
                $text .= "subinterface - ";
                PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['subinterface'] = "yes";
                PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['subinterfacecount'] = "0";
            }

            else
            {
                $text .= "count subinterface: " . $object->countSubInterfaces() . " - ";
                PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['subinterface'] = "false";
                PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['subinterfacecount'] = $object->countSubInterfaces();
            }

        }
        elseif( $object->type == "aggregate-group" )
        {
            $text .= "".$object->ae()." - ";
            PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ae'] = $object->ae();
        }


        if( $object->type == "layer3" )
        {
            $text .= "ip-addresse(s): ";
            foreach( $object->getLayer3IPv4Addresses() as $ip_address )
            {
                if( strpos( $ip_address, "." ) !== false )
                {
                    $text .= $ip_address . ",";
                    PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ipaddress'][] = $ip_address;
                }

                else
                {
                    #$object = $sub->addressStore->find( $ip_address );
                    #PH::print_stdout( $ip_address." ({$object->value()}) ,");
                }
            }
        }
        elseif( $object->type == "tunnel" || $object->type == "loopback" || $object->type == "vlan"  )
        {
            $text .= ", ip-addresse(s): ";
            foreach( $object->getIPv4Addresses() as $ip_address )
            {
                if( strpos( $ip_address, "." ) !== false )
                {
                    $text .= $ip_address . ",";
                    PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ipaddress'][] = $ip_address;
                }

                else
                {
                    #$object = $sub->addressStore->find( $ip_address );
                    #PH::print_stdout($text); $ip_address." ({$object->value()}) ,");
                }
            }
        }
        elseif( $object->type == "auto-key" )
        {
            $text .= " - IPsec config";
            $text .= " - IKE gateway: " . $object->gateway;
            $text .= " - interface: " . $object->interface;
            PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ike']['gw'] = $object->gateway;
            PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ike']['interface'] = $object->interface;
        }

        PH::print_stdout( $text );
    }

    public function load_IP_from_domxml( $tmpIP, $ipVariable, $ipObjectVariable)
    {
        //Todo - reference adding is missing, search object name if no IP
        $pan_object = $this->owner->owner;
        if( isset( $pan_object->owner ) )
        {
            //Panorama Template
            if( get_class($pan_object->owner) == "Template" || get_class($pan_object->owner) == "TemplateStack" )
            {
                $template_object = $pan_object->owner;
                $panorama_object = $template_object->owner;
                $shared_object = $panorama_object->addressStore->find($tmpIP);
                if( $shared_object != null )
                {

                    $shared_object->addReference($this);
                    $this->$ipVariable[] = $shared_object->name();
                    $this->$ipObjectVariable[] = $shared_object->value();
                }
                else
                {
                    $this->$ipVariable[] = $tmpIP;
                    $this->$ipObjectVariable[] = $tmpIP;
                }
            }
        }
        else
        {
            //NGFW - this is done earlier
            if( strpos( $tmpIP, "/" ) !== False )
            {
                $this->$ipVariable[] = $tmpIP;
                $this->$ipObjectVariable[] = $tmpIP;
            }
            else
            {
                $this->$ipVariable[] = $tmpIP;
                //If added it could be address obejct name
                #$this->$ipObjectVariable[] = $tmpIP;
            }
        }
    }
}