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

class EthernetInterface
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferenceableObject;
    use ObjectWithDescription;

    /** @var null|DOMElement */
    private $typeRoot = null;

    /** @var EthernetIfStore */
    public $owner;

    protected $classn = null;

    /** @var string */
    public $type = 'tmp';

    /** @var string */
    #public $_description;

    /** @var bool */
    protected $isSubInterface = FALSE;

    /** @var EthernetInterface[] */
    protected $subInterfaces = array();

    /** @var null|EthernetInterface */
    protected $parentInterface = null;

    /** @var int */
    protected $tag;

    /** @var int */
    protected $ae = null;

    protected $l3ipv4Addresses;
    protected $l3ipv6Addresses;

    protected $linkstate = "auto";

    public static $childn = 'EthernetInterface';

    static public $supportedTypes = array('layer3', 'layer2', 'virtual-wire', 'tap', 'ha', 'aggregate-group', 'log-card', 'decrypt-mirror', 'empty');

    /**
     * @param string $name
     * @param EthernetIfStore $owner
     */
    function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
        $this->classn = &self::$childn;
    }

    /**
     * @param DOMElement $xml
     */
    function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        //print "Int name found: {$this->name}\n";
        if( $this->name === FALSE )
            derr("interface name not found\n");

        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 )
                continue;

            $nodeName = $node->nodeName;

            if( array_search($nodeName, self::$supportedTypes) !== FALSE )
            {
                $this->type = $nodeName;
                $this->typeRoot = $node;
            }
            elseif( $nodeName == 'comment' )
            {
                $this->_description = $node->textContent;
                //print "Desc found: {$this->description}\n";
            }
            elseif( $nodeName == 'link-state' )
            {
                $this->linkstate = $node->textContent;
                //print "linkstate found: {$this->description}\n";
            }
        }

        if( $this->type == 'tmp' )
        {
            $this->type = 'empty';
            return;
        }

        if( $this->type == 'layer3' )
        {
            $this->l3ipv4Addresses = array();
            $ipNode = DH::findFirstElement('ip', $this->typeRoot);
            if( $ipNode !== FALSE )
            {
                foreach( $ipNode->childNodes as $l3ipNode )
                {
                    if( $l3ipNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmpIP = $l3ipNode->getAttribute('name');
                    #$this->l3ipv4Addresses[] = $tmpIP;

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
                                $this->l3ipv4Addresses[] = $shared_object->name();
                            }
                            else
                                $this->l3ipv4Addresses[] = $tmpIP;
                        }
                    }
                    else
                    {
                        //NGFW
                        if( strpos( $tmpIP, "/" ) !== False )
                            $this->l3ipv4Addresses[] = $tmpIP;
                        else
                        {
                            //object
                            $this->l3ipv4Addresses[] = $tmpIP;
                        }
                    }
                }
            }

            $this->l3ipv6Addresses = array();
            $ipNode = DH::findFirstElement('ipv6', $this->typeRoot);
            if( $ipNode !== FALSE )
            {
                $ipNode = DH::findFirstElement('address', $ipNode);
                if( $ipNode !== FALSE )
                {
                    foreach( $ipNode->childNodes as $l3ipNode )
                    {
                        if( $l3ipNode->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $tmpIP = $l3ipNode->getAttribute('name');
                        #$this->l3ipv6Addresses[] = $tmpIP;

                        //Todo - reference adding is missing, search object name if no IP
                        $pan_object = $this->owner->owner;
                        if( isset( $pan_object->owner ) )
                        {
                            //Panorama Template
                            #if( get_class($pan_object->owner) == "Template" )
                            if( get_class($pan_object->owner) == "Template" || get_class($pan_object->owner) == "TemplateStack" )
                            {
                                $template_object = $pan_object->owner;
                                $panorama_object = $template_object->owner;
                                $shared_object = $panorama_object->addressStore->find($tmpIP);
                                if( $shared_object != null )
                                {
                                    $shared_object->addReference($this);
                                    $this->l3ipv6Addresses[] = $shared_object->name();
                                }
                                else
                                    $this->l3ipv6Addresses[] = $tmpIP;
                            }
                        }
                        else
                        {
                            //NGFW
                            $this->l3ipv6Addresses[] = $tmpIP;
                        }

                    }
                }
            }
        }

        if( $this->type == 'aggregate-group' )
        {
            $this->ae = $this->typeRoot->textContent;
            #print "Interface: ".$this->name()."\n";
            #print "AE: ".$this->ae."\n";

            /** @var  AggregateEthernetInterface $aeInterface */
            $aeInterface = $this->owner->owner->network->aggregateEthernetIfStore->find($this->ae);
            if( $aeInterface != NULL )
                $aeInterface->addReference($this);
        }


        // looking for sub interfaces and stuff like that   :)
        foreach( $this->typeRoot->childNodes as $node )
        {
            if( $node->nodeType != 1 )
                continue;

            // sub interfaces here !
            if( $node->nodeName == 'units' )
            {
                foreach( $node->childNodes as $unitsNode )
                {
                    if( $unitsNode->nodeType != 1 )
                        continue;

                    #$newInterface = new EthernetInterface('tmp', $this->owner);
                    $newInterface = new $this->classn('tmp', $this->owner);
                    $newInterface->isSubInterface = TRUE;
                    $newInterface->parentInterface = $this;
                    $newInterface->type = &$this->type;
                    $newInterface->load_sub_from_domxml($unitsNode);
                    $this->subInterfaces[] = $newInterface;
                }
            }
        }
    }

    /**
     * @param DOMElement $xml
     */
    public function load_sub_from_domxml($xml)
    {
        $this->xmlroot = $xml;
        $this->name = DH::findAttribute('name', $xml);
        //print "subInt name found: {$this->name}\n";
        if( $this->name === FALSE )
            derr("address name not found\n");

        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 )
                continue;

            $nodeName = $node->nodeName;

            if( $nodeName == 'comment' )
            {
                $this->_description = $node->textContent;
                //print "Desc found: {$this->description}\n";
            }
            elseif( $nodeName == 'tag' )
            {
                $this->tag = $node->textContent;
            }
            elseif( $nodeName == 'aggregate-group' )
            {
                $this->ae = $node->textContent;
            }
        }

        if( $this->type == 'layer3' )
        {
            $this->l3ipv4Addresses = array();
            $ipNode = DH::findFirstElement('ip', $xml);
            if( $ipNode !== FALSE )
            {
                foreach( $ipNode->childNodes as $l3ipNode )
                {
                    if( $l3ipNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $this->l3ipv4Addresses[] = $l3ipNode->getAttribute('name');
                }
            }

            $this->l3ipv6Addresses = array();
            $ipNode = DH::findFirstElement('ipv6', $xml);
            if( $ipNode !== FALSE )
            {
                $ipNode = DH::findFirstElement('address', $ipNode);
                if( $ipNode !== FALSE )
                {
                    foreach( $ipNode->childNodes as $l3ipNode )
                    {
                        if( $l3ipNode->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $this->l3ipv6Addresses[] = $l3ipNode->getAttribute('name');
                    }
                }
            }
        }
    }

    /**
     * @return bool
     */
    public function isSubInterface()
    {
        return $this->isSubInterface;
    }

    /**
     * @return string
     */
    public function type()
    {
        return $this->type;
    }

    /**
     * @return int
     */
    public function tag()
    {
        return $this->tag;
    }

    /**
     * @return int
     */
    public function ae()
    {
        return $this->ae;
    }

    /**
     * @return int
     */
    public function subIfNumber()
    {
        if( !$this->isSubInterface )
            derr('can be called in sub interfaces only');

        $ar = explode('.', $this->name);

        if( count($ar) != 2 )
            derr('unsupported');

        return $ar[1];
    }

    public function getLayer3IPv4Addresses()
    {
        if( $this->type != 'layer3' )
            derr('cannot be requested from a non Layer3 Interface');

        if( $this->l3ipv4Addresses === null )
            return array();

        return $this->l3ipv4Addresses;
    }

    public function getLayer3IPv6Addresses()
    {
        if( $this->type != 'layer3' )
            derr('cannot be requested from a non Layer3 Interface');

        if( $this->l3ipv6Addresses === null )
            return array();

        return $this->l3ipv6Addresses;
    }

    public function getLayer3IPAddresses()
    {
        if( $this->type != 'layer3' )
            derr('cannot be requested from a non Layer3 Interface');

        if( $this->l3ipv6Addresses === null && $this->l3ipv4Addresses === null )
            return array();

        return array_merge( $this->l3ipv4Addresses, $this->l3ipv6Addresses );
    }

    public function countSubInterfaces()
    {
        return count($this->subInterfaces);
    }

    /**
     * @return EthernetInterface[]
     */
    public function subInterfaces()
    {
        return $this->subInterfaces;
    }

    function isEthernetType()
    {
        return TRUE;
    }

    /**
     * return true if change was successful false if not (duplicate rulename?)
     * @param string $name new name for the rule
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

        if( count( $this->subInterfaces() ) > 0 )
        {
            foreach($this->subInterfaces() as $sub)
            {
                $oldName = $sub->name();
                $tagName = explode( ".", $oldName );
                $sub->setName($name.".".$tagName[1]);
            }
        }


        return TRUE;

    }

    /**
     * return true if change was successful false if not (duplicate rulename?)
     * @param string $name new name for the rule
     * @return bool
     */
    public function setTag($tag)
    {
        if( $this->type != 'layer3' && $this->type != 'layer2' && $this->type != 'virtual-wire' )
            derr('cannot be requested from a ' . $this->type() . ' Interface');

        if( $this->tag == $tag )
            return TRUE;

        $this->tag = $tag;

        $tagNode = DH::findFirstElement('tag', $this->xmlroot);
        DH::setDomNodeText($tagNode, $tag);

        return TRUE;
    }

    /**
     * return true if change was successful false if not (duplicate rulename?)
     * @param string $name new name for the rule
     * @return bool
     */
    public function setAE($ae)
    {
        if( $this->type != 'aggregate-group' )
            derr('cannot be requested from a ' . $this->type() . ' Interface');

        if( $this->ae == $ae )
            return TRUE;

        $this->ae = $ae;

        $aeNode = DH::findFirstElementOrCreate('aggregate-group', $this->xmlroot);
        DH::setDomNodeText($aeNode, $ae);

        if( isset($this->owner) && $this->owner != null )
        {
            $aeInterface = $this->owner->owner->network->aggregateEthernetIfStore->find($ae);
            if( $aeInterface !== null )
                $aeInterface->addReference($this);
        }

        return TRUE;
    }

    /**
     * return true if change was successful false if not (duplicate ipaddress?)
     * @param string $ip
     * @return bool
     */
    public function addIPv4Address($ip)
    {
        if( $this->type != 'layer3' )
            derr('cannot be requested from a non Layer3 Interface');

        if( is_object($ip) )
        {
            $ip = $ip->name();
            mwarning( "adding address object to Interface not implemented yet", null, false );
        }

        $ip = $this->findorCreateAddressObject( $ip );


        $mapping_new = new IP4Map();
        $mapping_new->addMap(IP4Map::mapFromText($ip));
        foreach( $this->getLayer3IPv4Addresses() as $IPv4Address )
        {
            if( $IPv4Address == $ip )
                return TRUE;

            //avoid overlapping subnet
            $mapping = new IP4Map();
            $mapping->addMap(IP4Map::mapFromText($IPv4Address));
            if( $mapping->includesOtherMap($mapping_new) !== 0 )
            {
                $ip_array = explode("/", $ip);
                $ip = $ip_array[0] . "/32";
            }
        }

        $this->l3ipv4Addresses[] = $ip;

        if( $this->isSubInterface() )
            $tmp_xmlroot = $this->parentInterface->xmlroot;
        else
            $tmp_xmlroot = $this->xmlroot;

        $layer3Node = DH::findFirstElementOrCreate('layer3', $tmp_xmlroot);

        if( $this->isSubInterface() )
        {
            $tmp_units = DH::findFirstElementOrCreate('units', $layer3Node);
            $tmp_entry = DH::findFirstElementByNameAttrOrDie('entry', $this->name(), $tmp_units);
            $ipNode = DH::findFirstElementOrCreate('ip', $tmp_entry);
        }
        else
            $ipNode = DH::findFirstElementOrCreate('ip', $layer3Node);


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

            if( $this->isSubInterface() )
            {
                $xpath = $this->parentInterface->getXPath();
                $xpath .= "/layer3/units/entry[@name='" . $this->name . "']/ip";
            }
            else
                $xpath .= '/layer3/ip';

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
        if( $this->type != 'layer3' )
            derr('cannot be requested from a non Layer3 Interface');

        if( is_object($ip) )
            derr( "removing address object from Interface not implemented yet", null, False );

        $tmp_IPv4 = array();
        foreach( $this->getLayer3IPv4Addresses() as $key => $IPv4Address )
        {
            $tmp_IPv4[$IPv4Address] = $IPv4Address;
            if( $IPv4Address == $ip )
                unset($this->l3ipv4Addresses[$key]);
        }


        if( !array_key_exists($ip, $tmp_IPv4) )
        {
            PH::print_stdout( " ** skipped ** IP Address: " . $ip . " is not set on interface: " . $this->name() );
            return FALSE;
        }

        $this->removeAddressObjectReference( $ip );

        if( $this->isSubInterface() )
            $tmp_xmlroot = $this->parentInterface->xmlroot;
        else
            $tmp_xmlroot = $this->xmlroot;

        $layer3Node = DH::findFirstElementOrCreate('layer3', $tmp_xmlroot);

        if( $this->isSubInterface() )
        {
            $tmp_units = DH::findFirstElementOrCreate('units', $layer3Node);
            $tmp_entry = DH::findFirstElementByNameAttrOrDie('entry', $this->name(), $tmp_units);
            $ipNode = DH::findFirstElementOrCreate('ip', $tmp_entry);
        }
        else
            $ipNode = DH::findFirstElementOrCreate('ip', $layer3Node);


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

            if( $this->isSubInterface() )
            {
                $xpath = $this->parentInterface->getXPath();
                $xpath .= "/layer3/units/entry[@name='" . $this->name . "']/ip";
            }
            else
                $xpath .= '/layer3/ip';

            $con->sendDeleteRequest($xpath . "/entry[@name='{$ip}']");
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
        if( $this->type != 'layer3' )
            derr('cannot be requested from a non Layer3 Interface');

        if( is_object($ip) )
            derr( "removing address object from Interface not implemented yet", null, False );

        $tmp_IPv6 = array();
        foreach( $this->getLayer3IPv6Addresses() as $key => $IPv6Address )
        {
            $tmp_IPv6[$IPv6Address] = $IPv6Address;
            if( $IPv6Address == $ip )
                unset($this->l3ipv6Addresses[$key]);
        }


        if( !array_key_exists($ip, $tmp_IPv6) )
        {
            PH::print_stdout( " ** skipped ** IP Address: " . $ip . " is not set on interface: " . $this->name() );
            return FALSE;
        }

        $this->removeAddressObjectReference( $ip );

        if( $this->isSubInterface() )
            $tmp_xmlroot = $this->parentInterface->xmlroot;
        else
            $tmp_xmlroot = $this->xmlroot;

        $layer3Node = DH::findFirstElementOrCreate('layer3', $tmp_xmlroot);

        if( $this->isSubInterface() )
        {
            $tmp_units = DH::findFirstElementOrCreate('units', $layer3Node);
            $tmp_entry = DH::findFirstElementByNameAttrOrDie('entry', $this->name(), $tmp_units);
            $ipv6Node = DH::findFirstElementOrCreate('ipv6', $tmp_entry);
            $ipNode = DH::findFirstElementOrCreate('address', $ipv6Node);
        }
        else
        {
            $ipv6Node = DH::findFirstElementOrCreate('ipv6', $layer3Node);
            $ipNode = DH::findFirstElementOrCreate('address', $ipv6Node);
        }



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

            if( $this->isSubInterface() )
            {
                $xpath = $this->parentInterface->getXPath();
                $xpath .= "/layer3/units/entry[@name='" . $this->name . "']/ipv6/address";
            }
            else
                $xpath .= '/layer3/ipv6/address';

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
        if( $this->type != 'layer3' )
            derr('cannot be requested from a non Layer3 Interface');

        $ip = $this->findorCreateAddressObject( $ip );

        /*
        $mapping_new = new IP4Map();
        $mapping_new->addMap(IP4Map::mapFromText($ip));
        foreach( $this->getLayer3IPv4Addresses() as $IPv4Address )
        {
            if( $IPv4Address == $ip )
                return true;

            //avoid overlapping subnet
            $mapping = new IP4Map();
            $mapping->addMap(IP4Map::mapFromText($IPv4Address));
            if( $mapping->includesOtherMap($mapping_new) !== 0 )
            {
                $ip_array = explode( "/", $ip );
                $ip = $ip_array[0]."/32";
            }
        }
        */

        $this->l3ipv6Addresses[] = $ip;

        if( $this->isSubInterface() )
            $tmp_xmlroot = $this->parentInterface->xmlroot;
        else
            $tmp_xmlroot = $this->xmlroot;

        $layer3Node = DH::findFirstElementOrCreate('layer3', $tmp_xmlroot);

        if( $this->isSubInterface() )
        {
            $tmp_units = DH::findFirstElementOrCreate('units', $layer3Node);
            $tmp_entry = DH::findFirstElementByNameAttrOrDie('entry', $this->name(), $tmp_units);
            $ipv6Node = DH::findFirstElementOrCreate('ipv6', $tmp_entry);
            $ipNode = DH::findFirstElementOrCreate('address', $ipv6Node);
        }
        else
        {
            $ipv6Node = DH::findFirstElementOrCreate('ipv6', $layer3Node);
            $ipNode = DH::findFirstElementOrCreate('address', $ipv6Node);
        }

        $ipv6Enable = DH::findFirstElementOrCreate( 'enabled', $ipv6Node);
        $ipv6Enable->nodeValue = "yes";

        $tmp_ipaddress = DH::createElement($ipNode, 'entry', "");
        $tmp_ipaddress->setAttribute('name', $ip);

        $ipv6Enable = DH::findFirstElementOrCreate( 'enable-on-interface', $tmp_ipaddress);
        $ipv6Enable->nodeValue = "yes";

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

            if( $this->isSubInterface() )
            {
                $xpath = $this->parentInterface->getXPath();
                $xpath .= "/layer3/units/entry[@name='" . $this->name . "']/ipv6/address";
            }
            else
                $xpath .= '/layer3/ipv6/address';

            $con->sendSetRequest($xpath, "<entry name='{$ip}'/>");
        }

        return $ret;
    }


    public function replaceIPv4ObjectByValue( $context, $address_obj )
    {
        if( strpos( $address_obj->value(), ":" ) !== FALSE )
        {
            PH::print_stdout( "      - value: ".$address_obj->value() );
            PH::print_stdout( "    - only IPv4 Address can be added with this function" );
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


    /**
     * return true if change was successful false if not (duplicate ipaddress?)
     * @param string $ip
     * @return EthernetInterface
     */
    public function addSubInterface($tag, $name = "")
    {
        if( $this->type != 'layer3' && $this->type != 'layer2' && $this->type != 'virtual-wire' )
            derr('cannot be requested from a ' . $this->type() . ' Interface');


        $tmp_xmlroot = $this->xmlroot;
        $typeNode = DH::findFirstElement($this->type, $tmp_xmlroot);
        $unit = DH::findFirstElementOrCreate('units', $typeNode);


        if( $this->type == 'layer3' )
            $xmlElement = DH::importXmlStringOrDie($this->owner->owner->xmlroot->ownerDocument, EthernetInterface::$templatexmlsubl3);
        else
            $xmlElement = DH::importXmlStringOrDie($this->owner->owner->xmlroot->ownerDocument, EthernetInterface::$templatexmlsub);

        #$newInterface = new EthernetInterface('tmp', $this->owner);
        $newInterface = new $this->classn('tmp', $this->owner);
        $newInterface->isSubInterface = TRUE;
        $newInterface->parentInterface = $this;
        $newInterface->type = &$this->type;
        $newInterface->load_sub_from_domxml($xmlElement);
        $this->subInterfaces[] = $newInterface;


        if( $name != "" )
        {
            #$newInterface->setName( $this->name.".".$tag );
            $newInterface->setName($name);
        }
        else
            $newInterface->setName($this->name . "." . $tag);
        $newInterface->setTag($tag);

        $unit->appendChild($xmlElement);

        $newInterface->owner = null;
        $this->owner->addSubinterfaceToStore($newInterface);

        return $newInterface;
    }


    /**
     * Add a ip to this interface, it must be passed as an object or string
     * @param Address $ip Object to be added, or String
     * @return EthernetInterface
     */
    public function API_addSubInterface($tag)
    {
        $ret = $this->addSubInterface($tag);

        if( is_object($ret) )
        {
            $con = findConnector($this);

            $xpath = $this->getXPath();
            $xpath .= "/" . $this->type() . "/units";

            $con->sendSetRequest($xpath, "<entry name='{$this->name}.{$tag}'><tag>{$tag}</tag></entry>");
        }

        return $ret;
    }

    /**
     * return true if change was successful false if not (duplicate rulename?)
     * @param string $name new name for the rule
     * @return bool
     */
    public function setLinkState($linkstate)
    {
        if( $this->isSubInterface() )
            return false;
        
        $linkstate_array = array( "auto","up", "down" );
        if( !in_array( $linkstate, $linkstate_array) )
            return false;

        if( $this->linkstate == $linkstate )
            return TRUE;

        $this->linkstate = $linkstate;

        $linkNode = DH::findFirstElementOrCreate( 'link-state', $this->xmlroot);
        $linkNode->textContent = $linkstate;

        return TRUE;

    }

    public function getLinkState()
    {
        if ($this->isSubInterface())
            return null;

        return $this->linkstate;
    }
    //Todo: (20180722)
    //---(also needed for vlan / loopback / tunnel interface)
    //- add Virtual Router
    //- add Security Zone
    //- add Virtual System
    //- add Comment (low prio)
    //- add Management Profile (low prio)


    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getEthernetIfStoreXPath() . "/entry[@name='" . $this->name . "']";

        if( $this->owner->owner->owner !== null && get_class( $this->owner->owner->owner ) == "Template" )
        {
            $templateXpath = $this->owner->owner->owner->getXPath();
            $str = $templateXpath.$str;
        }

        return $str;
    }

    public function referencedObjectRenamed($h, $old, $replaceType = 'name')
    {
        if( is_object($h) )
        {
            if( get_class( $h ) == "Address" )
            {
                //Text replace
                $qualifiedNodeName = '//*[text()="'.$old.'"]';
                $xpathResult = DH::findXPath( $qualifiedNodeName, $this->xmlroot);
                foreach( $xpathResult as $node )
                {
                    if( $replaceType == "name" )
                        $node->textContent = $h->name();
                    elseif( $replaceType == "value" )
                        $node->textContent = $h->value();
                }


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
                if( $replaceType == "name" )
                    $item->setAttribute('name', $h->name());
                elseif( $replaceType == "value" )
                    $item->setAttribute('name', $h->value());
                }
            }
            elseif( get_class( $h ) == "AggregateEthernetInterface" )
            {
                $this->setAE($h->name());
            }

            return;
        }

        mwarning("object is not part of this Tunnel Interface : {$h->toString()}");
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

    public function findorCreateAddressObject( $ip )
    {
        if( strpos($ip, "/") === FALSE ){
            $tmp_vsys = $this->owner->owner->network->findVsysInterfaceOwner($this->name());
            if( is_object($tmp_vsys) )
            {
                ##$object = $tmp_vsys->addressStore->find($ip);
                $object = $tmp_vsys->addressStore->findOrCreate($ip);
            }

            else
                derr("vsys for interface: " . $this->name() . " not found. \n", $this);

            if( is_object($object) )
                $object->addReference($this);
            else
                derr("objectname: " . $ip . " not found. Can not be added to interface.\n", $this);

            return $object->value();
        }
        return $ip;
    }

    public function removeAddressObjectReference( $ip )
    {
        if( strpos($ip, "/") === FALSE ){
            $tmp_vsys = $this->owner->owner->network->findVsysInterfaceOwner($this->name());
            $object = $tmp_vsys->addressStore->find($ip);

            if( is_object($object) )
                $object->removeReference($this);
            else
                mwarning("objectname: " . $ip . " not found. Can not be removed from interface.\n", $this);
        }
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**">
  <layer3>
    <ipv6>
      <neighbor-discovery>
        <router-advertisement>
          <enable>no</enable>
        </router-advertisement>
      </neighbor-discovery>
    </ipv6>
    <ndp-proxy>
      <enabled>no</enabled>
    </ndp-proxy>
    <lldp>
      <enable>no</enable>
    </lldp>
    <ip></ip>
  </layer3>
</entry>';

    static public $templatexmll2 = '<entry name="**temporarynamechangeme**">
    <layer2>
        <lldp>
        <enable>no</enable>
        </lldp>
    </layer2>
</entry>';

    static public $templatexmlvw = '<entry name="**temporarynamechangeme**">
<virtual-wire>
<lldp>
  <enable>no</enable>
</lldp>
</virtual-wire>
</entry>';

    static public $templatexmlae = '<entry name="**temporarynamechangeme**">
<aggregate-group>ae1</aggregate-group>
</entry>';


    static public $templatexmlsubl3 = '<entry name="**temporarynamechangeme**">
    <ipv6>
      <neighbor-discovery>
        <router-advertisement>
          <enable>no</enable>
        </router-advertisement>
      </neighbor-discovery>
    </ipv6>
    <ndp-proxy>
      <enabled>no</enabled>
    </ndp-proxy>
    <adjust-tcp-mss>
      <enable>no</enable>
    </adjust-tcp-mss>
    <tag></tag>
    <ip></ip>
</entry>';

    static public $templatexmlsub = '<entry name="**temporarynamechangeme**">
    <tag></tag>
</entry>';

}