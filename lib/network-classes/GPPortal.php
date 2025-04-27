<?php

/**
 * ISC License
 *
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

class GPPortal
{

    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;

    /** @var null|GPPortalStore */
    public $owner = null;

    private $isTmp = TRUE;

    private $localAddress_interface = NULL;
    private $localAddress_IPfamiliy = NULL;
    private $localAddress_ipv4 = NULL;
    private $localAddress_ipv6 = NULL;


    /**
     * @param string $name
     * @param GPPortalStore $owner
     */
    public function __construct($name, $owner, $fromXmlTemplate = FALSE, $type = 'layer3')
    {
        if( !is_string($name) )
            derr('name must be a string');

        $this->owner = $owner;

        /*
        if( $this->owner->owner->isVirtualSystem() )
        {
            if( get_class( $this->owner->owner->owner ) === "SharedGatewayStore" )
                $this->attachedInterfaces = new InterfaceContainer($this, $this->owner->owner->owner->owner->network);
            else
                $this->attachedInterfaces = new InterfaceContainer($this, $this->owner->owner->owner->network);
        }
        else
            $this->attachedInterfaces = new InterfaceContainer($this, null);
        */

        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();

            /*
            if( $type == "virtual-wire" )
                $doc->loadXML(self::$templatexmlvw, XML_PARSE_BIG_LINES);
            elseif( $type == "layer2" )
                $doc->loadXML(self::$templatexmll2, XML_PARSE_BIG_LINES);
            else
                $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElementOrDie('entry', $doc);

            if($this->owner->xmlroot === null)
                $this->owner->xmlroot = DH::createElement( $this->owner->owner->xmlroot, "GPPortal" );

            $rootDoc = $this->owner->xmlroot->ownerDocument;
            $this->xmlroot = $rootDoc->importNode($node, TRUE);

            #$this->owner = null;
            $this->setName($name);
            $this->owner = $owner;

            $this->load_from_domxml($this->xmlroot);

            */
        }

        $this->name = $name;
    }

    /**
     * @param string $newName
     * @return bool
     */
    public function setName($newName)
    {
        $ret = $this->setRefName($newName);

        if( $this->xmlroot === null )
            return $ret;

        $this->xmlroot->setAttribute('name', $newName);

        return $ret;
    }


    public function isTmp()
    {
        return $this->isTmp;
    }


    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;
        $this->isTmp = FALSE;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("GPPortal name not found\n", $xml);

        if( strlen($this->name) < 1 )
            derr("GPPortal name '" . $this->name . "' is not valid", $xml);

        $portal_config_Node = DH::findFirstElement('portal-config', $xml);
        if( $portal_config_Node !== FALSE )
        {
            $local_address_Node = DH::findFirstElement('local-address', $portal_config_Node);
            if ($local_address_Node !== FALSE)
            {
                $interface_Node = DH::findFirstElement('interface', $local_address_Node);
                if ($interface_Node !== FALSE)
                {
                    $this->localAddress_interface = $interface_Node->textContent;

                    $vsys_interfaces = $this->owner->owner->importedInterfaces->getAll();
                    foreach ($vsys_interfaces as $vsys_interface) {
                        if ($vsys_interface->name() == $this->localAddress_interface)
                            $vsys_interface->addReference($this);
                    }
                }


                $ip_address_family__Node = DH::findFirstElement('ip-address-family', $local_address_Node);
                if ($ip_address_family__Node !== FALSE)
                    $this->localAddress_IPfamiliy = $ip_address_family__Node->textContent;

                $ip_Node = DH::findFirstElement('ip', $local_address_Node);
                if ($ip_Node !== FALSE) {
                    $ipv4_Node = DH::findFirstElement('ipv4', $ip_Node);
                    if ($ipv4_Node !== FALSE)
                    {
                        $this->localAddress_ipv4 = $ipv4_Node->textContent;

                        $tmp_address = $this->owner->owner->addressStore->find($this->localAddress_ipv4);
                        if( $tmp_address !== False && $tmp_address !== NULL )
                            $tmp_address->addReference($this);
                    }

                    $ipv6_Node = DH::findFirstElement('ipv6', $ip_Node);
                    if ($ipv6_Node !== FALSE)
                    {
                        $this->localAddress_ipv6 = $ipv6_Node->textContent;

                        $tmp_address = $this->owner->owner->addressStore->find($this->localAddress_ipv6);
                        if( $tmp_address !== False && $tmp_address !== NULL )
                            $tmp_address->addReference($this);
                    }
                }
            }
        }
    }


    public function API_setName($newname)
    {
        if( !$this->isTmp() )
        {
            $c = findConnectorOrDie($this);
            $path = $this->getXPath();

            $this->setName($newname);
            $c->sendRenameRequest($path, $newname);
        }
        else
        {
            mwarning('this is a temporary object, cannot be renamed from API');
        }
    }

    public function getLocalAddress_interface()
    {
        return $this->localAddress_interface;
    }

    public function getLocalAddress_IPfamiliy()
    {
        return $this->localAddress_IPfamiliy;
    }

    public function getLocalAddress_ipv4()
    {
        return $this->localAddress_ipv4;
    }

    public function getLocalAddress_ipv6()
    {
        return $this->localAddress_ipv6;
    }

    public function referencedObjectRenamed($h, $old, $replaceType = 'name')
    {
        if( is_object($h))
        {
            if( get_class( $h ) == "Address"  )
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

    public function &getXPath()
    {
        if( $this->isTmp() )
            derr('no xpath on temporary objects');

        $str = $this->owner->getXPath() . "entry[@name='" . $this->name . "']";

        if( $this->owner->owner->owner->owner  !== null && get_class( $this->owner->owner->owner->owner ) == "Template" )
        {
            $templateXpath = $this->owner->owner->owner->owner->getXPath();
            $str = $templateXpath.$str;
        }

        return $str;
    }


    static protected $templatexml = '<entry name="**temporarynamechangemeL3**"><network><layer3></layer3></network></entry>';

}



