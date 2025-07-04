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

class LoopbackInterface
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferenceableObject;

    protected $_ipv4Addresses = array();
    protected $_ipv6Addresses = array();

    /** @var string */
    public $type = 'loopback';

    public $owner;

    function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
    }


    public function isLoopbackType()
    {
        return TRUE;
    }

    /**
     * @return string
     */
    public function type()
    {
        return $this->type;
    }

    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("loopback name name not found\n");

        $ipNode = DH::findFirstElement('ip', $xml);
        if( $ipNode !== FALSE )
        {
            foreach( $ipNode->childNodes as $l3ipNode )
            {
                if( $l3ipNode->nodeType != XML_ELEMENT_NODE )
                    continue;

                $ip_string = $l3ipNode->getAttribute('name');
                if( !empty($ip_string) )
                {
                    if( strpos( $ip_string, "/" ) !== False )
                        $this->_ipv4Addresses[] = $ip_string;
                    else
                    {
                        //object
                        $this->_ipv4Addresses[] = $ip_string;
                    }
                }
            }
        }

        $ipv6Node = DH::findFirstElement('ipv6', $xml);
        if( $ipv6Node !== FALSE )
        {
            $ipNode = DH::findFirstElement('address', $ipv6Node);
            if( $ipNode !== FALSE )
            {
                foreach( $ipNode->childNodes as $l3ipNode )
                {
                    if( $l3ipNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $ip_string = $l3ipNode->getAttribute('name');
                    if( !empty($ip_string) )
                    {
                        if(filter_var($ip_string, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
                            $this->_ipv6Addresses[] = $ip_string;
                        else
                        {
                            //Todo: validation object
                            $this->_ipv6Addresses[] = $ip_string;
                        }
                    }
                }
            }
        }
    }

    public function getIPv4Addresses()
    {
        return $this->_ipv4Addresses;
    }

    public function getIPv6Addresses()
    {
        return $this->_ipv6Addresses;
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

        return TRUE;

    }

    public function referencedObjectRenamed($h, $old, $replaceType = 'name')
    {
        if( is_object($h) )
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
        /*
        if( $old === $new )
            return FALSE;

        $pos = array_search($old, $this->o, TRUE);

        if( $pos !== FALSE )
        {
            while( $pos !== FALSE )
            {
                unset($this->o[$pos]);
                $pos = array_search($old, $this->o, TRUE);
            }

            if( $new !== null && !$this->has($new->name()) )
            {
                $this->o[] = $new;
                $new->addReference($this);
            }
            $old->removeReference($this);

            if( $new === null || $new->name() != $old->name() )
                $this->rewriteXML();

            return TRUE;
        }
        #elseif( !$this->isDynamic() )
        #    mwarning("object is not part of this group: " . $old->toString());
        */


        return FALSE;
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

    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getLoopbackIfStoreXPath() . "/entry[@name='" . $this->name . "']";

        if( $this->owner->owner->owner !== null && get_class( $this->owner->owner->owner ) == "Template" )
        {
            $templateXpath = $this->owner->owner->owner->getXPath();
            $str = $templateXpath.$str;
        }

        return $str;
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**">
<adjust-tcp-mss>
  <enable>no</enable>
</adjust-tcp-mss>
<comment></comment>
</entry>';
}