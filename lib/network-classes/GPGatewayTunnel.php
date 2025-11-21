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

/**
 * Class GPGatewayTunnel
 * @property GPGatewayTunnelStore $owner
 */
class GPGatewayTunnel
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferenceableObject;

    public $owner;

    public $localInterface;
    public $tunnelInterface;


    public $type = 'notfound';


    public $proposal = null;
    public $interface = null;
    public $localIPv4 = null;
    public $localIPv6 = null;

    public $disabled = "no";

    /**
     * GPGatewayTunnel constructor.
     * @param string $name
     * @param GPGatewayTunnelStore $owner
     */
    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;

        $this->localInterface = new InterfaceContainer($this, $owner->owner->network);
        $this->tunnelInterface = new InterfaceContainer($this, $owner->owner->network);
    }

    /**
     * @param DOMElement $xml
     */
    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("tunnel name not found\n");

        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 )
                continue;

            if( $node->nodeName == 'local-address' )
            {
                $tmp = DH::findFirstElement('interface', $node);
                if( $tmp !== FALSE )
                {
                    $tmpInterface = $this->owner->owner->network->findInterface( $tmp->textContent );
                    if( $tmpInterface !== null )
                    {
                        $tmpInterface->addReference( $this->localInterface );

                        $this->localInterface->addInterface( $tmpInterface );
                    }
                    else
                    {
                        if( isset($this->owner->owner->owner)
                            && get_class($this->owner->owner->owner) == 'Template' || get_class($this->owner->owner->owner) == 'TemplateStack'
                        )
                            $tmp_owner = get_class($this->owner->owner->owner). " name: ".$this->owner->owner->owner->name();
                        else
                            $tmp_owner = get_class($this->owner->owner). " name: ".$this->owner->owner->name();

                        mwarning( "Interface: ".$tmp->textContent." not found for GPGatewayTunnel: ".$this->name()." in owner: ".$tmp_owner, null, false );
                    }

                }

                $tmp = DH::findFirstElement('ip', $node);
                if( $tmp !== FALSE )
                {
                    $tmp_interfaces = $this->localInterface->interfaces();

                    if( isset($tmp_interfaces[0]) )
                    {
                        /** @var EthernetInterface $tmp_usedInterface */
                        $tmp_usedInterface = $tmp_interfaces[0];

                        /** @var VirtualSystem $tmp_vsys */
                        $tmp_vsys = $tmp_usedInterface->importedByVSYS;

                        $tmp_ip = DH::findFirstElement('ipv4', $tmp);
                        if( $tmp_ip !== FALSE )
                        {
                            $this->localIPv4 = $tmp_ip->textContent;

                            if( $tmp_vsys !== null )
                            {
                                $tmp_address = $tmp_vsys->addressStore->find($this->localIPv4);
                                if( $tmp_address !== FALSE && $tmp_address !== NULL )
                                    $tmp_address->addReference( $this );
                            }
                        }


                        $tmp_ip = DH::findFirstElement('ipv6', $tmp);
                        if( $tmp_ip !== FALSE )
                        {
                            $this->localIPv6 = $tmp_ip->textContent;

                            if( $tmp_vsys !== null )
                            {
                                $tmp_address = $tmp_vsys->addressStore->find($this->localIPv6);
                                if ($tmp_address !== FALSE && $tmp_address !== NULL)
                                    $tmp_address->addReference($this);
                            }
                        }
                    }
                }
            }

            if( $node->nodeName == 'tunnel-interface' )
            {
                $tmpInterface = $this->owner->owner->network->findInterface( $node->textContent );
                if( $tmpInterface !== FALSE && $tmpInterface !== NULL )
                {
                    $tmpInterface->addReference( $this->tunnelInterface );
                    $this->tunnelInterface->addInterface( $tmpInterface );
                }
            }

            if( $node->nodeName == 'disabled' )
            {
                $this->disabled = $node->textContent;
            }
        }
    }


    /**
     * return true if change was successful false if not (duplicate GPGatewayTunnel name?)
     * @param string $name new name for the GPGatewayTunnel
     * @return bool
     */
    public function setName($name)
    {
        if( $this->name == $name )
            return TRUE;

        if( preg_match('/[^0-9a-zA-Z_\-\s]/', $name) )
        {
            $name = preg_replace('/[^0-9a-zA-Z_\-\s]/', "", $name);
            PH::print_stdout( " *** new name: " . $name );
            #mwarning( 'Name will be replaced with: '.$name."\n" );
        }


        /* TODO: 20180331 finalize needed
        if( isset($this->owner) && $this->owner !== null )
        {
            if( $this->owner->isRuleNameAvailable($name) )
            {
                $oldname = $this->name;
                $this->name = $name;
                $this->owner->ruleWasRenamed($this,$oldname);
            }
            else
                return false;
        }
*/
        if( $this->name != "**temporarynamechangeme**" )
            $this->setRefName($name);

        $this->name = $name;
        $this->xmlroot->setAttribute('name', $name);

        return TRUE;
    }


    public function setInterface($interface)
    {
        if( $this->interface == $interface )
            return TRUE;

        $this->interface = $interface;

        $tmp_ipsec_entry = DH::findFirstElementOrCreate('tunnel-interface', $this->xmlroot);
        DH::setDomNodeText($tmp_ipsec_entry, $interface);

        $tmp_interface = $this->owner->owner->network->findInterface($interface);
        $tmp_interface->addReference($this);

        return TRUE;
    }

    public function referencedObjectRenamed($h, $old, $replaceType = 'name')
    {
        if( get_class($h) == "EthernetInterface" )
        {
            if( $this->interface !== $h->name() )
            {
                //why set it again????
                $this->interface = $h->name();

                $this->rewriteInterface_XML();

                return;
            }
        }
        elseif( get_class( $h ) == "Address" )
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

        mwarning("object is not part of this object : {$h->toString()}", null, false);
    }

    public function rewriteInterface_XML()
    {
        $tmp_ipsec_entry = DH::findFirstElementOrCreate('tunnel-interface', $this->xmlroot);
        DH::setDomNodeText($tmp_ipsec_entry, $this->interface);
        #DH::createOrResetElement( $this->xmlroot, 'interface', $this->_interface->name());
    }
    public function getInterface()
    {
        return $this->interface;
    }


    public function isGPGatewayTunnelType()
    {
        return TRUE;
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

    static public $templatexml = '<entry name="**temporarynamechangeme**">
              <local-address></local-address>
              <tunnel-interface></tunnel-interface>
    </entry>';

}