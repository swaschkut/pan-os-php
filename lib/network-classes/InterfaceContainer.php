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
 * Class InterfaceContainer
 * @property VirtualSystem|Zone|VirtualRouter|PbfRule|DosRule $owner
 * @property EthernetInterface[]|AggregateEthernetInterface[]|LoopbackInterface[]|IPsecTunnel[]|TunnelInterface[]|VlanInterface[] $o
 */
class InterfaceContainer extends ObjRuleContainer
{
    /** @var  NetworkPropertiesContainer */
    public $parentCentralStore;

    public $owner;

    /**
     * @param VirtualSystem|DeviceCloud|Zone|VirtualRouter|PbfRule|DoSRule|DHCP|SecureWebGateway $owner
     * @param NetworkPropertiesContainer $centralStore
     */
    public function __construct($owner, $centralStore)
    {
        $this->owner = $owner;
        $this->parentCentralStore = $centralStore;

        $this->o = array();
    }

    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $interfaceString = $node->textContent;

            if( isset($this->owner->owner->owner) && (
                get_class( $this->owner->owner->owner ) === "Snippet" ||
                get_class( $this->owner->owner->owner ) === "Container" ||
                get_class( $this->owner->owner->owner ) === "DeviceCloud" ||
                get_class( $this->owner->owner->owner ) === "DeviceOnPrem" )
            )
            {
                if( strpos( $interfaceString, "$" ) !== FALSE )
                {
                    //Todo: 20220801 swaschkut
                    // - Buckbeak snippet issue with loading config as now network part was defined
                    #DH::DEBUGprintDOMDocument($node);
                    print get_class( $this->owner->owner->owner ).": ".$this->owner->owner->owner->name()." | ";
                    print "Snippet interface variable: ".$interfaceString."\n";
                }
                else
                {
                    mwarning( "not a correct Snippet interface variable", $xml, false );
                }

            }
            else
            {
                $interface = $this->parentCentralStore->findInterfaceOrCreateTmp($interfaceString);
                $this->add($interface);
            }
        }
    }

    public function rewriteXML()
    {
        DH::clearDomNodeChilds($this->xmlroot);

        foreach( $this->o as $entry )
        {
            $tmp = DH::createElement($this->xmlroot, "member", $entry->name());
        }
        #PH::print_stdout(get_class($this->owner));
        #PH::print_stdout($this->owner->name());
    }

    /**
     * @return EthernetInterface[]|AggregateEthernetInterface[]|LoopbackInterface[]|IPsecTunnel[]|TunnelInterface[]|VlanInterface[]
     */
    public function interfaces()
    {
        return $this->o;
    }

    /**
     * @param EthernetInterface[]|AggregateEthernetInterface[]|LoopbackInterface[]|IPsecTunnel[]|TunnelInterface[]|VlanInterface[] $if
     * @param bool $caseSensitive
     * @return bool
     */
    public function hasInterface($if)
    {
        return $this->has($if);
    }

    /**
     * @param string $ifName
     * @param bool $caseSensitive
     * @return bool
     */
    public function hasInterfaceNamed($ifName, $caseSensitive = TRUE)
    {
        return $this->has($ifName, $caseSensitive);
    }

    /**
     * @param EthernetInterface|AggregateEthernetInterface|LoopbackInterface|IPsecTunnel|TunnelInterface|VlanInterface $if
     * @return bool
     */
    public function addInterface($if)
    {
        if( $if->type() == 'aggregate-group' )
        {
            mwarning("Interface of type: aggregate-group can not be added to a vsys.\n");
            return FALSE;
        }


        if( $this->has($if) )
            return FALSE;

        $this->o[] = $if;
        $if->addReference($this);

        if( get_class( $this->owner ) !== "SecureWebGateway" &&
            get_class( $this->owner ) !== "GPGatewayTunnel" &&
            get_class( $this->owner ) !== "GreTunnel" &&
            get_class( $this->owner ) !== "IPsecTunnel"
        )
        {
            if( $this->xmlroot === null )
            {
                $importRoot = DH::findFirstElementOrCreate('import', $this->owner->xmlroot);
                $networkRoot = DH::findFirstElementOrCreate('network', $importRoot);
                $this->xmlroot = DH::findFirstElementOrCreate('interface', $networkRoot);
            }

            DH::createElement($this->xmlroot, 'member', $if->name());
        }


        return TRUE;
    }


    /**
     * @param EthernetInterface|AggregateEthernetInterface|LoopbackInterface|IPsecTunnel|TunnelInterface|VlanInterface $if
     * @return bool
     */
    public function API_addInterface($if)
    {
        //Todo: is this working for zone ??????????
        if( $this->addInterface($if) )
        {
            $con = findConnectorOrDie($this);

            $xpath = $this->owner->getXPath() . '/import/network/interface';
            $importRoot = DH::findFirstElementOrDie('import', $this->owner->xmlroot);
            $networkRoot = DH::findFirstElementOrDie('network', $importRoot);
            $importIfRoot = DH::findFirstElementOrDie('interface', $networkRoot);

            $con->sendSetRequest($xpath, "<member>{$if->name()}</member>");
        }

        return TRUE;
    }

    public function removeInterface($if)
    {
        if( $if->type() == 'aggregate-group' )
        {
            mwarning("Interface of type: aggregate-group can not be added to a vsys.\n");
            return FALSE;
        }


        if( $this->has($if) )
        {
            $tmp_key = array_search($if, $this->o);
            if( $tmp_key !== FALSE )
            {
                unset($this->o[$tmp_key]);
            }

            $if->removeReference($this);

            //DH::createElement( $this->xmlroot, 'member', $if->name() );

            $this->rewriteXML();

            return TRUE;
        }

        return FALSE;
    }


}