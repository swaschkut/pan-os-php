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
 * Class SecureWebGateway
 * @property NetworkPropertiesContainer $owner
 */
class SecureWebGateway
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferenceableObject;

    public $owner;

    public $localInterface;
    public $upstreamInterface;

    public $enablement;

    public $type = null;

    /** @var null|string[]|DOMElement */
    public $gateway = 'notfound';

    /** @var null|string[]|DOMElement */
    public $protocol = 'notfound';
    /** @var null|string[]|DOMElement */



    /**
     * SecureWebGateway constructor.
     * @param string $name
     * @param PANConf|PanoramaConf $owner
     */
    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;

        $this->localInterface = new InterfaceContainer($this, $owner->network);
        $this->upstreamInterface = new InterfaceContainer($this, $owner->network);
    }

    /**
     * @param DOMElement $xml
     */
    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        $tmp_enablement = DH::findFirstElement('enablement', $xml);
        $tmp_explicit_proxy = DH::findFirstElement('explicit-proxy', $tmp_enablement);
        if( $tmp_explicit_proxy !== null && $tmp_explicit_proxy !== false )
        {
            $this->type = "explicit-web-gateway";
        }
        else
        {
            DH::DEBUGprintDOMDocument($tmp_enablement);
            mwarning( "SecureWebGateway type not yet implemented", null, false );
        }

        if( $this->type !== null )
        {
            $tmp_type = DH::findFirstElement($this->type, $xml);
            if( $tmp_type !== null )
            {
                /*
                <explicit-web-gateway>
                    <proxy-ip>
                       <ipv4>10.10.0.254/24</ipv4>
                    </proxy-ip>
                    <interface>ethernet1/2</interface>
                    <upstream-interface>loopback.1</upstream-interface>
                    <dns-proxy>DNS_proxy</dns-proxy>
                    <log-setting>default</log-setting>
                    <authentication-method>none</authentication-method>
                    <sni-dest-check>no</sni-dest-check>
                 </explicit-web-gateway>
                 */
                $interface = DH::findFirstElement('interface', $tmp_type);
                $tmpInterface = $this->owner->network->findInterface( $interface->textContent );
                $this->localInterface->addInterface( $tmpInterface );
                $tmpInterface->addReference( $this->localInterface );

                $upstream_interface = DH::findFirstElement('upstream-interface', $tmp_type);
                $tmpInterface = $this->owner->network->findInterface( $upstream_interface->textContent );
                $this->upstreamInterface->addInterface( $tmpInterface );
                $tmpInterface->addReference( $this->upstreamInterface );
            }
        }
    }

    public function isSecureWebProxyType()
    {
        return TRUE;
    }


    static public $templatexml = '<entry name="**temporarynamechangeme**">
    </entry>';

}