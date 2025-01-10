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

class EDL
{
    use AddressCommon;
    use PathableName;
    use XmlConvertible;

    /** @var EDLStore|null */
    public $owner = null;

    public $type = null;
    public $recurring = null;
    public $url = null;

    /**
     * @param string $name
     * @param EDLStore|null $owner
     * @param bool $fromXmlTemplate
     */
    public function __construct($name, $owner, $fromXmlTemplate = FALSE)
    {
        $this->name = $name;


        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();
            $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElementOrDie('entry', $doc);

            $rootDoc = $owner->xmlroot->ownerDocument;

            $this->xmlroot = $rootDoc->importNode($node, TRUE);
            $this->load_from_domxml($this->xmlroot);

            $this->setName($name);
        }

        $this->owner = $owner;
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

    /**
     * @param string $newName
     */
    public function API_setName($newName)
    {
        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        $this->setName($newName);

        if( $c->isAPI() )
            $c->sendRenameRequest($xpath, $newName);
    }


    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getEDLStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
    }


    public function isTmp()
    {
        if( $this->xmlroot === null )
            return TRUE;
        return FALSE;
    }


    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("edl name not found\n", $xml);


        if( strlen($this->name) < 1 )
            derr("edl name '" . $this->name . "' is not valid.", $xml);

        $tmp_type_node = DH::findFirstElement('type', $xml);
        $tmp_type = DH::firstChildElement($tmp_type_node);
        if( $tmp_type !== FALSE )
        {
            $this->type = $tmp_type->nodeName;
            $supportedType = array('ip', 'domain', 'url', 'imei', 'imsi', 'predefined-ip', 'predefined-url');
            //todo: supported type: ip/domain/url/imei/imsi


            $tmp_recurring_node = DH::findFirstElement('recurring', $tmp_type);
            if ($tmp_recurring_node != False)
            {
                $tmp_recurring = DH::firstChildElement($tmp_recurring_node);
                if ($tmp_recurring != False)
                    $this->recurring = $tmp_recurring->nodeName;
            }

            $tmp_url_node = DH::findFirstElement('url', $tmp_type);
            if ($tmp_url_node != False)
                $this->url = $tmp_url_node->textContent;

            /*
            +<entry name="EDL_waschkut_IP">
            + <type>
            +  <ip>
            +   <recurring>
            +    <five-minute/>
            +   </recurring>
            +   <url>https://www.waschkut.de/PAN/EDL_domain.txt</url>
            +  </ip>
            + </type>
            +</entry>
            +<entry name="EDL_ip_list">
            + <type>
            +  <ip>
            +   <recurring>
            +    <five-minute/>
            +   </recurring>
            +   <url>http://</url>
            +  </ip>
            + </type>
            +</entry>
            +<entry name="EDL_url_list">
            + <type>
            +  <url>
            +   <recurring>
            +    <hourly/>
            +   </recurring>
            +   <url>http://</url>
            +  </url>
            + </type>
            +</entry>
            +<entry name="EDL_domain_list">
            + <type>
            +  <domain>
            +   <recurring>
            +    <hourly/>
            +   </recurring>
            +   <description>test</description>
            +   <url>https://www.waschkut.de/urllist.txt</url>
            +  </domain>
            + </type>
            +</entry>
            +<entry name="EDL_subscriber_identity_list">
            + <type>
            +  <imsi>
            +   <recurring>
            +    <five-minute/>
            +   </recurring>
            +   <url>http://</url>
            +  </imsi>
            + </type>
            +</entry>
            +<entry name="EDL_equipment_identity_list">
            + <type>
            +  <imei>
            +   <recurring>
            +    <five-minute/>
            +   </recurring>
            +   <url>http://</url>
            +  </imei>
            + </type>
            +</entry>
             */
            //todo - implement EDL reading type IP / FQDN
            # EDL take precedence over address / address-group  by name
            //todo: EDL of type IP-LIST can be used in security rule source/destination
        }
    }




    static public $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

    public function isEDL()
    {
        return TRUE;
    }


    /**
     * @param $otherObject EDL
     * @return bool
     */
    public function equals($otherObject)
    {
        if( !$otherObject->isEDL() )
            return FALSE;

        if( $otherObject->name != $this->name )
            return FALSE;

        return $this->sameValue($otherObject);
    }

    public function sameValue(EDL $otherObject)
    {
        if( $this->isTmp() && !$otherObject->isTmp() )
            return FALSE;

        if( $otherObject->isTmp() && !$this->isTmp() )
            return FALSE;


        return TRUE;
    }

    public function type()
    {
        if( $this->isTmp() )
            return null;


        return $this->type;
    }
    public function url()
    {
        return $this->url;
    }

    public function recurring()
    {
        return $this->recurring;
    }
}

