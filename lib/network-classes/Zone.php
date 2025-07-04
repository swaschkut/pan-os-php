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

class Zone
{

    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;

    /** @var null|ZoneStore */
    public $owner = null;

    private $isTmp = TRUE;

    public $externalVsys = array();

    public $type = 'tmp';


    /** @var InterfaceContainer */
    public $attachedInterfaces;

    public $zoneProtectionProfile = null;
    public $packetBufferProtection = FALSE;
    public $logsetting = null;

    public $userID = FALSE;

    public $_userAclInclude = array();
    public $_userAclExclude = array();
    public $_deviceAclInclude = array();
    public $_deviceAclExclude = array();


    const TypeTmp = 0;
    const TypeLayer3 = 1;
    const TypeExternal = 2;
    const TypeVirtualWire = 3;
    const TypeTap = 4;
    const TypeLayer2 = 5;
    const TypeTunnel = 6;

    static private $ZoneTypes = array(
        self::TypeTmp => 'tmp',
        self::TypeLayer3 => 'layer3',
        self::TypeExternal => 'external',
        self::TypeVirtualWire => 'virtual-wire',
        self::TypeTap => 'tap',
        self::TypeLayer2 => 'layer2',
        self::TypeTunnel => 'tunnel',
    );


    /**
     * @param string $name
     * @param ZoneStore $owner
     */
    public function __construct($name, $owner, $fromXmlTemplate = FALSE, $type = 'layer3')
    {
        if( !is_string($name) )
            derr('name must be a string');

        $this->owner = $owner;

        if( $this->owner->owner->isVirtualSystem() )
        {
            if( get_class( $this->owner->owner->owner ) === "SharedGatewayStore" )
                $this->attachedInterfaces = new InterfaceContainer($this, $this->owner->owner->owner->owner->network);
            else
                $this->attachedInterfaces = new InterfaceContainer($this, $this->owner->owner->owner->network);
        }
        else
            $this->attachedInterfaces = new InterfaceContainer($this, null);


        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();

            if( $type == "virtual-wire" )
                $doc->loadXML(self::$templatexmlvw, XML_PARSE_BIG_LINES);
            elseif( $type == "layer2" )
                $doc->loadXML(self::$templatexmll2, XML_PARSE_BIG_LINES);
            else
                $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElementOrDie('entry', $doc);

            if($this->owner->xmlroot === null)
                $this->owner->xmlroot = DH::createElement( $this->owner->owner->xmlroot, "zone" );

            $rootDoc = $this->owner->xmlroot->ownerDocument;
            $this->xmlroot = $rootDoc->importNode($node, TRUE);

            #$this->owner = null;
            $this->setName($name);
            $this->owner = $owner;

            $this->load_from_domxml($this->xmlroot);


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

    public function type()
    {
        return $this->type;
    }

    public function getExternalVsys()
    {
        if( $this->type() == "external" )
        {
            return reset($this->externalVsys );
        }

        return null;
    }

    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;
        $this->isTmp = FALSE;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("zone name not found\n", $xml);

        if( strlen($this->name) < 1 )
            derr("Zone name '" . $this->name . "' is not valid", $xml);

        $user_id_Node = DH::findFirstElement('enable-user-identification', $xml);
        if( $user_id_Node !== FALSE )
        {
            if( $user_id_Node->textContent === "yes" )
                $this->userID = TRUE;
        }

        $networkNode = DH::findFirstElement('network', $xml);
        if( $networkNode !== FALSE )
        {
            foreach( $networkNode->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE )
                    continue;

                if( $node->tagName == 'layer3' || $node->tagName == 'virtual-wire' )
                {
                    $this->type = $node->tagName;

                    if( $this->attachedInterfaces !== null )
                        $this->attachedInterfaces->load_from_domxml($node);
                }
                else if( $node->tagName == 'external' )
                {
                    $this->type = 'external';
                    foreach( $node->childNodes as $memberNode )
                    {
                        if( $memberNode->nodeType != XML_ELEMENT_NODE )
                            continue;
                        $this->externalVsys[$memberNode->textContent] = $memberNode->textContent;
                    }
                    if( $this->attachedInterfaces !== null )
                        $this->attachedInterfaces->load_from_domxml($node);
                }
                elseif( $node->tagName == 'tap' )
                {
                    $this->type = $node->tagName;
                }
                elseif( $node->tagName == 'tunnel' )
                {
                    $this->type = $node->tagName;
                }
                elseif( $node->tagName == 'layer2' )
                {
                    $this->type = $node->tagName;
                }
                elseif( $node->tagName == 'zone-protection-profile' )
                {
                    $this->zoneProtectionProfile = $node->textContent;
                }
                elseif( $node->tagName == 'log-setting' )
                {
                    $this->logsetting = $node->textContent;
                }
                elseif( $node->tagName == 'enable-packet-buffer-protection' )
                {

                }
                elseif( $node->tagName == 'net-inspection' )
                {

                }
                elseif( $node->tagName == 'prenat-identification' )
                {

                }
                else
                    mwarning("zone type: " . $node->tagName . " is not yet supported.", null, False);

            }
        }


        $userAclNode = DH::findFirstElement('user-acl', $xml);
        if( $userAclNode !== FALSE )
        {
            $includeListNode = DH::findFirstElement('include-list', $userAclNode);
            if( $includeListNode !== FALSE )
            {
                foreach( $includeListNode->childNodes as $node )
                {
                    if( $node->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $this->_userAclInclude[$node->textContent] = $node->textContent;
                    $this->ZoneInExludeList_addReference( $node->textContent );
                }
            }

            $excludeListNode = DH::findFirstElement('exclude-list', $userAclNode);
            if( $excludeListNode !== FALSE )
            {
                foreach( $excludeListNode->childNodes as $node )
                {
                    if( $node->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $this->_userAclExclude[$node->textContent] = $node->textContent;
                    $this->ZoneInExludeList_addReference( $node->textContent );
                }
            }
        }

        $deviceAclNode = DH::findFirstElement('device-acl', $xml);
        if( $deviceAclNode !== FALSE )
        {
            $includeListNode = DH::findFirstElement('include-list', $deviceAclNode);
            if( $includeListNode !== FALSE )
            {
                foreach( $includeListNode->childNodes as $node )
                {
                    if( $node->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $this->_deviceAclInclude[$node->textContent] = $node->textContent;
                    $this->ZoneInExludeList_addReference( $node->textContent );
                }
            }

            $excludeListNode = DH::findFirstElement('exclude-list', $deviceAclNode);
            if( $excludeListNode !== FALSE )
            {
                foreach ($excludeListNode->childNodes as $node)
                {
                    if ($node->nodeType != XML_ELEMENT_NODE)
                        continue;

                    $this->_deviceAclExclude[$node->textContent] = $node->textContent;
                    $this->ZoneInExludeList_addReference( $node->textContent );
                }
            }
        }
    }

    private function ZoneInExludeList_addReference( $objectName )
    {
        $findobject = $this->owner->owner->addressStore->find($objectName);
        if( is_object($findobject) )
            $findobject->addReference($this);
    }

    /**
     * @param $objectToAdd Zone
     * @param $displayOutput bool
     * @param $skipIfConflict bool
     * @param $outputPadding string|int
     */
    public function addObjectWhereIamUsed($objectToAdd, $displayOutput = FALSE, $outputPadding = '', $skipIfConflict = FALSE)
    {
        foreach( $this->refrules as $ref )
        {
            $refClass = get_class($ref);
            if( $refClass == 'ZoneRuleContainer' )
            {
                /** @var ZoneRuleContainer $ref */
                $ownerClass = get_class($ref->owner);

                if( $ownerClass == 'SecurityRule' )
                {
                    $ref->addZone($objectToAdd);
                }
                else
                {
                    derr("unsupported owner class '{$ownerClass}'");
                }
            }
            else
                derr("unsupported class '{$refClass}");
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

    /**
     * @param string $newZPP
     * @return bool
     */
    public function setZPP($newZPP)
    {
        if( $newZPP == "none" )
            $this->zoneProtectionProfile = null;
        else
            $this->zoneProtectionProfile = $newZPP;


        $valueRoot = DH::findFirstElement('network', $this->xmlroot);
        $zppRoot = DH::findFirstElementOrCreate('zone-protection-profile', $valueRoot);


        if( $newZPP != "none" )
            DH::setDomNodeText($zppRoot, $this->zoneProtectionProfile);
        else
            $valueRoot->removeChild($zppRoot);

        return TRUE;
    }

    /**
     * @param string $newZPP
     * @return bool
     */
    public function API_setZPP($newZPP)
    {
        if( !$this->setZPP($newZPP) )
            return FALSE;

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        if( $newZPP != 'none' )
        {
            $valueRoot = DH::findFirstElement('network', $this->xmlroot);
            $zppRoot = DH::findFirstElementOrCreate('zone-protection-profile', $valueRoot);
            $c->sendSetRequest($xpath . "/network", DH::dom_to_xml($zppRoot, -1, FALSE));
        }
        else
            $c->sendEditRequest($xpath, DH::dom_to_xml($this->xmlroot, -1, FALSE));

        return TRUE;
    }

    /**
     * @param string $newZPP
     * @return bool
     */
    public function setExternalVsys($vsys)
    {
        /** @var VirtualSystem $vsys */
        if( is_object($vsys) )
            $vsys_name = $vsys->name();
        else
            $vsys_name = $vsys;


        $valueRoot = DH::findFirstElement('network', $this->xmlroot);
        $externalRoot = DH::findFirstElementOrCreate('external', $valueRoot);
        $externalMemberRoot = DH::findFirstElementOrCreate('member', $externalRoot);
        $externalMemberRoot->textContent = $vsys_name;

        $this->externalVsys = array();
        $this->externalVsys[$vsys_name] = $vsys_name;

        return TRUE;
    }

    /**
     * @param string $newZPP
     * @return bool
     */
    public function useridEnable( $bool)
    {
        if( $bool )
            $this->userID = TRUE;
        else
            $this->userID = FALSE;

        $valueRoot = DH::findFirstElement('enable-user-identification', $this->xmlroot);

        if( $valueRoot !== FALSE )
        {
            if( $bool )
                DH::setDomNodeText($valueRoot, "yes");
            else
                $this->xmlroot->removeChild($valueRoot);
        }
        elseif( $bool )
        {
            $valueRoot = DH::findFirstElementOrCreate('enable-user-identification', $this->xmlroot);
            DH::setDomNodeText($valueRoot, "yes");
        }

        return TRUE;
    }

    /**
     * @param string $newZPP
     * @return bool
     */
    public function API_useridEnable($bool)
    {
        if( !$this->useridEnable($bool) )
            return FALSE;

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        $c->sendEditRequest($xpath, DH::dom_to_xml($this->xmlroot, -1, FALSE));

        return TRUE;
    }

    /**
     * @param bool
     * @return bool
     */
    public function setPaketBufferProtection($bool)
    {
        if( $bool )
            $this->packetBufferProtection = TRUE;
        else
            $this->packetBufferProtection = FALSE;


        $valueRoot = DH::findFirstElement('network', $this->xmlroot);
        $zppRoot = DH::findFirstElementOrCreate('enable-packet-buffer-protection', $valueRoot);


        if( $this->packetBufferProtection )
            DH::setDomNodeText($zppRoot, "yes");
        else
            $valueRoot->removeChild($zppRoot);

        return TRUE;
    }

    /**
     * @param bool
     * @return bool
     */
    public function API_setPaketBufferProtection($bool)
    {
        if( !$this->setPaketBufferProtection($bool) )
            return FALSE;

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        if( $bool )
        {
            $valueRoot = DH::findFirstElement('network', $this->xmlroot);
            $zppRoot = DH::findFirstElementOrCreate('enable-packet-buffer-protection', $valueRoot);
            $c->sendSetRequest($xpath . "/network", DH::dom_to_xml($zppRoot, -1, FALSE));
        }
        else
            $c->sendEditRequest($xpath, DH::dom_to_xml($this->xmlroot, -1, FALSE));

        return TRUE;
    }
    //                <enable-packet-buffer-protection>yes</enable-packet-buffer-protection>

    /**
     * @param string $newLogSetting
     * @return bool
     */
    public function setLogSetting($newLogSetting)
    {
        if( $newLogSetting == "none" )
            $this->logsetting = null;
        else
            $this->logsetting = $newLogSetting;


        $valueRoot = DH::findFirstElement('network', $this->xmlroot);
        $logsettingRoot = DH::findFirstElementOrCreate('log-setting', $valueRoot);


        if( $newLogSetting != "none" )
            DH::setDomNodeText($logsettingRoot, $this->logsetting);
        else
            $valueRoot->removeChild($logsettingRoot);

        return TRUE;
    }

    /**
     * @param string $newLogSetting
     * @return bool
     */
    public function API_setLogSetting($newLogSetting)
    {
        if( !$this->setLogSetting($newLogSetting) )
            return FALSE;

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        if( $newLogSetting != 'none' )
        {
            $valueRoot = DH::findFirstElement('network', $this->xmlroot);
            $logsettingRoot = DH::findFirstElementOrCreate('log-setting', $valueRoot);
            $c->sendSetRequest($xpath . "/network", DH::dom_to_xml($logsettingRoot, -1, FALSE));
        }
        else
            $c->sendEditRequest($xpath, DH::dom_to_xml($this->xmlroot, -1, FALSE));

        return TRUE;
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

            return;
        }

        mwarning("object is not part of this Zone : {$h->toString()}");
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

    public static function getZoneTypes()
    {
        return self::$ZoneTypes;
    }

    static protected $templatexml = '<entry name="**temporarynamechangemeL3**"><network><layer3></layer3></network></entry>';
    static protected $templatexmlvw = '<entry name="**temporarynamechangemeVW**"><network><virtual-wire></virtual-wire></network></entry>';
    static protected $templatexmll2 = '<entry name="**temporarynamechangemeL2**"><network><layer2></layer2></network></entry>';

}



