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
 * Class AddressRuleContainer
 * @property Address[]|AddressGroup[] $o
 * @property Rule|SecurityRule|NatRule $owner
 *
 * @method Address[]|AddressGroup[] getMembersDiff(AddressRuleContainer $otherObject)
 * @method displayMembersDiff(AddressRuleContainer $otherObject, $indent = 0, $toString = FALSE)
 *
 */
class AddressRuleContainer extends ObjRuleContainer
{
    /** @var null|AddressStore */
    public $parentCentralStore = null;

    public $fasthashcomp;

    // TODO implement 'multicast' support

    public function __construct($owner)
    {
        $this->owner = $owner;
    }


    /**
     * @param Address|AddressGroup|EDL $Obj
     * @return bool
     */
    public function addObject(Address|AddressGroup|EDL $Obj): bool
    {
        $this->fasthashcomp = null;

        $ret = parent::add($Obj);

        if( $ret && $this->xmlroot !== null )
        {
            if( count($this->o) > 1 )
            {
                if( $this->name == 'snathosts' && $this->owner->sourceNatTypeIs_Static() )
                {
                    if( $Obj->isEDL() )
                        return FALSE;
                    DH::createElement($this->xmlroot, 'translated-address', $Obj->name());
                }
                else
                    DH::createElement($this->xmlroot, 'member', $Obj->name());
            }
            else
            {
                $this->rewriteXML();
            }

            if( $this->name == 'snathosts' )
            {
                if( $Obj->isEDL() )
                    return FALSE;

                $this->owner->rewriteSNAT_XML();

                //what else need to be done?????
                //if more snathost are available what to do???
            }

        }

        return $ret;
    }

    /**
     * @param Address|AddressGroup|EDL $Obj
     * @return bool
     * @throws Exception
     */
    public function API_add(Address|AddressGroup|EDL $Obj): bool
    {
        if( $this->addObject($Obj) )
        {
            $con = findConnectorOrDie($this);

            if( $this->name == 'snathosts' )
            {
                $xpath = $this->owner->getXPath() . '/source-translation';
                $sourceNatRoot = DH::findFirstElementOrDie('source-translation', $this->owner->xmlroot);
                if( $con->isAPI() )
                    $con->sendEditRequest($xpath, DH::dom_to_xml($sourceNatRoot, -1, FALSE));
            }
            else
            {
                $xpath = $this->getXPath();

                if( count($this->o) == 1 )
                {
                    if( $con->isAPI() )
                        $con->sendEditRequest($xpath, $this->getXmlText_inline());
                }
                else
                    if( $con->isAPI() )
                        $con->sendSetRequest($xpath, "<member>{$Obj->name()}</member>");
            }

            return TRUE;
        }

        return FALSE;
    }


    /**
     * @param Address|AddressGroup|EDL $Obj
     * @param bool $rewriteXml
     * @param bool $forceAny
     * @param null $context
     * @return bool  True if Zone was found and removed. False if not found.
     */
    public function remove($Obj, bool $rewriteXml = TRUE, bool $forceAny = FALSE, $context = null): bool
    {
        $count = count($this->o);

        $ret = parent::remove($Obj);

        if( $ret && $count == 1 && !$forceAny )
        {
            $this->owner->setDisabled(true);
            /*
            $string = "you are trying to remove last Object from a rule which will set it to ANY, please use forceAny=true for object: " . $this->toString();
            if( $context === null )
                derr( $string );

            PH::ACTIONstatus( $context, 'skipped', $string);
            return false;
            */
        }

        if( $ret && $rewriteXml )
        {
            $this->rewriteXML();
        }
        return $ret;
    }

    /**
     * @param Address|AddressGroup|EDL $Obj
     * @param bool $forceAny
     * @param null $context
     * @return bool
     * @throws Exception
     */
    public function API_remove(Address|AddressGroup|EDL $Obj, bool $forceAny = FALSE, $context = null): bool
    {
        if( $this->remove($Obj, TRUE, $forceAny, $context) )
        {
            $con = findConnectorOrDie($this);

            if( $this->name == 'snathosts' )
            {
                if( $Obj->isEDL() )
                    return FALSE;
                
                $xpath = $this->owner->getXPath() . '/source-translation';
                $sourceNatRoot = DH::findFirstElementOrDie('source-translation', $this->owner->xmlroot);
                if( $con->isAPI() )
                    $con->sendEditRequest($xpath, DH::dom_to_xml($sourceNatRoot, -1, FALSE));
            }
            else
            {
                $xpath = $this->getXPath();

                if( count($this->o) == 0 )
                {
                    if( $con->isAPI() )
                        $con->sendEditRequest($xpath, $this->getXmlText_inline());
                    return TRUE;
                }

                $xpath = $xpath . "/member[text()='" . $Obj->name() . "']";
                if( $con->isAPI() )
                    $con->sendDeleteRequest($xpath);
            }

            return TRUE;
        }

        return FALSE;
    }


    public function API_sync( $new = false ): void
    {
        $con = findConnectorOrDie($this);

        if( $con->isAPI() )
        {
            if( $this->name == 'snathosts' )
            {
                $xpath = $this->owner->getXPath() . '/source-translation';
                $sourceNatRoot = DH::findFirstElementOrDie('source-translation', $this->owner->xmlroot);
                if( $con->isAPI() )
                    $con->sendEditRequest($xpath, DH::dom_to_xml($sourceNatRoot, -1, FALSE));
            }
            else
            {
                $xpath = &$this->getXPath();
                if( $con->isAPI() )
                    $con->sendEditRequest($xpath, $this->getXmlText_inline());
            }
        }
        elseif( $con->isSaseAPI() )
        {
            if( $new )
                $con->sendCreateRequest($this);
            else
                $con->sendPUTRequest($this);
        }


    }

    public function setAny(): void
    {
        $this->removeAll();

        $this->rewriteXML();
    }

    /**
     * @param Address|AddressGroup|string $object can be Address|AddressGroup object or object name (string)
     * @param bool $caseSensitive
     * @return bool
     */
    public function has($object, $caseSensitive = TRUE): bool
    {
        return parent::has($object, $caseSensitive);
    }

    /**
     * return true/false based if object is EDL or not
     * @return bool
     */
    public function hasEDL(): bool
    {
        foreach( $this->o as $member)
        {
            if( get_class($member) == "EDL" )
                return TRUE;
        }
        return FALSE;
    }

    /**
     * return an array with all objects
     * @return Address[]|AddressGroup[]
     */
    public function members(): array
    {
        return $this->o;
    }

    /**
     * return an array with all objects
     * @return Address[]|AddressGroup[]
     */
    public function all(): array
    {
        return $this->o;
    }


    /**
     * should only be called from a Rule constructor
     * @param DOMElement $xml
     * @throws Exception
     * @ignore
     */
    public function load_from_domxml(DOMElement $xml): void
    {
        //PH::print_stdout( "started to extract '".$this->toString()."' from xml" );
        $this->xmlroot = $xml;
        $i = 0;
        foreach( $xml->childNodes as $node )
        {
            /** @var DOMElement $node */
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $content = $node->textContent;

            if( $i == 0 && $content == 'any' )
            {
                return;
            }

            if( strlen($content) < 1 )
            {
                derr('this container has members with empty name!', $node);
            }

            //Todo: 20250329 swaschkut
            //this is now included in parentCentralStroe - which is AddressStore
            #$f = $this->owner->owner->owner->EDLStore->find($content, $this);
            #if( $f === null )
            $f = $this->parentCentralStore->findOrCreate($content, $this);
            $this->o[] = $f;
            $i++;
        }
    }


    public function rewriteXML(): void
    {
        if( $this->name == 'snathosts' )
        {
            $this->owner->rewriteSNAT_XML();
            return;
        }

        if( $this->xmlroot === null )
            return;

        DH::Hosts_to_xmlDom($this->xmlroot, $this->o);
    }

    public function toString_inline(): string
    {
        if( count($this->o) == 0 )
        {
            return '**ANY**';
        }

        return parent::toString_inline();
    }

    /**
     * return 0 if not match, 1 if this object is fully included in $network, 2 if this object is partially matched by $ref.
     * Always return 0 (not match) if this is object = ANY
     * @param IP4Map|string $network ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
     * @return int
     */
    public function includedInIP4Network(IP4Map|string $network): int
    {
        if( is_object($network) )
            $netStartEnd = $network;
        else
            $netStartEnd = IP4Map::mapFromText($network);

        if( count($this->o) == 0 )
            return 0;

        $result = -1;

        foreach( $this->o as $o )
        {
            if( get_class($o) === "EDL" )
                continue;

            if( $o->isRegion() )
                continue;

            $localResult = $o->includedInIP4Network($netStartEnd);
            if( $localResult == 1 )
            {
                if( $result == 2 )
                    continue;
                if( $result == -1 )
                    $result = 1;
                else if( $result == 0 )
                    return 2;
            }
            elseif( $localResult == 2 )
            {
                return 2;
            }
            elseif( $localResult == 0 )
            {
                if( $result == -1 )
                    $result = 0;
                else if( $result == 1 )
                    return 2;
            }
        }

        return $result;
    }

    /**
     * return 0 if not match, 1 if this object is fully included in $network, 2 if this object is partially matched by $ref.
     * Always return 0 (not match) if this is object = ANY
     * @param IP6Map|string $network ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
     * @return int
     */
    public function includedInIP6Network(IP6Map|string $network): int
    {
        if( is_object($network) )
            $netStartEnd = $network;
        else
            $netStartEnd = IP6Map::mapFromText($network);

        if( count($this->o) == 0 )
            return 0;

        $result = -1;

        foreach( $this->o as $o )
        {
            if( get_class($o) === "EDL" )
                continue;

            if( $o->isRegion() )
                continue;

            $localResult = $o->includedInIP6Network($netStartEnd);
            if( $localResult == 1 )
            {
                if( $result == 2 )
                    continue;
                if( $result == -1 )
                    $result = 1;
                else if( $result == 0 )
                    return 2;
            }
            elseif( $localResult == 2 )
            {
                return 2;
            }
            elseif( $localResult == 0 )
            {
                if( $result == -1 )
                    $result = 0;
                else if( $result == 1 )
                    return 2;
            }
        }

        return $result;
    }

    /**
     * return 0 if not match, 1 if $network is fully included in this object, 2 if $network is partially matched by this object.
     * @param $network IP4Map|string ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
     * @return int
     */
    public function includesIP4Network(IP4Map|string $network): int
    {
        if( is_object($network) )
            $netStartEnd = $network;
        else
            $netStartEnd = IP4map::mapFromText($network);

        if( count($this->o) == 0 )
            return 0;

        $result = -1;

        foreach( $this->o as $o )
        {
            if( get_class($o) === "EDL" )
                continue;

            if( $o->isRegion() )
                continue;

            $localResult = $o->includesIP4Network($netStartEnd);
            if( $localResult == 1 )
            {
                return 1;
            }
            elseif( $localResult == 2 )
            {
                $result = 2;
            }
            elseif( $localResult == 0 )
            {
                if( $result == -1 )
                    $result = 0;
            }
        }

        return $result;
    }

    /**
     * return 0 if not match, 1 if $network is fully included in this object, 2 if $network is partially matched by this object.
     * @param $network IP6Map|string ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
     * @return int
     */
    public function includesIP6Network(IP6Map|string $network): int
    {
        if( is_object($network) )
            $netStartEnd = $network;
        else
            $netStartEnd = IP6map::mapFromText($network);

        if( count($this->o) == 0 )
            return 0;

        $result = -1;

        foreach( $this->o as $o )
        {
            if( get_class($o) === "EDL" )
                continue;

            if( $o->isRegion() )
                continue;

            $localResult = $o->includesIP6Network($netStartEnd);
            if( $localResult == 1 )
            {
                return 1;
            }
            elseif( $localResult == 2 )
            {
                $result = 2;
            }
            elseif( $localResult == 0 )
            {
                if( $result == -1 )
                    $result = 0;
            }
        }

        return $result;
    }



    /**
     * Merge this set of objects with another one (in paramater). If one of them is 'any'
     * then the result will be 'any'.
     *
     */
    public function merge($other): void
    {
        $this->fasthashcomp = null;

        // This is Any ? then merge = Any
        if( count($this->o) == 0 )
            return;

        // this other is Any ? then this one becomes Any
        if( count($other->o) == 0 )
        {
            $this->setAny();
            return;
        }

        foreach( $other->o as $s )
        {
            $this->addObject($s);
        }

    }

    /**
     * To determine if a container has all the zones from another container. Very useful when looking to compare similar rules.
     * @param AddressRuleContainer $other
     * @param bool $anyIsAcceptable
     * @param array $foundAddress
     * @return boolean true if Zones from $other are all in this store
     */
    public function includesContainer(AddressRuleContainer $other, bool $anyIsAcceptable = TRUE, array &$foundAddress = array()): bool
    {
        $tmp_return = TRUE;

        if( !$anyIsAcceptable )
        {
            if( $this->count() == 0 || $other->count() == 0 )
                return FALSE;
        }

        if( $this->count() == 0 )
            return TRUE;

        if( $other->count() == 0 )
            return FALSE;

        $objects = $other->members();

        foreach( $objects as $o )
        {
            if( !$this->has($o) )
                $tmp_return = FALSE;
            else
                $foundAddress[] = $o;
        }

        if( !$tmp_return )
            return FALSE;

        return TRUE;

    }

    public function API_setAny(): void
    {
        $this->setAny();
        $xpath = &$this->getXPath();
        $con = findConnectorOrDie($this);

        if( $con->isAPI() )
        {
            $con->sendDeleteRequest($xpath);
            $con->sendSetRequest($xpath, '<member>any</member>');
        }
    }


    /**
     * @return string
     */
    public function &getXPath(): string
    {
        $str = $this->owner->getXPath() . '/' . $this->name;

        return $str;
    }

    /**
     * @return bool
     */
    public function isAny(): bool
    {
        return (count($this->o) == 0);
    }


    /**
     * @param Address|AddressGroup|EDL $object
     * @param bool $anyIsAcceptable
     * @return bool
     * @throws Exception
     */
    public function hasObjectRecursive(Address|AddressGroup|EDL $object, bool $anyIsAcceptable = FALSE): bool
    {
        if( $object === null )
            derr('cannot work with null objects');

        if( $anyIsAcceptable && $this->count() == 0 )
            return FALSE;

        foreach( $this->o as $o )
        {
            if( $o === $object )
                return TRUE;
            if( $o->isGroup() )
                if( $o->hasObjectRecursive($object) ) return TRUE;
        }

        return FALSE;
    }


    /**
     * To determine if a store has all the Address from another store, it will expand AddressGroups instead of looking for them directly. Very useful when looking to compare similar rules.
     * @param AddressRuleContainer $other
     * @param bool $anyIsAcceptable if any of these objects is Any the it will return false
     * @return bool true if Address objects from $other are all in this store
     */
    public function includesContainerExpanded(AddressRuleContainer $other, bool $anyIsAcceptable = TRUE): bool
    {

        if( !$anyIsAcceptable )
        {
            if( $this->count() == 0 || $other->count() == 0 )
                return FALSE;
        }

        if( $this->count() == 0 )
            return TRUE;

        if( $other->count() == 0 )
            return FALSE;

        $localA = array();
        $A = array();

        foreach( $this->o as $object )
        {
            if( $object->isGroup() )
            {
                $flat = $object->expand();
                $localA = array_merge($localA, $flat);
            }
            else
                $localA[] = $object;
        }
        $localA = array_unique_no_cast($localA);

        $otherAll = $other->all();

        foreach( $otherAll as $object )
        {
            if( $object->isGroup() )
            {
                $flat = $object->expand();
                $A = array_merge($A, $flat);
            }
            else
                $A[] = $object;
        }
        $A = array_unique_no_cast($A);

        $diff = array_diff_no_cast($A, $localA);

        if( count($diff) > 0 )
        {
            return FALSE;
        }


        return TRUE;

    }

    /**
     * @param null $RuleReferenceLocation
     * @return IP4Map
     * @throws Exception
     */
    public function getIP4Mapping( $RuleReferenceLocation = null ): IP4Map
    {
        if( $this->isAny() )
            return IP4Map::mapFromText('0.0.0.0/0');

        $mapObject = new IP4Map();

        if( $RuleReferenceLocation !== null )
        {
            foreach( $this->o as $key => $member )
                $this->o[$key] = $RuleReferenceLocation->addressStore->find($member->name());
        }

        foreach( $this->o as $member )
        {
            if( $member == null || get_class($member) === "EDL" )
                continue;
            if( $member->isTmpAddr() && !$member->nameIsValidRuleIPEntry() )
            {
                $mapObject->unresolved[$member->name()] = $member;
                continue;
            }
            elseif( $member->isAddress() )
            {
                /** @var Address $member */
                $localMap = $member->getIP4Mapping( $RuleReferenceLocation );
                $mapObject->addMap($localMap, TRUE);
            }
            elseif( $member->isGroup() )
            {
                /** @var AddressGroup $member */
                if( $member->isDynamic() )
                    $mapObject->unresolved[$member->name()] = $member;
                else
                {
                    $localMap = $member->getIP4Mapping( $RuleReferenceLocation );
                    $mapObject->addMap($localMap, TRUE);
                }
            }
            elseif( $member->isRegion() )
            {
                /** @var Region $member */
                $localMap = $member->getIP4Mapping( $RuleReferenceLocation );
                $mapObject->addMap($localMap, TRUE);
            }
            else
                derr('unsupported type of objects ' . $member->toString());
        }
        $mapObject->sortAndRecalculate();

        return $mapObject;
    }

    /**
     * @param null $RuleReferenceLocation
     * @return IP6Map
     * @throws Exception
     */
    public function getIP6Mapping( $RuleReferenceLocation = null ): IP6Map
    {
        if( $this->isAny() )
            return IP6Map::mapFromText('::/0');

        $mapObject = new IP6Map();

        if( $RuleReferenceLocation !== null )
        {
            foreach( $this->o as $key => $member )
                $this->o[$key] = $RuleReferenceLocation->addressStore->find($member->name());
        }

        foreach( $this->o as $member )
        {
            if( $member == null || get_class($member) === "EDL" )
                continue;
            if( $member->isTmpAddr() && !$member->nameIsValidRuleIPEntry() )
            {
                $mapObject->unresolved[$member->name()] = $member;
                continue;
            }
            elseif( $member->isAddress() )
            {
                /** @var Address $member */
                $localMap = $member->getIP6Mapping( $RuleReferenceLocation );
                $mapObject->addMap($localMap, TRUE);
            }
            elseif( $member->isGroup() )
            {
                /** @var AddressGroup $member */
                if( $member->isDynamic() )
                    $mapObject->unresolved[$member->name()] = $member;
                else
                {
                    $localMap = $member->getIP6Mapping( $RuleReferenceLocation );
                    $mapObject->addMap($localMap, TRUE);
                }
            }
            elseif( $member->isRegion() )
            {
                /** @var Region $member */
                $localMap = $member->getIP6Mapping( $RuleReferenceLocation );
                $mapObject->addMap($localMap, TRUE);
            }
            else
                derr('unsupported type of objects ' . $member->toString());
        }
        $mapObject->sortAndRecalculate();

        return $mapObject;
    }

    public function copy(AddressRuleContainer $other): void
    {
        $this->removeAll();

        foreach( $other->o as $member )
        {
            $this->add($member);
        }

        $this->rewriteXML();
    }


    /**
     * @param $zoneIP4Mapping array  array of IP start-end to zone ie  Array( 0=>Array('start'=>0, 'end'=>50, 'zone'=>'internet') 1=>...  )
     * @param $objectIsNegated bool  IP4Mapping of this object will be inverted before doing resolution
     * @return string[] containing zones matched
     * @throws Exception
     */
    public function &calculateZonesFromIP4Mapping(array &$zoneIP4Mapping, bool $objectIsNegated = FALSE): array
    {
        $zones = array();

        $objectsMapping = $this->getIP4Mapping();

        if( $objectIsNegated )
        {
            $fakeMapping = IP4Map::mapFromText('0.0.0.0-255.255.255.255');
            $fakeMapping->substract($objectsMapping);
            $objectsMapping = $fakeMapping;
        }

        foreach( $zoneIP4Mapping as &$zoneMapping )
        {
            $result = $objectsMapping->substractSingleIP4Entry($zoneMapping);

            if( $result != 0 )
            {
                $zones[$zoneMapping['zone']] = $zoneMapping['zone'];
            }

            if( $objectsMapping->count() == 0 )
                break;

        }

        return $zones;
    }

    /**
     * @param $zoneIP6Mapping array  array of IP start-end to zone ie  Array( 0=>Array('start'=>0, 'end'=>50, 'zone'=>'internet') 1=>...  )
     * @param $objectIsNegated bool  IP4Mapping of this object will be inverted before doing resolution
     * @return string[] containing zones matched
     * @throws Exception
     */
    public function &calculateZonesFromIP6Mapping(array &$zoneIP6Mapping, bool $objectIsNegated = FALSE): array
    {
        mwarning( "class AddressRuleContainer IPv6 not implemented", null, false );
        $zones = array();

        $objectsMapping = $this->getIP6Mapping();

        if( $objectIsNegated )
        {
            $fakeMapping = IP6Map::mapFromText('::/0');
            $fakeMapping->substract($objectsMapping);
            $objectsMapping = $fakeMapping;
        }

        //Todo: missing ADDRESS mapping implementation
        if( $zoneIP6Mapping == null )
            return $zones;
        foreach( $zoneIP6Mapping as &$zoneMapping )
        {
            $result = $objectsMapping->substractSingleIP6Entry($zoneMapping);

            if( $result != 0 )
            {
                $zones[$zoneMapping['zone']] = $zoneMapping['zone'];
            }

            if( $objectsMapping->count() == 0 )
                break;

        }

        return $zones;
    }

    /**
     * @return Address[]|AddressGroup[]
     */
    public function &membersExpanded($keepGroupsInList = FALSE): array
    {
        $localA = array();

        if( count($this->o) == 0 )
            return $localA;

        foreach( $this->o as $member )
        {
            if( $member->isGroup() )
            {
                $flat = $member->expand($keepGroupsInList);
                $localA = array_merge($localA, $flat);
                if( $keepGroupsInList )
                    $localA[] = $member;
            }
            else
                $localA[] = $member;
        }

        $localA = array_unique_no_cast($localA);

        return $localA;
    }


}





