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


class ServiceGroup
{
    use PathableName;
    use XmlConvertible;
    use ServiceCommon;

    /** @var Service[]|ServiceGroup[] */
    public $members = array();

    /** @var null|ServiceStore */
    public $owner = null;

    /** @var TagRuleContainer */
    public $tags;

    public $ancestor;

    public $childancestor;

    public function __construct($name, $owner = null, $fromTemplateXml = FALSE)
    {
        $this->owner = $owner;

        if( $fromTemplateXml )
        {
            $doc = new DOMDocument();
            $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElement('entry', $doc);

            if( $this->owner->serviceGroupRoot !== null )
                $rootDoc = $this->owner->serviceGroupRoot->ownerDocument;
            else
            {
                $tmpXML = DH::findFirstElementOrCreate( "service-group", $this->owner->owner->xmlroot );
                $this->owner->load_servicegroups_from_domxml( $tmpXML );
                $rootDoc = $this->owner->owner->xmlroot->ownerDocument;
            }

            $this->xmlroot = $rootDoc->importNode($node, TRUE);
            $this->load_from_domxml($this->xmlroot);

            $this->name = $name;
            $this->xmlroot->setAttribute('name', $name);
        }

        $this->name = $name;

        $this->tags = new TagRuleContainer($this);
    }


    /**
     * returns number of members in this group
     * @return int
     */
    public function count()
    {
        return count($this->members);
    }


    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("name not found\n");

        if( $this->owner->owner->version >= 60 )
        {
            $membersRoot = DH::findFirstElement('members', $this->xmlroot);

            if( $membersRoot === FALSE )
            {
                derr('unsupported syntax type ServiceGroup', $this->xmlroot);
            }
            foreach( $membersRoot->childNodes as $node )
            {
                /** @var DOMElement $node */
                if( $node->nodeType != XML_ELEMENT_NODE ) continue;

                $memberName = $node->textContent;

                if( strlen($memberName) < 1 )
                    derr('found a member with empty name !', $node);

                $f = $this->owner->findOrCreate($memberName, $this, TRUE);

                $alreadyInGroup = FALSE;
                foreach( $this->members as $member )
                {
                    if( $member === $f )
                    {
                        mwarning("duplicated member named '{$memberName}' detected in servicegroup '{$this->name}', you should review your XML config file", $this->xmlroot, FALSE, FALSE);
                        $alreadyInGroup = TRUE;
                        break;
                    }
                }
                if( $f->isGroup() )
                {
                    if( $this->name() == $f->name() )
                    {
                        mwarning("servicegroup with name: " . $this->name() . " is added as subgroup to itself, you should review your XML config file", $this->xmlroot, FALSE, false);
                        continue;
                    }
                }

                if( !$alreadyInGroup )
                    $this->members[] = $f;
            }

        }
        else
        {
            foreach( $xml->childNodes as $node )
            {
                if( $node->nodeType != 1 ) continue;

                $memberName = $node->textContent;

                if( strlen($memberName) < 1 )
                    derr('found a member with empty name !', $node);

                $f = $this->owner->findOrCreate($memberName, $this, TRUE);

                $alreadyInGroup = FALSE;
                foreach( $this->members as $member )
                    if( $member === $f )
                    {
                        mwarning("duplicated member named '{$memberName}' detected in servicegroup '{$this->name}', you should review your XML config file", $this->xmlroot, false, false);
                        $alreadyInGroup = TRUE;
                        break;
                    }

                if( !$alreadyInGroup )
                    $this->members[] = $f;

                $this->members[] = $f;

            }
        }

        if( $this->owner->owner->version >= 60 )
        {
            $tagRoot = DH::findFirstElement('tag', $xml);
            if( $tagRoot !== FALSE )
                $this->tags->load_from_domxml($tagRoot);
        }

    }

    /**
     * @param $newName string
     */
    public function setName($newName)
    {
        $this->setRefName($newName);
        $this->xmlroot->setAttribute('name', $newName);
    }

    /**
     * @param string $newName
     */
    public function API_setName($newName)
    {
        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        $this->setName($newName);

        if( $c->isAPI())
            $c->sendRenameRequest($xpath, $newName);
    }

    /**
     * @param Service|ServiceGroup $newObject
     * @param bool $rewriteXml
     * @return bool
     */
    public function addMember($newObject, $rewriteXml = TRUE)
    {

        if( !is_object($newObject) )
            derr("Only objects can be passed to this function");

        if( !in_array($newObject, $this->members, TRUE) )
        {
            $this->members[] = $newObject;
            $newObject->addReference($this);
            if( $rewriteXml )
            {
                if( $this->owner->owner->version >= 60 )
                {
                    $membersRoot = DH::findFirstElement('members', $this->xmlroot);
                    if( $membersRoot === FALSE )
                        derr('<members> not found');

                    DH::createElement($membersRoot, 'member', $newObject->name());
                }
                else
                {
                    DH::createElement($this->xmlroot, 'member', $newObject->name());
                }
            }

            return TRUE;
        }

        return FALSE;
    }

    /**
     * @param Service|ServiceGroup objectToRemove
     * @return bool
     */
    public function API_removeMember($objectToRemove)
    {
        $ret = $this->removeMember($objectToRemove);

        if( $ret )
        {
            $con = findConnector($this);
            $xpath = $this->getXPath();

            if( $this->owner->owner->version >= 60 )
                $xpath .= '/members';

            if( $con->isAPI())
                $con->sendDeleteRequest($xpath . "/member[text()='{$objectToRemove->name()}']");

            return $ret;
        }

        return $ret;
    }


    /**
     * Add a member to this group, it must be passed as an object
     * @param Service|ServiceGroup $newObject Object to be added
     * @return bool
     */
    public function API_addMember($newObject)
    {
        $ret = $this->addMember($newObject);

        if( $ret )
        {
            $con = findConnector($this);
            $xpath = $this->getXPath();

            if( $this->owner->owner->version >= 60 )
                $xpath .= '/members';

            if( $con->isAPI())
                $con->sendSetRequest($xpath, "<member>{$newObject->name()}</member>");
        }

        return $ret;
    }

    /**
     * @param Service|ServiceGroup $old
     * @param bool $rewritexml
     * @return bool
     */
    public function removeMember($old, $rewritexml = TRUE)
    {
        if( !is_object($old) )
            derr("Only objects can be passed to this function");


        $found = FALSE;
        $pos = array_search($old, $this->members, TRUE);

        if( $pos === FALSE )
            return FALSE;
        else
        {
            $found = TRUE;
            unset($this->members[$pos]);
            $old->removeReference($this);
            if( $rewritexml )
                $this->rewriteXML();
        }


        return $found;
    }

    public function &getXPath()
    {
        $str = $this->owner->getServiceGroupStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
    }

    /**
     * @param Service|ServiceGroup $old
     * @param Service|ServiceGroup $new
     * @return bool
     * @throws Exception
     */
    public function replaceReferencedObject($old, $new)
    {
        if( $old === null )
            derr("\$old cannot be null");

        $pos = array_search($old, $this->members, TRUE);

        if( $pos !== FALSE )
        {
            while( $pos !== FALSE )
            {
                unset($this->members[$pos]);
                $pos = array_search($old, $this->members, TRUE);
            }

            if( $new !== null && !$this->has( $new->name() ) )
            {
                $this->members[] = $new;
                $new->addReference($this);
            }
            $old->removeReference($this);

            if( $new === null || $new->name() != $old->name() )
                $this->rewriteXML();

            return TRUE;
        }

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
     * @param $obj Address|AddressGroup
     * @return bool
     */
    public function has($obj, $caseSensitive = TRUE)
    {
        #return array_search($obj, $this->members, TRUE) !== FALSE;
        if( is_string($obj) )
        {
            if( !$caseSensitive )
                $obj = strtolower($obj);

            foreach( $this->members as $o )
            {
                if( !$caseSensitive )
                {
                    if( $obj == strtolower($o->name()) )
                    {
                        return TRUE;
                    }
                }
                else
                {
                    if( $obj == $o->name() )
                        return TRUE;
                }
            }
            return FALSE;
        }

        if (in_array($obj, $this->members, true)) {
            return TRUE;
        }

        return FALSE;
    }

    public function rewriteXML()
    {
        if( !isset($this->owner->owner) )
            return;

        if( $this->xmlroot === false )
            return;

        if( $this->owner->owner->version >= 60 )
        {
            $membersRoot = DH::findFirstElement('members', $this->xmlroot);
            if( $membersRoot === FALSE )
            {
                derr('<members> not found');
            }
            DH::Hosts_to_xmlDom($membersRoot, $this->members, 'member', FALSE);
        }
        else
            DH::Hosts_to_xmlDom($this->xmlroot, $this->members, 'member', FALSE);
    }

    /**
     * @param Service|ServiceGroup $h
     *
     */
    public function referencedObjectRenamed($h)
    {
        //derr("****  SG referencedObjectRenamed was called  ****\n");
        if( in_array($h, $this->members, TRUE) )
            $this->rewriteXML();
    }

    public function isGroup()
    {
        return TRUE;
    }


    /**
     * @param Service|ServiceGroup $otherObject
     * @return bool true if objects have same same and values
     */
    public function equals($otherObject)
    {
        if( !$otherObject->isGroup() )
            return FALSE;

        if( $otherObject->name != $this->name )
            return FALSE;

        return $this->sameValue($otherObject);
    }

    /**
     * @param ServiceGroup $otherObject
     * @return bool true if both objects contain same objects names
     */
    public function sameValue(ServiceGroup $otherObject)
    {
        if( $this->isTmpSrv() && !$otherObject->isTmpSrv() )
            return FALSE;

        if( $otherObject->isTmpSrv() && !$this->isTmpSrv() )
            return FALSE;

        if( $otherObject->count() != $this->count() )
            return FALSE;

        $lO = array();
        $oO = array();

        foreach( $this->members as $a )
        {
            $lO[] = $a->name();
        }
        sort($lO);

        foreach( $otherObject->members as $a )
        {
            $oO[] = $a->name();
        }
        sort($oO);

        $diff = array_diff($oO, $lO);

        if( count($diff) != 0 )
            return FALSE;

        $diff = array_diff($lO, $oO);

        if( count($diff) != 0 )
            return FALSE;

        return TRUE;
    }

    public function &getValueDiff(ServiceGroup $otherObject)
    {
        $result = array('minus' => array(), 'plus' => array());

        $localObjects = $this->members;
        $otherObjects = $otherObject->members;


        usort($localObjects, '__CmpObjName');
        usort($otherObjects, '__CmpObjName');

        $diff = array_udiff($otherObjects, $localObjects, '__CmpObjName');

        if( count($diff) != 0 )
            foreach( $diff as $d )
            {
                $result['minus'][] = $d;
            }

        $diff = array_udiff($localObjects, $otherObjects, '__CmpObjName');
        if( count($diff) != 0 )
            foreach( $diff as $d )
            {
                $result['plus'][] = $d;
            }

        return $result;
    }


    /**
     * @param ServiceGroup $otherObject
     * @param int $indent
     * @param bool|false $toString
     * @return string|void
     */
    public function displayValueDiff(ServiceGroup $otherObject, $indent = 0, $toString = FALSE)
    {
        $retString = '';

        $indent = str_pad(' ', $indent);


        $retString .= $indent . "Diff for between " . $this->_PANC_shortName() . " vs " . $otherObject->_PANC_shortName() ."\n" ;
        $retString .= $indent . "  ' - ' means missing member \n";
        $retString .= $indent . "  ' + ' means additional member \n";
        $retString .= $indent . "       in ".$this->_PANC_shortName()."\n";


        $lO = array();
        $oO = array();

        foreach( $this->members as $a )
        {
            $lO[] = $a->name();
        }
        sort($lO);

        foreach( $otherObject->members as $a )
        {
            $oO[] = $a->name();
        }
        sort($oO);

        $diff = array_diff($oO, $lO);

        if( count($diff) != 0 )
        {
            foreach( $diff as $d )
            {
                if( !$toString )
                    PH::print_stdout(  $indent . " - $d" );
                else
                    $retString .= $indent . " - $d\n";
            }
        }

        $diff = array_diff($lO, $oO);
        if( count($diff) != 0 )
            foreach( $diff as $d )
            {
                if( !$toString )
                    PH::print_stdout(  $indent . " + $d");
                else
                    $retString .= $indent . " + $d\n";
            }

        if( $toString )
            return $retString;

        PH::print_stdout( $retString );
    }


    /**
     * @return ServiceDstPortMapping
     */
    public function dstPortMapping( $memberArray = array(), $RuleReferenceLocation = null)
    {
        $mapping = new ServiceDstPortMapping();

        if( !array_key_exists( $this->name(), $memberArray ) )
        {
            $memberArray[ $this->name() ] = $this->name();

            if( $RuleReferenceLocation !== null )
            {
                foreach( $this->members as $key => $member )
                {
                    $this->members[$key] = $RuleReferenceLocation->serviceStore->find($member->name());
                }
            }

            foreach( $this->members as $member )
            {
                if( $member->isTmpSrv() && $this->name() != 'service-http' && $this->name() != 'service-https' )
                    $mapping->unresolved[$member->name()] = $member;
                $localMapping = $member->dstPortMapping($memberArray);
                $mapping->mergeWithMapping($localMapping);
            }
        }

        return $mapping;
    }


    public function xml_convert_to_v6()
    {
        $newElement = $this->xmlroot->ownerDocument->createElement('members');
        $nodes = array();

        foreach( $this->xmlroot->childNodes as $node )
        {
            if( $node->nodeType != 1 )
                continue;

            $nodes[] = $node;
        }


        foreach( $nodes as $node )
        {
            $newElement->appendChild($node);
        }


        $this->xmlroot->appendChild($newElement);

        return;
    }


    /**
     * @param bool $keepGroupsInList
     * @return Service[]|ServiceGroup[] list of all member objects, if some of them are groups, they are exploded and their members inserted
     */
    public function &expand($keepGroupsInList = FALSE, &$grpArray=array(), $RuleReferenceLocation = null )
    {
        $ret = array();

        $grpArray[$this->name()] = $this;

        if( $RuleReferenceLocation !== null )
        {
            foreach( $this->members as $key => $member )
                $this->members[$key] = $RuleReferenceLocation->serviceStore->find($member->name());
        }

        foreach( $this->members as $object )
        {
            #$serial = spl_object_hash($object);
            $serial = $object->name();
            if( $object->isGroup() )
            {
                if( array_key_exists($serial, $grpArray) )
                {
                    mwarning("servicegroup with name: " . $this->name() . " is added as subgroup to itself, you should review your XML config file", $this->xmlroot, false, false);
                    mwarning("servicegroup with name: " . $object->name() . " is added as subgroup to servicegroup: " . $this->name() . ", you should review your XML config file", $object->xmlroot, false, false);
                    PH::print_stdout( "-------------");

                    continue;
                    #return $ret;
                }
                else
                    $grpArray[$serial] = $serial;

                if( $this->name() == $object->name() )
                {
                    mwarning("servicegroup with name: " . $this->name() . " is added as subgroup to itself, you should review your XML config file", $this->xmlroot, false, false);
                    continue;
                }

                /** @var ServiceGroup $object */
                $tmpList = $object->expand( $keepGroupsInList, $grpArray, $RuleReferenceLocation);

                $ret = array_merge($ret, $tmpList);
                unset($tmpList);
                if( $keepGroupsInList )
                    #$ret[$serial] = $object;
                    $ret[] = $object;
            }
            else
                #$ret[$serial] = $object;
                $ret[] = $object;
        }

        $ret = array_unique_no_cast($ret);

        return $ret;
    }

    /**
     * @return Service[]|ServiceGroup[]
     */
    public function members()
    {
        return $this->members;
    }


    /**
     * @param Service|ServiceGroup $object
     * @return bool
     */
    public function hasObjectRecursive($object)
    {
        if( $object === null )
            derr('cannot work with null objects');

        foreach( $this->members as $o )
        {
            if( $o === $object )
                return TRUE;
            if( $o->isGroup() )
                if( $o->hasObjectRecursive($object) ) return TRUE;
        }

        return FALSE;
    }

    /**
     * @param Service|ServiceGroup $object
     * @return bool
     */
    public function countObjectsRecursive()
    {
        return count( $this->membersRecursive() );
    }

    /**
     * @param Service|ServiceGroup $object
     * @return bool
     */
    public function hasTimeoutRecursive()
    {
        foreach( $this->membersRecursive() as $object)
        {
            /** @var Service $object */
            if( !empty( $object->getTimeout() ) )
                return true;
        }

        return FALSE;
    }

    /**
     * @param Service|ServiceGroup $object
     * @return array
     */
    public function membersRecursive()
    {
        $array = array();
        foreach( $this->members as $o )
        {
            if( $o->isService() )
                $array[] = $o;
            elseif( $o->isGroup() )
            {
                $tmp_array = $o->membersRecursive();
                $array = array_merge( $array, $tmp_array );
            }
        }

        return $array;
    }

    /**
     * @param string $objectName
     * @return bool
     */
    public function hasNamedObjectRecursive($objectName, $memberArray = array())
    {
        foreach( $this->members as $o )
        {
            if( !array_key_exists( $o->name(), $memberArray ) )
            {
                $memberArray[$o->name()] = $o->name();
                if( $o->name() === $objectName )
                    return TRUE;
                if( $o->isGroup() )
                    if( $o->hasNamedObjectRecursive($objectName, $memberArray) ) return TRUE;
            }
            else
                return FALSE;
        }

        return FALSE;
    }


    public function removeAll($rewriteXml = TRUE)
    {
        foreach( $this->members as $a )
        {
            $a->removeReference($this);
        }
        $this->members = array();


        if( $rewriteXml )
        {
            $this->rewriteXML();
        }
    }


    public function replaceGroupbyService( $context )
    {
        #if( $context->isAPI )
        #    derr("action 'replaceGroupByService' is not support in API/online mode yet");


        if( $this->isService() )
        {
            $string = "this is not a group";
            PH::ACTIONstatus($context, "SKIPPED", $string);
            return null;
        }
        if( !$this->isGroup() )
        {
            $string = "unsupported object type";
            PH::ACTIONstatus($context, "SKIPPED", $string);
            return null;
        }
        if( $this->count() < 1 )
        {
            $string = "group has no member";
            PH::ACTIONstatus($context, "SKIPPED", $string);
            return null;
        }

        $mapping = $this->dstPortMapping();
        if( $mapping->hasTcpMappings() && $mapping->hasUdpMappings() )
        {
            $string = "group has a mix of UDP and TCP based mappings, they cannot be merged in a single object";
            PH::ACTIONstatus($context, "SKIPPED", $string);
            return null;
        }

        foreach( $this->members() as $member )
        {
            if( $member->isTmpSrv() )
            {
                $string = "temporary services detected";
                PH::ACTIONstatus($context, "SKIPPED", $string);
                return null;
            }
        }

        $store = $this->owner;
        $store->remove($this);

        if( $mapping->hasUdpMappings() )
        {
            $tmp_string = str_replace("udp/", "", $mapping->udpMappingToText());
            $newService = $store->newService($this->name(), 'udp', $tmp_string);
        }
        else
        {
            $tmp_string = str_replace("tcp/", "", $mapping->tcpMappingToText() );
            $newService = $store->newService($this->name(), 'tcp', $tmp_string);
        }

        $this->replaceMeGlobally($newService);

        if( $mapping->hasUdpMappings() )
        {
            $tmp_dstmapping = $newService->dstPortMapping();
            $string = " * replaced by service with same name and value: {$tmp_dstmapping->udpMappingToText()}";
            PH::ACTIONlog($context, $string);
        }
        else
        {
            $tmp_dstmapping = $newService->dstPortMapping();
            $string = " * replaced by service with same name and value: {$tmp_dstmapping->tcpMappingToText()}";
            PH::ACTIONlog($context, $string);
        }



        return TRUE;
    }


    public function replaceByMembersAndDelete($context, $isAPI = FALSE, $rewriteXml = TRUE, $forceAny = FALSE)
    {
        if( !$this->isGroup() )
        {
            $string = "it's not a group";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }


        $thisRefs = $this->getReferences();

        $clearForAction = TRUE;
        foreach( $thisRefs as $thisRef )
        {
            $class = get_class($thisRef);
            if( $class != 'ServiceRuleContainer' && $class != 'ServiceGroup' )
            {
                $clearForAction = FALSE;
                $string = "because its used in unsupported class $class";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }
        }
        if( $clearForAction )
        {
            foreach( $thisRefs as $thisRef )
            {
                $class = get_class($thisRef);
                if( $class == 'ServiceRuleContainer' )
                {
                    /** @var ServiceRuleContainer $thisRef */

                    $string = "    - in Reference: {$thisRef->toString()}";
                    PH::ACTIONlog( $context, $string );

                    foreach( $this->members() as $thisMember )
                    {
                        $string = "      - adding {$thisMember->name()}";
                        PH::ACTIONlog( $context, $string );

                        if( $isAPI )
                            $thisRef->API_add($thisMember, $rewriteXml);
                        else
                            $thisRef->add($thisMember, $rewriteXml);
                    }
                    if( $isAPI )
                        $thisRef->API_remove($this, $rewriteXml, $forceAny);
                    else
                        $thisRef->remove($this, $rewriteXml, $forceAny);
                }
                elseif( $class == 'ServiceGroup' )
                {
                    /** @var ServiceGroup $thisRef */

                    $string = "    - in Reference: {$thisRef->toString()}";
                    PH::ACTIONlog( $context, $string );

                    foreach( $this->members() as $thisMember )
                    {
                        $string = "      - adding {$thisMember->name()}";
                        PH::ACTIONlog( $context, $string );

                        if( $isAPI )
                            $thisRef->API_addMember($thisMember);
                        else
                            $thisRef->addMember($thisMember, $rewriteXml);
                    }
                    if( $isAPI )
                        $thisRef->API_removeMember($this);
                    else
                        $thisRef->removeMember($this, $rewriteXml);
                }
                else
                {
                    derr('unsupported class');
                }

            }
            if( $isAPI )
                $this->owner->API_remove($this, TRUE);
            else
                $this->owner->remove($this, TRUE);
        }
    }

    public function replaceByMembers($context, $delete = FALSE, $isAPI = FALSE, $rewriteXml = TRUE, $forceAny = FALSE)
    {
        if( !$this->isGroup() )
        {
            $string = "it's not a group";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }


        $thisRefs = $this->getReferences();

        $clearForAction = TRUE;
        foreach( $thisRefs as $thisRef )
        {
            $class = get_class($thisRef);
            if( $class != 'ServiceRuleContainer' && $class != 'ServiceGroup' )
            {
                $clearForAction = FALSE;
                $string = "because its used in unsupported class $class";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }
        }
        if( $clearForAction )
        {
            foreach( $thisRefs as $thisRef )
            {
                $class = get_class($thisRef);
                if( $class == 'ServiceRuleContainer' )
                {
                    /** @var ServiceRuleContainer $thisRef */

                    $string = "    - in Reference: {$thisRef->toString()}";
                    PH::ACTIONlog( $context, $string );

                    foreach( $this->members() as $thisMember )
                    {
                        $string = "      - adding {$thisMember->name()}";
                        PH::ACTIONlog( $context, $string );

                        if( $isAPI )
                            $thisRef->API_add($thisMember, $rewriteXml);
                        else
                            $thisRef->add($thisMember, $rewriteXml);
                    }
                    if( $isAPI )
                        $thisRef->API_remove($this, $rewriteXml, $forceAny);
                    else
                        $thisRef->remove($this, $rewriteXml, $forceAny);
                }
                elseif( $class == 'ServiceGroup' )
                {
                    /** @var ServiceGroup $thisRef */

                    $string = "    - in Reference: {$thisRef->toString()}";
                    PH::ACTIONlog( $context, $string );

                    foreach( $this->members() as $thisMember )
                    {
                        $string = "      - adding {$thisMember->name()}";
                        PH::ACTIONlog( $context, $string );

                        if( $isAPI )
                            $thisRef->API_addMember($thisMember);
                        else
                            $thisRef->addMember($thisMember, $rewriteXml);
                    }
                    if( $isAPI )
                        $thisRef->API_removeMember($this);
                    else
                        $thisRef->removeMember($this, $rewriteXml);
                }
                else
                {
                    derr('unsupported class');
                }

            }

            if( $delete )
            {
                if( $isAPI )
                    $this->owner->API_remove($this, TRUE);
                else
                    $this->owner->remove($this, TRUE);
            }
        }
    }

    static protected $templatexml = '<entry name="**temporarynamechangeme**"><members></members></entry>';
    static protected $templatexmlroot = null;
}


