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


class AddressStore
{
    use PathableName;

    /** @var VirtualSystem|DeviceGroup|PanoramaConf|PANConf|null */
    public $owner;

    public $name;

    /** @var null|AddressStore */
    public $parentCentralStore = null;

    /** @var Address[]|AddressGroup[] */
    protected $_all = array();

    /** @var Address[] */
    protected $_addressObjects = array();

    /**@var Address[] */
    protected $_tmpAddresses = array();


    /** @var AddressGroup[] */
    protected $_addressGroups = array();

    /** @var Region[] */
    protected $_regionObjects = array();

    /** @var DOMElement */
    public $addressRoot;

    /** @var DOMElement */
    public $addressGroupRoot;

    /** @var DOMElement */
    public $regionRoot;

    /**
     * @param VirtualSystem|DeviceCloud|DeviceGroup|Container|PanoramaConf|PANConf|FawkesConf|null $owner
     */
    public function __construct($owner)
    {
        $this->owner = $owner;

        $this->setParentCentralStore( 'addressStore' );

        $this->_addressObjects = array();
        $this->_addressGroups = array();
        $this->_tmpAddresses = array();
    }

    private function &getBaseXPath()
    {
        $class = get_class($this->owner);

        if( $class == 'PanoramaConf' || $class == 'PANConf' )
        {
            $str = "/config/shared";
        }
        else
            $str = $this->owner->getXPath();

        return $str;
    }

    public function &getAddressStoreXPath()
    {
        $path = $this->getBaseXPath() . '/address';
        return $path;
    }

    public function &getAddressGroupStoreXPath()
    {
        $path = $this->getBaseXPath() . '/address-group';
        return $path;
    }


    /**
     * For developer use only
     * @param DOMElement $xml
     *
     */
    public function load_addresses_from_domxml($xml)
    {
        $this->addressRoot = $xml;

        $duplicatesRemoval = array();

        foreach( $this->addressRoot->childNodes as $node )
        {
            /** @var DOMElement $node */
            if( $node->nodeType != XML_ELEMENT_NODE ) continue;

            $ns = new Address('', $this);
            $loadedOK = $ns->load_from_domxml($node);

            if( !$loadedOK )
                continue;

            $objectName = $ns->name();

            if( isset($this->_all[$objectName]) )
            {
                if( PH::$enableXmlDuplicatesDeletion )
                    $duplicatesRemoval[] = $node;
                mwarning("an object with name '{$objectName}' already exists in this store, please investigate your xml file as this will be ignored and could eventually be lost.", $node, false);
                continue;
            }

            $this->_addressObjects[$objectName] = $ns;
            $this->_all[$objectName] = $ns;
        }

        foreach( $duplicatesRemoval as $node )
        {
            $node->parentNode->removeChild($node);
        }
    }


    /**
     * For developer use only
     * @param DOMElement $xml
     *
     */
    public function load_regions_from_domxml($xml)
    {
        $this->regionRoot = $xml;

        $duplicatesRemoval = array();

        foreach( $this->regionRoot->childNodes as $node )
        {
            /** @var DOMElement $node */
            if( $node->nodeType != XML_ELEMENT_NODE ) continue;

            $tmp = DH::findFirstElement( "address", $node);
            if ( $tmp === false )
            {
                //object is TMP - predefined
                continue;
            }

            $ns = new Region('', $this);
            $loadedOK = $ns->load_from_domxml($node);

            if( !$loadedOK )
                continue;

            $objectName = $ns->name();

            if( isset($this->_all[$objectName]) )
            {
                if( PH::$enableXmlDuplicatesDeletion )
                    $duplicatesRemoval[] = $node;
                mwarning("an object with name '{$objectName}' already exists in this store, please investigate your xml file as this will be ignored and could eventually be lost.", $node, false);
                continue;
            }

            $this->_regionObjects[$objectName] = $ns;
            $this->_all[$objectName] = $ns;
        }

        foreach( $duplicatesRemoval as $node )
        {
            $node->parentNode->removeChild($node);
        }
    }


    /*private function remergeAll()
    {
        $this->all = array_merge($this->_addressObjects, $this->_addressGroups, $this->_tmpAddresses);


        $this->regen_Indexes();
    }*/

    /**
     * Returns an Array with all Address , AddressGroups, TmpAddress objects in this store
     * @param $withFilter string|null
     * @param bool $sortByDependencies
     * @return Address[]|AddressGroup[]
     */
    public function all($withFilter = null, $sortByDependencies = FALSE)
    {
        $query = null;

        if( $withFilter !== null && $withFilter != '' )
        {
            $errMesg = '';
            $query = new RQuery('address');
            if( $query->parseFromString($withFilter, $errMsg) === FALSE )
            {
                mwarning("error while parsing query: {$errMesg} - filter: {$withFilter}", null, FALSE);
                return array();
            }


            $res = array();
            foreach( $this->_all as $obj )
            {
                if( $query->matchSingleObject($obj) )
                    $res[] = $obj;
            }
            return $res;
        }

        if( !$sortByDependencies )
            return $this->_all;

        $result = array();

        foreach( $this->_tmpAddresses as $object )
            $result[] = $object;

        foreach( $this->_addressObjects as $object )
            $result[] = $object;

        foreach( $this->addressGroups(TRUE) as $object )
            $result[] = $object;

        foreach( $this->_regionObjects as $object )
            $result[] = $object;

        return $result;
    }


    public function load_addressgroups_from_domxml($xml)
    {
        $this->addressGroupRoot = $xml;

        $duplicatesRemoval = array();

        foreach( $xml->childNodes as $node )
        {
            /** @var DOMElement $node */
            if( $node->nodeType != XML_ELEMENT_NODE ) continue;

            $name = $node->getAttribute('name');
            if( strlen($name) == 0 )
                derr("unsupported empty group name", $node);

            $ns = new AddressGroup($name, $this);

            if( isset($this->_tmpAddresses[$name]) )
            {
                $tmpObj = $this->_tmpAddresses[$name];
                $tmpObj->replaceMeGlobally($ns);
                $this->remove($tmpObj);
            }

            if( isset($this->_all[$name]) )
            {
                if( PH::$enableXmlDuplicatesDeletion )
                    $duplicatesRemoval[] = $node;
                mwarning("an object with name '{$name}' already exists in this store, please investigate your xml file", $node, false);
                continue;
            }

            $this->_addressGroups[$name] = $ns;
            $this->_all[$name] = $ns;
        }

        foreach( $duplicatesRemoval as $node )
        {
            $node->parentNode->removeChild($node);
        }

        foreach( $xml->childNodes as $node )
        {
            /** @var DOMElement $node */
            if( $node->nodeType != 1 ) continue;

            $name = $node->getAttribute('name');
            if( isset( $this->_addressGroups[$name] ) )
            {
                $ns = $this->_addressGroups[$name];
                $ns->load_from_domxml($node);
            }
            else
                mwarning( "earlier warning available that: an object with name '{$name}' already exists in this store, please investigate your xml file as this will be ignored and could eventually be lost.",$node, false);
        }
    }


    /**
     * returns true if $object is in this store. False if not
     * @param Address|AddressGroup $object
     * @return bool
     */
    public function inStore($object)
    {
        if( $object === null )
            derr('a NULL object? really ?');

        $objectName = $object->name();

        if( isset($this->_all[$objectName]) )
        {
            if( $this->_all[$objectName] === $object )
                return TRUE;
        }

        return FALSE;
    }


    /**
     * This count all objects in the store, including Tmp,Address and Groups
     *
     */
    public function count()
    {
        return count($this->_all);
    }


    /**
     *
     *
     */
    public function countAddressGroups()
    {
        return count($this->_addressGroups);
    }


    public function countAddresses()
    {
        return count($this->_addressObjects);
    }


    public function countTmpAddresses()
    {
        return count($this->_tmpAddresses);
    }

    public function countRegionObjects()
    {
        return count($this->_regionObjects);
    }

    /**
     *
     * @ignore
     */
    protected function findParentCentralStore( $storeType )
    {
        $this->parentCentralStore = null;

        if( $this->owner )
        {
            $curo = $this;
            while( isset($curo->owner) && $curo->owner !== null )
            {
                if( isset($curo->owner->$storeType) && $curo->owner->$storeType !== null )
                {
                    $this->parentCentralStore = $curo->owner->$storeType;
                    return;
                }
                $curo = $curo->owner;
            }
        }
    }

    /**
     *
     * @ignore
     */
    protected function setParentCentralStore( $storeType )
    {
        if( isset($owner->parentDeviceGroup) && $owner->parentDeviceGroup !== null )
            $this->parentCentralStore = $owner->parentDeviceGroup->$storeType;

        elseif( isset($owner->parentContainer) && $owner->parentContainer !== null )
            $this->parentCentralStore = $owner->parentContainer->$storeType;

        else
            $this->findParentCentralStore( $storeType );
    }

    /**
     * Should only be called from a CentralStore or give unpredictable results
     * @param string $objectName
     * @param ReferenceableObject $ref
     * @param bool $nested
     * @return Address|AddressGroup|null
     */
    //Todo: check if $nested = false; must be set
    #NEW - public function find($objectName, $ref = null, $nested = FALSE)
    public function find($objectName, $ref = null, $nested = TRUE)
    {
        $f = null;

        $foundObject = $this->owner->EDLStore->find($objectName, $ref, $nested);
        if( $foundObject !== null )
            return $foundObject;

        if( isset($this->_all[$objectName]) )
        {
            $foundObject = $this->_all[$objectName];
            $foundObject->addReference($ref);
            return $foundObject;
        }

        // when load a PANOS firewall attached to a Panorama
        if( $nested && isset($this->panoramaShared) )
        {
            $f = $this->panoramaShared->find($objectName, $ref, FALSE);

            if( $f !== null )
                return $f;
        }
        // when load a PANOS firewall attached to a Panorama
        if( $nested && isset($this->panoramaDG) )
        {
            $f = $this->panoramaDG->find($objectName, $ref, FALSE);
            if( $f !== null )
                return $f;
        }

        if( $nested && $this->parentCentralStore !== null )
        {
            $f = $this->parentCentralStore->find($objectName, $ref, $nested);
        }

        return $f;
    }

    public function findOrCreate($fn, $ref = null, $nested = TRUE)
    {
        $f = $this->find($fn, $ref, $nested);

        if( $f !== null )
            return $f;

        $f = $this->createTmp($fn, $ref);

        return $f;
    }

    /**
     * @param string $name
     * @param ReferenceableObject $ref
     * @param bool $nested
     * @return Address|null
     */
    public function findTmpAddress($name, $ref = null, $nested = TRUE)
    {
        if( $nested )
            derr("nested is not supported yet");

        if( !isset($this->_tmpAddresses[$name]) )
            return null;

        if( $ref !== null )
            $this->_tmpAddresses[$name]->addReference($ref);

        return $this->_tmpAddresses[$name];
    }

    public function displayTmpAddresss()
    {
        PH::print_stdout( "Tmp addresses for " . $this->toString() );
        foreach( $this->_tmpAddresses as $object )
        {
            PH::print_stdout(  " - " . $object->name() );
        }

        PH::print_stdout();
    }


    public function toString_inline()
    {
        $arr = &$this->_all;
        $c = count($arr);


        if( $c == 0 )
        {
            $ret = '**ANY**';
            return $ret;
        }

        $first = TRUE;

        $ret = '';

        foreach( $arr as $s )
        {
            if( $first )
            {
                $ret .= $s->name();
            }
            else
                $ret .= ',' . $s->name();


            $first = FALSE;
        }

        return $ret;

    }

    /**
     * @param Address|AddressGroup $s
     * @return bool
     */
    public function API_add($s)
    {
        $ret = $this->add($s);

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            $xpath = $s->getXPath();

            if( $con->isAPI())
                $con->sendSetRequest($xpath, DH::domlist_to_xml($s->xmlroot->childNodes, -1, FALSE));
            elseif( $con->isSaseAPI())
            {
                //how to add multiple objects???
            }
        }

        return $ret;
    }

    /**
     * @param Address|AddressGroup $s
     * @return bool if object was added. wrong if it was already there or another object with same name.
     *
     * @throws Exception
     */
    public function add($s)
    {
        $objectName = $s->name();

        // there is already an object named like that
        if( isset($this->_all[$objectName]) && $this->_all[$objectName] !== $s && !$this->_all[$objectName]->isType_TMP() )
        {
            derr('You cannot add object with same name in a store');
        }

        $class = get_class($s);

        if( $class == 'Address' )
        {
            if( $s->type() == 'tmp' )
            {
                $this->_tmpAddresses[$objectName] = $s;
            }
            else
            {
                $this->_addressObjects[$objectName] = $s;

                if( $this->addressRoot == null )
                    $this->addressRoot = DH::findFirstElementOrCreate( 'address', $this->owner->xmlroot );
                $this->addressRoot->appendChild($s->xmlroot);
            }

            $this->_all[$objectName] = $s;
        }
        elseif( $class == 'AddressGroup' )
        {
            $this->_addressGroups[$objectName] = $s;
            $this->_all[$objectName] = $s;

            if( $this->addressGroupRoot == null )
                $this->addressGroupRoot = DH::findFirstElementOrCreate( 'address-group', $this->owner->xmlroot );

            $this->addressGroupRoot->appendChild($s->xmlroot);
        }
        else
            derr('invalid class found');


        $s->owner = $this;


        return TRUE;
    }

    /**
     * @param Address|AddressGroup $s
     * @param bool $cleanInMemory
     * @return bool
     */
    public function API_remove($s, $cleanInMemory = FALSE)
    {
        $xpath = null;

        if( !$s->isTmpAddr() )
            $xpath = $s->getXPath();

        $ret = $this->remove($s, $cleanInMemory);

        if( $ret && !$s->isTmpAddr() )
        {
            $con = findConnectorOrDie($this);
            if( $con->isAPI())
                $con->sendDeleteRequest($xpath);
            elseif( $con->isSaseAPI() )
                $con->sendDELETERequest($s);
        }

        return $ret;
    }

    /**
     * @param Address|AddressGroup $s
     * @param bool $cleanInMemory
     * @return bool
     */
    public function remove($s, $cleanInMemory = FALSE)
    {
        $class = get_class($s);

        $objectName = $s->name();


        if( !isset($this->_all[$objectName]) )
        {
            mwarning('Tried to remove an object that is not part of this store', null, false);
            return FALSE;
        }

        unset($this->_all[$objectName]);


        if( $class == 'Address' )
        {
            if( $s->isTmpAddr() )
            {
                unset($this->_tmpAddresses[$objectName]);
            }
            else
            {
                unset($this->_addressObjects[$objectName]);
            }
        }
        else if( $class == 'AddressGroup' )
        {
            unset($this->_addressGroups[$objectName]);
            if( $cleanInMemory )
                $s->removeAll(FALSE);
        }
        else if( $class == 'Region' )
        {
            unset($this->_regionObjects[$objectName]);
            if( $cleanInMemory )
                $s->removeAll(FALSE);
        }
        else
            derr('AddressStore remove - invalid class found');

        $s->owner = null;


        if( !$s->isTmpAddr() )
        {
            if( $class == "Address" )
            {
                if( count($this->_addressObjects) > 0 )
                    $this->addressRoot->removeChild($s->xmlroot);
                else
                    DH::clearDomNodeChilds($this->addressRoot);

            }
            else if( $class == "AddressGroup" )
            {
                if( count($this->_addressGroups) > 0 )
                    $this->addressGroupRoot->removeChild($s->xmlroot);
                else
                    DH::clearDomNodeChilds($this->addressGroupRoot);
            }
            elseif( $class == "Region" )
            {
                if( count($this->_regionObjects) > 0 )
                    $this->regionRoot->removeChild($s->xmlroot);
                else
                    DH::clearDomNodeChilds($this->regionRoot);
            }
            else
                derr('unsupported AddressStore remove class');
        }

        if( $cleanInMemory )
            $s->xmlroot = null;

        if( $class == 'AddressGroup' )
        {
            //Todo: swaschkut 20201109 - update readonly section
            //if address-group - remove address-group there and decrease max-internal-id
        }


        return TRUE;
    }


    public function rewriteAddressStoreXML()
    {
        DH::clearDomNodeChilds($this->addressRoot);
        foreach( $this->_addressObjects as $s )
        {
            $this->addressRoot->appendChild($s->xmlroot);
        }
    }

    public function rewriteAddressGroupStoreXML()
    {
        DH::clearDomNodeChilds($this->addressGroupRoot);
        foreach( $this->_addressGroups as $s )
        {
            $this->addressGroupRoot->appendChild($s->xmlroot);
        }
    }


    /**
     * @param $name string
     * @param $type string
     * @param $value string
     * @param string $description
     * @return Address
     * @throws Exception
     */
    public function newAddress($name, $type, $value, $description = '')
    {
        $found = $this->find($name, null, FALSE);
        if( $found !== null && !$found->isGroup() && !$found->isType_TMP() )
            derr("cannot create Address named '" . $name . "' as this name is already in use");

        $newObject = new Address($name, $this, TRUE);
        $newObject->setType($type);
        $newObject->setValue($value);
        $newObject->setDescription($description);

        $this->add($newObject);

        return $newObject;
    }

    /**
     * @param $name string
     * @param $type string
     * @param $value string
     * @param string $description
     * @return Address
     * @throws Exception
     */
    public function API_newAddress($name, $type, $value, $description = '')
    {
        $newObject = $this->newAddress($name, $type, $value, $description);

        $con = findConnectorOrDie($this);
        $xpath = $newObject->getXPath();
        if( $con->isAPI() )
            $con->sendSetRequest($xpath, $newObject, TRUE);
        elseif( $con->isSaseAPI() )
            $con->sendCreateRequest($newObject);

        return $newObject;
    }


    /**
     * Creates a new Address Group named '$name' . Will exit with error if a group with that
     * name already exists
     * @param string $name
     * @return AddressGroup
     **/
    public function newAddressGroup($name)
    {
        $found = $this->find($name, null, FALSE);
        if( $found !== null )
            derr("cannot create AddressGroup named '" . $name . "' as this name is already in use");

        $newGroup = new AddressGroup($name, $this, TRUE);
        $newGroup->setName($name);
        $this->add($newGroup);

        //Todo: swaschkut 20201109 - update readonly section
        //add addressgroup - increase max-internal-id

        return $newGroup;

    }

    /**
     * Creates a new Address Group named '$name' . Will exit with error if a group with that
     * name already exists
     * @param $name string
     * @return AddressGroup
     **/
    public function API_newAddressGroup($name)
    {
        $found = $this->find($name, null, FALSE);
        if( $found !== null )
            derr("cannot create AddressGroup named '" . $name . "' as this name is already in use");

        $newObject = $this->newAddressGroup($name);

        $con = findConnectorOrDie($this);
        $xpath = $newObject->getXPath();
        if( $con->isAPI() )
            $con->sendSetRequest($xpath, $newObject, TRUE);
        elseif( $con->isSaseAPI() )
            $con->sendCreateRequest($newObject);


        return $newObject;
    }


    /**
     * Creates a new Address Group named '$name' . Will exit with error if a group with that
     * name already exists
     * @param string $name
     * @return AddressGroup
     **/
    public function newAddressGroupDynamic($name)
    {
        $found = $this->find($name, null, FALSE);
        if( $found !== null )
            derr("cannot create AddressGroup named '" . $name . "' as this name is already in use");

        $newGroup = new AddressGroup($name, $this, TRUE, "dynamic");
        $newGroup->setName($name);
        $newGroup->setDynamic(TRUE );
        $this->add($newGroup);

        //Todo: swaschkut 20201109 - update readonly section
        //add addressgroup - increase max-internal-id

        return $newGroup;

    }

    /**
     * Returns an Array with all AddressGroup in this store.
     * @return AddressGroup[]
     *
     * @var bool $sortByDependencies
     */
    public function addressGroups($sortByDependencies = FALSE)
    {
        if( !$sortByDependencies )
            return $this->_addressGroups;

        $result = array();

        $sortingArray = array();

        foreach( $this->_addressGroups as $group )
        {
            if( $group->isDynamic() )
            {
                $result[] = $group;
                continue;
            }

            $sortingArray[$group->name()] = array();

            $subGroups = $group->expand(TRUE);

            foreach( $subGroups as $subGroup )
            {
                if( !$subGroup->isGroup() || $subGroup->isDynamic() )
                    continue;
                if( $subGroup->owner !== $this )
                    continue;

                if( $group->name() !== $subGroup->name() )
                    $sortingArray[$group->name()][$subGroup->name()] = TRUE;
                #$sortingArray[$group->name()][$subGroup->name()] = TRUE;
            }
        }

        $loopCount = 0;
        while( count($sortingArray) > 0 )
        {
            foreach( $sortingArray as $groupName => &$groupDependencies )
            {
                if( count($groupDependencies) == 0 )
                {
                    $result[] = $this->_addressGroups[$groupName];
                    unset($sortingArray[$groupName]);

                    foreach( $sortingArray as &$tmpGroupDeps )
                    {
                        if( isset($tmpGroupDeps[$groupName]) )
                            unset($tmpGroupDeps[$groupName]);
                    }
                }
            }

            $loopCount++;

            if( $loopCount > 40 )
            {
                print_r( $sortingArray );
                PH::print_stdout("AddressGroup LOOP detected | please manual manipulate your configuration file, check the output above!!");
                derr("cannot determine groups dependencies after 40 loops iterations: are there too many nested groups for '".get_class($this->owner)."': '".$this->owner->name()."' ?", NULL, FALSE);
            }
            /*
            if( $loopCount > 40 )
            {
                print_r( $sortingArray );
                foreach( $sortingArray as $groupName => &$groupDependencies )
                {
                    $result[] = $this->_addressGroups[$groupName];
                }
                #derr("cannot determine groups dependencies after 40 loops iterations: are there too many nested groups for '".get_class($this->owner)."': '".$this->owner->name()."' ?", NULL, FALSE);
                mwarning("cannot determine groups dependencies after 40 loops iterations: are there too many nested groups for '".get_class($this->owner)."': '".$this->owner->name()."' ?", NULL, FALSE);
                break;
            }
            */
        }

        return $result;
    }

    /**
     * Returns an Array with all Address object in this store (which are not 'tmp');
     * @return Address[]
     *
     */
    public function addressObjects()
    {
        return $this->_addressObjects;
    }

    public function addressTMPipObjects()
    {
        $tmp_array = array();
        foreach( $this->_tmpAddresses as $tmpAddress )
        {
            if( filter_var($tmpAddress->name(), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ||
                filter_var($tmpAddress->name(), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) )
                $tmp_array[] = $tmpAddress;
        }
        return $tmp_array;
    }

    public function addressANDtmpIPObjects()
    {
        $tmp_array = $this->addressTMPipObjects();
        $all = array_merge( $this->_addressObjects, $tmp_array );
        return $all;
    }

    /**
     * @return Address[]|AddressGroup[]
     */
    public function nestedPointOfView_old()
    {
        $current = $this;

        $objects = array();

        while( TRUE )
        {
            foreach( $current->_addressObjects as $o )
            {
                if( !isset($objects[$o->name()]) )
                    $objects[$o->name()] = $o;
            }
            foreach( $current->_addressGroups as $o )
            {
                if( !isset($objects[$o->name()]) )
                    $objects[$o->name()] = $o;
            }


            if( isset($current->owner->owner) && $current->owner->owner !== null && !$current->owner->owner->isFawkes() && !$current->owner->owner->isBuckbeak() )
                $current = $current->owner->owner->addressStore;
            else
                break;
        }

        return $objects;
    }

    /**
     * @return Address[]|AddressGroup[]
     */
    public function nestedPointOfView()
    {
        $current = $this;

        $objects = array();
        $objects_overwritten = array();

        while( TRUE )
        {
            if( get_class( $current->owner ) == "PanoramaConf" )
                $location = "shared";
            else
                $location = $current->owner->name();

            foreach( $current->_addressObjects as $o )
            {
                if( !isset($objects[$o->name()]) )
                    $objects[$o->name()] = $o;
                else
                {
                    $tmp_o = &$objects[ $o->name() ];
                    $tmp_ref_count = $tmp_o->countReferences();

                    $objects_overwritten[$o->name()][$tmp_o->owner->owner->name()] = $tmp_o;
                    $objects_overwritten[$o->name()][$location] = $o;

                    if( $tmp_ref_count == 0 && $tmp_o->isAddress() )
                    {
                        // if object is /32, let's remove it to match equivalent non /32 syntax
                        $tmp_value = $tmp_o->value();
                        if( $tmp_o->isType_ipNetmask() && strpos($tmp_o->value(), '/32') !== FALSE )
                            $tmp_value = substr($tmp_value, 0, strlen($tmp_value) - 3);

                        $o_value = $o->value();
                        if( $o->isType_ipNetmask() && strpos($o->value(), '/32') !== FALSE )
                            $o_value = substr($o_value, 0, strlen($o_value) - 3);
                        $o_ref_count = $o->countReferences();

                        if( $tmp_value != $o_value && ($o_ref_count > 0) )
                        {
                            if( $location != "shared" )
                                foreach( $o->refrules as $ref )
                                    $tmp_o->addReference( $ref );
                        }
                    }
                }
            }

            foreach( $current->_tmpAddresses as $o )
            {
                if( empty($o->value()) )
                    continue;

                if( !isset($objects[$o->name()]) )
                    $objects[$o->name()] = $o;
                else
                {
                    $tmp_o = &$objects[ $o->name() ];
                    $tmp_ref_count = $tmp_o->countReferences();

                    $objects_overwritten[$o->name()][$tmp_o->owner->owner->name()] = $tmp_o;
                    $objects_overwritten[$o->name()][$location] = $o;

                    if( $tmp_ref_count == 0 && $tmp_o->isAddress() )
                    {
                        $tmp_value = $tmp_o->value();
                        if( ($tmp_o->isType_ipNetmask() || $tmp_o->isType_TMP() ) && strpos($tmp_o->value(), '/') == FALSE )
                            $tmp_value = $tmp_value . "/32";

                        $o_value = $o->value();
                        if( ( $o->isType_ipNetmask() || $o->isType_TMP() ) && strpos($o->value(), '/') == FALSE )
                            $o_value = $o_value . "/32";
                        $o_ref_count = $o->countReferences();

                        if( $tmp_value != $o_value && ($o_ref_count > 0) )
                        {
                            if( $location != "shared" )
                                foreach( $o->refrules as $ref )
                                    $tmp_o->addReference( $ref );
                        }
                    }
                }
            }

            foreach( $current->_addressGroups as $o )
            {
                if( !isset($objects[$o->name()]) )
                    $objects[$o->name()] = $o;
                else
                {
                    $tmp_o = &$objects[ $o->name() ];
                    $tmp_ref_count = $tmp_o->countReferences();

                    $objects_overwritten[$o->name()][$tmp_o->owner->owner->name()] = $tmp_o;
                    $objects_overwritten[$o->name()][$location] = $o;

                    if( $tmp_ref_count == 0 && $tmp_o->isGroup() )
                    {
                        $tmp_mapping = $tmp_o->getFullMapping();
                        $tmp_value = $tmp_mapping['ip4']->dumpToString();

                        $o_mapping = $o->getFullMapping();
                        $o_value = $o_mapping['ip4']->dumpToString();
                        $o_ref_count = $o->countReferences();

                        if( $tmp_value != $o_value && ( $o_ref_count > 0) )
                        {
                            if( $location != "shared" )
                                foreach( $o->refrules as $ref )
                                    $tmp_o->addReference( $ref );
                        }
                    }
                }
            }

            if( isset($current->owner->parentDeviceGroup) && $current->owner->parentDeviceGroup !== null )
                $current = $current->owner->parentDeviceGroup->addressStore;
            elseif( isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                $current = $current->owner->parentContainer->addressStore;
            elseif( isset($current->owner->owner) && $current->owner->owner !== null && !$current->owner->owner->isFawkes() && !$current->owner->owner->isBuckbeak() )
                $current = $current->owner->owner->addressStore;
            else
                break;
        }

/*
        foreach( $objects_overwritten as $key => $DGs )
        {
            PH::print_stdout(  "NAME: ".$key."\n";
            foreach( $DGs as $key2 => $object )
            {
                if( $object->isAddress() )
                {
                    PH::print_stdout(  "   - DG: ".$key2." value: ".$object->value() );
                    PH::print_stdout(  "");
                    $object->display_references(7);
                }
                else
                {
                    PH::print_stdout(  "   - DG: ".$key2 );

                    $object->display_references(7);
                }
            }

            PH::print_stdout(  "");
        }*/

        return $objects;
    }

    /**
     * Used to create an object that is 'temporary' : means that is not supported (like Regions)
     * or that is on Panorama. This is a trick to play with objects that don't exist in the conf.
     *
     * @param string $name
     * @param ReferenceableObject $ref
     * @return Address
     */
    function createTmp($name, $ref = null)
    {
        if( isset($this->_all[$name]) )
        {
            mwarning("cannot create a TMP object named '{$name}' because an object with that name already existed and was returned by this function");
            return $this->_all[$name];
        }

        $f = new Address($name, $this);
        $f->setValue($name);
        $f->setType('tmp');

        $this->add($f);
        $f->addReference($ref);

        return $f;
    }


    /**
     * @param Address|AddressGroup $h
     * @param string $oldName
     * @return bool
     * @throws Exception
     */
    public function referencedObjectRenamed($h, $oldName)
    {
        if( $this->_all[$oldName] !== $h )
        {
            mwarning("Unexpected : object is not part of this library");
            return FALSE;
        }

        $newName = $h->name();

        unset($this->_all[$oldName]);
        $this->_all[$newName] = $h;

        $class = get_class($h);

        if( $class == 'Address' )
        {
            unset($this->_addressObjects[$oldName]);
            $this->_addressObjects[$newName] = $h;
        }
        elseif( $class == 'AddressGroup' )
        {
            unset($this->_addressGroups[$oldName]);
            $this->_addressGroups[$newName] = $h;
        }
        else
            derr('unsupported class');

        return TRUE;

    }


    public function countUnused()
    {
        $count = 0;
        foreach( $this->_all as $o )
        {
            if( $o->countReferences() == 0 )
                $count++;
        }

        return $count;
    }

    public function countUnusedAddresses()
    {
        $count = 0;
        foreach( $this->_addressObjects as $o )
        {
            if( $o->countReferences() == 0 )
                $count++;
        }

        return $count;
    }

    public function countUnusedAddressGroups()
    {
        $count = 0;
        foreach( $this->_addressGroups as $o )
        {
            if( $o->countReferences() == 0 )
                $count++;
        }

        return $count;
    }

    public function storeName()
    {
        return "addressStore";
    }

    /**
     * Returns an Array with all Address|AddressGroup inside this store
     * @return Address[]|AddressGroup[]
     */
    public function &resultingObjectSet()
    {

        $res = array();

        if( isset($this->owner->parentDeviceGroup) )
        {
            $varName = $this->storeName();
            /** @var AddressStore $var */
            $var = $this->owner->parentDeviceGroup->$varName;
            #$var = $this->owner->parentDeviceGroup->addressStore;
            $res = $var->resultingObjectSet();
        }
        elseif( $this->owner->isPanorama() )
        {
            $varName = $this->storeName();
            /** @var AddressStore $var */
            $var = $this->owner->$varName;
            #$var = $this->owner->addressStore;
            $res = $var->all();
        }

        if( !$this->owner->isPanorama() )
            $res = array_merge($res, $this->all());

        return $res;
    }

    public function move( $context, $object )
    {
        if( $object->isTmpAddr() )
        {
            $string = "this is a temporary object";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $object->isRegion() )
        {
            $string = "this is a Region object - not supported yet";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $localLocation = 'shared';

        if( !$object->owner->owner->isPanorama() && !$object->owner->owner->isFirewall() )
            $localLocation = $object->owner->owner->name();

        $targetLocation = $context->arguments['location'];
        $targetStore = null;

        if( $localLocation == $targetLocation )
        {
            $string = "because original and target destinations are the same: $targetLocation";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $targetLocation == 'shared' )
        {
            $findSubSystem = $rootObject;
            $targetStore = $rootObject->addressStore;
        }
        else
        {
            $findSubSystem = $rootObject->findSubSystemByName($targetLocation);
            if( $findSubSystem === null )
                derr("cannot find VSYS/DG named '$targetLocation'");

            $targetStore = $findSubSystem->addressStore;
        }

        if( $localLocation == 'shared' )
        {
            $reflocations = $object->getReferencesLocation();

            foreach( $object->getReferences() as $ref )
            {
                if( PH::getLocationString($ref) != $targetLocation )
                {
                    $skipped = TRUE;
                    //check if targetLocation is parent of reflocation
                    if( $findSubSystem->owner->isPanorama() )
                        $locations = $findSubSystem->childDeviceGroups(TRUE);
                    elseif( $findSubSystem->owner->isFirewall() )
                    {
                        $locations = array();
                        $skipped = TRUE;
                    }


                    foreach( $locations as $childloc )
                    {
                        if( PH::getLocationString($ref) == $childloc->name() )
                            $skipped = FALSE;
                    }

                    if( $skipped )
                    {
                        $string = "moving from SHARED to sub-level is NOT possible because of references on higher DG level";
                        PH::ACTIONstatus( $context, "SKIPPED", $string );
                        return;
                    }
                }
            }
        }

        if( $localLocation != 'shared' && $targetLocation != 'shared' )
        {
            if( $context->baseObject->isFirewall() )
            {
                $string = "moving between VSYS is not supported";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }


            foreach( $object->getReferences() as $ref )
            {
                if( PH::getLocationString($ref) != $targetLocation )
                {
                    $skipped = TRUE;
                    //check if targetLocation is parent of reflocation
                    $locations = $findSubSystem->childDeviceGroups(TRUE);
                    foreach( $locations as $childloc )
                    {
                        if( PH::getLocationString($ref) == $childloc->name() )
                            $skipped = FALSE;
                    }

                    if( $skipped )
                    {
                        $string = "moving between 2 VSYS/DG is not possible because of references on higher DG level";
                        PH::ACTIONstatus( $context, "SKIPPED", $string );
                        return;
                    }
                }
            }
        }

        $conflictObject = $targetStore->find($object->name(), null, FALSE);
        if( $conflictObject === null )
        {
            if( $object->isGroup() && !$object->isDynamic() )
            {
                foreach( $object->members() as $memberObject )
                {
                    if( $targetStore->find($memberObject->name(), null, true ) === null )
                    {
                        $string = "this group has an object named '{$memberObject->name()} that does not exist in target location '{$targetLocation}'";
                        PH::ACTIONstatus( $context, "SKIPPED", $string );
                        return;
                    }
                }
            }
            elseif( $object->isAddress() && !$object->isType_TMP() && !$object->isRegion() )
            {
                foreach( $object->tags->getAll() as $tag )
                {
                    if( $findSubSystem->tagStore->find($tag->name(), null, true ) === null )
                    {
                        $string = "this address object has a tag named '{$tag->name()} that does not exist in target location '{$targetLocation}'";
                        PH::ACTIONstatus( $context, "SKIPPED", $string );
                        return;
                    }
                }
            }

            if( !$context->subSystem->isFirewall() && !$context->subSystem->isVirtualSystem() )
            {

                //validation if upper/lower level is not changed
                $tmplocalSub = $rootObject->findSubSystemByName($localLocation);
                if( $tmplocalSub->isPanorama() )
                {
                    /** @var PanoramaConf $tmplocalSub */
                    $tmpChildSubs = $tmplocalSub->deviceGroups;
                }
                else
                    $tmpChildSubs = $tmplocalSub->childDeviceGroups();

                $lowerLevelMove = FALSE;
                foreach( $tmpChildSubs as $childDG )
                {
                    if( $targetLocation == $childDG->name() )
                        $lowerLevelMove = TRUE;
                }

                if( !$lowerLevelMove )
                {
                    $startLocation = $tmplocalSub;
                    $endLocation = $findSubSystem;
                }
                else
                {
                    $endLocation = $tmplocalSub;
                    $startLocation = $findSubSystem;
                }
                $skipped = FALSE;
                do
                {
                    if( !isset($startLocation->parentDeviceGroup->addressStore) )
                        break;

                    $tmpObject = $startLocation->parentDeviceGroup->addressStore->find($object->name(), null, FALSE);
                    if( $tmpObject != null )
                    {
                        if( ($object->isGroup() and $tmpObject->isGroup()) || ($object->isGroup() and !$tmpObject->isGroup()) || (!$object->isGroup() and $tmpObject->isGroup()) )
                            $skipped = TRUE;
                        elseif( $object->type() != $tmpObject->type() )
                            $skipped = TRUE;
                        elseif( $object->value() != $tmpObject->value() )
                            $skipped = TRUE;
                    }

                    if( !$skipped )
                        $startLocation = $startLocation->parentDeviceGroup;
                    else
                    {
                        if( !$lowerLevelMove )
                            $string = "moving to upper level DG is not possible because of object available at lower DG level with same name but different object type or value";
                        else
                            $string = "moving to lower level DG is not possible because of object available at upper DG level with same name but different object type or value";
                        PH::ACTIONstatus($context, "SKIPPED", $string);
                        return;
                    }
                } while( $startLocation != $endLocation );
            }
            ///////////////////////////////

            $string = "moved, no conflict";
            PH::ACTIONlog( $context, $string );

            if( $context->isAPI )
            {
                $oldXpath = $object->getXPath();
                $object->owner->remove($object);
                $targetStore->add($object);
                $object->API_sync();
                $context->connector->sendDeleteRequest($oldXpath);
            }
            else
            {
                $object->owner->remove($object);
                $targetStore->add($object);
            }
            return;
        }

        if( $context->arguments['mode'] == 'skipifconflict' )
        {
            $string = "there is an object with same name. Choose another mode to resolve this conflict";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $text = "there is a conflict with an object of same name and type. Please use address-merger.php script with argument 'allowmergingwithupperlevel'";
        if( $conflictObject->isGroup() )
            $text .= " - Group";
        else
            $text .= " - ".$conflictObject->type();
        PH::ACTIONlog( $context, $text );

        if( $conflictObject->isGroup() && !$object->isGroup() || !$conflictObject->isGroup() && $object->isGroup() )
        {
            $string = "because conflict has mismatching types";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $conflictObject->isTmpAddr() )
        {
            $string = "because the conflicting object is TMP| value: ".$conflictObject->value();
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            //normally the $object must be moved and the conflicting TMP object must be replaced by this $object
            return;
        }

        if( $object->isGroup() )
        {
            $localMap = $object->getIP4Mapping();
            $targetMap = $conflictObject->getIP4Mapping();

            if( $object->equals($conflictObject) && $localMap->equals($targetMap) )
                //if( $object->equals($conflictObject) )
            {
                //
                //bug; deep matching ip4mapping needed

                $string = "Removed because target has same content";
                PH::ACTIONlog( $context, $string );

                $object->replaceMeGlobally($conflictObject);
                if( $context->isAPI )
                    $object->owner->API_remove($object);
                else
                    $object->owner->remove($object);

                return;
            }
            else
            {
                $object->displayValueDiff($conflictObject, 9);
                if( $context->arguments['mode'] == 'removeifmatch' )
                {
                    $string = "because of mismatching group content";
                    PH::ACTIONstatus( $context, "SKIPPED", $string );
                    return;
                }

                if( !$localMap->equals($targetMap) )
                {
                    $string = "because of mismatching group content and numerical values";
                    PH::ACTIONstatus( $context, "SKIPPED", $string );
                    return;
                }

                $string = "Removed because it has same numerical value";
                PH::ACTIONlog( $context, $string );

                $object->replaceMeGlobally($conflictObject);
                if( $context->isAPI )
                    $object->owner->API_remove($object);
                else
                    $object->owner->remove($object);

                return;

            }
        }

        if( $object->equals($conflictObject) )
        {
            $string = "Removed because target has same content";
            PH::ACTIONlog( $context, $string );

            $object->replaceMeGlobally($conflictObject);

            if( $context->isAPI )
                $object->owner->API_remove($object);
            else
                $object->owner->remove($object);
            return;
        }
        elseif( $object->isType_ipNetmask() )
        {
            if( str_replace('/32', '', $conflictObject->value()) == str_replace('/32', '', $object->value()) )
            {
                $string = "Removed because target has same content";
                PH::ACTIONlog( $context, $string );

                $object->replaceMeGlobally($conflictObject);

                if( $context->isAPI )
                    $object->owner->API_remove($object);
                else
                    $object->owner->remove($object);
                return;
            }
        }

        if( $context->arguments['mode'] == 'removeifmatch' )
            return;

        $localMap = $object->getIP4Mapping();
        $targetMap = $conflictObject->getIP4Mapping();

        if( !$localMap->equals($targetMap) )
        {
            $string = "because of mismatching content and numerical values";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "Removed because target has same numerical value";
        PH::ACTIONlog( $context, $string );

        $object->replaceMeGlobally($conflictObject);
        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);

        return true;
    }

}

