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

/**
 * Class InterfaceManagementProfileStore
 * @property $o InterfaceManagementProfile[]
 * @property PANConf $owner
 */
class InterfaceManagementProfileStore extends ObjStore
{
    public $owner;

    public static $childn = 'InterfaceManagementProfile';

    /** @var InterfaceManagementProfile[] */
    protected $_all = array();

    protected $fastMemToIndex = null;
    protected $fastNameToIndex = null;

    public function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
        $this->classn = &self::$childn;
    }

    /**
     * @return InterfaceManagementProfile[]
     */
    public function interfaceManagementProfile()
    {
        return $this->o;
    }

    /**
     * Creates a new InterfaceManagementProfile in this store. It will be placed at the end of the list.
     * @param string $name name of the new InterfaceManagementProfile
     * @return InterfaceManagementProfile
     */
    public function newInterfaceManagementProfile($name)
    {
        $InterfaceManagementProfile = new InterfaceManagementProfile($name, $this);
        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, InterfaceManagementProfile::$templatexml);

        $InterfaceManagementProfile->load_from_domxml($xmlElement);

        $InterfaceManagementProfile->owner = null;
        $InterfaceManagementProfile->setName($name);

        $this->addProfil($InterfaceManagementProfile);

        $this->_all[$InterfaceManagementProfile->name()] = $InterfaceManagementProfile;

        return $InterfaceManagementProfile;
    }

    /**
     * @param InterfaceManagementProfile $InterfaceManagementProfile
     * @return bool
     */
    public function addProfil($InterfaceManagementProfile)
    {
        if( !is_object($InterfaceManagementProfile) )
            derr('this function only accepts InterfaceManagementProfile class objects');

        if( $InterfaceManagementProfile->owner !== null )
            derr('Trying to add a InterfaceManagementProfile that has a owner already !');


        $ser = spl_object_hash($InterfaceManagementProfile);

        if( !isset($this->fastMemToIndex[$ser]) )
        {
            $InterfaceManagementProfile->owner = $this;

            if( $this->xmlroot === null )
                $this->createXmlRoot();

            $this->xmlroot->appendChild($InterfaceManagementProfile->xmlroot);

            $ret = $this->add($InterfaceManagementProfile);

            return TRUE;
        }
        else
            derr('You cannot add a InterfaceManagementProfile that is already here :)');

        return FALSE;
    }

    public function createXmlRoot()
    {
        if( $this->xmlroot === null )
        {
            $xml = DH::findFirstElementOrCreate('devices', $this->owner->xmlroot);
            $xml = DH::findFirstElementOrCreate('entry', $xml);
            $xml = DH::findFirstElementOrCreate('network', $xml);
            $xml = DH::findFirstElementOrCreate('profiles', $xml);

            $this->xmlroot = DH::findFirstElementOrCreate('interface-management-profiles', $xml);
        }
    }


    /**
     * @param InterfaceManagementProfile $s
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

        $s->owner = null;

        $this->xmlroot->removeChild($s->xmlroot);

        if( $cleanInMemory )
            $s->xmlroot = null;

        return TRUE;
    }

    /**
     * @param $InterfaceManagementProfile string
     * @return null|InterfaceManagementProfile
     */
    public function findInterfaceManagementProfile($InterfaceManagementProfile)
    {
        return $this->findByName($InterfaceManagementProfile);
    }
} 