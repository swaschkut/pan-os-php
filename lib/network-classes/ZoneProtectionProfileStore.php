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
 * Class ZoneProtectionProfileStore
 * @property $o ZoneProtectionProfile[]
 * @property PANConf $owner
 */
class ZoneProtectionProfileStore extends ObjStore
{
    public $owner;

    public static $childn = 'ZoneProtectionProfile';

    /** @var ZoneProtectionProfile[] */
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
     * @return ZoneProtectionProfile[]
     */
    public function zoneProtectionProfile()
    {
        return $this->o;
    }

    /**
     * Creates a new IPsecCryptoProfil in this store. It will be placed at the end of the list.
     * @param string $name name of the new IPsecCryptoProfil
     * @return ZoneProtectionProfile
     */
    public function newZoneProtectionProfile($name)
    {
        $ZoneProtectionProfile = new ZoneProtectionProfile($name, $this);
        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, ZoneProtectionProfile::$templatexml);

        $ZoneProtectionProfile->load_from_domxml($xmlElement);

        $ZoneProtectionProfile->owner = null;
        $ZoneProtectionProfile->setName($name);

        $this->addProfil($ZoneProtectionProfile);

        $this->_all[$ZoneProtectionProfile->name()] = $ZoneProtectionProfile;

        return $ZoneProtectionProfile;
    }

    /**
     * @param ZoneProtectionProfile $ZoneProtectionProfile
     * @return bool
     */
    public function addProfil($ZoneProtectionProfile)
    {
        if( !is_object($ZoneProtectionProfile) )
            derr('this function only accepts ZoneProtectionProfile class objects');

        if( $ZoneProtectionProfile->owner !== null )
            derr('Trying to add a ZoneProtectionProfile that has a owner already !');


        $ser = spl_object_hash($ZoneProtectionProfile);

        if( !isset($this->fastMemToIndex[$ser]) )
        {
            $ZoneProtectionProfile->owner = $this;

            if( $this->xmlroot === null )
                $this->createXmlRoot();

            $this->xmlroot->appendChild($ZoneProtectionProfile->xmlroot);

            $ret = $this->add($ZoneProtectionProfile);

            return TRUE;
        }
        else
            derr('You cannot add a ZoneProtectionProfile that is already here :)');

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

            $this->xmlroot = DH::findFirstElementOrCreate('zone-protection-profiles', $xml);
        }
    }


    /**
     * @param ZoneProtectionProfile $s
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
     * @param $ZoneProtectionProfile string
     * @return null|IPsecTunnel
     */
    public function findZoneProtectionProfile($ZoneProtectionProfile)
    {
        return $this->findByName($ZoneProtectionProfile);
    }
} 