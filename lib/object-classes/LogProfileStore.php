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
 * Class LogProfileStore
 * @property LogProfile[] $o
 * @property VirtualSystem|DeviceGroup|PanoramaConf|PANConf|Container|DeviceCloud $owner
 * @method LogProfile[] getAll()
 */
class LogProfileStore extends ObjStore
{
    /** @var null|LogProfileStore */
    public $parentCentralStore = null;

    public static $childn = 'LogProfile';


    public function __construct($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;
        $this->o = array();

        if( isset($owner->parentDeviceGroup) && $owner->parentDeviceGroup !== null )
            $this->parentCentralStore = $owner->parentDeviceGroup->LogProfileStore;
        elseif( isset($owner->parentContainer) && $owner->parentContainer !== null )
        {
            $this->parentCentralStore = $owner->parentContainer->LogProfileStore;
        }
        else
            $this->findParentCentralStore( 'LogProfileStore' );

    }

    /**
     * @param $name
     * @param null $ref
     * @param bool $nested
     * @return null|LogProfile
     */
    public function find($name, $ref = null, $nested = TRUE)
    {
        $f = $this->findByName($name, $ref, $nested);

        if( $f !== null )
            return $f;

        if( $nested && $this->parentCentralStore !== null )
            return $this->parentCentralStore->find($name, $ref, $nested);

        return null;
    }

    public function removeAllLogProfiles()
    {
        $this->removeAll();
        $this->rewriteXML();
    }

    /**
     * add a LogProfile to this store. Use at your own risk.
     * @param LogProfile $Obj
     * @param bool
     * @return bool
     */

    public function addLogProfile( $Obj, $rewriteXML = TRUE)
    {
        $ret = $this->add($Obj);
        if( $ret && $rewriteXML )
        {
            if( $this->xmlroot === null )
            {
                $tmp_xmlroot = DH::findFirstElementOrCreate('log-settings', $this->owner->xmlroot);
                $this->xmlroot = DH::findFirstElementOrCreate('profiles', $tmp_xmlroot);
            }

            $this->xmlroot->appendChild($Obj->xmlroot);
        }
        return $ret;
    }


    /**
     * @param string $base
     * @param string $suffix
     * @param integer|string $startCount
     * @return string
     */
    public function findAvailableLogProfileName($base, $suffix, $startCount = '')
    {
        $maxl = 31;
        $basel = strlen($base);
        $suffixl = strlen($suffix);
        $inc = $startCount;
        $basePlusSuffixL = $basel + $suffixl;

        while( TRUE )
        {
            $incl = strlen(strval($inc));

            if( $basePlusSuffixL + $incl > $maxl )
            {
                $newname = substr($base, 0, $basel - $suffixl - $incl) . $suffix . $inc;
            }
            else
                $newname = $base . $suffix . $inc;

            if( $this->find($newname) === null )
                return $newname;

            if( $startCount == '' )
                $startCount = 0;
            $inc++;
        }
    }


    /**
     * return LogProfiles in this store
     * @return LogProfile[]
     */
    public function logprofiles()
    {
        return $this->o;
    }

    function createLogProfile($name, $ref = null)
    {
        if( $this->find($name, null, FALSE) !== null )
            derr('LogProfile named "' . $name . '" already exists, cannot create');

        if( $this->xmlroot === null )
        {
            if( $this->owner->isDeviceGroup() || $this->owner->isVirtualSystem() || $this->owner->isContainer() || $this->owner->isDeviceCloud() )
            {
                $tmp_xmlroot = DH::findFirstElementOrCreate('log-settings', $this->owner->xmlroot);
                $this->xmlroot = DH::findFirstElementOrCreate('profiles', $tmp_xmlroot);
            }
            else
            {
                $tmp_xmlroot = DH::findFirstElementOrCreate('log-settings', $this->owner->sharedroot);
                $this->xmlroot = DH::findFirstElementOrCreate('profiles', $tmp_xmlroot);
            }
        }

        $newLogProfile = new LogProfile($name, $this, TRUE);

        if( $ref !== null )
            $newLogProfile->addReference($ref);

        $this->addLogProfile($newLogProfile);

        return $newLogProfile;
    }

    function findOrCreate($name, $ref = null, $nested = TRUE)
    {
        $f = $this->find($name, $ref, $nested);

        if( $f !== null )
            return $f;

        return $this->createLogProfile($name, $ref);
    }

    function API_createLogProfile($name, $ref = null)
    {
        $newLogProfile = $this->createLogProfile($name, $ref);

        if( !$newLogProfile->isTmp() )
        {
            $xpath = $this->getXPath();
            $con = findConnectorOrDie($this);
            $element = $newLogProfile->getXmlText_inline();

            if( $con->isAPI() )
                $con->sendSetRequest($xpath, $element);
        }

        return $newLogProfile;
    }


    /**
     * @param LogProfile $LogProfile
     *
     * @return bool  True if Zone was found and removed. False if not found.
     */
    public function removeLogProfile(LogProfile $LogProfile)
    {
        $ret = $this->remove($LogProfile);

        if( $ret && !$LogProfile->isTmp() && $this->xmlroot !== null )
        {
            if( $this->count() > 0 )
                $this->xmlroot->removeChild($LogProfile->xmlroot);
            else
                DH::clearDomNodeChilds($this->xmlroot);
        }

        return $ret;
    }

    /**
     * @param LogProfile $LogProfile
     * @return bool
     */
    public function API_removeLogProfile(LogProfile $LogProfile)
    {
        $xpath = null;

        if( !$LogProfile->isTmp() )
            $xpath = $LogProfile->getXPath();

        $ret = $this->removeLogProfile($LogProfile);

        if( $ret && !$LogProfile->isTmp() )
        {
            $con = findConnectorOrDie($this);

            if( $con->isAPI() )
                $con->sendDeleteRequest($xpath);
        }

        return $ret;
    }

    public function &getXPath()
    {
        $str = '';

        if( $this->owner->isDeviceGroup() || $this->owner->isVirtualSystem() || $this->owner->isContainer() || $this->owner->isDeviceCloud() )
            $str = $this->owner->getXPath();
        elseif( $this->owner->isPanorama() || $this->owner->isFirewall() )
            $str = '/config/shared';
        else
            derr('unsupported');

        $str = $str . '/log-settings/profiles';

        return $str;
    }


    private function &getBaseXPath()
    {
        if( $this->owner->isPanorama() || $this->owner->isFirewall() )
        {
            $str = "/config/shared";
        }
        else
            $str = $this->owner->getXPath();


        return $str;
    }

    public function &getLogProfileStoreXPath()
    {
        $path = $this->getBaseXPath() . '/log-settings/profiles';
        return $path;
    }

    public function rewriteXML()
    {
        if( count($this->o) > 0 )
        {
            if( $this->xmlroot === null )
                return;

            $this->xmlroot->parentNode->removeChild($this->xmlroot);
            $this->xmlroot = null;
        }

        if( $this->xmlroot === null )
        {
            if( count($this->o) > 0 )
                DH::findFirstElementOrCreate('log-settings', $this->owner->xmlroot);
        }

        DH::clearDomNodeChilds($this->xmlroot);
        foreach( $this->o as $o )
        {
            if( !$o->isTmp() )
                $this->xmlroot->appendChild($o->xmlroot);
        }
    }



    /**
     * @return LogProfile[]
     */
    public function nestedPointOfView()
    {
        $current = $this;

        $objects = array();

        while( TRUE )
        {
            if( get_class( $current->owner ) == "PanoramaConf" )
                $location = "shared";
            else
                $location = $current->owner->name();

            foreach( $current->o as $o )
            {
                if( !isset($objects[$o->name()]) )
                    $objects[$o->name()] = $o;
                else
                {
                    $tmp_o = &$objects[ $o->name() ];
                    $tmp_ref_count = $tmp_o->countReferences();

                    if( $tmp_ref_count == 0 )
                    {
                        //Todo: check if object value is same; if same to not add ref
                        if( $location != "shared" )
                            foreach( $o->refrules as $ref )
                                $tmp_o->addReference( $ref );
                    }
                }
            }

            if( isset($current->owner->parentDeviceGroup) && $current->owner->parentDeviceGroup !== null )
                $current = $current->owner->parentDeviceGroup->LogProfileStore;
            elseif( isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                $current = $current->owner->parentContainer->LogProfileStore;
            elseif( isset($current->owner->owner) && $current->owner->owner !== null && !$current->owner->owner->isFawkes() && !$current->owner->owner->isBuckbeak() )
                $current = $current->owner->owner->LogProfileStore;
            else
                break;
        }

        return $objects;
    }

    public function storeName()
    {
        return "LogProfileStore";
    }

}


