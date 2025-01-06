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
 * Class GPPortalStore
 *
 * @property GPPortalStore $parentCentralStore
 * @property GPPortal[] $o
 *
 */
class GPPortalStore extends ObjStore
{
    /** @var DeviceGroup|PanoramaConf|VirtualSystem */
    public $owner;

    public $parentCentralStore = null;

    public static $childn = 'GPPortal';

    /**
     * @param VirtualSystem|DeviceCloud|DeviceGroup|PanoramaConf|Container|FawkesConf $owner
     */
    public function __construct($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;

        $this->findParentCentralStore( 'GPPortalStore' );
    }


    /**
     * looks for a GPPortal named $name ,return that GPPortal object, null if not found
     * @param string $name
     * @return GPPortal
     */
    public function find($name, $ref = null, $nested = false)
    {
        return $this->findByName($name, $ref, $nested);
    }


    /**
     * add a GPPortal to this store. Use at your own risk.
     * @param GPPortal
     * @param bool
     * @return bool
     */
    public function addGPPortal(GPPortal $GPPortal, $rewriteXML = TRUE)
    {
        $fasthashcomp = null;

        $ret = $this->add($GPPortal);

        if( $ret && $rewriteXML && !$GPPortal->isTmp() && $this->xmlroot !== null )
        {
            $this->xmlroot->appendChild($GPPortal->xmlroot);
        }
        return $ret;
    }


    /**
     * remove a GPPortal a GPPortal to this store.
     * @param GPPortal
     *
     * @return bool  True if GPPortal was found and removed. False if not found.
     */
    public function removeGPPortal(GPPortal $GPPortal)
    {
        $ret = $this->remove($GPPortal);

        if( $ret && !$GPPortal->isTmp() && $this->xmlroot !== null )
        {
            $this->xmlroot->removeChild($GPPortal->xmlroot);
        }

        return $ret;
    }

    /**
     * @param GPPortal|string $GPPortalName can be GPPortal object or GPPortal name (string). this is case sensitive
     * @return bool
     */
    public function hasGPPortalNamed($GPPortalName, $caseSensitive = TRUE)
    {
        return $this->has($GPPortalName, $caseSensitive);
    }


    /**
     * return an array with all GPPortals in this store
     * @return GPPortal[]
     */
    public function GPPortals()
    {
        return $this->o;
    }


    public function rewriteXML()
    {
        if( $this->xmlroot !== null )
        {
            DH::clearDomNodeChilds($this->xmlroot);
            foreach( $this->o as $GPPortal )
            {
                if( !$GPPortal->isTmp() )
                    $this->xmlroot->appendChild($GPPortal->xmlroot);
            }
        }

    }


    public function &getXPath()
    {
        if( $this->xmlroot === null )
            derr('unsupported on virtual Stores');

        $xpath = $this->owner->getXPath() . "/global-protect/global-protect-gateway/";

        return $xpath;

    }


    public function newGPPortal($name, $type)
    {
        foreach( $this->GPPortals() as $GPPortal )
        {
            if( $GPPortal->name() == $name )
                derr("GPPortal: " . $name . " already available\n");
        }

        $found = $this->find($name, null, FALSE);
        if( $found !== null )
            derr("cannot create GPPortal named '" . $name . "' as this name is already in use ");

        $ns = new GPPortal($name, $this, TRUE, $type);

        $this->addGPPortal($ns);

        return $ns;

    }


}



