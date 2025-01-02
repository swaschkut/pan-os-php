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
 * Class GPGatewayStore
 *
 * @property GPGatewayStore $parentCentralStore
 * @property GPGateway[] $o
 *
 */
class GPGatewayStore extends ObjStore
{
    /** @var DeviceGroup|PanoramaConf|VirtualSystem */
    public $owner;

    public $parentCentralStore = null;

    public static $childn = 'GPGateway';

    /**
     * @param VirtualSystem|DeviceCloud|DeviceGroup|PanoramaConf|Container|FawkesConf $owner
     */
    public function __construct($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;

        $this->findParentCentralStore( 'GPGatewayStore' );
    }


    /**
     * looks for a GPGateway named $name ,return that GPGateway object, null if not found
     * @param string $name
     * @return GPGateway
     */
    public function find($name, $ref = null, $nested = false)
    {
        return $this->findByName($name, $ref, $nested);
    }


    /**
     * add a GPGateway to this store. Use at your own risk.
     * @param GPGateway
     * @param bool
     * @return bool
     */
    public function addGPGateway(GPGateway $GPGateway, $rewriteXML = TRUE)
    {
        $fasthashcomp = null;

        $ret = $this->add($GPGateway);

        if( $ret && $rewriteXML && !$GPGateway->isTmp() && $this->xmlroot !== null )
        {
            $this->xmlroot->appendChild($GPGateway->xmlroot);
        }
        return $ret;
    }


    /**
     * remove a GPGateway a GPGateway to this store.
     * @param GPGateway
     *
     * @return bool  True if GPGateway was found and removed. False if not found.
     */
    public function removeGPGateway(GPGateway $GPGateway)
    {
        $ret = $this->remove($GPGateway);

        if( $ret && !$GPGateway->isTmp() && $this->xmlroot !== null )
        {
            $this->xmlroot->removeChild($GPGateway->xmlroot);
        }

        return $ret;
    }

    /**
     * @param GPGateway|string $GPGatewayName can be GPGateway object or GPGateway name (string). this is case sensitive
     * @return bool
     */
    public function hasGPGatewayNamed($GPGatewayName, $caseSensitive = TRUE)
    {
        return $this->has($GPGatewayName, $caseSensitive);
    }


    /**
     * return an array with all GPGateways in this store
     * @return GPGateway[]
     */
    public function GPGateways()
    {
        return $this->o;
    }


    public function rewriteXML()
    {
        if( $this->xmlroot !== null )
        {
            DH::clearDomNodeChilds($this->xmlroot);
            foreach( $this->o as $GPGateway )
            {
                if( !$GPGateway->isTmp() )
                    $this->xmlroot->appendChild($GPGateway->xmlroot);
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


    public function newGPGateway($name, $type)
    {
        foreach( $this->GPGateways() as $GPGateway )
        {
            if( $GPGateway->name() == $name )
                derr("GPGateway: " . $name . " already available\n");
        }

        $found = $this->find($name, null, FALSE);
        if( $found !== null )
            derr("cannot create GPGateway named '" . $name . "' as this name is already in use ");

        $ns = new GPGateway($name, $this, TRUE, $type);

        $this->addGPGateway($ns);

        return $ns;

    }


}



