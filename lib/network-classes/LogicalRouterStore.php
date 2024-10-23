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
 * Class IPsecTunnelStore
 * @property $o IPsecTunnel[]
 */
class LogicalRouterStore extends ObjStore
{

    /** @var null|PANConf */
    public $owner;

    public static $childn = 'LogicalRouter';

    protected $fastMemToIndex;
    protected $fastNameToIndex;


    public function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
        $this->classn = &self::$childn;
    }

    /**
     * @return LogicalRouter[]
     */
    public function logicalRouters()
    {
        return $this->o;
    }

    /**
     * @param $vrName string
     * @return null|LogicalRouter
     */
    public function findLogicalRouter($vrName)
    {
        return $this->findByName($vrName);
    }

    /**
     * Creates a new LogicalRouter in this store. It will be placed at the end of the list.
     * @param string $name name of the new LogicalRouter
     * @return LogicalRouter
     */
    public function newLogicalRouter($name)
    {
        foreach( $this->logicalRouters() as $vr )
        {
            if( $vr->name() == $name )
                derr("LogicalRouter: " . $name . " already available\n");
        }

        $logicalRouter = new logicalRouter($name, $this);
        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, logicalRouter::$templatexml);

        $logicalRouter->load_from_domxml($xmlElement);

        $logicalRouter->owner = null;
        $logicalRouter->setName($name);

        //20190507 - which add method is best, is addlogicalRouter needed??
        $this->addlogicalRouter($logicalRouter);
        $this->add($logicalRouter);

        return $logicalRouter;
    }

    /**
     * @param LogicalRouter $logicalRouter
     * @return bool
     */
    public function addLogicalRouter($logicalRouter)
    {
        if( !is_object($logicalRouter) )
            derr('this function only accepts logicalRouter class objects');

        if( $logicalRouter->owner !== null )
            derr('Trying to add a logicalRouter that has a owner already !');


        $ser = spl_object_hash($logicalRouter);

        if( !isset($this->fastMemToIndex[$ser]) )
        {
            $logicalRouter->owner = $this;

            $this->fastMemToIndex[$ser] = $logicalRouter;
            $this->fastNameToIndex[$logicalRouter->name()] = $logicalRouter;

            if( $this->xmlroot === null )
                $this->createXmlRoot();

            $this->xmlroot->appendChild($logicalRouter->xmlroot);

            return TRUE;
        }
        else
            derr('You cannot add a logicalRouter that is already here :)');

        return FALSE;
    }

    public function createXmlRoot()
    {
        if( $this->xmlroot === null )
        {
            $xml = DH::findFirstElementOrCreate('devices', $this->owner->xmlroot);
            $xml = DH::findFirstElementOrCreate('entry', $xml);
            $xml = DH::findFirstElementOrCreate('network', $xml);

            $this->xmlroot = DH::findFirstElementOrCreate('logical-router', $xml);
        }
    }

    private function &getBaseXPath()
    {

        $str = "";
        /*
                if( $this->owner->owner->isTemplate() )
                    $str .= $this->owner->owner->getXPath();
                elseif( $this->owner->isPanorama() || $this->owner->isFirewall() )
                    $str = '/config/shared';
                else
                    derr('unsupported');
        */

        //TODO: intermediate solution
        $str .= '/config/devices/entry/network';

        return $str;
    }

    public function &getlogicalRouterStoreXPath()
    {
        $path = $this->getBaseXPath() . '/logical-router';
        return $path;
    }

}