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
 * Class CertificateStore
 *
 * @property SSL_TLSServiceProfileStore $parentCentralStore
 * @property SSL_TLSServiceProfile[] $o
 *
 */
class SSL_TLSServiceProfileStore extends ObjStore
{
    /** @var DeviceGroup|PanoramaConf|VirtualSystem */
    public $owner;

    public $parentCentralStore = null;

    public static $childn = 'SSL_TLSServiceProfile';

    /**
     * @param VirtualSystem|DeviceCloud|DeviceGroup|PanoramaConf|PANConf|Container|FawkesConf|Template $owner
     */
    public function __construct($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;

        $this->findParentCentralStore( 'SSL_TLSServiceProfileStore' );
    }


    /**
     * looks for a SSL_TLSServiceProfile named $name ,return that SSL_TLSServiceProfile object, null if not found
     * @param string $name
     * @return SSL_TLSServiceProfile
     */
    public function find($name, $ref = null, $nested = false)
    {
        return $this->findByName($name, $ref, $nested);
    }


    /**
     * add a SSL_TLSServiceProfile to this store. Use at your own risk.
     * @param SSL_TLSServiceProfile
     * @param bool
     * @return bool
     */
    public function addSSL_TLSServiceProfile(SSL_TLSServiceProfile $ssl_tlsServiceProfile, $rewriteXML = TRUE)
    {
        $fasthashcomp = null;

        $ret = $this->add($ssl_tlsServiceProfile);

        if( $ret && $rewriteXML && !$ssl_tlsServiceProfile->isTmp() && $this->xmlroot !== null )
        {
            $this->xmlroot->appendChild($ssl_tlsServiceProfile->xmlroot);
        }
        return $ret;
    }


    /**
     * remove a SSL_TLSServiceProfile from this store.
     * @param SSL_TLSServiceProfile
     *
     * @return bool  True if Zone was found and removed. False if not found.
     */
    public function removeSSL_TLSServiceProfile(SSL_TLSServiceProfile $SSL_TLSServiceProfile)
    {
        $ret = $this->remove($SSL_TLSServiceProfile);

        if( $ret && !$SSL_TLSServiceProfile->isTmp() && $this->xmlroot !== null )
        {
            $this->xmlroot->removeChild($SSL_TLSServiceProfile->xmlroot);
        }

        return $ret;
    }

    /**
     * @param SSL_TLSServiceProfile|string $SSL_TLSServiceProfileName can be Zone object or certificate name (string). this is case sensitive
     * @return bool
     */
    public function hasSSL_TLSServiceProfileNamed($SSL_TLSServiceProfileName, $caseSensitive = TRUE)
    {
        return $this->has($SSL_TLSServiceProfileName, $caseSensitive);
    }


    /**
     * return an array with all Zones in this store
     * @return Zone[]
     */
    public function SSL_TLSServiceProfiles()
    {
        return $this->o;
    }


    public function rewriteXML()
    {
        if( $this->xmlroot !== null )
        {
            DH::clearDomNodeChilds($this->xmlroot);
            foreach( $this->o as $certificate )
            {
                if( !$certificate->isTmp() )
                    $this->xmlroot->appendChild($certificate->xmlroot);
            }
        }

    }


    public function &getXPath()
    {
        if( $this->xmlroot === null )
            derr('unsupported on virtual Stores');

        $xpath = $this->owner->getXPath() . "/ssl-tls-service-profile/";

        return $xpath;

    }


    public function newSSL_TLSServiceProfile($name, $type)
    {
        foreach( $this->SSL_TLSServiceProfiles() as $certificate )
        {
            if( $certificate->name() == $name )
                derr("Zone: " . $name . " already available\n");
        }

        $found = $this->find($name, null, FALSE);
        if( $found !== null )
            derr("cannot create SSL_TLSServiceProfile named '" . $name . "' as this name is already in use ");

        $ns = new SSL_TLSServiceProfile($name, $this, TRUE, $type);

        $this->addSSL_TLSServiceProfile($ns);

        return $ns;

    }


}



