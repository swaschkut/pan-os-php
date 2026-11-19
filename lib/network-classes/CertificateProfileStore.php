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
 * Class CertificateProfileStore
 *
 * @property CertificateProfile[] $o
 */
class CertificateProfileStore extends ObjStore
{
    /** @var PANConf|VirtualSystem|Template|TemplateStack|PanoramaConf */
    public $owner;

    public $parentCentralStore = null;

    public static $childn = 'CertificateProfile';

    /**
     * @param PANConf|VirtualSystem|Template|TemplateStack|PanoramaConf $owner
     */
    public function __construct($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;
    }

    /**
     * @param string $name
     * @return CertificateProfile|null
     */
    public function find($name, $ref = null, $nested = FALSE)
    {
        return $this->findByName($name, $ref, FALSE);
    }

    /**
     * @return CertificateProfile[]
     */
    public function certificateProfiles()
    {
        return $this->o;
    }

    /**
     * @param CertificateProfile $certificateProfile
     * @param bool $rewriteXML
     * @return bool
     */
    public function addCertificateProfile(CertificateProfile $certificateProfile, $rewriteXML = TRUE)
    {
        $ret = $this->add($certificateProfile);

        if( $ret && $rewriteXML && !$certificateProfile->isTmp() && $this->xmlroot !== null )
            $this->xmlroot->appendChild($certificateProfile->xmlroot);

        return $ret;
    }

    /**
     * @param CertificateProfile $certificateProfile
     * @return bool
     */
    public function removeCertificateProfile(CertificateProfile $certificateProfile)
    {
        $ret = $this->remove($certificateProfile);

        if( $ret && !$certificateProfile->isTmp() && $this->xmlroot !== null )
            $this->xmlroot->removeChild($certificateProfile->xmlroot);

        return $ret;
    }

    /**
     * @param CertificateProfile|string $certificateProfileName
     * @return bool
     */
    public function hasCertificateProfileNamed($certificateProfileName, $caseSensitive = TRUE)
    {
        return $this->has($certificateProfileName, $caseSensitive);
    }

    public function rewriteXML()
    {
        if( $this->xmlroot !== null )
        {
            DH::clearDomNodeChilds($this->xmlroot);
            foreach( $this->o as $certificateProfile )
                if( !$certificateProfile->isTmp() )
                    $this->xmlroot->appendChild($certificateProfile->xmlroot);
        }
    }

    public function &getXPath()
    {
        if( $this->xmlroot === null )
            derr('unsupported on virtual Stores');

        $xpath = $this->owner->getXPath() . "/certificate-profile/";

        return $xpath;
    }
}
