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
 * Certificate profile (Device > Certificate Management > Certificate Profile)
 *
 * <certificate-profile><entry name="...">
 *   <CA><entry name="ca-certificate"><default-ocsp-url/><ocsp-verify-certificate/><template-name/></entry></CA>
 *   <username-field><subject>common-name</subject></username-field>
 *   <domain/> <use-crl/> <use-ocsp/> <crl-receive-timeout/> <ocsp-receive-timeout/> <cert-status-timeout/>
 *   <block-unknown-cert/> <block-timeout-cert/> <block-unauthenticated-cert/> <block-expired-cert/> <ocsp-exclude-nonce/>
 * </entry></certificate-profile>
 *
 * Locations: firewall shared / vsys, template shared / vsys, template stack shared.
 */
class CertificateProfile
{
    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;

    /** @var null|CertificateProfileStore */
    public $owner = null;

    private $isTmp = TRUE;

    public $_type = 'tmp';

    /** CA certificate name => array( 'default-ocsp-url' => , 'ocsp-verify-certificate' => , 'template-name' => ) */
    public $caCertificates = array();

    /** e.g. array( 'subject' => 'common-name' ) */
    public $usernameField = array();

    public $domain = null;

    /** all single value settings, e.g. 'use-crl' => 'yes', 'block-expired-cert' => 'yes' */
    public $settings = array();

    static public $settingNames = array( 'use-crl', 'use-ocsp', 'crl-receive-timeout', 'ocsp-receive-timeout', 'cert-status-timeout',
        'block-unknown-cert', 'block-timeout-cert', 'block-unauthenticated-cert', 'block-expired-cert', 'ocsp-exclude-nonce' );

    /**
     * @param string $name
     * @param CertificateProfileStore $owner
     */
    public function __construct($name, $owner, $fromXmlTemplate = FALSE)
    {
        if( !is_string($name) )
            derr('name must be a string');

        $this->owner = $owner;

        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();
            $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);
            $node = DH::findFirstElementOrDie('entry', $doc);

            $rootDoc = $this->owner->xmlroot->ownerDocument;
            $this->xmlroot = $rootDoc->importNode($node, TRUE);

            $this->setName($name);
            $this->owner = $owner;

            $this->load_from_domxml($this->xmlroot);
        }

        $this->name = $name;
    }

    /**
     * @param string $newName
     * @return bool
     */
    public function setName($newName)
    {
        $ret = $this->setRefName($newName);

        if( $this->xmlroot === null )
            return $ret;

        $this->xmlroot->setAttribute('name', $newName);

        return $ret;
    }

    public function isTmp()
    {
        return $this->isTmp;
    }

    public function type()
    {
        return $this->_type;
    }

    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;
        $this->isTmp = FALSE;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("CertificateProfile name not found\n", $xml);

        if( strlen($this->name) < 1 )
            derr("CertificateProfile name '" . $this->name . "' is not valid", $xml);

        $this->caCertificates = array();
        $this->usernameField = array();
        $this->domain = null;
        $this->settings = array();

        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;
            /** @var DOMElement $node */

            if( $node->nodeName == 'CA' )
            {
                foreach( $node->childNodes as $ca )
                {
                    if( $ca->nodeType != XML_ELEMENT_NODE || $ca->nodeName != 'entry' )
                        continue;
                    $caName = DH::findAttribute('name', $ca);
                    if( $caName === FALSE || $caName === '' )
                        continue;
                    $details = array();
                    foreach( $ca->childNodes as $d )
                        if( $d->nodeType == XML_ELEMENT_NODE )
                            $details[$d->nodeName] = $d->textContent;
                    $this->caCertificates[$caName] = $details;
                }
            }
            elseif( $node->nodeName == 'username-field' )
            {
                foreach( $node->childNodes as $d )
                    if( $d->nodeType == XML_ELEMENT_NODE )
                        $this->usernameField[$d->nodeName] = $d->textContent;
            }
            elseif( $node->nodeName == 'domain' )
                $this->domain = $node->textContent;
            elseif( in_array($node->nodeName, self::$settingNames, TRUE) )
                $this->settings[$node->nodeName] = $node->textContent;
        }

        $this->resolveCACertificates();
    }

    /**
     * @return string[]
     */
    public function caCertificateNames()
    {
        return array_keys($this->caCertificates);
    }

    /**
     * CA certificate objects as seen from this profile's location; a name that cannot be found is left out.
     * The certificates get this profile as reference.
     * @return Certificate[]
     */
    public function resolveCACertificates()
    {
        $ret = array();
        foreach( $this->caCertificateNames() as $caName )
        {
            $certificate = $this->findCertificate($caName);
            if( $certificate === null )
                continue;
            $certificate->addReference($this);
            $ret[$caName] = $certificate;
        }
        return $ret;
    }

    /**
     * certificate lookup in the order PAN-OS uses for this location:
     * vsys -> shared (firewall or template); template stack -> its templates in stack order
     * @param string $name
     * @return Certificate|null
     */
    public function findCertificate($name)
    {
        foreach( $this->certificateStoresInScope() as $store )
        {
            $certificate = $store->find($name, null, FALSE);
            if( $certificate !== null )
                return $certificate;
        }
        return null;
    }

    /**
     * @return CertificateStore[]
     */
    public function certificateStoresInScope()
    {
        $stores = array();
        if( $this->owner === null )
            return $stores;

        $location = $this->owner->owner;
        while( $location !== null )
        {
            if( isset($location->certificateStore) && $location->certificateStore !== null && !in_array($location->certificateStore, $stores, TRUE) )
                $stores[] = $location->certificateStore;

            if( $location instanceof TemplateStack )
            {
                foreach( $location->templates as $template )
                    if( is_object($template) && $template->certificateStore !== null )
                        $stores[] = $template->certificateStore;
                break;
            }
            if( $location instanceof Template )
                break;

            $location = isset($location->owner) ? $location->owner : null;
        }

        return $stores;
    }

    public function API_setName($newname)
    {
        if( !$this->isTmp() )
        {
            $c = findConnectorOrDie($this);
            $path = $this->getXPath();

            $this->setName($newname);
            $c->sendRenameRequest($path, $newname);
        }
        else
        {
            mwarning('this is a temporary object, cannot be renamed from API');
        }
    }

    public function &getXPath()
    {
        if( $this->isTmp() )
            derr('no xpath on temporary objects');

        $str = $this->owner->getXPath() . "entry[@name='" . $this->name . "']";

        return $str;
    }

    static protected $templatexml = '<entry name="**temporarynamechangeme**"></entry>';
}
