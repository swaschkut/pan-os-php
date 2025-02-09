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
class ThreatPolicyStore extends ObjStore
{
    /** @var array|Threat[] */
    public $vulnerabilityPolicy = array();

    /** @var array|Threat[] */
    public $spywarePolicy = array();

    public $wildfirePolicy = array();
    public $fileblockingPolicy = array();

    public static $childn = 'Threat';

    public function __construct($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;
        $this->o = array();

    }

    public function load_vulnerabilityPolicy_from_domxml(DOMElement $xml)
    {
        foreach( $xml->childNodes as $threatx )
        {
            if( $threatx->nodeType != XML_ELEMENT_NODE )
                continue;

            $threatName = DH::findAttribute('name', $threatx);
            if( $threatName === FALSE )
                derr("threat name not found\n");

            $threat = new ThreatPolicyVulnerability($threatName, $this);
            $threat->type = 'vulnerabilityPolicy';
            $threat->xmlroot = $threatx;
            $threat->vulnerabilitypolicy_load_from_domxml( $threatx );

            $this->add($threat);

            $this->vulnerabilityPolicy[] = $threat;
        }
    }

    public function load_spywarePolicy_from_domxml(DOMElement $xml)
    {
        foreach( $xml->childNodes as $threatx )
        {
            if( $threatx->nodeType != XML_ELEMENT_NODE )
                continue;

            $threatName = DH::findAttribute('name', $threatx);
            if( $threatName === FALSE )
                derr("threat name not found\n");

            $threat = new ThreatPolicySpyware($threatName, $this);
            $threat->type = 'spywarePolicy';
            $threat->xmlroot = $threatx;
            $threat->spywarepolicy_load_from_domxml( $threatx );

            $this->add($threat);

            $this->spywarePolicy[] = $threat;
        }
    }

    public function load_wildfirePolicy_from_domxml(DOMElement $xml)
    {
        foreach( $xml->childNodes as $threatx )
        {
            if( $threatx->nodeType != XML_ELEMENT_NODE )
                continue;

            $threatName = DH::findAttribute('name', $threatx);
            if( $threatName === FALSE )
                derr("threat name not found\n");

            $threat = new ThreatPolicyWildfire($threatName, $this);
            $threat->type = 'wildfirePolicy';
            $threat->xmlroot = $threatx;
            $threat->wildfirepolicy_load_from_domxml( $threatx );

            $this->add($threat);

            $this->wildfirePolicy[] = $threat;
        }
    }


    public function load_fileblockingPolicy_from_domxml(DOMElement $xml)
    {
        foreach( $xml->childNodes as $threatx )
        {
            if( $threatx->nodeType != XML_ELEMENT_NODE )
                continue;

            $threatName = DH::findAttribute('name', $threatx);
            if( $threatName === FALSE )
                derr("threat name not found\n");

            $threat = new ThreatPolicyFileBlocking($threatName, $this);
            $threat->type = 'fileblockingPolicy';
            $threat->xmlroot = $threatx;
            $threat->fileblockingpolicy_load_from_domxml( $threatx );

            $this->add($threat);

            $this->fileblockingPolicy[] = $threat;
        }
    }

    public function add($threat_obj)
    {
        $this->o[] = $threat_obj;
    }
}
