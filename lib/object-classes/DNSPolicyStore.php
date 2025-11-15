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
class DNSPolicyStore extends ObjStore
{
    /** @var array|DNS[] */
    public $dnsPolicy = array();

    public static $childn = 'DNS';


    public $tmp_dns_prof_array = array(
        "pan-dns-sec-adtracking",
        "pan-dns-sec-cc",
        "pan-dns-sec-ddns",
        "pan-dns-sec-grayware",
        "pan-dns-sec-malware",
        "pan-dns-sec-parked",
        "pan-dns-sec-phishing",
        "pan-dns-sec-proxy",
        "pan-dns-sec-recent"
    );

    public $tmp_adns_prof_array = array(
        "pan-adns-sec-dnsmisconfig",
        "pan-adns-sec-hijacking"
    );

    public function __construct($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;
        $this->o = array();

    }

    public function load_dnsPolicy_from_domxml(DOMElement $xml)
    {
        foreach( $xml->childNodes as $dnsx )
        {
            if( $dnsx->nodeType != XML_ELEMENT_NODE )
                continue;

            $dnsName = DH::findAttribute('name', $dnsx);
            if( $dnsName === FALSE )
                derr("threat name not found\n");

            $dns = new DNSPolicy($dnsName, $this);
            $dns->type = 'DNSPolicy';
            $dns->xmlroot = $dnsx;
            $dns->load_from_domxml( $dnsx );

            $this->add($dns);

            $this->dnsPolicy[] = $dns;
        }
    }

    public function add($dns_obj)
    {
        $this->o[] = $dns_obj;
    }
}
