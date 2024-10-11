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


class Threat
{
    use ReferenceableObject;
    use PathableName;

    public $type = 'tmp';

    public $threatname = null;
    public $category = null;
    public $severity = null;
    private $cve = array();
    public $min_engine_version = null;
    public $max_engine_version = null;
    public $default_action = 'allow';
    public $disabled = false;

    /** @var ThreatStore|null */
    public $owner;
    public $xmlroot;

    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
        $this->xmlroot = null;
    }

    public function load_from_domxml( $threatx )
    {
        $tmp = DH::findFirstElement('disable', $threatx);
        if( $tmp !== FALSE )
        {
            if( $tmp->textContent == "yes" )
                $this->disabled = true;
        }

        $tmp = DH::findFirstElement('threatname', $threatx);
        if( $tmp !== FALSE )
            $this->threatname = $tmp->textContent;

        $tmp = DH::findFirstElement('category', $threatx);
        if( $tmp !== FALSE )
        {
            //'filter=!(category eq browser-hijack) and !(category eq adware) and !(category eq spyware) and !(category eq backdoor) and !(category eq data-theft) and !(category eq keylogger) and !(category eq webshell) and !(category eq botnet) and !(category eq net-worm) and !(category eq command-and-control) and !(category eq phishing-kit) and !(category eq cryptominer) and !(category eq downloader) and !(category eq hacktool) and !(category eq tls-fingerprint) and !(category eq fraud) and !(category eq info-leak) and !(category eq post-exploitation) and !(category eq phishing) and !(category eq code-execution) and !(category eq overflow) and !(category eq dos) and !(category eq brute-force) and !(category eq sql-injection) and !(category eq insecure-credentials) and !(category eq protocol-anomaly) and !(category eq code-obfuscation) and !(category eq exploit-kit)'
            /*
            * browser-hijack
             * adware
             *
             * spyware
             * backdoor
             * data-theft
             * keylogger
             * webshell
             * botnet
             * net-worm
             * command-and-control
             * phishing-kit
             * cryptominer
             * downloader
             * hacktool
             * tls-fingerprint
             * fraud
             * info-leak
             * post-exploitation
             * phishing
             * code-execution
             * overflow
             * dos
             * brute-force
             * sql-injection
             * insecure-credentials
             * protocol-anomaly
             * code-obfuscation
             * exploit-kit
            */
            $this->category = $tmp->textContent;
        }


        $tmp = DH::findFirstElement('severity', $threatx);
        if( $tmp !== FALSE )
        {
            /*
             * informational
             * low
             * medium
             * high
             * critical
             */
            $this->severity = $tmp->textContent;
        }


        $tmp = DH::findFirstElement('engine-version', $threatx);
        if( $tmp !== FALSE )
        {
            #<engine-version min="8.0"/>
            $engine = DH::findAttribute( 'min', $tmp );
            $tmp_engine_array = explode(".", $engine);
            if( count($tmp_engine_array) < 3 && $tmp_engine_array[0] > 1 )
                $this->min_engine_version = $tmp_engine_array[0].$tmp_engine_array[1];
            else
                $this->min_engine_version = $tmp_engine_array[0];

            $engine = DH::findAttribute( 'max', $tmp );
            $tmp_engine_array = explode(".", $engine);
            if( count($tmp_engine_array) < 3 && $tmp_engine_array[0] > 1 )
                $this->max_engine_version = $tmp_engine_array[0].$tmp_engine_array[1];
            else
                $this->max_engine_version = $tmp_engine_array[0];
        }


        $tmp = DH::findFirstElement('default-action', $threatx);
        if( $tmp !== FALSE )
        {
            /* possible values
           allow
           alert
           reset-both
           reset-client
           reset-server
           drop-all-packets
            */
            $this->default_action = $tmp->textContent;
        }

        $tmp = DH::findFirstElement('cve', $threatx);
        if( $tmp !== FALSE )
        {
            $this->cve = array();

            foreach( $tmp->childNodes as $node ) {
                /** @var DOMElement $node */
                if ($node->nodeType != XML_ELEMENT_NODE) continue;

                $this->cve[] = $node->textContent;
            }
        }

    }

    public function type()
    {
        return $this->type;
    }

    public function name()
    {
        return $this->name;
    }

    public function threatname()
    {
        return $this->threatname;
    }

    public function severity()
    {
        return $this->severity;
    }

    public function defaultAction()
    {
        return $this->default_action;
    }

    public function category()
    {
        return $this->category;
    }

    public function cve()
    {
        return $this->cve;
    }

    public function display($padding = "")
    {
        PH::print_stdout( $padding . "* " . get_class($this) . " '{$this->name()}' " );

        $tmp_min_engine_version = "";
        $tmp_max_engine_version = "";
        if( !empty($this->min_engine_version) )
            $tmp_min_engine_version =  " min-engine-version: '".$this->min_engine_version."'";
        if( !empty($this->max_engine_version) )
            $tmp_max_engine_version =  " max-engine-version: '".$this->max_engine_version."'";

        PH::print_stdout( "          - Threatname: '{$this->threatname()}'  category: '{$this->category()}' severity: '{$this->severity()}'  default-action: '{$this->defaultAction()}' cve: '".implode(",", $this->cve())."' ".$tmp_min_engine_version.$tmp_max_engine_version );

        PH::$JSON_TMP['sub']['object'][$this->name()]['name'] = $this->name();
        PH::$JSON_TMP['sub']['object'][$this->name()]['type'] = get_class($this);
        PH::$JSON_TMP['sub']['object'][$this->name()]['category'] = $this->category();
        PH::$JSON_TMP['sub']['object'][$this->name()]['host'] = $this->category();
        PH::$JSON_TMP['sub']['object'][$this->name()]['severity'] = $this->severity();
        PH::$JSON_TMP['sub']['object'][$this->name()]['default-action'] = $this->defaultAction();
        PH::$JSON_TMP['sub']['object'][$this->name()]['cve'] = $this->cve();
        PH::$JSON_TMP['sub']['object'][$this->name()]['min_engine_version'] = $this->min_engine_version;
        PH::$JSON_TMP['sub']['object'][$this->name()]['max_engine_version'] = $this->max_engine_version;
    }
}


