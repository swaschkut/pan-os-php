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


class DNSPolicy
{
    use ReferenceableObject;
    use PathableName;

    public $type = 'tmp';

    /** @var AntiSpywareProfile|null */
    public $owner;
    public $xmlroot;

    public $logLevel = null;
    public $action = null;
    public $packetCapture = null;

    public $advanced = null;

    public function __construct($name, $owner, $advanced = false)
    {
        $this->owner = $owner;
        $this->name = $name;
        $this->xmlroot = null;
        $this->advanced = $advanced;
    }

    public function load_from_domxml( $tmp_entry1 )
    {
        $this->xmlroot = $tmp_entry1;

        $tmp = DH::findFirstElement('log-level', $tmp_entry1);
        if( $tmp !== FALSE )
        {
            $this->logLevel = $tmp->textContent;
        }

        $tmp = DH::findFirstElement('action', $tmp_entry1);
        if( $tmp !== FALSE )
        {
            $this->action = $tmp->textContent;
        }

        $tmp = DH::findFirstElement('packet-capture', $tmp_entry1);
        if( $tmp !== FALSE )
        {
            $this->packetCapture = $tmp->textContent;
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

    public function logLevel()
    {
        return $this->logLevel;
    }

    public function action()
    {
        return $this->action;
    }

    public function packetCapture()
    {
        return $this->packetCapture;
    }

    public function display($padding="")
    {
        $string = "";
        $string .= $padding."          '".$this->name()."':";

        if( isset( $this->logLevel ) )
        {
            $string .= " - log-level: '".$this->logLevel()."'";
            PH::$JSON_TMP['sub']['object'][$this->owner->name()]['rule'][$this->name()]['log-level'] = $this->logLevel();
        }

        if( $this->action() !== null )
        {
            $string .= " - action: '".$this->action()."'";
            PH::$JSON_TMP['sub']['object'][$this->owner->name()]['rule'][$this->name()]['action'] = $this->action();
        }

        if( $this->packetCapture() !== null )
        {
            $string .= " - packet-capture: '".$this->packetCapture()."'";
            PH::$JSON_TMP['sub']['object'][$this->owner->name()]['rule'][$this->name()]['packet-capture'] = $this->packetCapture();
        }

        PH::print_stdout( $string );
    }

    public function spyware_dns_security_rule_bestpractice()
    {
        if( ( $this->name() == "pan-dns-sec-cc"
                || $this->name() == "pan-dns-sec-malware"
                || $this->name() == "pan-dns-sec-phishing"
            )
            && $this->action() != "sinkhole"
            && $this->packetCapture() != "single-packet"
        )
            return false;
        else
            return true;
    }
}


