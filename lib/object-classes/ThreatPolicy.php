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


class ThreatPolicy
{
    use ReferenceableObject;
    use PathableName;

    public $type = 'tmp';

    /** @var AntiSpywareProfile|VulnerabilityProfile|null */
    public $owner;
    public $xmlroot;

    public $severity = array();
    public $fileType = array();
    public $action = null;

    public $threatname = null;
    public $packetCapture = null;
    public $category = null;
    public $host = null;
    public $direction = null;
    public $analysis = null;

    //Todo:
    //add CVE / VEndorID for Vulnerability Profilte
    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
        $this->xmlroot = null;
    }

    public function load_from_domxml( $tmp_entry1 )
    {
        $tmp = DH::findFirstElement('severity', $tmp_entry1);
        if( $tmp !== FALSE )
        {
            foreach( $tmp->childNodes as $member )
            {
                if( $member->nodeType != XML_ELEMENT_NODE )
                    continue;

                $this->severity[$member->textContent] = $member->textContent;
            }
        }

        $tmp = DH::findFirstElement('file-type', $tmp_entry1);
        if( $tmp !== FALSE )
        {
            foreach( $tmp->childNodes as $member )
            {
                if( $member->nodeType != XML_ELEMENT_NODE )
                    continue;

                $this->fileType[$member->textContent] = $member->textContent;
            }
        }

        $tmp = DH::findFirstElement('action', $tmp_entry1);
        if( $tmp !== FALSE )
        {
            $tmp_action = DH::firstChildElement($tmp);
            if( $tmp_action !== FALSE )
                $this->action = $tmp_action->nodeName;

            if( $this->owner->secprof_type == 'file-blocking' )
                $this->action = $tmp->textContent;
        }

        $tmp = DH::findFirstElement('packet-capture', $tmp_entry1);
        if( $tmp !== FALSE )
        {
            $this->packetCapture = $tmp->textContent;
        }

        $tmp = DH::findFirstElement('category', $tmp_entry1);
        if( $tmp !== FALSE )
        {
            $this->category = $tmp->textContent;
        }

        $tmp = DH::findFirstElement('host', $tmp_entry1);
        if( $tmp !== FALSE )
        {
            $this->host = $tmp->textContent;
        }

        $tmp = DH::findFirstElement('direction', $tmp_entry1);
        if( $tmp !== FALSE )
        {
            $this->direction = $tmp->textContent;
        }

        $tmp = DH::findFirstElement('analysis', $tmp_entry1);
        if( $tmp !== FALSE )
        {
            $this->analysis = $tmp->textContent;
        }

        $tmp = DH::findFirstElement('threat-name', $tmp_entry1);
        if( $tmp !== FALSE )
        {
            $this->threatname = $tmp->textContent;
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

    public function action()
    {
        return $this->action;
    }
    public function category()
    {
        return $this->category;
    }

    public function fileType()
    {
        return $this->fileType;
    }

    public function packetCapture()
    {
        return $this->packetCapture;
    }
    public function host()
    {
        return $this->host;
    }
    public function direction()
    {
        return $this->direction;
    }
    public function analysis()
    {
        return $this->analysis;
    }


    public function display()
    {
        $string = "";
        $string .= "          '".$this->name()."':";

        if( isset( $this->severity ) )
        {
            $string .= " - severity: '".implode(",", $this->severity())."'";
            PH::$JSON_TMP['sub']['object'][$this->owner->name()]['rule'][$this->name()]['severity'] = implode(",", $this->severity());
        }

        if( $this->threatname() !== null )
        {
            $string .= " - threat-name: '".$this->threatname()."'";
            PH::$JSON_TMP['sub']['object'][$this->owner->name()]['rule'][$this->name()]['threat-name'] = $this->threatname();
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

        if( $this->category() !== null )
        {
            $string .= " - category: '".$this->category()."'";
            PH::$JSON_TMP['sub']['object'][$this->owner->name()]['rule'][$this->name()]['category'] = $this->category();
        }

        if( $this->host() !== null )
        {
            $string .= " - host: '".$this->host()."'";
            PH::$JSON_TMP['sub']['object'][$this->owner->name()]['rule'][$this->name()]['host'] = $this->host();
        }
        PH::print_stdout( $string );
    }
}


