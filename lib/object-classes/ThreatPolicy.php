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
    public $filetype = array();
    public $application = array();
    public $action = null;
    public $default_action = null;

    public $threatname = null;
    public $packetCapture = null;
    public $category = null;
    public $host = null;
    public $direction = null;
    public $analysis = null;

    const OTHER_CATEGORY = "**any-other-category**";   // stands for every category no rule names

    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
        $this->xmlroot = null;
    }

    public function load_from_domxml( $tmp_entry1 )
    {
        $this->xmlroot = $tmp_entry1;

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

                $this->filetype[$member->textContent] = $member->textContent;
            }
        }

        $tmp = DH::findFirstElement('application', $tmp_entry1);
        if( $tmp !== FALSE )
        {
            foreach( $tmp->childNodes as $member )
            {
                if( $member->nodeType != XML_ELEMENT_NODE )
                    continue;

                $this->application[$member->textContent] = $member->textContent;
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

    /**
     * A rule naming a particular threat applies to that threat only.
     * ThreatPolicyVulnerability extends this with CVE and vendor-id.
     */
    public function namesParticularThreats()
    {
        return ( $this->threatname ?? "any" ) !== "any";
    }

    /**
     * PAN-OS's match: severity, host and category must all match; 'any' and an absent element match every value.
     * $host is null for profiles without a host (anti-spyware): then the host is not checked.
     */
    /**
     * The categories a first-match check must try for these rules: every category a rule names,
     * plus OTHER_CATEGORY for all categories no rule names.
     * @param ThreatPolicy[] $rules
     * @return string[]
     */
    public static function categoriesOf( $rules )
    {
        $categories = array( self::OTHER_CATEGORY );
        foreach( $rules as $rule )
            if( ( $rule->category() ?? "any" ) !== "any" && !in_array( $rule->category(), $categories, TRUE ) )
                $categories[] = $rule->category();
        return $categories;
    }

    /**
     * A rule name not yet used in this profile: $name, or $name_1, $name_2, ...
     * newThreatPolicyXML() rewrites an existing rule of the same name, so new rules must get a free name.
     */
    public static function uniqueRuleName( DOMElement $profileXml, $name )
    {
        $rules = DH::findFirstElement( 'rules', $profileXml );
        if( $rules === FALSE )
            return $name;
        $candidate = $name;
        for( $i = 1; DH::findFirstElementByNameAttr( 'entry', $candidate, $rules ) !== null; $i++ )
            $candidate = $name . "_" . $i;
        return $candidate;
    }

    public function matchesThreat( $severity, $host, $category )
    {
        if( !empty( $this->severity ) && !in_array( 'any', $this->severity, TRUE ) && !in_array( $severity, $this->severity, TRUE ) )
            return FALSE;
        if( $host !== null && ( $this->host ?? "any" ) !== "any" && $this->host !== $host )
            return FALSE;
        if( ( $this->category ?? "any" ) !== "any" && $this->category !== $category )
            return FALSE;
        return TRUE;
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

    public function filetype()
    {
        return $this->filetype;
    }

    public function application()
    {
        return $this->application;
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
        $string = "          '" . $this->name() . "':";

        if( $this->severity() !== null && !empty($this->severity() ) )
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

        if( $this->filetype() !== null && !empty( $this->filetype() ) )
        {
            $string .= " - fileType: '".implode(",", $this->filetype())."'";
            PH::$JSON_TMP['sub']['object'][$this->owner->name()]['rule'][$this->name()]['fileType'] = $this->filetype();
        }

        if( $this->application() !== null && !empty( $this->application() ) )
        {
            $string .= " - application: '".implode(",", $this->application())."'";
            PH::$JSON_TMP['sub']['object'][$this->owner->name()]['rule'][$this->name()]['application'] = $this->application();
        }

        if( $this->direction() !== null )
        {
            $string .= " - direction: '".$this->direction()."'";
            PH::$JSON_TMP['sub']['object'][$this->owner->name()]['rule'][$this->name()]['direction'] = $this->direction();
        }

        if( $this->analysis() !== null )
        {
            $string .= " - analysis: '".$this->analysis()."'";
            PH::$JSON_TMP['sub']['object'][$this->owner->name()]['rule'][$this->name()]['analysis'] = $this->analysis();
        }
        PH::print_stdout( $string );
    }

    public function newThreatPolicyXML( $xmlroot, $name, $severity = null, $action = "alert", $host_type = 'any' )
    {
        $packet_capture = "disable";
        $threat_name = "any";
        $category = "any";

        $tmp_rules_xmlroot = DH::findFirstElementOrCreate('rules', $xmlroot);
        $tmp_entry = DH::findFirstElementByNameAttrOrCreate("entry", $name, $tmp_rules_xmlroot, $xmlroot->ownerDocument);

        $this->xmlroot = $tmp_rules_xmlroot;

        if( $severity !== null )
        {
            $tmp_severity = DH::findFirstElementOrCreate('severity', $tmp_entry);
            $tmp_severity_member = DH::findFirstElementOrCreate('member', $tmp_severity);
            $tmp_severity_member->textContent = $severity;
            $this->severity[] = $severity;
        }

        $tmp_action = DH::findFirstElementOrCreate('action', $tmp_entry);
        $tmp_action_node = DH::findFirstElementOrCreate($action, $tmp_action);

        $tmp_threat_name = DH::findFirstElementOrCreate('threat-name', $tmp_entry);
        $tmp_threat_name->textContent = $threat_name;
        $this->threatname = $threat_name;

        $tmp_category = DH::findFirstElementOrCreate('category', $tmp_entry);
        $tmp_category->textContent = $category;
        //$this->category[] = $category;

        $tmp_packet_capture = DH::findFirstElementOrCreate('packet-capture', $tmp_entry);
        $tmp_packet_capture->textContent = $packet_capture;
        $this->packetCapture = $packet_capture;

        return $tmp_entry;
    }

    public function getFullThreatPolicyText()
    {
        $stringSeverity = "";
        if( !empty($this->severity) )
            $stringSeverity = " - severity:'". implode( ",", $this->severity )."'";
        $stringApplication = "";
        if( !empty($this->application) )
            $stringApplication = " - application:'". implode( ",", $this->application )."'";
        $stringFileType = "";
        if( !empty($this->filetype) )
            $stringFileType = " - filetype:'". implode( ",", $this->filetype )."'";
        $stringPacketCapture = "";
        if( $this->packetCapture() !== null )
            $stringPacketCapture = " - packetCapture:'".$this->packetCapture()."'";
        $stringCategory = "";
        if( $this->category() !== null )
            $stringCategory = " - category:'".$this->category()."'";
        $stringHost = "";
        if( $this->host() !== null )
            $stringHost = " - host:'".$this->host()."'";
        $stringThreatName = "";
        if( $this->threatname !== null )
            $stringThreatName = " - threat-name:'".$this->threatname()."'";
        $stringAction = "";
        if( $this->action() !== null )
            $stringAction = " - action:'".$this->action()."'";
        $stringDirection = "";
        if( $this->direction() !== null )
            $stringDirection = " - direction:'".$this->direction()."'";
        $stringAnalysis = "";
        if( $this->analysis() !== null )
            $stringAnalysis = " - analysis:'".$this->analysis()."'";

        $tmp_string = "'".$this->name()."' | ".$stringSeverity.$stringThreatName.$stringAction.$stringApplication.$stringFileType.$stringPacketCapture.$stringCategory.$stringHost.$stringDirection.$stringAnalysis;

        return $tmp_string;
    }
}


