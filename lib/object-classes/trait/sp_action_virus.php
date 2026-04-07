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

trait sp_action_virus
{
    public function load_from_domxml_virus_decoder( DOMElement $xml )
    {
        $tmp_decoder = DH::findFirstElement('decoder', $xml);
        if( $tmp_decoder !== FALSE )
        {
            $tmp_array = array();

            $tmp_decoder_http2_found = false;
            foreach( $tmp_decoder->childNodes as $tmp_entry )
            {
                if( $tmp_entry->nodeType != XML_ELEMENT_NODE )
                    continue;


                $appName = DH::findAttribute('name', $tmp_entry);
                if( $appName == "http2" )
                    $tmp_decoder_http2_found = true;
                if( $appName === FALSE )
                    derr("Virus SecurityProfile decoder name not found\n");

                $action = DH::findFirstElement('action', $tmp_entry);
                if( $action !== FALSE )
                {
                    $this->$appName['action'] = $action->textContent;
                }
                else
                {
                    $this->$appName['action'] = "----";
                }


                $action_wildfire = DH::findFirstElement('wildfire-action', $tmp_entry);
                if( $action_wildfire !== FALSE )
                {
                    $this->$appName['wildfire-action'] = $action_wildfire->textContent;
                }
                else
                {
                    $this->$appName['wildfire-action'] = "----";
                }

                $action_mlav_action = DH::findFirstElement('mlav-action', $tmp_entry);
                if( $action_mlav_action !== FALSE )
                {
                    $this->$appName['mlav-action'] = $action_mlav_action->textContent;
                }
                else
                {
                    $this->$appName['mlav-action'] = "----";
                }
            }

            $http2_xml_string = '<entry name="http2">
  <action>allow</action>
  <wildfire-action>allow</wildfire-action>
  <mlav-action>allow</mlav-action>
</entry>';

            if( !$tmp_decoder_http2_found && $this->owner->owner->version >= 90 )
            {
                $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $http2_xml_string);
                $tmp_decoder->appendChild($xmlElement);

                $this->http2['action'] = "allow";
                $this->http2['wildfire-action'] = "allow";
                $this->http2['mlav-action'] = "allow";
            }
        }
    }

    public function load_from_domxml_virus_threat_exception( DOMElement $xml )
    {
        $tmp_threat_exception = DH::findFirstElement('threat-exception', $xml);
        if( $tmp_threat_exception !== FALSE )
        {
            $tmp_array[$this->secprof_type][$this->name]['threat-exception'] = array();
            foreach( $tmp_threat_exception->childNodes as $tmp_entry1 )
            {
                if( $tmp_entry1->nodeType != XML_ELEMENT_NODE )
                    continue;

                $tmp_name = DH::findAttribute('name', $tmp_entry1);
                if( $tmp_name === FALSE )
                    derr("VB severity name not found\n");

                $this->threatException[$tmp_name]['name'] = $tmp_name;

                $action = DH::findFirstElement('action', $tmp_entry1);
                if( $action !== FALSE )
                {
                    if( $action->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_action = DH::firstChildElement($action);
                    $tmp_array[$this->secprof_type][$this->name]['threat-exception'][$tmp_name]['action'] = $tmp_action->nodeName;
                    $this->threatException[$tmp_name]['action'] = $tmp_action->nodeName;
                }
            }
        }
    }

    public function load_from_domxml_virus_inlineml( DOMElement $xml )
    {
        $tmp_rule = DH::findFirstElement('mlav-engine-filebased-enabled', $xml);
        if( $tmp_rule !== FALSE && !$tmp_rule->hasChildNodes() )
        {
            $xml->removeChild($tmp_rule);
            $tmp_rule = DH::findFirstElement('mlav-engine-filebased-enabled', $xml);
        }

        if( $tmp_rule !== FALSE )
        {
            $this->additional['mlav-engine-filebased-enabled'] = array();
            $tmp_mica_MSOffice_found = false;
            $tmp_mica_Shell_found = false;
            $tmp_mica_OOXML_found = false;
            $tmp_mica_MachO_found = false;
            foreach( $tmp_rule->childNodes as $tmp_entry1 )
            {
                if ($tmp_entry1->nodeType != XML_ELEMENT_NODE)
                    continue;

                $name = DH::findAttribute("name", $tmp_entry1);
                if( $name == "MSOffice" )
                    $tmp_mica_MSOffice_found = TRUE;
                elseif( $name == "Shell" )
                    $tmp_mica_Shell_found = TRUE;
                elseif( $name == "OOXML" )
                    $tmp_mica_OOXML_found = TRUE;
                elseif( $name == "MachO" )
                    $tmp_mica_MachO_found = TRUE;

                $tmp_inline_policy_action = DH::findFirstElement("mlav-policy-action", $tmp_entry1);
                if( $tmp_inline_policy_action !== FALSE )
                    $this->additional['mlav-engine-filebased-enabled'][$name]['mlav-policy-action'] = $tmp_inline_policy_action->textContent;
                else
                {
                    $tmp_inline_policy_action = DH::findFirstElementOrCreate("mlav-policy-action", $tmp_entry1);
                    $tmp_inline_policy_action->textContent = "disable";
                    $this->additional['mlav-engine-filebased-enabled'][$name]['mlav-policy-action'] = "disable";
                }
            }

            $MSOFFICE_xmlstring = '<entry name="MSOffice">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>';
            $Shell_xmlstring = '<entry name="Shell">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>';

            $OOXML_xmlstring = '<entry name="OOXML">
  <mlav-policy-action>disable</mlav-policy-action>
</entry>';
            $MachO_xmlstring = '<entry name="MachO">
  <mlav-policy-action>disable</mlav-policy-action>
</entry>';

            if( !$tmp_mica_MSOffice_found && $this->owner->owner->version >= 100)
            {
                $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $MSOFFICE_xmlstring);
                $tmp_rule->appendChild($xmlElement);

                $this->additional['mlav-engine-filebased-enabled']['MSOffice']['mlav-policy-action'] = "disable";
            }
            if( !$tmp_mica_Shell_found && $this->owner->owner->version >= 100)
            {
                $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $Shell_xmlstring);
                $tmp_rule->appendChild($xmlElement);

                $this->additional['mlav-engine-filebased-enabled']['Shell']['mlav-policy-action'] = "disable";
            }
            if( !$tmp_mica_OOXML_found && $this->owner->owner->version >= 111)
            {
                $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $OOXML_xmlstring);
                $tmp_rule->appendChild($xmlElement);

                $this->additional['mlav-engine-filebased-enabled']['OOXML']['mlav-policy-action'] = "disable";
            }
            if( !$tmp_mica_MachO_found && $this->owner->owner->version >= 111 )
            {
                $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $MachO_xmlstring);
                $tmp_rule->appendChild($xmlElement);

                $this->additional['mlav-engine-filebased-enabled']['MachO']['mlav-policy-action'] = "disable";
            }
        }
        else
        {
            $xmlstring = '<mlav-engine-filebased-enabled>
  <entry name="Windows Executables">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="PowerShell Script 1">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="PowerShell Script 2">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="Executable Linked Format">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="MSOffice">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="Shell">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
</mlav-engine-filebased-enabled>';

            $xmlstring_111 = '<mlav-engine-filebased-enabled>
  <entry name="Windows Executables">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="PowerShell Script 1">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="PowerShell Script 2">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="Executable Linked Format">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="MSOffice">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="Shell">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="OOXML">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="MachO">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
</mlav-engine-filebased-enabled>';

            if( $this->owner->owner->version >= 111 )
                $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $xmlstring_111);
            elseif( $this->owner->owner->version >= 100 )
                $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $xmlstring);

            if( $this->owner->owner->version >= 100 )
                $xml->appendChild($xmlElement);

            if( $this->owner->owner->version >= 100 )
            {
                $this->additional['mlav-engine-filebased-enabled']['Windows Executables']['mlav-policy-action'] = "disable";
                $this->additional['mlav-engine-filebased-enabled']['PowerShell Script 1']['mlav-policy-action'] = "disable";
                $this->additional['mlav-engine-filebased-enabled']['PowerShell Script 2']['mlav-policy-action'] = "disable";
                $this->additional['mlav-engine-filebased-enabled']['Executable Linked Format']['mlav-policy-action'] = "disable";
                $this->additional['mlav-engine-filebased-enabled']['MSOffice']['mlav-policy-action'] = "disable";
                $this->additional['mlav-engine-filebased-enabled']['Shell']['mlav-policy-action'] = "disable";
            }
            if( $this->owner->owner->version >= 111 )
            {
                $this->additional['mlav-engine-filebased-enabled']['OOXML']['mlav-policy-action'] = "disable";
                $this->additional['mlav-engine-filebased-enabled']['MachO']['mlav-policy-action'] = "disable";
            }
        }
    }

    public function display_virus_decoder(): void
    {
        foreach( $this->tmp_virus_prof_array as $key => $type )
        {
            PH::print_stdout(  "       o " . PH::boldText($type) );
            //was not set in specific config files
            if( isset( $this->$type['action'] ) )
            {
                PH::print_stdout(  "          - action:          '" . $this->$type['action'] . "'");
                PH::$JSON_TMP['sub']['object'][$this->name()]['decoder'][$type]['action'] = $this->$type['action'];
            }

            if( isset( $this->$type['wildfire-action'] ) )
            {
                PH::print_stdout(  "          - wildfire-action: '" . $this->$type['wildfire-action'] . "'" );
                PH::$JSON_TMP['sub']['object'][$this->name()]['decoder'][$type]['wildfire-action'] = $this->$type['wildfire-action'];
            }

            if( isset( $this->$type['mlav-action'] ) )
            {
                PH::print_stdout(  "          - mlav-action: '" . $this->$type['mlav-action'] . "'" );
                PH::$JSON_TMP['sub']['object'][$this->name()]['decoder'][$type]['mlav-action'] = $this->$type['mlav-action'];
            }
        }
    }

    public function display_virus_threat_exception(): void
    {
        if( !empty( $this->threatException ) )
        {
            PH::print_stdout("        - threat-exception:" );

            foreach( $this->threatException as $threatname => $threat )
            {
                PH::$JSON_TMP['sub']['object'][$this->name()]['threat-exception'][$threatname]['name'] = $threat['name'];

                $string = "             '" . $threat['name'] . "'";
                if( isset( $threat['action'] ) )
                {
                    $string .= "  - action : ".$threat['action'];
                    PH::$JSON_TMP['sub']['object'][$this->name()]['threat-exception'][$threatname]['action'] = $threat['action'];
                }

                PH::print_stdout(  $string );
            }
        }
    }

    public function display_virus_inlineml(): void
    {
        if( !empty( $this->additional['mlav-engine-filebased-enabled'] ) )
        {
            if( !empty( $this->additional['mlav-engine-filebased-enabled'] ) )
            {
                PH::print_stdout("        ----------------------------------------");
                PH::print_stdout("        - mlav-engine-filebased-enabled: ");

                foreach ($this->additional['mlav-engine-filebased-enabled'] as $name => $threat)
                    PH::print_stdout("          * " . $name . " - mlav-policy-action :" . $this->additional['mlav-engine-filebased-enabled'][$name]['mlav-policy-action']);
            }
        }
    }


    public function virus_bp_visibility_JSON( $checkType, $secprof_type, $av_action_type = null )
    {
        $checkArray = array();

        if( $checkType !== "bp" && $checkType !== "visibility" )
            derr( "only 'bp' or 'visibility' argument allowed" );

        if( $secprof_type == "virus" )
        {
            if( $av_action_type !== "action" && $av_action_type !== "wildfire-action" && $av_action_type !== "mlav-action")
                derr( "only 'action' or 'wildfire-action' or 'mlav-action' argument allowed as av_action_type" );
        }


        ###############################
        $details = PH::getBPjsonFile( );

        $array_type = "rule";

        if( isset($details[$secprof_type][$array_type]) )
        {
            if( $checkType == "bp" )
            {
                if( isset($details[$secprof_type][$array_type]['bp'][$av_action_type]))
                    $checkArray = $details[$secprof_type][$array_type]['bp'][$av_action_type];
                else
                    derr( "this JSON bp/visibility JSON file does not have 'bp' -> '".$array_type."' defined correctly for: '".$secprof_type."' '".$av_action_type."'", null, FALSE );
            }
            elseif( $checkType == "visibility")
            {
                if( isset($details[$secprof_type][$array_type]['visibility'][$av_action_type]))
                    $checkArray = $details[$secprof_type][$array_type]['visibility'][$av_action_type];
                else
                    derr( "this JSON bp/visibility JSON file does not have 'visibility' -> '".$array_type."' defined correctly for: '".$secprof_type."' '".$av_action_type."'", null, FALSE );
            }
        }

        return $checkArray;
    }

    public function check_bp_json($av_type, $check_array, $av_action_type): bool
    {
        $bestpractise = FALSE;

        if (in_array($av_type, $check_array['type']))
        {
            foreach ($check_array['action'] as $validate_action)
            {
                $negate_string = "";
                if (strpos($validate_action, "!") !== FALSE)
                    $negate_string = "!";
                if ($negate_string . $this->$av_type[$av_action_type] === $validate_action)
                {
                    $bestpractise = TRUE;
                    break;
                }
                else
                    $bestpractise = FALSE;
            }
        }
        else
        {
            foreach ($check_array['action-not-matching-type'] as $validate_action)
            {
                $negate_string = "";
                if (strpos($validate_action, "!") !== FALSE)
                    $negate_string = "!";
                if ($negate_string . $this->$av_type[$av_action_type] === $validate_action)
                {
                    $bestpractise = TRUE;
                    break;
                }
                else
                    $bestpractise = FALSE;
            }
        }

        return $bestpractise;
    }

    public function check_visibility_json($av_type, $check_array, $av_action_type)
    {
        $bestpractise = FALSE;

        foreach( $check_array as $validate )
        {
            $negate_string = "";
            if( strpos($validate, "!" ) !== FALSE )
                $negate_string = "!";

            if( $negate_string.$this->$av_type[$av_action_type] === $validate)
                $bestpractise = FALSE;
            else
                $bestpractise = TRUE;
        }

        return $bestpractise;
    }

    public function av_action_best_practice()
    {
        return $this->av_general_action_best_practice( "action" );
    }

    public function av_action_visibility()
    {
        return $this->av_general_action_visibility( "action" );
    }

    public function av_wildfireaction_best_practice()
    {

        return $this->av_general_action_best_practice( "wildfire-action" );
    }

    public function av_wildfireaction_visibility()
    {

        return $this->av_general_action_visibility( "wildfire-action" );
    }

    public function av_mlavaction_best_practice()
    {

        return $this->av_general_action_best_practice( "mlav-action" );
    }

    public function av_mlavaction_is_visibility(): ?bool
    {
        return $this->av_general_action_visibility( "mlav-action" );
    }


    public function av_general_action_best_practice( $av_action_type ): ?bool
    {
        if( $av_action_type != "action" && $av_action_type != "wildfire-action" && $av_action_type != "mlav-action")
            derr( "only support specific valued like action / wildfire-action / mlav-action" );

        $bestpractise = FALSE;

        #if( $this->secprof_type != 'virus' )
        #    return null;

        $check_array = $this->virus_bp_visibility_JSON( "bp", "virus", $av_action_type );

        if( isset($this->tmp_virus_prof_array) )
        {
            foreach( $this->tmp_virus_prof_array as $key => $type )
            {
                if( isset( $this->$type[$av_action_type] ) )
                {
                    $bestpractise = $this->check_bp_json($type, $check_array, $av_action_type);

                    if($bestpractise == FALSE)
                        return FALSE;
                }
            }
        }

        return $bestpractise;
    }

    public function av_general_action_visibility( $av_action_type ): ?bool
    {
        if( $av_action_type != "action" && $av_action_type != "wildfire-action" && $av_action_type != "mlav-action")
            derr( "only support specific valued like action / wildfire-action / mlav-action" );

        $bestpractise = FALSE;

        #if( $this->secprof_type != 'virus' )
        #    return null;

        $check_array = $this->virus_bp_visibility_JSON( "visibility", "virus", $av_action_type );

        if( isset($this->tmp_virus_prof_array) )
        {
            foreach( $this->tmp_virus_prof_array as $key => $type )
            {
                if( isset( $this->$type[$av_action_type] ) )
                {
                    $bestpractise = $this->check_visibility_json($type, $check_array, $av_action_type);

                    if($bestpractise == FALSE)
                        return FALSE;
                }
            }
        }

        return $bestpractise;
    }
}