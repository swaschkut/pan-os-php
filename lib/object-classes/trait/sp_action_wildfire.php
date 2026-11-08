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

trait sp_action_wildfire
{

    public function load_from_domxml_wf_rules( DOMElement $xml ): void
    {
        $tmp_rule = DH::findFirstElement('rules', $xml);
        if( $tmp_rule !== FALSE )
        {
            foreach( $tmp_rule->childNodes as $tmp_entry1 )
            {
                if( $tmp_entry1->nodeType != XML_ELEMENT_NODE )
                    continue;

                $rule_name = DH::findAttribute('name', $tmp_entry1);
                if( $rule_name === FALSE )
                    derr("VB severity name not found\n");

                $threadPolicy_obj = new ThreatPolicyWildfire( $rule_name, $this );
                $threadPolicy_obj->wildfirepolicy_load_from_domxml( $tmp_entry1 );
                $this->rules_obj[] = $threadPolicy_obj;
                $threadPolicy_obj->addReference( $this );

                $this->owner->owner->ThreatPolicyStore->add($threadPolicy_obj);
            }
        }
    }

    public function load_from_domxml_wf_inlineml( DOMElement $xml ): void
    {
        $tmp_rule = DH::findFirstElement('cloud-inline-analysis', $xml);
        if( $tmp_rule !== FALSE )
        {
            if( $tmp_rule->textContent == "yes")
                $this->cloud_inline_analysis_enabled = true;
        }
        else
        {
            if( $this->owner->owner->version >= 111 )
            {
                $tmp_rule = DH::findFirstElementOrCreate('cloud-inline-analysis', $xml);
                $tmp_rule->textContent = "no";
                $this->cloud_inline_analysis_enabled = false;
            }
        }

        $tmp_rule = DH::findFirstElement('mica-engine-wildfire-rules', $xml);
        if( $tmp_rule !== FALSE && !$tmp_rule->hasChildNodes() )
        {
            $xml->removeChild($tmp_rule);
            $tmp_rule = DH::findFirstElement('mica-engine-wildfire-rules', $xml);
        }
        if( $tmp_rule !== FALSE )
        {
            $this->additional['mica-engine-wildfire-rules'] = array();
            foreach( $tmp_rule->childNodes as $tmp_entry1 )
            {
                if ($tmp_entry1->nodeType != XML_ELEMENT_NODE)
                    continue;

                $name = DH::findAttribute("name", $tmp_entry1);

                $tmp_action = DH::findFirstElement("action", $tmp_entry1);
                if( $tmp_action !== FALSE )
                    $this->additional['mica-engine-wildfire-rules'][$name]['action'] = $tmp_action->textContent;

                $tmp_direction = DH::findFirstElement("direction", $tmp_entry1);
                if( $tmp_direction !== FALSE )
                    $this->additional['mica-engine-wildfire-rules'][$name]['direction'] = $tmp_direction->textContent;

                $tmp_application = DH::findFirstElement("application", $tmp_entry1);
                if( $tmp_application !== FALSE )
                {
                    $tmp_app_array = array();
                    foreach( $tmp_application->childNodes as $tmp_entry_app )
                    {
                        if ($tmp_entry_app->nodeType != XML_ELEMENT_NODE)
                            continue;

                        $tmp_app_array[$tmp_entry_app->textContent] = $tmp_entry_app->textContent;
                    }
                    $this->additional['mica-engine-wildfire-rules'][$name]['application'] = $tmp_app_array;
                }
                $tmp_file_type = DH::findFirstElement("file-type", $tmp_entry1);
                if( $tmp_file_type !== FALSE )
                {
                    $tmp_file_type_array = array();
                    foreach( $tmp_file_type->childNodes as $tmp_entry_file_type )
                    {
                        if ($tmp_entry_file_type->nodeType != XML_ELEMENT_NODE)
                            continue;

                        $tmp_file_type_array[$tmp_entry_file_type->textContent] = $tmp_entry_file_type->textContent;
                    }
                    $this->additional['mica-engine-wildfire-rules'][$name]['file-type'] = $tmp_file_type_array;
                }
            }
        }
    }

    public function display_wildfire(): void
    {
        if( !empty( $this->rules_obj ) )
        {
            PH::print_stdout("        - wildfire-rules:");

            foreach ($this->rules_obj as $rulename => $rule)
            {
                $rule->display();
            }
        }

        if( !empty( $this->additional['mica-engine-wildfire-rules'] ) )
        {
            PH::print_stdout("        ----------------------------------------");
            $cloud_enabled = "no";
            if( $this->cloud_inline_analysis_enabled )
                $cloud_enabled = "yes";
            PH::print_stdout("        - wildfire-inline-rules: [mica-engine-enabled: ".$cloud_enabled."]");

            foreach ($this->additional['mica-engine-wildfire-rules'] as $rulename => $rule)
                PH::print_stdout("          '".$rulename."': - fileType: '".implode(",", $rule['file-type'])."' - application: '".implode(",", $rule['application'])."' - direction: '".$rule['direction']."'  - action: '".$rule['action']."'" );
        }
    }

    public function wildfire_rules_best_practice(): ?bool
    {
        $bp_set = null;
        if (!empty($this->rules_obj))
        {
            $bp_set = false;

            $first_array_key = array_key_first($this->rules_obj);

            $check_array = $this->rules_obj[$first_array_key]->wildfire_rule_bp_visibility_JSON( "visibility", "wildfire" );
            $checkBP_array = $this->rules_obj[$first_array_key]->wildfire_rule_bp_visibility_JSON( "bp", "wildfire" );
            $this->wildfire_rules_coverage();

            $first_array_key2 = array_key_first($checkBP_array);
            foreach( $checkBP_array[$first_array_key2]['filetype'] as $bp_array )
            {
                if( isset($this->rule_coverage[$bp_array]) )
                {
                    if( is_array($checkBP_array[$first_array_key2]['analysis']) )
                    {
                        if( !in_array($this->rule_coverage[$bp_array]['analysis'], $checkBP_array[0]['analysis']) )
                            return false;
                        else
                            $bp_set = true;
                    }
                    else
                    {
                        if( $checkBP_array[$first_array_key2]['analysis'] !== $this->rule_coverage[$bp_array]['analysis'] )
                            return false;
                        else
                            $bp_set = true;
                    }
                }
                #else
                #    return false;
            }

            foreach( $check_array[$first_array_key2]['filetype'] as $bp_array )
            {
                if( isset($this->rule_coverage[$bp_array]) )
                {
                    #print_r($this->rule_coverage[$bp_array]);
                    $checkAction = $check_array[0]['analysis'];
                    if( is_array($checkAction) )
                    {
                        //anything I need to do here:????
                        #print_r( $checkAction );
                    }
                    else
                    {
                        if( strpos( $checkAction, "!" ) !== FALSE )
                        {
                            $checkAction = str_replace("!", "", $checkAction);
                            if( $checkAction === $this->rule_coverage[$bp_array]['analysis'] )
                                return false;
                            else
                                $bp_set = true;
                        }
                        else
                        {
                            #print "checkAction: ".$checkAction."\n";
                            #print "compare: ".$this->rule_coverage[$bp_array]['analysis']."\n";
                            if( $checkAction !== $this->rule_coverage[$bp_array]['analysis'] )
                                return false;
                            else
                                $bp_set = true;
                        }
                    }
                }
            }
        }
        return $bp_set;
    }

    public function wildfire_rules_visibility(): ?bool
    {
        $bp_set = null;
        if (!empty($this->rules_obj)) {
            $bp_set = false;

            foreach ($this->rules_obj as $rulename => $rule) {
                /** @var ThreatPolicyWildfire $rule */
                if ($rule->wildfire_rule_visibility())
                    #$bp_set = true;
                    return true;
                else
                    $bp_set = false;
                #return false;
            }
        }
        return $bp_set;
    }

    public function wildfire_rules_coverage(): void
    {
        if (!empty($this->rules_obj))
        {
            foreach ($this->rules_obj as $rulename => $rule)
            {
                /** @var ThreatPolicyWildfire $rule */
                foreach( $rule->filetype as $filetype_detail )
                {
                    if( !isset($this->rule_coverage[$filetype_detail]) )
                    {
                        $this->rule_coverage[$filetype_detail]['direction'] = $rule->direction;
                        $this->rule_coverage[$filetype_detail]['analysis'] = $rule->analysis;
                    }
                }
            }
        }
    }

    public function is_best_practice(): bool
    {
        if( $this->owner->owner->version >= 112 )
        {
            if( $this->wildfire_rules_best_practice()
                && $this->cloud_inline_analysis_best_practice($this->owner->bp_json_file)
            )
                return TRUE;
            else
                return FALSE;
        }
        else
        {
            if( $this->wildfire_rules_best_practice() )
                return TRUE;
            else
                return FALSE;
        }
    }

    public function is_visibility(): bool
    {
        if( $this->owner->owner->version >= 112 )
        {
            if( $this->wildfire_rules_visibility()
                && $this->cloud_inline_analysis_visibility($this->owner->bp_json_file)
            )
                return TRUE;
            else
                return FALSE;
        }
        else
        {
            if( $this->wildfire_rules_visibility()
            )
                return TRUE;
            else
                return FALSE;
        }
    }

    public function is_adoption(): bool
    {
        #if at least one spyware rule is set -> adoption, if not false
        if( count($this->rules_obj) > 0 )
            return true;
        else
            return false;
    }

    public function wf_inlineML_AlertOnlySet(): void
    {
        $sendAPI = false;
        $tmp_mlav_engine = DH::findFirstElement('cloud-inline-analysis', $this->xmlroot);
        if ($this->owner->owner->version >= 112)
        {
            if ($tmp_mlav_engine === False)
                $tmp_mlav_engine = DH::findFirstElementOrCreate('cloud-inline-analysis', $this->xmlroot);

            $tmp_mlav_engine->textContent = "yes";
            $sendAPI = true;
        }


        $tmp_mlav_engine = DH::findFirstElement('mica-engine-wildfire-rules', $this->xmlroot);
        if ($this->owner->owner->version >= 112)
        {
            if ($tmp_mlav_engine === False)
                $tmp_mlav_engine = DH::findFirstElementOrCreate('mica-engine-wildfire-rules', $this->xmlroot);
        }
        if ($tmp_mlav_engine !== False)
        {
            if (!$tmp_mlav_engine->hasChildNodes())
            {
                $xmlString1 = '<entry name="wf_inline_alert">
   <application>
    <member>any</member>
   </application>
   <file-type>
    <member>any</member>
   </file-type>
   <direction>both</direction>
   <action>alert</action>
  </entry>';
                $xmlString2 = '<entry name="wf_inline_allow">
   <application>
    <member>any</member>
   </application>
   <file-type>
    <member>any</member>
   </file-type>
   <direction>both</direction>
   <action>allow</action>
  </entry>';
                //if ($this->owner->owner->version == 111 )
                //    $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $xmlString2);
                //else
                if ($this->owner->owner->version >= 112 )
                    $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $xmlString1);

                $tmp_mlav_engine->appendChild($xmlElement);

                $sendAPI = true;
            }

            $action_other_then_allow_alert = false;
            foreach ($tmp_mlav_engine->childNodes as $mlav_engine_entry)
            {
                if ($mlav_engine_entry->nodeType != XML_ELEMENT_NODE)
                    continue;

                $name = DH::findAttribute("name", $mlav_engine_entry);

                $action_xmlNode = DH::findFirstElementOrCreate("action", $mlav_engine_entry);
                if ($action_xmlNode->textContent == "allow")
                {
                    if ($this->owner->owner->version >= 112)
                    {
                        $action_xmlNode->textContent = "alert";
                        $this->additional['mica-engine-wildfire-rules'][$name]['action'] = "alert";

                        $sendAPI = true;
                    }
                }
                elseif ($action_xmlNode->textContent == "alert")
                {

                }
                else
                {
                    $action_other_then_allow_alert = true;
                }
            }

            if (!$action_other_then_allow_alert)
            {
                $tmp_mlav_engine = DH::findFirstElementOrCreate('cloud-inline-analysis', $this->xmlroot);
                $tmp_mlav_engine->textContent = "yes";

                $sendAPI = true;
            }
        }
    }

    public function wf_rules_AlertOnlySet(&$add_WF_alert): void
    {
        foreach( $this->rules_obj as $rule )
        {
            /** @var ThreatPolicyWildfire $rule */
            if( ($rule->analysis() == "public-cloud" || $rule->analysis() == "private-cloud" )
                && $rule->direction() == "both"
                && in_array("any", $rule->application() )
                && in_array("any", $rule->filetype() )
            )
            {
                $add_WF_alert = false;
                break;
            }


        }

        if( $add_WF_alert )
        {
            $tmp_name = "alert_vcp";
            $threadPolicy_obj = new ThreatPolicyWildfire( $tmp_name, $this);
            $threadPolicy_obj->type = "ThreatPolicyWildfire";

            $threadPolicy_obj->analysis = "public-cloud";
            $threadPolicy_obj->direction = "both";
            $threadPolicy_obj->filetype[] = "any";
            $threadPolicy_obj->application[] = "any";

            $this->rules_obj[] = $threadPolicy_obj;
            $threadPolicy_obj->addReference( $this );

            $this->owner->owner->ThreatPolicyStore->add($threadPolicy_obj);

            $threadPolicy_obj->newThreatPolicyXML($this->xmlroot, $tmp_name, null, $threadPolicy_obj->action);

        }
    }

    public function wf_inlineML_BestPracticeSet(): void
    {
        $tmp_mlav_engine = DH::findFirstElement('cloud-inline-analysis', $this->xmlroot);
        if( $this->owner->owner->version >= 111 )
        {
            if( $tmp_mlav_engine === False )
                $tmp_mlav_engine = DH::findFirstElementOrCreate('cloud-inline-analysis', $this->xmlroot);

            $tmp_mlav_engine->textContent = "yes";
        }


        $tmp_mlav_engine = DH::findFirstElement('mica-engine-wildfire-rules', $this->xmlroot);
        if( $this->owner->owner->version >= 111 )
        {
            if ($tmp_mlav_engine === False)
                $tmp_mlav_engine = DH::findFirstElementOrCreate('mica-engine-wildfire-rules', $this->xmlroot);
        }
        if( $tmp_mlav_engine !== False )
        {
            if( !$tmp_mlav_engine->hasChildNodes() )
            {
                $xmlString1 = '<entry name="wf_inline_block">
   <application>
    <member>any</member>
   </application>
   <file-type>
    <member>any</member>
   </file-type>
   <direction>both</direction>
   <action>block</action>
  </entry>';
                $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $xmlString1);
                $tmp_mlav_engine->appendChild($xmlElement);
            }

            foreach ($tmp_mlav_engine->childNodes as $mlav_engine_entry)
            {
                if( $mlav_engine_entry->nodeType != XML_ELEMENT_NODE )
                    continue;

                $name = DH::findAttribute( "name", $mlav_engine_entry);

                $action_xmlNode = DH::findFirstElementOrCreate("action", $mlav_engine_entry);
                $action_xmlNode->textContent = "block";

                $this->additional['mica-engine-wildfire-rules'][$name]['action'] = "block";
            }
        }
    }

    public function wf_rules_BestPracticeSet(): void
    {

    }

    public function AlertOnlySet(): void
    {
        $this->wf_inlineML_AlertOnlySet();

        $add_WF_alert = true;
        $this->wf_rules_AlertOnlySet($add_WF_alert);
    }

    public function BestPracticeSet(): void
    {
        $this->wf_inlineML_BestPracticeSet();

        //nothing todo
        //$this->wf_rules_BestPracticeSet();
    }
}