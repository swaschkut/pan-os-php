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


            $check_array = $this->rules_obj[0]->wildfire_rule_bp_visibility_JSON( "visibility", "wildfire" );
            $checkBP_array = $this->rules_obj[0]->wildfire_rule_bp_visibility_JSON( "bp", "wildfire" );
            $this->wildfire_rules_coverage();


            foreach( $checkBP_array[0]['filetype'] as $bp_array )
            {
                if( isset($this->rule_coverage[$bp_array]) )
                {
                    if( is_array($checkBP_array[0]['analysis']) )
                    {
                        if( !in_array($this->rule_coverage[$bp_array]['analysis'], $checkBP_array[0]['analysis']) )
                            return false;
                        else
                            $bp_set = true;
                    }
                    else
                    {
                        if( $checkBP_array[0]['analysis'] !== $this->rule_coverage[$bp_array]['analysis'] )
                            return false;
                        else
                            $bp_set = true;
                    }
                }
                #else
                #    return false;
            }

            foreach( $check_array[0]['filetype'] as $bp_array )
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
}