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

    /**
     * @return bool|null null: wildfire -> rule -> bp (filetype) not listed in the BP JSON (N/A);
     *                   FALSE: listed, but the profile has no rule
     */
    public function wildfire_rules_best_practice(): ?bool
    {
        $details = PH::getBPjsonFile();
        $checkBP_array = $details['wildfire']['rule']['bp'] ?? array();
        $check_array = $details['wildfire']['rule']['visibility'] ?? array();
        $first_array_key2 = is_array( $checkBP_array ) ? array_key_first( $checkBP_array ) : null;
        if( $first_array_key2 === null || empty( $checkBP_array[$first_array_key2]['filetype'] ) )
            return null;

        $bp_set = false;
        if (!empty($this->rules_obj))
        {
            $this->wildfire_rules_coverage();

            foreach( $checkBP_array[$first_array_key2]['filetype'] as $bp_array )
            {
                if( isset($this->rule_coverage[$bp_array]) )
                {
                    if( !isset( $checkBP_array[$first_array_key2]['analysis'] ) )
                        $bp_set = true;     // analysis not listed: not checked
                    elseif( is_array($checkBP_array[$first_array_key2]['analysis']) )
                    {
                        if( !in_array($this->rule_coverage[$bp_array]['analysis'], $checkBP_array[$first_array_key2]['analysis']) )
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

            $first_vis_key = is_array( $check_array ) ? array_key_first( $check_array ) : null;
            foreach( ( $first_vis_key !== null ? ( $check_array[$first_vis_key]['filetype'] ?? array() ) : array() ) as $bp_array )
            {
                if( isset($this->rule_coverage[$bp_array]) && isset( $check_array[$first_vis_key]['analysis'] ) )
                {
                    #print_r($this->rule_coverage[$bp_array]);
                    $checkAction = $check_array[$first_vis_key]['analysis'];
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

    /**
     * @return bool|null null: wildfire -> rule -> visibility not listed in the visibility JSON (N/A);
     *                   FALSE: listed, but no rule passes (or the profile has no rule)
     */
    public function wildfire_rules_visibility(): ?bool
    {
        if( empty( PH::getBPjsonFile()['wildfire']['rule']['visibility'] ) )
            return null;

        $bp_set = false;
        if (!empty($this->rules_obj)) {
            $bp_set = false;

            foreach ($this->rules_obj as $rulename => $rule) {
                /** @var ThreatPolicyWildfire $rule */
                if ($rule->wildfire_rule_visibility() === TRUE)
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

    public function is_best_practice(): ?bool
    {
        // the inline-ML part returns null where the PAN-OS version has none (SecurityProfile2::$bpFeatureMinVersion)
        return PH::bpCombine( array( $this->wildfire_rules_best_practice(), $this->cloud_inline_analysis_best_practice($this->owner->bp_json_file) ) );
    }

    public function is_visibility(): ?bool
    {
        // the inline-ML part returns null where the PAN-OS version has none (SecurityProfile2::$bpFeatureMinVersion)
        return PH::bpCombine( array( $this->wildfire_rules_visibility(), $this->cloud_inline_analysis_visibility($this->owner->bp_json_file) ) );
    }

    public function is_adoption(): bool
    {
        #if at least one spyware rule is set -> adoption, if not false
        if( count($this->rules_obj) > 0 )
            return true;
        else
            return false;
    }

    /**
     * alert-only-set of the WF inline cloud analysis (mica-engine-wildfire-rules).
     * The action comes from the BP JSON wildfire -> cloud-inline -> visibility (entry with type 'any', as the checks);
     * a negated condition ('!allow') keeps a compliant value, else 'alert'. Nothing listed in the BP JSON or a
     * PAN-OS version without inline ML: no change.
     * Inline analysis still off: every rule gets 'alert' before it is enabled (enabling must not start blocking).
     */
    public function wf_inlineML_AlertOnlySet(): void
    {
        $this->wf_inlineML_setFromJSON( 'visibility', 'alert' );
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

    /**
     * best-practice-set of the WF inline cloud analysis (mica-engine-wildfire-rules).
     * The action comes from the BP JSON wildfire -> cloud-inline -> bp (entry with type 'any', as the checks);
     * a negated condition ('!allow') keeps a compliant value, else 'block'. Nothing listed in the BP JSON or a
     * PAN-OS version without inline ML: no change.
     * The direction of every rule is set as well where the BP JSON gives one (the best-practice check compares it).
     */
    public function wf_inlineML_BestPracticeSet(): void
    {
        $this->wf_inlineML_setFromJSON( 'bp', 'block' );
    }

    private function wf_inlineML_setFromJSON( string $section, string $fallback ): void
    {
        $validate = $this->inlineML_jsonAction( $section, 'wildfire' );
        if( $validate === null )
            return;

        // direction of the BP JSON entry with type 'any' (string or list)
        $direction = null;
        $check_array = $this->bp_visibility_JSON( $section, 'wildfire' );
        foreach( $check_array['inline-policy-action'] as $entry )
            if( isset( $entry['type'][0] ) && $entry['type'][0] == 'any' && isset( $entry['direction'] ) )
            {
                $direction = is_array( $entry['direction'] ) ? (string)$entry['direction'][0] : (string)$entry['direction'];
                break;
            }
        if( $direction !== null && strpos( $direction, '!' ) === 0 )
            $direction = null;

        $wasEnabled = !empty( $this->cloud_inline_analysis_enabled );
        $container = DH::findFirstElementOrCreate( 'mica-engine-wildfire-rules', $this->xmlroot );
        if( !$container->hasChildNodes() )
        {
            $value = self::inlineML_newValue( $validate, $fallback );
            $ruleDirection = $direction !== null ? $direction : 'both';
            $ruleName = 'wf_inline_'.$value;
            $xmlString = '<entry name="'.$ruleName.'"><application><member>any</member></application><file-type><member>any</member></file-type>'
                .'<direction>'.$ruleDirection.'</direction><action>'.$value.'</action></entry>';
            $container->appendChild( DH::importXmlStringOrDie( $this->xmlroot->ownerDocument, $xmlString ) );
            $this->additional['mica-engine-wildfire-rules'][$ruleName]['action'] = $value;
            $this->additional['mica-engine-wildfire-rules'][$ruleName]['direction'] = $ruleDirection;
        }
        else
        {
            $this->inlineML_setEntriesFromJSON( $section, 'wildfire', 'mica-engine-wildfire-rules', 'action', $fallback,
                $section == 'visibility' && !$wasEnabled );

            if( $section == 'bp' && $direction !== null )
            {
                foreach( $container->childNodes as $rule )
                {
                    if( $rule->nodeType != XML_ELEMENT_NODE )
                        continue;
                    $name = DH::findAttribute( "name", $rule );
                    $directionNode = DH::findFirstElementOrCreate( 'direction', $rule );
                    if( $directionNode->textContent !== $direction )
                    {
                        $directionNode->textContent = $direction;
                        $this->additional['mica-engine-wildfire-rules'][$name]['direction'] = $direction;
                    }
                }
            }
        }

        $tmp_enable = DH::findFirstElementOrCreate( 'cloud-inline-analysis', $this->xmlroot );
        $tmp_enable->textContent = "yes";
        $this->cloud_inline_analysis_enabled = true;

        if( $this->secprof_type == 'wildfire' )
            $this->bpSetVerify( $section, 'WF inline ML', $section == 'bp' ? $this->cloud_inline_analysis_best_practice() : $this->cloud_inline_analysis_visibility() );
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