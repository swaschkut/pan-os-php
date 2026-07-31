<?php

class SecurityProfile2
{
    const TypeTmp = 0;
    const TypeVirus = 1;
    const TypeSpyware = 2;
    const TypeVulnerability = 3;
    const TypeFile_blocking = 4;
    const TypeWildfire_analysis = 5;
    const TypeUrl_filtering = 6;
    const TypeData_filtering = 7;
    const TypeDNS_security = 8;
    const TypeSaas_security = 9;

    const TypeVirus_and_Wildfire_analysis = 10;

    static public $SecurityProfileTypes = array(
        self::TypeTmp => 'tmp',
        self::TypeVirus => 'virus',
        self::TypeSpyware => 'spyware',
        self::TypeVulnerability => 'vulnerability',
        self::TypeFile_blocking => 'file-blocking',
        self::TypeWildfire_analysis => 'wildfire-analysis',
        self::TypeUrl_filtering => 'url-filtering',
        self::TypeData_filtering => 'data-filtering',
        self::TypeDNS_security => 'dns-security',
        self::TypeSaas_security => 'saas-security',
        self::TypeVirus_and_Wildfire_analysis => 'virus-and-wildfire-analysis'
    );

    public $type = self::TypeTmp;

    public $bp_json_file = null;


    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getSecurityProfileStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
    }

    public function cloud_inline_analysis_best_practice( $bp_json_file = null )
    {
        $this->bp_json_file = $bp_json_file;
        $this->bp_json_file = PH::getBPjsonFile( );

        $bp_set = FALSE;

        if( $this->secprof_type != 'spyware' and $this->secprof_type != 'vulnerability'
            and $this->secprof_type != 'virus' and $this->secprof_type != 'wildfire'
            and $this->secprof_type != 'dns-security' and $this->secprof_type != 'virus-and-wildfire-analysis'
        )
            return null;

        $check_array = $this->bp_visibility_JSON( "bp", $this->secprof_type);

        if( isset($this->cloud_inline_analysis_enabled) && $this->cloud_inline_analysis_enabled )
        {
            if( isset($this->additional['mica-engine-vulnerability-enabled']) )
            {
                foreach( $this->additional['mica-engine-vulnerability-enabled'] as $name)
                {
                    if( isset($check_array['inline-policy-action'] ) )
                    {
                        foreach ($check_array['inline-policy-action'] as $validate) {
                            if (isset($validate['type']) && $validate['type'][0] == 'any') {
                                $bp_set = $this->bp_stringValidation($name, 'inline-policy-action', $validate['action'][0]);
                                if (!$bp_set)
                                    return FALSE;
                            }
                        }

                        if ($bp_set == FALSE)
                            return false;
                    }
                }
            }

            if( isset($this->additional['mica-engine-spyware-enabled']) )
            {
                foreach( $this->additional['mica-engine-spyware-enabled'] as $name)
                {
                    if( isset($check_array['inline-policy-action'] ) )
                    {
                        foreach ($check_array['inline-policy-action'] as $validate) {
                            if (isset($validate['type']) && $validate['type'][0] == 'any') {
                                $bp_set = $this->bp_stringValidation($name, 'inline-policy-action', $validate['action'][0]);
                                if (!$bp_set)
                                    return FALSE;
                            }
                        }
                        if ($bp_set == FALSE)
                            return false;
                    }
                }
            }

            if( isset($this->additional['mica-engine-wildfire-rules']) )
            {
                foreach( $this->additional['mica-engine-wildfire-rules'] as $name)
                {
                    if( isset($check_array['inline-policy-action'] ) )
                    {
                        foreach( $check_array['inline-policy-action'] as $validate )
                        {
                            if( isset($validate['type']) && $validate['type'][0] == 'any' )
                            {
                                $bp_set = $this->bp_stringValidation($name, 'action', $validate['action'][0]);
                                if (!$bp_set)
                                    return FALSE;
                            }
                        }
                        if($bp_set == FALSE)
                            return false;
                    }
                }
            }
        }

        //AV iii) Wildfire Inline ML Tab
        //- all models must be set to 'enable (inherit per-protocol actions)'
        if( isset($this->additional['mlav-engine-filebased-enabled']) )
        {
            foreach( $this->additional['mlav-engine-filebased-enabled'] as $name)
            {
                if( isset($check_array['inline-policy-action'] ) )
                {
                    foreach ($check_array['inline-policy-action'] as $validate) {
                        if (isset($validate['type']) && $validate['type'][0] == 'any') {
                            $bp_set = $this->bp_stringValidation($name, 'mlav-policy-action', $validate['action'][0]);
                            if (!$bp_set)
                                return FALSE;
                        }
                    }

                    if ($bp_set == FALSE)
                        return false;
                }
            }
        }

        return $bp_set;
    }

    public function cloud_inline_analysis_visibility( $bp_json_file = null )
    {
        $this->bp_json_file = $bp_json_file;
        $this->bp_json_file = PH::getBPjsonFile( );

        $bp_set = FALSE;

        if( $this->secprof_type != 'spyware' and $this->secprof_type != 'vulnerability'
            and $this->secprof_type != 'virus' and $this->secprof_type != 'wildfire'
            and $this->secprof_type != 'dns-security' and $this->secprof_type != 'virus-and-wildfire-analysis'
        )
            return null;

        $check_array = $this->bp_visibility_JSON( "visibility", $this->secprof_type);

        if( isset($this->cloud_inline_analysis_enabled) && $this->cloud_inline_analysis_enabled )
        {
            if( isset($this->additional['mica-engine-vulnerability-enabled']) )
            {
                foreach( $this->additional['mica-engine-vulnerability-enabled'] as $name)
                {
                    if( isset($check_array['inline-policy-action'] ) )
                    {
                        foreach ($check_array['inline-policy-action'] as $validate) {
                            if (isset($validate['type']) && $validate['type'][0] == 'any') {
                                $bp_set = $this->visibility_stringValidation($name, 'inline-policy-action', $validate['action'][0]);
                                if (!$bp_set)
                                    return FALSE;
                            }
                        }

                        if (!$bp_set)
                            return FALSE;
                    }
                }
            }
            else
            {
                if ( $this->secprof_type == 'vulnerability' && $this->owner->owner->version < 110)
                {
                    return null;
                }
            }

            if( isset($this->additional['mica-engine-spyware-enabled']) )
            {
                foreach( $this->additional['mica-engine-spyware-enabled'] as $name)
                {
                    if( isset($check_array['inline-policy-action'] ) )
                    {
                        foreach ($check_array['inline-policy-action'] as $validate) {
                            if (isset($validate['type']) && $validate['type'][0] == 'any') {
                                $bp_set = $this->visibility_stringValidation($name, 'inline-policy-action', $validate['action'][0]);
                                if (!$bp_set)
                                    return FALSE;
                            } else {
                                //todo: speciall now for LDL
                                #print_r($validate);
                            }
                        }

                        if ($bp_set == FALSE)
                            return FALSE;
                    }
                }
            }
            else
            {
                if ( $this->secprof_type == 'spyware' && $this->owner->owner->version < 102)
                {
                    return null;
                }
            }

            if( isset($this->additional['mica-engine-wildfire-rules']) )
            {
                if ( $this->owner->owner->version < 111 )
                    return null;
                elseif ( $this->owner->owner->version == 111 )
                    return true;

                foreach( $this->additional['mica-engine-wildfire-rules'] as $name)
                {
                    if( isset($check_array['inline-policy-action'] ) )
                    {
                        foreach ($check_array['inline-policy-action'] as $validate)
                        {
                            if (isset($validate['type']) && $validate['type'][0] == 'any')
                            {
                                $bp_set = $this->visibility_stringValidation($name, 'action', $validate['action'][0]);
                                if (!$bp_set)
                                    return FALSE;
                            }
                            else
                            {
                                //todo: speciall now for LDL
                                #print_r($validate);
                            }
                        }

                        if ($bp_set == FALSE)
                            return FALSE;
                    }
                }
            }
            else
            {
                if ( ($this->secprof_type == 'wildfire' || $this->secprof_type == 'virus-and-wildfire-analysis' ) && $this->owner->owner->version < 112)
                {
                    if ( $this->owner->owner->version < 111 )
                        return null;
                    elseif ( $this->owner->owner->version == 111 )
                    {
                        //>=111 wf mica-engine but always allow!!!
                        return true;
                    }
                }
            }
        }
        else
        {
            if ( ($this->secprof_type == 'wildfire' || $this->secprof_type == 'virus-and-wildfire-analysis' ) )
            {
                if ( $this->owner->owner->version < 111 )
                    return null;
                elseif ( $this->owner->owner->version == 111 )
                {
                    //>=111 wf mica-engine but always allow!!!
                    return true;
                }
            }
        }

        //AV iii) Wildfire Inline ML Tab
        //- all models must be set to 'enable (inherit per-protocol actions)'
        if( isset($this->additional['mlav-engine-filebased-enabled']) )
        {
            foreach( $this->additional['mlav-engine-filebased-enabled'] as $type => $name)
            {
                if( isset($check_array['inline-policy-action'] ) )
                {
                    //$check_array is unique for all AV/AS/VP from JSON file
                    foreach ($check_array['inline-policy-action'] as $validate) {
                        if (isset($validate['type']) && $validate['type'][0] == 'any') {
                            $bp_set = $this->visibility_stringValidation($name, 'mlav-policy-action', $validate['action'][0]);
                            if (!$bp_set)
                                return FALSE;
                            #$bp_set = $this->visibility_stringValidation($name, 'mlav-policy-action', $validate);
                        }

                    }

                    if ($bp_set == FALSE)
                        return false;
                }
            }
        }
        else
        {
            if ( ($this->secprof_type == 'virus' || $this->secprof_type == 'virus-and-wildfire-analysis' ) )
            {
                if( $this->owner->owner->version < 102 )
                {
                    return null;
                }
            }
        }

        return $bp_set;
    }



    public function mica_getFullTextHTML(&$string_mica_engine, $bestPractice = false, $visibility = false, $bp_NOT_sign = "", $visible_NOT_sign = "")
    {
        if( !empty( $this->additional['mica-engine-spyware-enabled'] ) )
        {
            if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                $add_to_array = true;
            else
                $add_to_array = false;

            $enabled = "[no]";

            if( $this->cloud_inline_analysis_enabled )
                $enabled = "[yes]";
            else
            {
                if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                {
                    if( $bestPractice )
                        $enabled .= $bp_NOT_sign;
                    if( $visibility )
                        $enabled .= $visible_NOT_sign;
                }
                else
                    $add_to_array = true;
            }

            if( $add_to_array )
                $string_mica_engine[] = "mica-engine-spyware-enabled: ". $enabled;

            ////////////////////
            foreach ($this->additional['mica-engine-spyware-enabled'] as $type => $array)
            {
                $tmp_string = $type . " - inline-policy-action :" . $this->additional['mica-engine-spyware-enabled'][$type]['inline-policy-action'];
                if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                    $add_to_array = true;
                else
                    $add_to_array = false;

                if( $bestPractice )
                {
                    if( isset(PH::$shadow_bp_jsonfile['spyware']['cloud-inline']['bp']) )
                    {
                        $check_array = PH::$shadow_bp_jsonfile['spyware']['cloud-inline']['bp'];
                        if( isset($check_array['inline-policy-action']) )
                        {
                            $bp_set = TRUE;
                            foreach( $check_array['inline-policy-action'] as $detailed_check )
                            {
                                if ($detailed_check['type'][0] == "any") {
                                    if ($detailed_check['action'][0] !== $this->additional['mica-engine-spyware-enabled'][$type]['inline-policy-action'])
                                        $bp_set = FALSE;
                                }
                            }
                            if($bp_set == FALSE)
                            {
                                if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                                    $tmp_string .= $bp_NOT_sign;
                                else
                                    $add_to_array = true;
                            }
                        }
                    }
                }

                if( $visibility )
                {
                    if( isset(PH::$shadow_bp_jsonfile['spyware']['cloud-inline']['visibility']) )
                    {
                        $check_array = PH::$shadow_bp_jsonfile['spyware']['cloud-inline']['visibility'];
                        if( isset($check_array['inline-policy-action']) )
                        {
                            $bp_set = TRUE;
                            foreach( $check_array['inline-policy-action'] as $detailed_check )
                            {
                                if ($detailed_check['type'][0] == "any") {
                                    $validate = $detailed_check['action'][0];
                                    $negate_string = "";
                                    if (strpos($validate, "!") !== FALSE)
                                        $negate_string = "!";
                                    if ($validate === $negate_string . $this->additional['mica-engine-spyware-enabled'][$type]['inline-policy-action'])
                                        $bp_set = FALSE;
                                }
                            }
                            if($bp_set == FALSE)
                            {
                                if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                                    $tmp_string .= $visible_NOT_sign;
                                else
                                    $add_to_array = true;
                            }
                        }
                    }
                }

                //Todo: swaschkut 2025115  LDL missing
                if( isset($this->additional['mica-engine-spyware-enabled'][$type]['local-deep-learning']) )
                {
                    if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                        $tmp_string .= " - local-deep-learning :".$this->additional['mica-engine-spyware-enabled'][$type]['local-deep-learning'];
                }

                if( $add_to_array )
                    $string_mica_engine[] = $tmp_string;
            }

        }

        if( !empty( $this->additional['mica-engine-vulnerability-enabled'] ) )
        {
            if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                $add_to_array = true;
            else
                $add_to_array = false;

            $enabled = "[no]";
            if( $this->cloud_inline_analysis_enabled )
                $enabled = "[yes]";
            else
            {
                if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                {
                    if( $bestPractice )
                        $enabled .= $bp_NOT_sign;
                    if( $visibility )
                        $enabled .= $visible_NOT_sign;
                }
                else
                    $add_to_array = true;
            }

            if( $add_to_array )
                $string_mica_engine[] = "mica-engine-vulnerability-enabled: ". $enabled;

            ////////
            foreach ($this->additional['mica-engine-vulnerability-enabled'] as $type => $array)
            {
                $tmp_string = $type . " - inline-policy-action :" . $this->additional['mica-engine-vulnerability-enabled'][$type]['inline-policy-action'];
                if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                    $add_to_array = true;
                else
                    $add_to_array = false;

                if( $bestPractice )
                {
                    if( isset(PH::$shadow_bp_jsonfile['vulnerability']['cloud-inline']['bp']) )
                    {
                        $check_array = PH::$shadow_bp_jsonfile['vulnerability']['cloud-inline']['bp'];
                        if( isset($check_array['inline-policy-action']) )
                        {
                            $bp_set = TRUE;
                            foreach( $check_array['inline-policy-action'] as $detailed_check )
                            {
                                if( $detailed_check['type'][0] == "any" )
                                {
                                    if( $detailed_check['action'][0] !== $this->additional['mica-engine-vulnerability-enabled'][$type]['inline-policy-action'] )
                                        $bp_set = FALSE;
                                }
                            }

                            if($bp_set == FALSE)
                            {
                                if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                                    $tmp_string .= $bp_NOT_sign;
                                else
                                    $add_to_array = true;
                            }
                        }
                    }
                }

                if( $visibility )
                {
                    if( isset(PH::$shadow_bp_jsonfile['vulnerability']['cloud-inline']['visibility']) )
                    {
                        $check_array = PH::$shadow_bp_jsonfile['vulnerability']['cloud-inline']['visibility'];
                        if( isset($check_array['inline-policy-action']) )
                        {
                            $bp_set = TRUE;
                            foreach( $check_array['inline-policy-action'] as $detailed_check )
                            {
                                if ($detailed_check['type'][0] == "any")
                                {
                                    $validate = $detailed_check['action'][0];
                                    $negate_string = "";
                                    if (strpos($validate, "!") !== FALSE)
                                        $negate_string = "!";
                                    if ($validate === $negate_string . $this->additional['mica-engine-vulnerability-enabled'][$type]['inline-policy-action'])
                                        $bp_set = FALSE;
                                }
                            }

                            if($bp_set == FALSE)
                            {
                                if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                                    $tmp_string .= $visible_NOT_sign;
                                else
                                    $add_to_array = true;
                            }
                        }
                    }

                }

                if( $add_to_array )
                    $string_mica_engine[] = $tmp_string;
            }

        }

        if( !empty( $this->additional['mlav-engine-filebased-enabled'] ) )
        {
            if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                $add_to_array = true;
            else
                $add_to_array = false;

            if( $add_to_array )
                $string_mica_engine[] = "mlav-engine-filebased-enabled: ";

            foreach ($this->additional['mlav-engine-filebased-enabled'] as $type => $array)
            {
                $tmp_string = $type . " - mlav-policy-action :" . $this->additional['mlav-engine-filebased-enabled'][$type]['mlav-policy-action'];
                if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                    $add_to_array = true;
                else
                    $add_to_array = false;


                if( $bestPractice )
                {
                    if( isset(PH::$shadow_bp_jsonfile['virus']['cloud-inline']['bp']) )
                    {
                        $check_array = PH::$shadow_bp_jsonfile['virus']['cloud-inline']['bp'];
                        if( isset($check_array['inline-policy-action']) )
                        {
                            $bp_set = TRUE;
                            foreach( $check_array['inline-policy-action'] as $detailed_check )
                            {
                                if ($detailed_check['type'][0] == "any") {
                                    if ($detailed_check['action'][0] !== $this->additional['mlav-engine-filebased-enabled'][$type]['mlav-policy-action'])
                                        $bp_set = FALSE;
                                }
                            }

                            if($bp_set == FALSE)
                            {
                                if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                                    $tmp_string .= $bp_NOT_sign;
                                else
                                    $add_to_array = true;
                            }
                        }
                    }
                }

                if( $visibility )
                {
                    if( isset(PH::$shadow_bp_jsonfile['virus']['cloud-inline']['visibility']) )
                    {
                        $check_array = PH::$shadow_bp_jsonfile['virus']['cloud-inline']['visibility'];
                        if( isset($check_array['inline-policy-action']) )
                        {
                            $bp_set = TRUE;
                            foreach( $check_array['inline-policy-action'] as $detailed_check )
                            {
                                if ($detailed_check['type'][0] == "any")
                                {
                                    $validate = $detailed_check['action'][0];
                                    $negate_string = "";
                                    if (strpos($validate, "!") !== FALSE)
                                        $negate_string = "!";
                                    if ($validate === $negate_string . $this->additional['mlav-engine-filebased-enabled'][$type]['mlav-policy-action'])
                                        $bp_set = FALSE;
                                }
                            }

                            if($bp_set == FALSE)
                            {
                                if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                                    $tmp_string .= $visible_NOT_sign;
                                else
                                    $add_to_array = true;
                            }
                        }
                    }
                }

                if( $add_to_array )
                    $string_mica_engine[] = $tmp_string;
            }

        }

        if( !empty( $this->additional['mica-engine-wildfire-rules'] ) )
        {
            if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                $add_to_array = true;
            else
                //todo: missing part - so always add it
                $add_to_array = true;

            $enabled = "[no]";
            if ($this->cloud_inline_analysis_enabled)
                $enabled = "[yes]";
            else
            {
                if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                {
                    #if( $bestPractice )
                    #    $enabled .= $bp_NOT_sign;
                    #if( $visibility )
                    #    $enabled .= $visible_NOT_sign;
                }
                else
                    $add_to_array = true;
            }

            if( $add_to_array )
                $string_mica_engine[] = "mica-engine-wildfire-rules: " . $enabled;


            foreach( $this->additional['mica-engine-wildfire-rules'] as $rulename => $rule )
            {

                $tmp_string = "'".$rulename."' | - application:'".implode(",", $rule['application'])."' - fileType:'".implode(",", $rule['file-type'])."' - direction:'".$rule['direction']."'  - action:'".$rule['action']."'";;

                /*
                             "visibility": {
                "inline-policy-action": [
                    {
                        "type": [
                            "any"
                        ],
                        "action": [
                            "!allow"
                        ]
                    }
                ]
            }
                 */
                if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                    $string_mica_engine[] = $tmp_string;
                else
                {
                    //Todo: validation must be done against BP setting file!!!!
                    #if( !in_array( "any", $rule['application']) || !in_array( "any", $rule['file-type']) ||  $rule['direction'] !== "both" )
                        //not working correct
                        $string_mica_engine[] = $tmp_string;
                }
            }

        }
    }

    public function botnet_getFullTextHTML(&$string_dns_list, &$string_dns_sinkhole, &$string_dns_security, &$string_adns_security, &$string_dns_whitelist, $bestPractice = false, $visibility = false, $bp_NOT_sign = "", $visible_NOT_sign = "")
    {
        if( isset($this->additional['botnet-domain']) )
        {
            foreach( $this->additional['botnet-domain'] as $type => $threat )
            {
                if( $type == "lists" && $string_dns_list !== null )
                {
                    foreach( $this->additional['botnet-domain']['lists'] as $name => $rule )
                    {
                        if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                            $add_to_array = true;
                        else
                            $add_to_array = false;

                        //$string = $name." -  action: ".$value['action'];
                        $string = "";
                        $string .= $rule->name();

                        $string .= " - action: '".$rule->action."'";
                        $string .= " - packet-capture: '".$rule->packetCapture()."'";

                        /** @var DNSPolicy $rule */
                        if( $bestPractice && !$rule->spyware_lists_bestpractice() )
                        {
                            if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                                $string .= $bp_NOT_sign;
                            else
                            {
                                $add_to_array = true;
                            }
                        }
                        if( $visibility && !$rule->spyware_lists_visibility() )
                        {
                            if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                                $string .= $visible_NOT_sign;
                            else
                            {
                                $add_to_array = true;
                            }
                        }

                        if( $add_to_array )
                            $string_dns_list[] =  $string;
                    }

                }
                elseif( $type == "sinkhole" && $string_dns_sinkhole !== null )
                {
                    foreach( $this->additional['botnet-domain'][$type] as $name => $value )
                    {
                        if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                            $add_to_array = true;
                        else
                            $add_to_array = false;

                        if( $add_to_array )
                        {
                            $string_dns_sinkhole[] = $name.": ".$value;
                        }
                    }

                }
                elseif( $type == "dns-security-categories" && $string_dns_security !== null )
                {
                    foreach( $this->additional['botnet-domain'][$type] as $name => $rule )
                    {
                        if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                            $add_to_array = true;
                        else
                            $add_to_array = false;

                        $string = "";
                        $string .= $rule->name();

                        $string .= " - log-level: '".$rule->logLevel()."'";
                        $string .= " - action: '".$rule->action."'";
                        $string .= " - packet-capture: '".$rule->packetCapture()."'";
                        /** @var DNSPolicy $rule */
                        if( $bestPractice && !$rule->spyware_dns_security_rule_bestpractice() )
                        {
                            if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                                $string .= $bp_NOT_sign;
                            else
                            {
                                $add_to_array = true;
                            }
                        }

                        if( $visibility && !$rule->spyware_dns_security_rule_visibility() )
                        {
                            if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                                $string .= $visible_NOT_sign;
                            else
                            {
                                $add_to_array = true;
                            }
                        }


                        if( $add_to_array )
                            $string_dns_security[] = $string;
                    }
                }
                elseif( $type == "advanced-dns-security-categories" && $string_adns_security !== null )
                {
                    if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                        $add_to_array = true;
                    else
                        $add_to_array = false;

                    if( $add_to_array )
                    {
                        $string_adns_security[] = "";
                        $string_adns_security[] = "---Advanced DNS Security Categories";
                    }

                    foreach( $this->additional['botnet-domain'][$type] as $name => $rule )
                    {
                        if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                            $add_to_array = true;
                        else
                            $add_to_array = false;

                        $string = "";
                        $string .= $rule->name();

                        $string .= " - log-level: '".$rule->logLevel()."'";
                        $string .= " - action: '".$rule->action."'";
                        #adns does not have packet-capture
                        //$string .= " - packet-capture: '".$rule->packetCapture()."'";
                        /** @var DNSPolicy $rule */
                        //Todo: TBD
                        if( $bestPractice && !$rule->spyware_advanced_dns_security_rule_bestpractice() )
                        {
                            if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                                $string .= $bp_NOT_sign;
                            else
                            {
                                $add_to_array = true;
                            }
                        }

                        if( $visibility && !$rule->spyware_advanced_dns_security_rule_visibility() )
                        {
                            if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                                $string .= $visible_NOT_sign;
                            else
                            {
                                $add_to_array = true;
                            }
                        }


                        if( $add_to_array )
                            $string_adns_security[] = $string;
                    }
                }
                elseif( $type == "whitelist" && $string_dns_whitelist !== null )
                {
                    foreach( $this->additional['botnet-domain'][$type] as $name => $value )
                    {
                        if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                            $add_to_array = true;
                        else
                            $add_to_array = false;

                        $string = $value['name'];
                        if( isset($value['description']) )
                            $string .= "' | description:'".$value['description'];

                        if( $add_to_array )
                        {
                            $string_dns_whitelist[] = $string;
                        }
                    }
                }

            }
        }

    }

    public function url_siteaccess_getFullTextHTML(&$tmp_array, $bestPractice = false, $visibility = false, $bp_text_yes = "", $bp_text_no = "")
    {
        if( $visibility )
        {
            $sanitized_action = $this->allow;
            foreach( $sanitized_action as $key => $url_category)
            {
                if( isset($this->owner->owner->customURLProfileStore) )
                {
                    $custom_url_category_obj = $this->owner->owner->customURLProfileStore->find($url_category);
                    if( $custom_url_category_obj !== NULL )
                        unset( $sanitized_action[$key] );
                }
            }

            if( empty($sanitized_action) )
                $tmp_array[] = "yes";
            else
                $tmp_array[] = 'ALLOW: "set all pre-defined URL-category action to alert"';
        }

        if( $bestPractice )
        {
            $countAllow = count( $this->allow );
            $countAlert = count( $this->alert );
            $countBlock = count( $this->block );
            $tmp_array[] = "Allow (".$countAllow.")";
            $tmp_array[] = "Alert (".$countAlert.")";
            $tmp_array[] = "Block (".$countBlock.")";
            $tmp_array[] = "------------------------";

            $check_array = $this->url_siteaccess_bp_visibility_JSON( "bp", "url" );
            #print_r($check_array);
            $block_categories_to_check = array();
            $alert_categories_to_check = array();
            foreach( $check_array as $check )
            {
                if( isset( $check['action'] ) )
                {
                    if( $check['action'] == 'block' )
                    {
                        if( isset( $check['type'] ) )
                            $block_categories_to_check = array_merge( $block_categories_to_check, $check['type'] );
                    }
                    elseif( $check['action'] == 'alert' )
                    {
                        if( isset( $check['type'] ) )
                            $alert_categories_to_check = array_merge( $alert_categories_to_check, $check['type'] );
                    }
                }
            }

            #if( isset($check_array[0]['type']) )
            #    $block_categories = $check_array[0]['type'];
            #else
            if( empty( $block_categories_to_check ) )
                $block_categories_to_check = array('command-and-control','compromised-website','grayware','malware','phishing','ransomware','scanning-activity');

            $notBlock = array();
            foreach( $block_categories_to_check as $block_category )
            {
                if( !in_array( $block_category, $this->block ) )
                    $notBlock[] = $block_category;

            }
            if( !empty($notBlock) )
            {
                $tmp_array[] = 'BLOCK missing: ';
                $tmp_array = array_merge( $tmp_array, $notBlock );
            }
            $notAlert = array();
            foreach( $alert_categories_to_check as $alert_category )
            {
                if( !in_array( $alert_category, $this->alert ) && !in_array( $alert_category, $this->block ) )
                    $notAlert[] = $alert_category;

            }
            if( !empty($notAlert) )
            {
                $tmp_array[] = 'ALERT missing: ';
                $tmp_array = array_merge( $tmp_array, $notAlert );
            }

            if( empty($notBlock) && empty($notAlert) )
                $tmp_array[] = "yes";
        }

        return $tmp_array;
    }

    public function url_credentials_getFullTextHTML(&$tmp_array, $bestPractice = false, $visibility = false, $bp_text_yes = "", $bp_text_no = "")
    {
        if ($visibility)
        {
            $sanitized_action = $this->allow_credential;
            foreach( $sanitized_action as $key => $url_category)
            {
                if( isset( $this->owner->owner->customURLProfileStore) )
                {
                    $custom_url_category_obj = $this->owner->owner->customURLProfileStore->find($url_category);
                    if( $custom_url_category_obj !== NULL )
                        unset( $sanitized_action[$key] );
                }
            }

            if( empty($sanitized_action) )
                $tmp_array[] = "yes";
            else
                $tmp_array[] = 'ALLOW: "set all pre-defined URL-category action to alert"';
        }

        if ($bestPractice)
        {
            $countAllowcredential = count( $this->allow_credential );
            $countAlertcredential = count( $this->alert_credential );
            $countBlockcredential = count( $this->block_credential );
            $tmp_array[] = "Allow (".$countAllowcredential.")";
            $tmp_array[] = "Alert (".$countAlertcredential.")";
            $tmp_array[] = "Block (".$countBlockcredential.")";
            $tmp_array[] = "------------------------";

            $check_array = $this->url_siteaccess_bp_visibility_JSON( "bp", "url" );

            $block_categories_to_check = array();
            $alert_categories_to_check = array();
            foreach( $check_array as $check )
            {
                if( isset( $check['action'] ) )
                {
                    if( $check['action'] == 'block' )
                    {
                        if( isset( $check['type'] ) )
                            $block_categories_to_check = array_merge( $block_categories_to_check, $check['type'] );
                    }
                    elseif( $check['action'] == 'alert' )
                    {
                        if( isset( $check['type'] ) )
                            $alert_categories_to_check = array_merge( $alert_categories_to_check, $check['type'] );
                    }
                }
            }

            if( empty( $block_categories_to_check ) )
                $block_categories_to_check = array('command-and-control','compromised-website','grayware','malware','phishing','ransomware','scanning-activity');

            $notBlock = array();
            foreach( $block_categories_to_check as $block_category )
            {
                if( !in_array( $block_category, $this->block_credential ) )
                    $notBlock[] = $block_category;

            }
            if( !empty($notBlock) )
            {
                $tmp_array[] = 'BLOCK missing: ';
                $tmp_array = array_merge( $tmp_array, $notBlock );
            }
            $notAlert = array();
            foreach( $alert_categories_to_check as $alert_category )
            {
                if( !in_array( $alert_category, $this->alert_credential ) && !in_array( $alert_category, $this->block_credential ) )
                    $notAlert[] = $alert_category;

            }
            if( !empty($notAlert) )
            {
                $tmp_array[] = 'ALERT missing: ';
                $tmp_array = array_merge( $tmp_array, $notAlert );
            }

            if( empty($notBlock) && empty($notAlert) )
                $tmp_array[] = "yes";
        }

        return $tmp_array;
    }

    public function url_credentials_tab_getFullTextHTML(&$tmp_array, $bestPractice = false, $visibility = false, $bp_text_yes = "", $bp_text_no = "")
    {
        if ($visibility)
        {
            $tmp_array[] = "mode: ".$this->credential_mode;
            $tmp_array[] = "log-severity: ".$this->credential_log;
            $tmp_array[] = "----";

            if( $this->url_usercredentialsubmission_visibility_tab() )
                $tmp_array[] = $bp_text_yes;
            else
                $tmp_array[] = $bp_text_no;
        }

        if ($bestPractice)
        {
            $tmp_array[] = "mode: ".$this->credential_mode;
            $tmp_array[] = "log-severity: ".$this->credential_log;
            $tmp_array[] = "----";

            if( $this->url_usercredentialsubmission_best_practice_tab() )
                $tmp_array[] = $bp_text_yes;
            else
                $tmp_array[] = $bp_text_no;
        }

        return $tmp_array;
    }

    public function visibility_stringValidation($array, $key, $validate)
    {
        $negate_string = "";
        if( strpos( $validate, "!" ) !== FALSE )
            $negate_string = "!";
        if( $negate_string.$array[$key] == $validate )
            $bp_set = FALSE;
        else
            $bp_set = TRUE;

        return $bp_set;
    }

    public function bp_stringValidation($array, $key, $validate)
    {
        $negate_string = "";
        if( strpos( $validate, "!" ) !== FALSE )
            $negate_string = "!";
        if( $negate_string.$array[$key] == $validate )
            $bp_set = TRUE;
        else
            $bp_set = FALSE;

        return $bp_set;
    }


    public function bp_visibility_JSON( $checkType, $secprof_type )
    {
        $checkArray = array();

        if( $checkType !== "bp" && $checkType !== "visibility" )
            derr( "only 'bp' or 'visibility' argument allowed" );

        $details = PH::getBPjsonFile( );

        $array_type = "cloud-inline";
        $check_action_type = "inline-policy-action";


        if( isset($details[$secprof_type][$array_type]) )
        {
            if( $checkType == "bp" )
            {
                if( isset($details[$secprof_type][$array_type]['bp'][$check_action_type]) )
                    $checkArray = $details[$secprof_type][$array_type]['bp'];
                else
                    mwarning( "this JSON bp/visibility JSON file customised 'bp' -> '".$check_action_type."' for: '".$secprof_type."'", null, FALSE );
            }
            elseif( $checkType == "visibility")
            {
                if( isset($details[$secprof_type][$array_type]['visibility'][$check_action_type]) )
                    $checkArray = $details[$secprof_type][$array_type]['visibility'];
                else
                    mwarning( "this JSON bp/visibility JSON file customised 'visibility' -> '".$check_action_type."' for: '".$secprof_type."'", null, FALSE );
            }
        }

        return $checkArray;
    }

    public function countDisabledRefRule()
    {
        $counter = 0;
        foreach( $this->refrules as $refrule )
        {
            if( get_class($refrule) == "SecurityRule" )
            {
                /** @var Rule $refrule */
                if( $refrule->isDisabled() )
                    $counter++;
            }
            elseif( get_class($refrule) == "SecurityProfileGroup" )
            {
                foreach( $refrule->refrules as $refrule2 )
                {
                    /** @var Rule $refrule2 */
                    if( $refrule2->isDisabled() )
                        $counter++;
                }
            }
        }
        return $counter;
    }

    public function isTmpSecProf()
    {
        if( $this->type === self::$SecurityProfileTypes[self::TypeTmp] )
            return TRUE;

        return FALSE;
    }

    public function isTmp()
    {
        return self::isTmpSecProf();
    }

}

