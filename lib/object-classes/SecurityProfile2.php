<?php

class SecurityProfile2
{
    /** set by the mergers: same-name profile in a parent / child device group */
    public $ancestor;
    public $childancestor;

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
     * The one place for the PAN-OS version a visibility / best-practice setting exists from.
     * Below it the check of the setting returns null (N/A), for visibility and best practice alike;
     * the filters ('is.visibility', 'is.best-practice', '.na'), the profile exports and the BP statistics
     * (StatCollectorTrait::bp_check_definitions()) all read it from here.
     */
    public static $bpFeatureMinVersion = array(
        'virus-mica' => 100,                // AV inline ML (mlav-engine-filebased-enabled)
        'mlav-action' => 100,               // AV decoder mlav-action
        'spyware-dns' => 100,               // AS DNS security categories (botnet-domains dns-security-categories)
        'spyware-mica' => 102,              // AS inline cloud analysis (mica-engine-spyware-enabled)
        'url-mica' => 102,                  // URL local-inline-cat / cloud-inline-cat
        'vulnerability-mica' => 110,        // VP inline cloud analysis (mica-engine-vulnerability-enabled)
        'wildfire-mica' => 112,             // WF inline cloud analysis (mica-engine-wildfire-rules)
        'spyware-advanced-dns' => 112,      // AS advanced DNS security categories
        'spyware-local-deep-learning' => 112,   // AS inline cloud analysis: local-deep-learning per detector
    );

    /** TRUE when PAN-OS version $version has the setting $feature (key of $bpFeatureMinVersion); version 0: unknown, TRUE */
    public static function bpFeatureSupportedInVersion( string $feature, int $version ): bool
    {
        if( !isset( self::$bpFeatureMinVersion[$feature] ) )
            derr( "unknown BP feature '".$feature."'" );
        return $version <= 0 || $version >= self::$bpFeatureMinVersion[$feature];
    }

    /** TRUE when the PAN-OS version of this profile's location has the setting $feature */
    public function bpFeatureSupported( string $feature ): bool
    {
        // inlineVersion(): the PAN-OS version of the location; SCM / Prisma Access always the current feature set
        $version = $this->inlineVersion();
        $version = is_numeric( $version ) ? intval( $version ) : 0;
        return self::bpFeatureSupportedInVersion( $feature, $version );
    }

    /** the $bpFeatureMinVersion key of the inline-ML (cloud-inline) setting of a profile type; null: none */
    public static function cloud_inline_feature( $secprof_type ): ?string
    {
        $map = array(
            'virus' => 'virus-mica',
            'virus-and-wildfire-analysis' => 'virus-mica',
            'spyware' => 'spyware-mica',
            'vulnerability' => 'vulnerability-mica',
            'wildfire' => 'wildfire-mica',
        );
        return $map[$secprof_type] ?? null;
    }


    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getSecurityProfileStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
    }

    public function AlertOnlySet()
    {}

    public function BestPracticeSet()
    {}

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

        // the PAN-OS version has no inline ML for this type: N/A
        $feature = self::cloud_inline_feature( $this->secprof_type );
        if( $feature !== null && !$this->bpFeatureSupported( $feature ) )
            return null;

        $check_array = $this->bp_visibility_JSON( "bp", $this->secprof_type);
        // not listed in the BP JSON: not checked -> N/A
        if( !self::cloud_inline_listed( $check_array ) )
            return null;

        if( isset($this->cloud_inline_analysis_enabled) && $this->cloud_inline_analysis_enabled )
        {
            if( isset($this->additional['mica-engine-vulnerability-enabled']) )
            {
                foreach( $this->additional['mica-engine-vulnerability-enabled'] as $name)
                {
                    if( isset($check_array['inline-policy-action'] ) )
                    {
                        foreach ($check_array['inline-policy-action'] as $validate) {
                            if (isset($validate['type']) && $validate['type'][0] == 'any' && !empty($validate['action'])) {
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
                            if (isset($validate['type']) && $validate['type'][0] == 'any' && !empty($validate['action'])) {
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

            // AS detectors: local-deep-learning as the BP JSON lists it (from PAN-OS 11.2)
            if( isset($this->additional['mica-engine-spyware-enabled']) && $this->inlineML_localDeepLearningComplies( 'bp' ) === FALSE )
                return FALSE;

            // virus-and-wildfire-analysis: its WildFire part only where the PAN-OS version has it
            if( isset($this->additional['mica-engine-wildfire-rules']) && $this->bpFeatureSupported( 'wildfire-mica' ) )
            {
                foreach( $this->additional['mica-engine-wildfire-rules'] as $name)
                {
                    if( isset($check_array['inline-policy-action'] ) )
                    {
                        $bp_set = FALSE;
                        $bp_application_set = FALSE;
                        $bp_direction_set = FALSE;

                        foreach( $check_array['inline-policy-action'] as $validate )
                        {
                            if( isset($validate['type']) && $validate['type'][0] == 'any' && !empty($validate['action']) )
                            {
                                $bp_set = $this->bp_stringValidation($name, 'action', $validate['action'][0]);

                                if( isset($validate['direction']) )
                                    $bp_direction_set = $this->bp_stringValidation($name, 'direction', $validate['direction']);

                                $bp_application_set = FALSE;
                                if( isset($validate['application']) && $validate['application'][0] == 'any' )
                                    $bp_application_set = TRUE;

                                if (!$bp_set || !$bp_direction_set || !$bp_application_set)
                                    return FALSE;
                            }
                        }
                        if(!$bp_set || !$bp_direction_set || !$bp_application_set)
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
                        if (isset($validate['type']) && $validate['type'][0] == 'any' && !empty($validate['action'])) {
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

    /**
     * PAN-OS version for the inline cloud analysis checks: SCM / Prisma Access (BuckbeakConf, FawkesConf) always has
     * the current feature set - its XML carries the version of the base configuration (11.1), with which the WildFire
     * inline cloud analysis would count as compliant without a check
     */
    public function inlineVersion()
    {
        $sub = is_object($this->owner) ? $this->owner->owner : null;
        $root = $sub;
        for( $i = 0; $i < 5 && is_object($root) && !( $root instanceof BuckbeakConf || $root instanceof FawkesConf || $root instanceof PANConf || $root instanceof PanoramaConf ); $i++ )
            $root = isset($root->owner) ? $root->owner : null;
        if( $root instanceof BuckbeakConf || $root instanceof FawkesConf )
            return 121;
        return is_object($sub) ? $sub->version : null;
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

        // the PAN-OS version has no inline ML for this type: N/A
        $feature = self::cloud_inline_feature( $this->secprof_type );
        if( $feature !== null && !$this->bpFeatureSupported( $feature ) )
            return null;

        $check_array = $this->bp_visibility_JSON( "visibility", $this->secprof_type);
        // not listed in the visibility JSON: not checked -> N/A
        if( !self::cloud_inline_listed( $check_array ) )
            return null;

        if( isset($this->cloud_inline_analysis_enabled) && $this->cloud_inline_analysis_enabled )
        {
            if( isset($this->additional['mica-engine-vulnerability-enabled']) )
            {
                foreach( $this->additional['mica-engine-vulnerability-enabled'] as $name)
                {
                    if( isset($check_array['inline-policy-action'] ) )
                    {
                        foreach ($check_array['inline-policy-action'] as $validate) {
                            if (isset($validate['type']) && $validate['type'][0] == 'any' && !empty($validate['action'])) {
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

            if( isset($this->additional['mica-engine-spyware-enabled']) )
            {
                foreach( $this->additional['mica-engine-spyware-enabled'] as $name)
                {
                    if( isset($check_array['inline-policy-action'] ) )
                    {
                        foreach ($check_array['inline-policy-action'] as $validate) {
                            if (isset($validate['type']) && $validate['type'][0] == 'any' && !empty($validate['action'])) {
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

            // AS detectors: local-deep-learning as the BP JSON lists it (from PAN-OS 11.2)
            if( isset($this->additional['mica-engine-spyware-enabled']) && $this->inlineML_localDeepLearningComplies( 'visibility' ) === FALSE )
                return FALSE;

            // virus-and-wildfire-analysis: its WildFire part only where the PAN-OS version has it
            if( isset($this->additional['mica-engine-wildfire-rules']) && $this->bpFeatureSupported( 'wildfire-mica' ) )
            {
                foreach( $this->additional['mica-engine-wildfire-rules'] as $name)
                {
                    if( isset($check_array['inline-policy-action'] ) )
                    {
                        $bp_set = FALSE;
                        $bp_application_set = FALSE;
                        $bp_direction_set = FALSE;

                        foreach ($check_array['inline-policy-action'] as $validate)
                        {
                            if (isset($validate['type']) && $validate['type'][0] == 'any' && !empty($validate['action']))
                            {
                                $bp_set = $this->visibility_stringValidation($name, 'action', $validate['action'][0]);

                                if( isset($validate['direction']) )
                                    $bp_direction_set = $this->visibility_stringValidation($name, 'direction', $validate['direction'][0]);

                                $bp_application_set = FALSE;
                                if( isset($validate['application']) && $validate['application'][0] == 'any' )
                                    $bp_application_set = TRUE;

                                if (!$bp_set || !$bp_direction_set || !$bp_application_set)
                                    return FALSE;
                            }
                            else
                            {
                                //todo: speciall now for LDL
                                #print_r($validate);
                            }
                        }

                        if (!$bp_set || !$bp_direction_set || !$bp_application_set)
                            return FALSE;
                    }
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
                        if (isset($validate['type']) && $validate['type'][0] == 'any' && !empty($validate['action'])) {
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

        return $bp_set;
    }



    public function mica_getFullTextHTML(&$string_mica_engine, $bestPractice = false, $visibility = false, $bp_NOT_sign = "", $visible_NOT_sign = "")
    {
        // the PAN-OS version has no inline ML for this type: list the settings, but mark nothing as not BP / not visible
        $feature = self::cloud_inline_feature( $this->secprof_type ?? null );
        if( $feature !== null && !$this->bpFeatureSupported( $feature ) )
        {
            $bestPractice = false;
            $visibility = false;
        }

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
                    // not listed in the JSON (null): no sign
                    if( $bestPractice && $this->cloud_inline_analysis_best_practice() === FALSE )
                        $enabled .= $bp_NOT_sign;
                    if( $visibility && $this->cloud_inline_analysis_visibility() === FALSE )
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

                // local-deep-learning: shown with the settings; not BP / not visible as the BP JSON lists it (from PAN-OS 11.2)
                if( isset($this->additional['mica-engine-spyware-enabled'][$type]['local-deep-learning']) )
                {
                    $ldl_string = " - local-deep-learning :".$this->additional['mica-engine-spyware-enabled'][$type]['local-deep-learning'];
                    $ldl_signs = "";
                    if( $bestPractice && $this->inlineML_localDeepLearningDetectorComplies( 'bp', $type ) === FALSE )
                        $ldl_signs .= $bp_NOT_sign;
                    if( $visibility && $this->inlineML_localDeepLearningDetectorComplies( 'visibility', $type ) === FALSE )
                        $ldl_signs .= $visible_NOT_sign;

                    if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                        $tmp_string .= $ldl_string.$ldl_signs;
                    elseif( $ldl_signs !== "" || ( ( $bestPractice || $visibility ) && ( $this->inlineML_localDeepLearningDetectorComplies( 'bp', $type ) === FALSE || $this->inlineML_localDeepLearningDetectorComplies( 'visibility', $type ) === FALSE ) ) )
                    {
                        // list mode without signs: the detector is listed because its local-deep-learning does not comply
                        $tmp_string .= $ldl_string;
                        $add_to_array = true;
                    }
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
                    // not listed in the JSON (null): no sign
                    if( $bestPractice && $this->cloud_inline_analysis_best_practice() === FALSE )
                        $enabled .= $bp_NOT_sign;
                    if( $visibility && $this->cloud_inline_analysis_visibility() === FALSE )
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
                    // not listed in the JSON (null): no sign
                    if( $bestPractice && $this->cloud_inline_analysis_best_practice() === FALSE )
                        $enabled .= $bp_NOT_sign;
                    if( $visibility && $this->cloud_inline_analysis_visibility() === FALSE )
                        $enabled .= $visible_NOT_sign;
                }
                else
                    $add_to_array = true;
            }

            if( $add_to_array )
                $string_mica_engine[] = "mica-engine-wildfire-rules: " . $enabled;


            foreach( $this->additional['mica-engine-wildfire-rules'] as $type => $rule )
            {

                $tmp_string = "'".$type."' | - application:'".implode(",", $rule['application'])."' - fileType:'".implode(",", $rule['file-type'])."' - direction:'".$rule['direction']."'  - action:'".$rule['action']."'";;

                if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                    $add_to_array = true;
                else
                    $add_to_array = false;


                if( $bestPractice )
                {
                    if( isset(PH::$shadow_bp_jsonfile['wildfire']['cloud-inline']['bp']) )
                    {
                        $check_array = PH::$shadow_bp_jsonfile['wildfire']['cloud-inline']['bp'];
                        if( isset($check_array['inline-policy-action']) )
                        {
                            $bp_set = TRUE;
                            foreach( $check_array['inline-policy-action'] as $detailed_check )
                            {
                                if ($detailed_check['type'][0] == "any")
                                {
                                    if ($detailed_check['action'][0] !== $this->additional['mica-engine-wildfire-rules'][$type]['action'])
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
                    if( isset(PH::$shadow_bp_jsonfile['wildfire']['cloud-inline']['visibility']) )
                    {
                        $check_array = PH::$shadow_bp_jsonfile['wildfire']['cloud-inline']['visibility'];
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
                                    if ($validate === $negate_string . $this->additional['mica-engine-wildfire-rules'][$type]['action'])
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
                        if( $bestPractice && $rule->spyware_lists_bestpractice() === FALSE )
                        {
                            if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                                $string .= $bp_NOT_sign;
                            else
                            {
                                $add_to_array = true;
                            }
                        }
                        if( $visibility && $rule->spyware_lists_visibility() === FALSE )
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
                        if( $bestPractice && $rule->spyware_dns_security_rule_bestpractice() === FALSE )
                        {
                            if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                                $string .= $bp_NOT_sign;
                            else
                            {
                                $add_to_array = true;
                            }
                        }

                        if( $visibility && $rule->spyware_dns_security_rule_visibility() === FALSE )
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
                        if( $bestPractice && $rule->spyware_advanced_dns_security_rule_bestpractice() === FALSE )
                        {
                            if( !empty($bp_NOT_sign) && !empty($visible_NOT_sign) )
                                $string .= $bp_NOT_sign;
                            else
                            {
                                $add_to_array = true;
                            }
                        }

                        if( $visibility && $rule->spyware_advanced_dns_security_rule_visibility() === FALSE )
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

            $tmp_check = $this->url_usercredentialsubmission_visibility_tab();
            if( $tmp_check === null )
                $tmp_array[] = "[N/A]";
            elseif( $tmp_check )
                $tmp_array[] = $bp_text_yes;
            else
                $tmp_array[] = $bp_text_no;
        }

        if ($bestPractice)
        {
            $tmp_array[] = "mode: ".$this->credential_mode;
            $tmp_array[] = "log-severity: ".$this->credential_log;
            $tmp_array[] = "----";

            $tmp_check = $this->url_usercredentialsubmission_best_practice_tab();
            if( $tmp_check === null )
                $tmp_array[] = "[N/A]";
            elseif( $tmp_check )
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


    /**
     * cloud-inline -> bp|visibility -> inline-policy-action: only entries with type 'any' and an action are checked.
     * None of them: the BP JSON asks for nothing (key missing, empty list, ...) -> N/A
     */
    /**
     * Set-actions (alert-only-set: $section 'visibility', best-practice-set: $section 'bp'): the value to write into
     * one field so that it complies with the BP JSON condition $validate, as the checks read it
     * (visibility_stringValidation() / bp_stringValidation()).
     *  - the current value complies: null (no change)
     *  - positive condition ('reset-both', 'yes'): that value
     *  - negated condition ('!allow'): $fallback, which must comply itself (else a warning and null)
     * @return string|null
     */
    public function bpTargetValue( string $section, $current, string $validate, string $fallback ): ?string
    {
        $complies = function( $value ) use ( $section, $validate )
        {
            $tmp = array( 'v' => (string)$value );
            return $section == 'bp' ? $this->bp_stringValidation( $tmp, 'v', $validate ) : $this->visibility_stringValidation( $tmp, 'v', $validate );
        };

        if( $current !== null && $current !== '' && $complies( $current ) )
            return null;

        if( strpos( $validate, '!' ) !== 0 )
            return $validate;

        if( !$complies( $fallback ) )
        {
            mwarning( "BP JSON ".$section." '".$validate."': the value '".$fallback."' the action would set does not comply - '".$this->name()."' not changed", null, FALSE );
            return null;
        }
        return $fallback;
    }

    /**
     * the action of the BP JSON cloud-inline -> $section -> inline-policy-action entry with type 'any' (the entry the
     * checks use) for profile type $jsonType (virus, spyware, vulnerability, wildfire);
     * null: nothing listed, or the PAN-OS version has no inline ML for the type - the set-action changes nothing
     */
    public function inlineML_jsonAction( string $section, string $jsonType ): ?string
    {
        $feature = self::cloud_inline_feature( $jsonType );
        if( $feature !== null && !$this->bpFeatureSupported( $feature ) )
            return null;

        $check_array = $this->bp_visibility_JSON( $section, $jsonType );
        if( !self::cloud_inline_listed( $check_array ) )
            return null;

        foreach( $check_array['inline-policy-action'] as $validate )
            if( isset( $validate['type'][0] ) && $validate['type'][0] == 'any' && !empty( $validate['action'] ) )
                return is_array( $validate['action'] ) ? (string)$validate['action'][0] : (string)$validate['action'];

        return null;
    }

    /**
     * Set-actions for the inline-ML models / detectors of AV, AS, VP: field $field of every entry of $container
     * gets the value the BP JSON asks for (inlineML_jsonAction(), bpTargetValue()).
     * $forceFallback: every entry that is not $fallback gets $fallback (alert-only-set while inline analysis is
     * still off: enabling it must not start blocking).
     * @return bool|null null: the BP JSON asks for nothing / PAN-OS version without inline ML; else TRUE: changed
     */
    public function inlineML_setEntriesFromJSON( string $section, string $jsonType, string $container, string $field, string $fallback, bool $forceFallback = false ): ?bool
    {
        $validate = $this->inlineML_jsonAction( $section, $jsonType );
        if( $validate === null )
            return null;

        $node = DH::findFirstElement( $container, $this->xmlroot );
        if( $node === FALSE )
            return FALSE;

        $changed = FALSE;
        foreach( $node->childNodes as $entry )
        {
            if( $entry->nodeType != XML_ELEMENT_NODE )
                continue;

            $name = DH::findAttribute( "name", $entry );
            $fieldNode = DH::findFirstElementOrCreate( $field, $entry );

            if( $forceFallback )
                $target = ( $fieldNode->textContent === $fallback ) ? null : $fallback;
            else
                $target = $this->bpTargetValue( $section, $fieldNode->textContent, $validate, $fallback );

            if( $target === null )
                continue;

            $fieldNode->textContent = $target;
            $this->additional[$container][$name][$field] = $target;
            $changed = TRUE;
        }

        return $changed;
    }

    /** the value a new inline-ML entry gets from the BP JSON condition: a positive value as it is, a negated one: $fallback */
    public static function inlineML_newValue( string $validate, string $fallback ): string
    {
        return strpos( $validate, '!' ) === 0 ? $fallback : $validate;
    }

    /**
     * after a set-action: the check of the BP JSON section must now pass; a warning when it does not
     * (the action and the check disagree - e.g. a condition the action cannot fulfil)
     */
    public function bpSetVerify( string $section, string $what, $checkResult ): void
    {
        if( $checkResult === FALSE )
            mwarning( "'".$this->name()."' ".$what.": after the set-action the ".( $section == 'bp' ? 'best-practice' : 'visibility' )." check still fails", null, FALSE );
    }

    /** a value against one BP JSON condition: 'enable' -> equal, '!disable' -> not equal */
    public static function bpValueComplies( $value, string $validate ): bool
    {
        if( strpos( $validate, '!' ) === 0 )
            return (string)$value !== substr( $validate, 1 );
        return (string)$value === $validate;
    }

    /**
     * AS inline cloud analysis: the BP JSON spyware -> cloud-inline -> bp|visibility -> inline-policy-action entries
     * with 'local-deep-learning'; each as array( 'types' => detector names or 'any', 'validate' => 'enable' / '!disable' )
     */
    public static function inlineML_localDeepLearningEntries( $check_array ): array
    {
        $ret = array();
        if( !isset( $check_array['inline-policy-action'] ) || !is_array( $check_array['inline-policy-action'] ) )
            return $ret;
        foreach( $check_array['inline-policy-action'] as $entry )
        {
            if( empty( $entry['local-deep-learning'] ) || empty( $entry['type'] ) )
                continue;
            $validate = is_array( $entry['local-deep-learning'] ) ? (string)$entry['local-deep-learning'][0] : (string)$entry['local-deep-learning'];
            $types = is_array( $entry['type'] ) ? $entry['type'] : array( $entry['type'] );
            $ret[] = array( 'types' => $types, 'validate' => $validate );
        }
        return $ret;
    }

    /**
     * local-deep-learning of one AS detector against the BP JSON ($section 'bp' / 'visibility').
     * null: the BP JSON lists nothing for this detector, or the PAN-OS version has no local deep learning
     * @return bool|null
     */
    public function inlineML_localDeepLearningDetectorComplies( string $section, string $detector ): ?bool
    {
        if( !$this->bpFeatureSupported( 'spyware-local-deep-learning' ) )
            return null;
        $ret = null;
        foreach( self::inlineML_localDeepLearningEntries( $this->bp_visibility_JSON( $section, 'spyware' ) ) as $entry )
        {
            if( !in_array( 'any', $entry['types'], TRUE ) && !in_array( $detector, $entry['types'], TRUE ) )
                continue;
            $value = $this->additional['mica-engine-spyware-enabled'][$detector]['local-deep-learning'] ?? '';
            if( !self::bpValueComplies( $value, $entry['validate'] ) )
                return FALSE;
            $ret = TRUE;
        }
        return $ret;
    }

    /**
     * local-deep-learning of all AS detectors (inlineML_localDeepLearningDetectorComplies()):
     * FALSE: one listed detector does not comply; TRUE: all listed comply; null: nothing listed / not supported
     */
    public function inlineML_localDeepLearningComplies( string $section ): ?bool
    {
        $ret = null;
        foreach( array_keys( $this->additional['mica-engine-spyware-enabled'] ?? array() ) as $detector )
        {
            $tmp = $this->inlineML_localDeepLearningDetectorComplies( $section, $detector );
            if( $tmp === FALSE )
                return FALSE;
            if( $tmp === TRUE )
                $ret = TRUE;
        }
        return $ret;
    }

    /**
     * Set-actions: local-deep-learning of every AS detector the BP JSON lists gets the value asked for
     * (positive: that value; '!disable': 'enable', '!enable': 'disable'). Nothing listed / PAN-OS without local deep
     * learning: no change. @return bool TRUE: changed
     */
    public function inlineML_localDeepLearningSetFromJSON( string $section ): bool
    {
        if( !$this->bpFeatureSupported( 'spyware-local-deep-learning' ) )
            return FALSE;
        $container = DH::findFirstElement( 'mica-engine-spyware-enabled', $this->xmlroot );
        if( $container === FALSE )
            return FALSE;

        $entries = self::inlineML_localDeepLearningEntries( $this->bp_visibility_JSON( $section, 'spyware' ) );
        $changed = FALSE;
        foreach( $container->childNodes as $detectorNode )
        {
            if( $detectorNode->nodeType != XML_ELEMENT_NODE )
                continue;
            $detector = DH::findAttribute( "name", $detectorNode );
            foreach( $entries as $entry )
            {
                if( !in_array( 'any', $entry['types'], TRUE ) && !in_array( $detector, $entry['types'], TRUE ) )
                    continue;
                $node = DH::findFirstElementOrCreate( 'local-deep-learning', $detectorNode );
                if( self::bpValueComplies( $node->textContent, $entry['validate'] ) )
                    continue;
                $target = $entry['validate'];
                if( strpos( $target, '!' ) === 0 )
                    $target = ( substr( $target, 1 ) == 'disable' ) ? 'enable' : 'disable';
                $node->textContent = $target;
                $this->additional['mica-engine-spyware-enabled'][$detector]['local-deep-learning'] = $target;
                $changed = TRUE;
            }
        }
        return $changed;
    }

    /** threat rule (AS / VP): set the action element and the object */
    public function threatRule_setAction( $rule, string $action ): void
    {
        $rule->action = $action;
        $tmp = DH::findFirstElementOrCreate( "action", $rule->xmlroot );
        while( ( $child = DH::firstChildElement( $tmp ) ) !== FALSE && $child !== null )
            $tmp->removeChild( $child );
        $tmp->appendChild( DH::importXmlStringOrDie( $rule->xmlroot->ownerDocument, '<'.$action.'/>' ) );
    }

    /** threat rule (AS / VP): set packet-capture */
    public function threatRule_setPacketCapture( $rule, string $packetCapture ): void
    {
        $tmp = DH::findFirstElementOrCreate( "packet-capture", $rule->xmlroot );
        $tmp->textContent = $packetCapture;
        $rule->packetCapture = $packetCapture;
    }

    /**
     * threat rule (AS / VP): a new rule with threat-name any, the given severities, category and host;
     * appended, or inserted directly before $beforeRule (PAN-OS first match: it then decides for these severities)
     */
    public function threatRule_new( string $ruleClass, array $severities, string $action, ?string $packetCapture, string $category = 'any', string $host = 'any', $beforeRule = null )
    {
        $ruleName = ThreatPolicy::uniqueRuleName( $this->xmlroot, implode( "-", $severities ) . ( $host !== 'any' ? "_".$host : "" ) );
        $rule = new $ruleClass( $ruleName, $this );
        $rule->type = $ruleClass;
        $rule->action = $action;
        if( $host !== 'any' || $ruleClass == 'ThreatPolicyVulnerability' )
            $rule->host = $host;

        $entry = $rule->newThreatPolicyXML( $this->xmlroot, $ruleName, $severities[0], $action, $host );
        $rule->xmlroot = $entry;

        $severityNode = DH::findFirstElementOrCreate( 'severity', $entry );
        foreach( array_slice( $severities, 1 ) as $severity )
        {
            $member = $entry->ownerDocument->createElement( 'member' );
            $member->textContent = $severity;
            $severityNode->appendChild( $member );
            $rule->severity[] = $severity;
        }
        if( $category !== 'any' )
        {
            DH::findFirstElementOrCreate( 'category', $entry )->textContent = $category;
            $rule->category = $category;
        }
        if( $packetCapture !== null )
            $this->threatRule_setPacketCapture( $rule, $packetCapture );

        // position: in the XML and in rules_obj (first match reads both in this order)
        $position = count( $this->rules_obj );
        if( $beforeRule !== null )
        {
            $entry->parentNode->insertBefore( $entry, $beforeRule->xmlroot );
            $index = array_search( $beforeRule, array_values( $this->rules_obj ), TRUE );
            if( $index !== FALSE )
                $position = $index;
        }
        $rules = array_values( $this->rules_obj );
        array_splice( $rules, $position, 0, array( $rule ) );
        $this->rules_obj = $rules;

        $rule->addReference( $this );
        $this->owner->owner->ThreatPolicyStore->add( $rule );

        return $rule;
    }

    /**
     * Set-actions for the threat rules of AS / VP (alert-only-set: $section 'visibility', best-practice-set: 'bp'),
     * the reverse of the rules check (spyware_rules_check() / vulnerability_rules_check()): PAN-OS reads the rules
     * top-down, the first rule matching a threat's severity, host and category decides. For every severity the BP
     * JSON <jsonType> -> rule -> $section lists, every host and every category, the first matching rule must pass:
     *  - no rule matches: a new rule is appended (severity, host any, category any)
     *  - the rule fails and applies only to listed severities: its action / packet-capture is set
     *  - the rule fails and applies to other severities as well (e.g. 'any'): a new rule for the listed severities
     *    is inserted directly before it, so the other severities keep their action
     * Action / packet-capture: a listed value is kept, else the first listed one ('block-ip' only when it is the only
     * one, it needs more settings); visibility '!allow': 'alert' ('default' for a new low / informational rule).
     * Nothing listed in the BP JSON: no change.
     * @param callable $firstMatch function( $severity, $host, $category ): ?ThreatPolicy
     * @param callable $check      function(): ?bool, the profile's rules check of $section
     * @return bool TRUE: changed
     */
    public function threatRules_setFromJSON( string $section, string $jsonType, string $ruleClass, array $hosts, callable $firstMatch, callable $check ): bool
    {
        $check_array = PH::getBPjsonFile()[$jsonType]['rule'][$section] ?? array();
        $severities = ThreatPolicy::checkedSeverities( $check_array );
        if( count( $severities ) == 0 )
            return FALSE;

        $all = array( "critical", "high", "medium", "low", "informational" );
        $anyMode = in_array( 'any', $severities, TRUE );
        $listed = $anyMode ? $all : $severities;
        $exclude = ( $section == 'bp' ) ? ( $check_array['category-exclude'] ?? array() ) : array();
        $actions = (array)( $check_array['action'] ?? array() );
        $captures = ( $section == 'bp' ) ? (array)( $check_array['packet-capture'] ?? array() ) : array();

        $passes = function( $rule, $severity ) use ( $section, $check_array )
        {
            $check = $check_array;
            $check['severity'] = array( $severity );
            $ret = ( $section == 'bp' ) ? $rule->check_bp_json( $check ) : $rule->check_visibility_json( $check );
            return $ret !== FALSE;
        };
        // the action a rule must get for $severity; null: the current one complies / nothing listed
        $targetAction = function( $current, $severity, $isNew ) use ( $section, $actions )
        {
            if( empty( $actions ) )
                return $isNew ? ( in_array( $severity, array( "low", "informational" ) ) ? "default" : "alert" ) : null;
            if( $section == 'bp' )
            {
                if( !$isNew && in_array( $current, $actions, TRUE ) )
                    return null;
                foreach( $actions as $action )
                    if( $action !== 'block-ip' )
                        return $action;
                mwarning( "BP JSON rule -> bp -> action lists only 'block-ip', which needs more settings - '".$this->name()."' not changed", null, FALSE );
                return null;
            }
            // visibility: '!x' entries; a positive entry is not a value the action can set
            $negated = array();
            foreach( $actions as $action )
            {
                if( strpos( $action, '!' ) !== 0 )
                {
                    mwarning( "BP JSON rule -> visibility -> action '".$action."' is not a negated condition - '".$this->name()."' not changed", null, FALSE );
                    return null;
                }
                $negated[] = substr( $action, 1 );
            }
            if( !$isNew && !in_array( $current, $negated, TRUE ) )
                return null;
            $fallback = ( $isNew && in_array( $severity, array( "low", "informational" ) ) ) ? "default" : "alert";
            return in_array( $fallback, $negated, TRUE ) ? null : $fallback;
        };
        $targetCapture = function( $current, $isNew ) use ( $captures )
        {
            if( empty( $captures ) || ( !$isNew && in_array( $current, $captures, TRUE ) ) )
                return null;
            return $captures[0];
        };

        $changed = FALSE;
        for( $step = 0; $step < 100 && $check() === FALSE; $step++ )
        {
            $fixed = FALSE;
            foreach( $listed as $severity )
            {
                $categories = $anyMode ? array( ThreatPolicy::OTHER_CATEGORY ) : ThreatPolicy::categoriesOf( $this->rules_obj );
                foreach( $hosts as $host )
                {
                    foreach( $categories as $category )
                    {
                        if( in_array( $category, $exclude, TRUE ) )
                            continue;
                        $rule = $firstMatch( $severity, $host, $category );
                        if( $rule !== null && $passes( $rule, $severity ) && ( !$anyMode || ( $rule->category() ?? 'any' ) === 'any' ) )
                            continue;

                        if( $rule === null )
                        {
                            $action = $targetAction( null, $severity, TRUE );
                            if( $action === null )
                                return $changed;
                            $this->threatRule_new( $ruleClass, array( $severity ), $action, $targetCapture( null, TRUE ) );
                        }
                        else
                        {
                            $covered = ( empty( $rule->severity() ) || in_array( 'any', $rule->severity(), TRUE ) ) ? $all : array_values( $rule->severity() );
                            $action = $targetAction( $rule->action(), $severity, FALSE );
                            $capture = $targetCapture( $rule->packetCapture(), FALSE );
                            if( $action === null && $capture === null )
                                return $changed;     // fails for another reason this action cannot fix
                            if( count( array_diff( $covered, $listed ) ) == 0 )
                            {
                                if( $action !== null )
                                    $this->threatRule_setAction( $rule, $action );
                                if( $capture !== null )
                                    $this->threatRule_setPacketCapture( $rule, $capture );
                            }
                            else
                            {
                                $newAction = $targetAction( null, $severity, TRUE );
                                if( $newAction === null )
                                    return $changed;
                                $this->threatRule_new( $ruleClass, array_values( array_intersect( $covered, $listed ) ), $newAction, $targetCapture( null, TRUE ),
                                    $rule->category() ?? 'any', $rule->host ?? 'any', $rule );
                            }
                        }
                        $changed = TRUE;
                        $fixed = TRUE;
                        break 3;    // the rules changed: start again
                    }
                }
            }
            if( !$fixed )
                break;
        }

        $this->bpSetVerify( $section, ucfirst( $jsonType )." rules", $check() );
        return $changed;
    }

    /**
     * the value to set from a BP JSON value list, as the DNS / list checks read it: positive values ('sinkhole',
     * 'single-packet'): the current one is kept when listed, else the first; negated ones only ('!none', '!allow'):
     * the current one is kept when not excluded, else $fallback (null when $fallback is excluded as well)
     * @return string|null null: no change
     */
    public static function bpListTarget( $list, $current, string $fallback ): ?string
    {
        $list = (array)$list;
        $positive = array();
        $negated = array();
        foreach( $list as $value )
        {
            if( strpos( (string)$value, '!' ) === 0 )
                $negated[] = substr( $value, 1 );
            else
                $positive[] = (string)$value;
        }
        if( !empty( $positive ) )
            return in_array( (string)$current, $positive, TRUE ) ? null : $positive[0];
        if( empty( $negated ) || !in_array( (string)$current, $negated, TRUE ) )
            return null;
        return in_array( $fallback, $negated, TRUE ) ? null : $fallback;
    }

    /**
     * DNS security category / DNS list (DNSPolicy): set action, packet-capture or log-level in the XML and the object.
     * The action keeps its XML form: text (dns-security-categories) or an element (<action><sinkhole/></action>, lists).
     */
    public function dnsPolicy_setValue( $rule, string $field, string $value, bool $actionAsElement = false ): void
    {
        if( $field == 'action' )
        {
            $node = DH::findFirstElement( 'action', $rule->xmlroot );
            if( $node !== FALSE && $node !== null )
                $asElement = ( DH::firstChildElement( $node ) !== FALSE && DH::firstChildElement( $node ) !== null );
            else
            {
                $node = DH::findFirstElementOrCreate( 'action', $rule->xmlroot );
                $asElement = $actionAsElement;
            }
            if( $asElement )
            {
                while( ( $child = DH::firstChildElement( $node ) ) !== FALSE && $child !== null )
                    $node->removeChild( $child );
                $node->textContent = '';
                $node->appendChild( DH::importXmlStringOrDie( $rule->xmlroot->ownerDocument, '<'.$value.'/>' ) );
            }
            else
                $node->textContent = $value;
            $rule->action = $value;
        }
        elseif( $field == 'packet-capture' )
        {
            DH::findFirstElementOrCreate( 'packet-capture', $rule->xmlroot )->textContent = $value;
            $rule->packetCapture = $value;
        }
        elseif( $field == 'log-level' )
        {
            DH::findFirstElementOrCreate( 'log-level', $rule->xmlroot )->textContent = $value;
            $rule->logLevel = $value;
        }
    }

    /**
     * Set-actions for one DNS security category / DNS list (DNSPolicy) from its BP JSON entry (the first entry whose
     * 'type' names it, as the checks): action, packet-capture, log-level - each where the entry lists it.
     * @param array $fallbacks field => value for a negated condition ('!none' -> 'default')
     * @return bool TRUE: changed
     */
    public function dnsPolicy_setFromJSONEntries( $rule, $entries, array $fallbacks, bool $actionAsElement = false ): bool
    {
        $entry = null;
        foreach( (array)$entries as $candidate )
            if( in_array( $rule->name(), (array)( $candidate['type'] ?? array() ), TRUE ) )
            {
                $entry = $candidate;
                break;
            }
        if( $entry === null )
            return FALSE;

        $current = array( 'action' => $rule->action(), 'packet-capture' => $rule->packetCapture(), 'log-level' => $rule->logLevel() );
        $changed = FALSE;
        foreach( array( 'action', 'packet-capture', 'log-level' ) as $field )
        {
            if( !isset( $entry[$field] ) || ( $field == 'packet-capture' && !empty( $rule->advanced ) ) )
                continue;
            $target = self::bpListTarget( $entry[$field], $current[$field], $fallbacks[$field] ?? '' );
            if( $target === null || $target === '' )
                continue;
            $this->dnsPolicy_setValue( $rule, $field, $target, $actionAsElement );
            $changed = TRUE;
        }
        return $changed;
    }

    public static function cloud_inline_listed( $check_array ): bool
    {
        if( !isset( $check_array['inline-policy-action'] ) || !is_array( $check_array['inline-policy-action'] ) )
            return FALSE;
        foreach( $check_array['inline-policy-action'] as $validate )
            if( isset( $validate['type'][0] ) && $validate['type'][0] == 'any' && !empty( $validate['action'] ) )
                return TRUE;
        return FALSE;
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

