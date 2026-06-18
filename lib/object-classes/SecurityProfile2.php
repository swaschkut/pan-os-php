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

            if( isset($this->additional['mica-engine-wildfire-rules']) )
            {
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

        return $bp_set;
    }




    public function build_cloud_inline_comprehensive_array_old( $bp_json_file = null )
    {
        $this->bp_json_file = $bp_json_file ?: PH::getBPjsonFile();

        $results = [
            'all'         => [],
            'visible'     => [],
            'not visible' => [],
            'bp'          => [],
            'not bp'      => []
        ];

        $supported_types = [
            'spyware', 'vulnerability', 'virus', 'wildfire',
            'dns-security', 'virus-and-wildfire-analysis'
        ];

        if ( !in_array($this->secprof_type, $supported_types) ) {
            return $results;
        }

        $check_array = $this->bp_visibility_JSON("visibility", $this->secprof_type);
        $cloud_enabled = isset($this->cloud_inline_analysis_enabled) && $this->cloud_inline_analysis_enabled;

        // Helper closure to extract the expected Best Practice target action string (e.g., "!allow")
        $get_bp_action = function($check_array, $action_key) {
            if (isset($check_array[$action_key])) {
                foreach ($check_array[$action_key] as $validate) {
                    if (isset($validate['type']) && $validate['type'][0] == 'any' && isset($validate['action'][0])) {
                        return $validate['action'][0];
                    }
                }
            }
            return null;
        };

        $engines = [
            'mica-engine-vulnerability-enabled' => ['label' => '', 'key' => 'inline-policy-action', 'check_cloud' => true],
            'mica-engine-spyware-enabled'       => ['label' => '', 'key' => 'inline-policy-action', 'check_cloud' => true],
            'mica-engine-wildfire-rules'        => ['label' => '', 'key' => 'action',               'check_cloud' => true],
            'mlav-engine-filebased-enabled'     => ['label' => '',  'key' => 'mlav-policy-action',   'check_cloud' => false]
        ];

        foreach ($engines as $config_key => $meta) {
            if ( isset($this->additional[$config_key]) ) {

                // EXPLICIT GUARD: Check if the entire engine is disabled at the parent level (e.g., [no])
                $engine_value = $this->additional[$config_key];
                $is_engine_disabled = ($engine_value === 'no' || $engine_value === false || empty($engine_value));

                // If the structure contains a sub-list even when disabled, or if we mock/track the definitions:
                // Ensure we handle arrays or lookups cleanly
                $items_to_loop = is_array($engine_value) ? $engine_value : [];

                // Fallback definitions if the engine is completely disabled string '[no]' but you still need to log its rules
                if ($is_engine_disabled) {
                    if ($config_key === 'mica-engine-spyware-enabled') {
                        $items_to_loop = [
                            'HTTP Command and Control detector' => 'alert',
                            'HTTP2 Command and Control detector' => 'alert',
                            'SSL Command and Control detector' => 'allow',
                            'Unknown-TCP Command and Control detector' => 'alert',
                            'Unknown-UDP Command and Control detector' => 'allow'
                        ];
                    } elseif ($config_key === 'mica-engine-vulnerability-enabled') {
                        $items_to_loop = [
                            'SQL Injection' => 'reset-both',
                            'Command Injection' => 'reset-both'
                        ];
                    }
                }

                $action_key = $meta['key'];
                $bp_action = $get_bp_action($check_array, 'inline-policy-action');

                foreach ( $items_to_loop as $key => $name ) {

                    // 1. EXTRACT REAL CONFIGURATION VALUE EXPLICITLY
                    $actual_action_value = null;
                    if (is_array($name)) {
                        if (isset($name[$action_key])) {
                            $actual_action_value = $name[$action_key];
                        }
                    } elseif (!$is_engine_disabled) {
                        // Raw string validation matching lookup if engine is alive
                        $possible_actions = ['enable(alert-only)', 'disable', 'enable', 'alert', 'allow', 'drop', 'reset-both', 'reset-client', 'reset-server', 'block'];
                        foreach ($possible_actions as $action_candidate) {
                            if ($this->visibility_stringValidation($name, $action_key, $action_candidate)) {
                                $actual_action_value = $action_candidate;
                                break;
                            }
                        }
                    } else {
                        // If parent engine is disabled, the value is explicitly what's defined in the array map
                        $actual_action_value = $name;
                    }

                    if ($actual_action_value === null) {
                        $actual_action_value = 'unknown';
                    }

                    // 2. BEST PRACTICE & VISIBILITY OVERRIDES BASED ON ENGINE STATUS
                    if ($is_engine_disabled) {
                        // If the parent engine is explicitly disabled, nothing under it is visible or a best practice!
                        $is_bp = false;
                        $is_visible = false;
                    } else {
                        // Normal native class validation checking loops
                        $is_bp = false;
                        if (!empty($bp_action)) {
                            $is_bp = (bool)$this->visibility_stringValidation($name, $action_key, $bp_action);
                        }

                        $is_disabled = (strtolower($actual_action_value) === 'disable');
                        if ($meta['check_cloud']) {
                            $is_visible = $cloud_enabled && !$is_disabled;
                        } else {
                            $is_visible = !$is_disabled;
                        }
                    }

                    // PHP 8 Safe display text label matching
                    if (is_array($name)) {
                        $displayName = isset($name['name']) ? $name['name'] : (!is_numeric($key) ? $key : 'Rule');
                    } else {
                        $displayName = is_numeric($key) ? $name : $key;
                    }

                    $log_string = "{$meta['label']} ($displayName) - {$action_key} : {$actual_action_value}";

                    // 3. ACCURATE DOCKING INTO THE BUCKETS
                    $results['all'][] = $log_string;

                    if ($is_visible) {
                        $results['visible'][] = $log_string;
                    } else {
                        $results['not visible'][] = $log_string;
                    }

                    if ($is_bp) {
                        $results['bp'][] = $log_string;
                    } else {
                        $results['not bp'][] = $log_string;
                    }
                }
            }
        }

        return $results;
    }

    public function build_cloud_inline_comprehensive_array( $bp_json_file = null )
    {
        $this->bp_json_file = $bp_json_file ?: PH::getBPjsonFile();

        $results = [
            'all'         => [],
            'visible'     => [],
            'not visible' => [],
            'bp'          => [],
            'not bp'      => []
        ];

        $supported_types = [
            'spyware', 'vulnerability', 'virus', 'wildfire',
            'dns-security', 'virus-and-wildfire-analysis'
        ];

        if ( !in_array($this->secprof_type, $supported_types) ) {
            return $results;
        }

        $check_array = $this->bp_visibility_JSON("visibility", $this->secprof_type);
        $cloud_enabled = isset($this->cloud_inline_analysis_enabled) && $this->cloud_inline_analysis_enabled;

        // Helper closure to extract the expected Best Practice target action string (e.g., "!allow")
        $get_bp_action = function($check_array, $action_key) {
            if (isset($check_array[$action_key])) {
                foreach ($check_array[$action_key] as $validate) {
                    if (isset($validate['type']) && $validate['type'][0] == 'any' && isset($validate['action'][0])) {
                        return $validate['action'][0];
                    }
                }
            }
            return null;
        };

        $engines = [
            'mica-engine-vulnerability-enabled' => ['label' => '', 'key' => 'inline-policy-action', 'check_cloud' => true],
            'mica-engine-spyware-enabled'       => ['label' => '', 'key' => 'inline-policy-action', 'check_cloud' => true],
            'mica-engine-wildfire-rules'        => ['label' => '', 'key' => 'action',               'check_cloud' => true],
            'mlav-engine-filebased-enabled'     => ['label' => '', 'key' => 'mlav-policy-action',   'check_cloud' => false]
        ];

        foreach ($engines as $config_key => $meta) {
            if ( isset($this->additional[$config_key]) ) {

                $engine_value = $this->additional[$config_key];
                $is_engine_disabled = ($engine_value === 'no' || $engine_value === false || empty($engine_value));

                $items_to_loop = is_array($engine_value) ? $engine_value : [];

                // Fallback definitions if the engine is completely disabled
                if ($is_engine_disabled) {
                    if ($config_key === 'mica-engine-spyware-enabled') {
                        $items_to_loop = [
                            'HTTP Command and Control detector' => 'alert',
                            'HTTP2 Command and Control detector' => 'alert',
                            'SSL Command and Control detector' => 'allow',
                            'Unknown-TCP Command and Control detector' => 'alert',
                            'Unknown-UDP Command and Control detector' => 'allow'
                        ];
                    } elseif ($config_key === 'mica-engine-vulnerability-enabled') {
                        $items_to_loop = [
                            'SQL Injection' => 'reset-both',
                            'Command Injection' => 'reset-both'
                        ];
                    }
                }

                $action_key = $meta['key'];
                // FIX 1: Use the dynamic engine action key instead of hardcoded 'inline-policy-action'
                $bp_action = $get_bp_action($check_array, $action_key);

                foreach ( $items_to_loop as $key => $name ) {

                    // 1. EXTRACT REAL CONFIGURATION VALUE EXPLICITLY
                    $actual_action_value = null;
                    if (is_array($name)) {
                        if (isset($name[$action_key])) {
                            $actual_action_value = $name[$action_key];
                        }
                    } elseif (!$is_engine_disabled) {
                        $possible_actions = ['enable(alert-only)', 'disable', 'enable', 'alert', 'allow', 'drop', 'reset-both', 'reset-client', 'reset-server', 'block'];
                        foreach ($possible_actions as $action_candidate) {
                            if ($this->visibility_stringValidation($name, $action_key, $action_candidate)) {
                                $actual_action_value = $action_candidate;
                                break;
                            }
                        }
                    } else {
                        $actual_action_value = $name;
                    }

                    if ($actual_action_value === null) {
                        $actual_action_value = 'unknown';
                    }

                    // 2. BEST PRACTICE & VISIBILITY CALCULATIONS
                    $is_bp = false;
                    if (!empty($bp_action)) {
                        // FIX 2: Explicitly handle logical negation "!allow" manually
                        if (strpos($bp_action, '!') === 0) {
                            $negated_value = substr($bp_action, 1); // extracts "allow"

                            // It is Best Practice if the actual action does NOT equal the negated value
                            $is_bp = ($actual_action_value !== $negated_value && $actual_action_value !== 'unknown');
                        } else {
                            // Fall back to your native helper validation for standard values
                            if (!$is_engine_disabled) {
                                $is_bp = (bool)$this->visibility_stringValidation($name, $action_key, $bp_action);
                            } else {
                                $is_bp = ($actual_action_value === $bp_action);
                            }
                        }
                    }

                    // FIX 3: Visibility is simple: if the parent engine is completely off, items are not visible.
                    if ($is_engine_disabled) {
                        $is_visible = false;
                    } else {
                        $is_disabled = (strtolower($actual_action_value) === 'disable');
                        if ($meta['check_cloud']) {
                            $is_visible = $cloud_enabled && !$is_disabled;
                        } else {
                            $is_visible = !$is_disabled;
                        }
                    }

                    // PHP 8 Safe display text label matching
                    if (is_array($name)) {
                        $displayName = isset($name['name']) ? $name['name'] : (!is_numeric($key) ? $key : 'Rule');
                    } else {
                        $displayName = is_numeric($key) ? $name : $key;
                    }

                    $log_string = "{$meta['label']}($displayName) - {$action_key} : {$actual_action_value}";

                    // 3. DOCKING INTO BUCKETS
                    $results['all'][] = $log_string;

                    if ($is_visible) {
                        $results['visible'][] = $log_string;
                    } else {
                        $results['not visible'][] = $log_string;
                    }

                    if ($is_bp) {
                        $results['bp'][] = $log_string;
                    } else {
                        $results['not bp'][] = $log_string;
                    }
                }
            }
        }

        return $results;
    }

    /**
     * Helper to validate an action against the BP JSON rules array
     */
    private function validateInlineAction($data, $action_key, $check_array)
    {
        if ( !isset($check_array['inline-policy-action']) ) {
            return false;
        }

        $has_validated = false;
        foreach ( $check_array['inline-policy-action'] as $validate ) {
            if ( isset($validate['type']) && $validate['type'][0] === 'any' ) {
                $has_validated = true;
                // Passes the underlying array structure down to your original string validator safely
                if ( !$this->visibility_stringValidation($data, $action_key, $validate['action'][0]) ) {
                    return false;
                }
            }
        }

        return $has_validated;
    }

    /**
     * Helper to format strings dynamically and sort them into target buckets
     */
    private function logResult(&$results, $base_string, $is_visible, $is_bp)
    {
        $formatted_string = $base_string;
        if (!$is_bp) {
            $formatted_string .= " | **NOT BP**";
        }
        if (!$is_visible) {
            $formatted_string .= " | **NOT VISIBLE**";
        }

        // Distribute items into their respective collection buckets
        $results['all'][] = $formatted_string;

        if ($is_visible) {
            $results['visible'][] = $formatted_string;
        } else {
            $results['not visible'][] = $formatted_string;
        }

        if ($is_bp) {
            $results['bp'][] = $formatted_string;
        } else {
            $results['not bp'][] = $formatted_string;
        }
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

