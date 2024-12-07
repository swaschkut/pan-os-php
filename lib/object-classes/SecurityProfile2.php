<?php

class SecurityProfile2
{
    public $bp_json_file = null;

    public function cloud_inline_analysis_best_practice( $bp_json_file )
    {
        $this->bp_json_file = $bp_json_file;

        $bp_set = FALSE;

        if( $this->secprof_type != 'spyware' and $this->secprof_type != 'vulnerability' and $this->secprof_type != 'virus' )
            return null;

        $check_array = $this->bp_visibility_JSON( "bp", $this->secprof_type);

        if( isset($this->cloud_inline_analysis_enabled) && $this->cloud_inline_analysis_enabled )
        {
            if( isset($this->additional['mica-engine-vulnerability-enabled']) )
            {
                foreach( $this->additional['mica-engine-vulnerability-enabled'] as $name)
                {
                    foreach( $check_array['inline-policy-action'] as $validate )
                    {
                        $bp_set = $this->bp_stringValidation($name, 'inline-policy-action', $validate);
                    }
                    if($bp_set == FALSE)
                        return false;
                }
            }

            if( isset($this->additional['mica-engine-spyware-enabled']) )
            {
                foreach( $this->additional['mica-engine-spyware-enabled'] as $name)
                {
                    foreach( $check_array['inline-policy-action'] as $validate )
                    {
                        $bp_set = $this->bp_stringValidation($name, 'inline-policy-action', $validate);
                    }
                    if($bp_set == FALSE)
                        return false;
                }
            }
        }

        //AV iii) Wildfire Inline ML Tab
        //- all models must be set to 'enable (inherit per-protocol actions)'
        if( isset($this->additional['mlav-engine-filebased-enabled']) )
        {
            foreach( $this->additional['mlav-engine-filebased-enabled'] as $name)
            {
                foreach( $check_array['inline-policy-action'] as $validate )
                {
                    $bp_set = $this->bp_stringValidation($name, 'mlav-policy-action', $validate);
                }
                if($bp_set == FALSE)
                    return false;
            }
        }

        return $bp_set;
    }

    public function cloud_inline_analysis_visibility( $bp_json_file )
    {
        $this->bp_json_file = $bp_json_file;

        $bp_set = FALSE;

        if( $this->secprof_type != 'spyware' and $this->secprof_type != 'vulnerability' and $this->secprof_type != 'virus' )
            return null;

        $check_array = $this->bp_visibility_JSON( "visibility", $this->secprof_type);

        if( isset($this->cloud_inline_analysis_enabled) && $this->cloud_inline_analysis_enabled )
        {
            if( isset($this->additional['mica-engine-vulnerability-enabled']) )
            {
                foreach( $this->additional['mica-engine-vulnerability-enabled'] as $name)
                {
                    foreach( $check_array['inline-policy-action'] as $validate )
                    {
                        $bp_set = $this->visibility_stringValidation($name, 'inline-policy-action', $validate);
                    }
                    if($bp_set == FALSE)
                        return FALSE;
                }
            }

            if( isset($this->additional['mica-engine-spyware-enabled']) )
            {
                foreach( $this->additional['mica-engine-spyware-enabled'] as $name)
                {
                    foreach( $check_array['inline-policy-action'] as $validate )
                    {
                        $bp_set = $this->visibility_stringValidation($name, 'inline-policy-action', $validate);
                    }
                    if($bp_set == FALSE)
                        return FALSE;
                }
            }
        }

        //AV iii) Wildfire Inline ML Tab
        //- all models must be set to 'enable (inherit per-protocol actions)'
        if( isset($this->additional['mlav-engine-filebased-enabled']) )
        {
            foreach( $this->additional['mlav-engine-filebased-enabled'] as $type => $name)
            {
                //$check_array is unique for all AV/AS/VP from JSON file
                foreach( $check_array['inline-policy-action'] as $validate )
                {
                    $bp_set = $this->visibility_stringValidation($name, 'mlav-policy-action', $validate);
                }
                if($bp_set == FALSE)
                    return false;
            }
        }

        return $bp_set;
    }


    private function visibility_stringValidation($array, $key, $validate)
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

    private function bp_stringValidation($array, $key, $validate)
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

    public function getBPjsonFile()
    {
        //Todo: this is duplicate code, also available in class SecurityProfileStore

        ###############################
        if( PH::$shadow_bp_jsonfile == null )
        {
            $filename = $this->bp_json_file;

            $JSONarray = file_get_contents( $filename);

            if( $JSONarray === false )
                derr("cannot open file '{$filename}");

            $details = json_decode($JSONarray, true);

            if( $details === null )
                derr( "invalid JSON file provided", null, FALSE );
        }
        else
            $details = PH::$shadow_bp_jsonfile;

        return $details;
    }

    public function bp_visibility_JSON( $checkType, $secprof_type )
    {
        $checkArray = array();

        if( $checkType !== "bp" && $checkType !== "visibility" )
            derr( "only 'bp' or 'visibility' argument allowed" );

        $details = $this->getBPjsonFile();

        $array_type = "cloud-inline";
        $check_action_type = "inline-policy-action";


        if( isset($details[$secprof_type][$array_type]) )
        {
            if( $checkType == "bp" )
            {
                if( isset($details[$secprof_type][$array_type]['bp'][$check_action_type]) )
                    $checkArray = $details[$secprof_type][$array_type]['bp'];
                else
                    derr( "this JSON bp/visibility JSON file does not have 'bp' -> '".$check_action_type."' defined correctly for: '".$secprof_type."'", null, FALSE );
            }
            elseif( $checkType == "visibility")
            {
                if( isset($details[$secprof_type][$array_type]['visibility'][$check_action_type]) )
                    $checkArray = $details[$secprof_type][$array_type]['visibility'];
                else
                    derr( "this JSON bp/visibility JSON file does not have 'visibility' -> '".$check_action_type."' defined correctly for: '".$secprof_type."'", null, FALSE );
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

}

