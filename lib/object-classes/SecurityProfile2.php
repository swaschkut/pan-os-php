<?php

class SecurityProfile2
{

    public function cloud_inline_analysis_define_bp_visibility()
    {
        $this->checkArray['virus'] = array();
        $this->checkArray['virus']['cloud-inline']['bp']['inline-policy-action'] = array('enable');
        $this->checkArray['spyware']['cloud-inline']['bp']['inline-policy-action'] = array('reset-both');
        $this->checkArray['vulnerability']['cloud-inline']['bp']['inline-policy-action'] = array('reset-both');

        $this->checkArray['virus']['cloud-inline']['visibility']['inline-policy-action'] = array('!disable');
        $this->checkArray['spyware']['cloud-inline']['visibility']['inline-policy-action'] = array('!allow');
        $this->checkArray['vulnerability']['cloud-inline']['visibility']['inline-policy-action'] = array('!allow');
    }

    public function cloud_inline_analysis_best_practice()
    {
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
                        if( $name['inline-policy-action'] == $validate )
                            $bp_set = TRUE;
                        else
                            $bp_set = FALSE;
                    }
                    if($bp_set == FALSE)
                        return false;
                    /*
                     if( $name['inline-policy-action'] == "reset-both" )
                            $bp_set = TRUE;
                       else
                           return FALSE;
                     */
                }
            }

            if( isset($this->additional['mica-engine-spyware-enabled']) )
            {
                foreach( $this->additional['mica-engine-spyware-enabled'] as $name)
                {
                    foreach( $check_array['inline-policy-action'] as $validate )
                    {
                        if( $name['inline-policy-action'] == $validate )
                            $bp_set = TRUE;
                        else
                            $bp_set = FALSE;
                    }
                    if($bp_set == FALSE)
                        return false;
                    /*
                    if( $name['inline-policy-action'] == "reset-both" )
                        $bp_set = TRUE;
                    else
                        return FALSE;
                    */
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
                    if( $name['mlav-policy-action'] == $validate )
                        $bp_set = TRUE;
                    else
                        $bp_set = FALSE;
                }
                if($bp_set == FALSE)
                    return false;
                /*
                if( $name['mlav-policy-action'] == "enable" )
                    $bp_set = TRUE;
                else
                    return FALSE;
                */
            }
        }

        return $bp_set;
    }

    public function cloud_inline_analysis_visibility()
    {
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
                        if( "!".$name['inline-policy-action'] == $validate )
                            $bp_set = FALSE;
                        else
                            $bp_set = TRUE;
                    }
                    if($bp_set == FALSE)
                        return FALSE;
                    /*
                    if( $name['inline-policy-action'] == "allow" )
                        return FALSE;
                    else
                        $bp_set =  TRUE;
                    */
                }
            }

            if( isset($this->additional['mica-engine-spyware-enabled']) )
            {
                foreach( $this->additional['mica-engine-spyware-enabled'] as $name)
                {
                    foreach( $check_array['inline-policy-action'] as $validate )
                    {
                        if( "!".$name['inline-policy-action'] == $validate )
                            $bp_set = FALSE;
                        else
                            $bp_set = TRUE;
                    }
                    if($bp_set == FALSE)
                        return FALSE;
                    /*
                    if( $name['inline-policy-action'] == "allow" )
                        return FALSE;
                    else
                        $bp_set =  TRUE;
                    */
                }
            }
        }

        //AV iii) Wildfire Inline ML Tab
        //- all models must be set to 'enable (inherit per-protocol actions)'
        if( isset($this->additional['mlav-engine-filebased-enabled']) )
        {
            foreach( $this->additional['mlav-engine-filebased-enabled'] as $type => $name)
            {
                foreach( $check_array['inline-policy-action'] as $validate )
                {
                    if( "!".$name['mlav-policy-action'] == $validate )
                        $bp_set = FALSE;
                    else
                        $bp_set = TRUE;
                }
                if($bp_set == FALSE)
                    return false;
                /*
                if( $name['mlav-policy-action'] == "disable" )
                    return FALSE;
                else
                    $bp_set =  TRUE;
                */
            }
        }

        return $bp_set;
    }

    public function bp_visibility_JSON( $checkType, $secprof_type )
    {
        $checkArray = array();

        if( $checkType !== "bp" && $checkType !== "visibility" )
            derr( "only 'bp' or 'visibility' argument allowed" );

        ###############################
        //add bp JSON filename to UTIL???
        //so this can be flexible if customer like to use its own file

        //get actual file space
        $filename = dirname(__FILE__)."/../../utils/api/v1/bp/bp_sp_panw.json";
        $JSONarray = file_get_contents( $filename);

        if( $JSONarray === false )
            derr("cannot open file '{$filename}");

        $details = json_decode($JSONarray, true);

        if( $details === null )
            derr( "invalid JSON file provided", null, FALSE );

        #print_r($details);

        if( isset($details[$secprof_type]['cloud-inline']) )
        {
            if( $checkType == "bp" )
            {
                if( isset($details[$secprof_type]['cloud-inline']['bp']['inline-policy-action']) )
                    #$checkArray = $details[$secprof_type]['cloud-inline']['bp']['inline-policy-action']."\n";
                    $checkArray = $details[$secprof_type]['cloud-inline']['bp'];
                else
                    derr( "this JSON bp/visibility JSON file does not have 'bp' -> 'inline-policy-action' defined correctly for: '".$secprof_type."'", null, FALSE );
            }
            elseif( $checkType == "visibility")
            {
                if( isset($details[$secprof_type]['cloud-inline']['visibility']['inline-policy-action']) )
                    #$checkArray[] = $details[$secprof_type]['cloud-inline']['visibility']['inline-policy-action']."\n";
                    $checkArray = $details[$secprof_type]['cloud-inline']['visibility'];
                else
                    derr( "this JSON bp/visibility JSON file does not have 'visibility' -> 'inline-policy-action' defined correctly for: '".$secprof_type."'", null, FALSE );
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

