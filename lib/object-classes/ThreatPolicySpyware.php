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


class ThreatPolicySpyware extends ThreatPolicy
{
    public $checkArray;

    public function __construct($name, $owner)
    {
        parent::__construct($name, $owner);
    }


    public function spyware_rule_bp_visibility_JSON( $checkType )
    {
        //Todo: swaschkut 20241126
        //if file already read store it complete at UTIL and read array from there

        $secprof_type = "spyware";
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

        if( isset($details[$secprof_type]['rule']) )
        {
            if( $checkType == "bp" )
            {
                if( isset($details[$secprof_type]['rule']['bp']))
                    $checkArray = $details[$secprof_type]['rule']['bp'];
                else
                    derr( "this JSON bp/visibility JSON file does not have 'bp' -> 'rule' defined correctly for: '".$secprof_type."'", null, FALSE );
            }
            elseif( $checkType == "visibility")
            {
                if( isset($details[$secprof_type]['rule']['visibility']))
                    $checkArray = $details[$secprof_type]['rule']['visibility'];
                else
                    derr( "this JSON bp/visibility JSON file does not have 'visibility' -> 'rule' defined correctly for: '".$secprof_type."'", null, FALSE );
            }
        }

        return $checkArray;
    }

    public function check_bp_json( $check_array )
    {
        foreach( $check_array['severity'] as $severity_check )
        {
            if( in_array( $severity_check, $this->severity ) )
            {
                $action_bp = FALSE;
                foreach( $check_array['action'] as $action_check)
                {
                    if( $this->action() == $action_check )
                    {
                        $action_bp = TRUE;
                        break;
                    }
                    else
                        $action_bp = FALSE;
                }
                if( $action_bp == FALSE )
                    return FALSE;

                $packet_bp = FALSE;
                foreach( $check_array['packet-capture'] as $packet_check )
                {
                    if( $this->packetCapture() == $packet_check )
                    {
                        $packet_bp = TRUE;
                        break;
                    }
                    else
                        $packet_bp = FALSE;
                }
                if( $packet_bp == FALSE )
                    return FALSE;

                if( $action_check && $packet_bp )
                    return true;
            }
        }

        return TRUE;
    }

    public function check_visibility_json( $check_array )
    {
        foreach( $check_array['severity'] as $severity_check )
        {
            if( in_array( $severity_check, $this->severity ) )
            {
                $action_bp = FALSE;
                foreach( $check_array['action'] as $action_check)
                {
                    $negate_string = "";
                    if( strpos( $action_check, "!" ) !== FALSE )
                        $negate_string = "!";
                    if( $negate_string.$this->action() == $action_check )
                    {
                        $action_bp = FALSE;
                        break;
                    }
                    else
                        $action_bp = TRUE;
                }
                if( $action_bp == FALSE )
                    return FALSE;
                else
                    return TRUE;
            }
        }

        return TRUE;
    }

    public function spyware_rule_best_practice()
    {
        $check_array = $this->spyware_rule_bp_visibility_JSON( "bp" );
        $bestpractise = $this->check_bp_json( $check_array );

        if ($bestpractise == FALSE)
            return FALSE;
        else
            return TRUE;
    }

    public function spyware_rule_visibility()
    {
        $check_array = $this->spyware_rule_bp_visibility_JSON( "visibility" );
        $bestpractise = $this->check_visibility_json( $check_array );

        if ($bestpractise == FALSE)
            return FALSE;
        else
            return TRUE;
    }

    public function spywarepolicy_load_from_domxml( $threatx )
    {
        $this->type = "ThreatPolicySpyware";
        $this->load_from_domxml( $threatx );
    }
}
