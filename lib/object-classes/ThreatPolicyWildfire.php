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


class ThreatPolicyWildfire extends ThreatPolicy
{
    public $checkArray;

    public function __construct($name, $owner)
    {
        parent::__construct($name, $owner);
    }


    public function wildfire_rule_bp_visibility_JSON( $checkType, $secprof_type )
    {
        $checkArray = array();

        if( $checkType !== "bp" && $checkType !== "visibility" )
            derr( "only 'bp' or 'visibility' argument allowed" );

        ###############################
        $details = PH::getBPjsonFile( );

        $array_type = "rule";

        if( isset($details[$secprof_type][$array_type]) )
        {
            if( $checkType == "bp" )
            {
                if( isset($details[$secprof_type][$array_type]['bp']))
                    $checkArray = $details[$secprof_type][$array_type]['bp'];
                else
                    derr( "this JSON bp/visibility JSON file does not have 'bp' -> '".$array_type."' defined correctly for: '".$secprof_type."'", null, FALSE );
            }
            elseif( $checkType == "visibility")
            {
                if( isset($details[$secprof_type][$array_type]['visibility']))
                    $checkArray = $details[$secprof_type][$array_type]['visibility'];
                else
                    derr( "this JSON bp/visibility JSON file does not have 'visibility' -> '".$array_type."' defined correctly for: '".$secprof_type."'", null, FALSE );
            }
        }

        return $checkArray;
    }

    public function check_bp_json( $check_array )
    {
        foreach( $check_array as $check )
        {
            foreach( $check as $validate => $values )
            {
                if( is_array( $values ) )
                {
                    //application
                    //filetype
                    foreach( $values as $value )
                    {
                        if( !in_array( $value, $this->$validate ) )
                            return false;
                    }
                }
                else
                {
                    //direction
                    //analysis
                    if( $this->$validate != $values )
                        return false;
                }
            }
        }

        return TRUE;
    }

    public function check_visibility_json( $check_array )
    {
        foreach( $check_array as $check )
        {
            foreach( $check as $validate => $values )
            {
                if( is_array( $values ) )
                {
                    //application
                    //filetype
                    foreach( $values as $value )
                    {
                        if( !in_array( $value, $this->$validate ) )
                            return false;
                    }
                }
                else
                {
                    //direction
                    //analysis
                    if( $this->$validate != $values )
                        return false;
                }
            }
        }

        return TRUE;
    }

    public function wildfire_rule_best_practice()
    {
        $check_array = $this->wildfire_rule_bp_visibility_JSON( "bp", "wildfire" );
        $bestpractise = $this->check_bp_json( $check_array );

        if ($bestpractise == FALSE)
            return FALSE;
        else
            return TRUE;
    }

    public function wildfire_rule_visibility()
    {
        $check_array = $this->wildfire_rule_bp_visibility_JSON( "visibility", "wildfire" );
        $bestpractise = $this->check_visibility_json( $check_array );

        if ($bestpractise == FALSE)
            return FALSE;
        else
            return TRUE;
    }

    public function wildfirepolicy_load_from_domxml( $threatx )
    {
        $this->type = "ThreatPolicyWildfire";
        $this->load_from_domxml( $threatx );
    }
}
