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

    public function newThreatPolicyXML( $xmlroot, $name, $severity = null, $action = "alert", $host_type = 'any' )
    {
        $tmp_rules_xmlroot = DH::findFirstElementOrCreate('rules', $xmlroot);
        $tmp_entry = DH::findFirstElementByNameAttrOrCreate("entry", $name, $tmp_rules_xmlroot, $xmlroot->ownerDocument);

        $this->xmlroot = $tmp_rules_xmlroot;


        $tmp_analysis = DH::findFirstElementOrCreate('analysis', $tmp_entry);
        $tmp_analysis->textContent = "public-cloud";

        $tmp_direction = DH::findFirstElementOrCreate('direction', $tmp_entry);
        $tmp_direction->textContent = "both";

        $tmp_application = DH::findFirstElementOrCreate('application', $tmp_entry);
        $tmp_app_member = DH::createElement( $tmp_application, 'member', 'any' );

        $tmp_file_type = DH::findFirstElementOrCreate('file-type', $tmp_entry);
        $tmp_file_type_member = DH::createElement( $tmp_file_type, 'member', 'any' );

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
        $bp_debug = false;
        if( $bp_debug )
            print_r($check_array);

        foreach( $check_array as $check )
        {
            foreach( $check as $validate => $values )
            {
                if( is_array( $values ) )
                {
                    //application
                    //filetype
                    $checkArray = false;
                    $bpCheckArray = false;
                    foreach( $values as $value )
                    {
                        if( is_array( $this->$validate) )
                        {
                            if( !in_array( $value, $this->$validate ) )
                            {
                                if( $bp_debug )
                                    print "return FALSE\n";
                                return false;
                            }

                        }
                        else
                        {
                            if( $bp_debug )
                                print_r($values);
                            $checkArray = true;
                            if( $bp_debug )
                                print "value == validate: ".$value." ".$this->$validate."\n";
                            if( $value == $this->$validate )
                                $bpCheckArray = true;
                        }
                    }
                    if( $checkArray )
                    {
                        if( $bp_debug )
                            print "checkArray\n";
                        if( $bpCheckArray == FALSE )
                        {
                            if( $bp_debug )
                                print "return FALSE\n";
                            return false;
                        }

                    }
                }
                else
                {
                    //direction
                    //analysis
                    if( $this->$validate != $values )
                    {
                        if( $bp_debug )
                            print "return FALSE\n";
                        return false;
                    }
                }
            }
        }

        if( $bp_debug )
            print "return TRUE\n";

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
                    $checkArray = false;
                    $bpCheckArray = false;
                    foreach( $values as $value )
                    {
                        if( is_array( $this->$validate) )
                        {
                            if( !in_array( $value, $this->$validate ) )
                                return false;
                        }
                        else
                        {
                            $checkArray = true;
                            if( $value == $this->$validate )
                                $bpCheckArray = true;
                        }
                    }
                    if( $checkArray )
                    {
                        if( $bpCheckArray == FALSE )
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
