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


class DNSPolicy
{
    use ReferenceableObject;
    use PathableName;

    public $type = 'tmp';

    /** @var AntiSpywareProfile|null */
    public $owner;
    public $xmlroot;

    public $logLevel = null;
    public $action = null;
    public $packetCapture = null;

    public $advanced = null;

    public function __construct($name, $owner, $advanced = false)
    {
        $this->owner = $owner;
        $this->name = $name;
        $this->xmlroot = null;
        $this->advanced = $advanced;
    }

    public function load_from_domxml( $tmp_entry1 )
    {
        $this->xmlroot = $tmp_entry1;

        $tmp = DH::findFirstElement('log-level', $tmp_entry1);
        if( $tmp !== FALSE )
        {
            $this->logLevel = $tmp->textContent;
        }

        $tmp = DH::findFirstElement('action', $tmp_entry1);
        if( $tmp !== FALSE && $tmp !== NULL )
        {
            $child = DH::firstChildElement($tmp);
            if( $child !== FALSE )
                $this->action = $child->nodeName;
            else
                $this->action = $tmp->textContent;
        }

        if( $this->advanced === FALSE )
        {
            $tmp = DH::findFirstElement('packet-capture', $tmp_entry1);
            if( $tmp !== FALSE )
            {
                $this->packetCapture = $tmp->textContent;
            }
        }
    }




    public function type()
    {
        return $this->type;
    }

    public function name()
    {
        return $this->name;
    }

    public function logLevel()
    {
        return $this->logLevel;
    }

    public function action()
    {
        return $this->action;
    }

    public function packetCapture()
    {
        return $this->packetCapture;
    }

    public function display($padding="")
    {
        $string = $padding . "          '" . $this->name() . "':";

        if( isset( $this->logLevel ) )
        {
            $string .= " - log-level: '".$this->logLevel()."'";
            PH::$JSON_TMP['sub']['object'][$this->owner->name()]['rule'][$this->name()]['log-level'] = $this->logLevel();
        }

        if( $this->action() !== null )
        {
            $string .= " - action: '".$this->action()."'";
            PH::$JSON_TMP['sub']['object'][$this->owner->name()]['rule'][$this->name()]['action'] = $this->action();
        }

        if( $this->packetCapture() !== null )
        {
            $string .= " - packet-capture: '".$this->packetCapture()."'";
            PH::$JSON_TMP['sub']['object'][$this->owner->name()]['rule'][$this->name()]['packet-capture'] = $this->packetCapture();
        }

        PH::print_stdout( $string );
    }

    public function spyware_dns_bp_visibility_JSON( $checkType, $advanced = false )
    {
        $secprof_type = "spyware";
        $checkArray = array();

        $dns_string = "dns";
        if( $advanced )
            $dns_string = "advanced-dns";

        if( $checkType !== "bp" && $checkType !== "visibility" )
            derr( "only 'bp' or 'visibility' argument allowed" );

        ###############################
        $details = PH::getBPjsonFile( );

        if( isset($details[$secprof_type][$dns_string]) )
        {
            if( $checkType == "bp" )
            {
                if( isset($details[$secprof_type][$dns_string]['bp']))
                    $checkArray = $details[$secprof_type][$dns_string]['bp'];
                else
                    mwarning( "this JSON bp/visibility JSON file customised 'bp' -> '".$dns_string."' defined correctly for: '".$secprof_type, null, FALSE );
            }
            elseif( $checkType == "visibility")
            {
                if( isset($details[$secprof_type][$dns_string]['visibility']))
                    $checkArray = $details[$secprof_type][$dns_string]['visibility'];
                #else
                //until now all settings are visibilty
                #    derr( "this JSON bp/visibility JSON file does not have 'visibility' -> 'dns' defined correctly for: '".$secprof_type, null, FALSE );
            }
        }

        return $checkArray;
    }

    public function spyware_dns_security_rule_bestpractice()
    {
        $tmp_debug = false;

        $check_array = $this->spyware_dns_bp_visibility_JSON( "bp");

        if( $tmp_debug )
            print_r( $check_array );
        if( isset( $check_array['action'] ) )
        {
            foreach( $check_array['action'] as $validate )
            {
                $bp_action = FALSE;
                $bp_packet = FALSE;
                $bp_loglevel = FALSE;

                foreach( $validate['type'] as $name )
                {
                    if( $this->name() == $name )
                    {
                        if( $tmp_debug )
                            print "0) name: ".$name."\n";

                        if( isset( $validate['action'] ) )
                        {
                            foreach( $validate['action'] as $final_action_check )
                            {
                                if( $tmp_debug )
                                    print "1) action: ".$this->action()." |validate: ".$final_action_check."\n";
                                if( $this->action() == $final_action_check )
                                {
                                    $bp_action = TRUE;
                                    if( $tmp_debug )
                                        print "1-0) true\n";
                                    break;
                                }
                                else
                                {
                                    $bp_action = FALSE;
                                    if( $tmp_debug )
                                        print "1-1) false\n";
                                }

                            }
                        }
                        else
                            $bp_action = TRUE;


                        if( isset( $validate['packet-capture'] ) )
                        {
                            foreach( $validate['packet-capture'] as $final_packet_check )
                            {
                                if( $tmp_debug )
                                    print "2) packet: ".$this->packetCapture()." |validate: ".$final_packet_check."\n";
                                if( $this->packetCapture() == $final_packet_check )
                                {
                                    $bp_packet = TRUE;
                                    if( $tmp_debug )
                                        print "2-0) true\n";
                                    break;
                                }
                                else
                                {
                                    $bp_packet = FALSE;
                                    if( $tmp_debug )
                                        print "2-1) false\n";
                                }
                            }
                        }
                        else
                            $bp_packet = TRUE;

                        if( isset( $validate['log-level'] ) )
                        {
                            foreach( $validate['log-level'] as $final_loglevel_check )
                            {
                                if( $tmp_debug )
                                    print "3) log-level: ".$this->logLevel()." |validate: ".$final_loglevel_check."\n";
                                $negate_string = "";
                                if( strpos($final_loglevel_check, '!') !== FALSE )
                                    $negate_string = "!";
                                if( $negate_string.$this->logLevel == $final_loglevel_check )
                                {
                                    $bp_loglevel = FALSE;
                                    if( $tmp_debug )
                                        print "3-0) false\n";
                                    break;
                                }
                                else
                                {
                                    $bp_loglevel = TRUE;
                                    if( $tmp_debug )
                                        print "3-1) true\n";
                                }
                            }
                        }



                        if( $bp_action && $bp_packet && $bp_loglevel )
                            return TRUE;
                        else
                            return FALSE;
                    }
                }
            }
        }


        return TRUE;
    }

    public function spyware_dns_security_rule_visibility()
    {
        $tmp_debug = false;

        $check_array = $this->spyware_dns_bp_visibility_JSON( "visibility");

        if( $tmp_debug )
            print_r( $check_array );
        if( isset($check_array['action']) )
        {
            foreach( $check_array['action'] as $validate )
            {
                $bp_action = FALSE;
                $bp_packet = FALSE;
                $bp_loglevel = FALSE;

                foreach( $validate['type'] as $name )
                {
                    if( $this->name() == $name )
                    {
                        if( $tmp_debug )
                            print "0) name: ".$name."\n";

                        if( isset( $validate['action'] ) )
                        {
                            foreach( $validate['action'] as $final_action_check )
                            {
                                if( $tmp_debug )
                                    print "1) action: ".$this->action()." |validate: ".$final_action_check."\n";
                                if( $this->action() == $final_action_check )
                                {
                                    $bp_action = TRUE;
                                    if( $tmp_debug )
                                        print "1-0) true\n";
                                    break;
                                }
                                else
                                {
                                    $bp_action = FALSE;
                                    if( $tmp_debug )
                                        print "1-1) false\n";
                                }

                            }
                        }
                        else
                            $bp_action = TRUE;


                        if( isset( $validate['packet-capture'] ) )
                        {
                            foreach( $validate['packet-capture'] as $final_packet_check )
                            {
                                if( $tmp_debug )
                                    print "2) packet: ".$this->packetCapture()." |validate: ".$final_packet_check."\n";
                                if( $this->packetCapture() == $final_packet_check )
                                {
                                    $bp_packet = TRUE;
                                    if( $tmp_debug )
                                        print "2-0) true\n";
                                    break;
                                }
                                else
                                {
                                    $bp_packet = FALSE;
                                    if( $tmp_debug )
                                        print "2-1) false\n";
                                }
                            }
                        }
                        else
                            $bp_packet = TRUE;

                        if( isset( $validate['log-level'] ) )
                        {
                            foreach( $validate['log-level'] as $final_loglevel_check )
                            {
                                if( $tmp_debug )
                                    print "3) log-level: ".$this->logLevel()." |validate: ".$final_loglevel_check."\n";
                                $negate_string = "";
                                if( strpos($final_loglevel_check, '!') !== FALSE )
                                    $negate_string = "!";
                                if( $negate_string.$this->logLevel == $final_loglevel_check )
                                {
                                    $bp_loglevel = FALSE;
                                    if( $tmp_debug )
                                        print "3-0) false\n";
                                    break;
                                }
                                else
                                {
                                    $bp_loglevel = TRUE;
                                    if( $tmp_debug )
                                        print "3-1) true\n";
                                }
                            }
                        }
                        else
                            $bp_loglevel = TRUE;



                        #if( $bp_action && $bp_packet && $bp_loglevel )
                        if( $bp_action && $bp_packet && $bp_loglevel )
                            return TRUE;
                        else
                            return FALSE;
                    }
                }
            }
        }


        return TRUE;
    }

    public function spyware_advanced_dns_security_rule_bestpractice()
    {
        $tmp_debug = false;

        $check_array = $this->spyware_dns_bp_visibility_JSON( "bp", true);

        if( $tmp_debug )
            print_r( $check_array );

        if( isset($check_array['action']) )
        {
            foreach( $check_array['action'] as $validate )
            {
                $bp_action = FALSE;
                $bp_packet = FALSE;
                $bp_loglevel = FALSE;

                foreach( $validate['type'] as $name )
                {
                    if( $this->name() == $name )
                    {
                        if( $tmp_debug )
                            print "0) name: ".$name."\n";

                        if( isset( $validate['action'] ) )
                        {
                            foreach( $validate['action'] as $final_action_check )
                            {
                                if( $tmp_debug )
                                    print "1) action: ".$this->action()." |validate: ".$final_action_check."\n";
                                if( $this->action() == $final_action_check )
                                {
                                    $bp_action = TRUE;
                                    if( $tmp_debug )
                                        print "1-0) true\n";
                                    break;
                                }
                                else
                                {
                                    $bp_action = FALSE;
                                    if( $tmp_debug )
                                        print "1-1) false\n";
                                }

                            }
                        }
                        else
                            $bp_action = TRUE;


                        if( isset( $validate['packet-capture'] ) )
                        {
                            foreach( $validate['packet-capture'] as $final_packet_check )
                            {
                                if( $tmp_debug )
                                    print "2) packet: ".$this->packetCapture()." |validate: ".$final_packet_check."\n";
                                if( $this->packetCapture() == $final_packet_check )
                                {
                                    $bp_packet = TRUE;
                                    if( $tmp_debug )
                                        print "2-0) true\n";
                                    break;
                                }
                                else
                                {
                                    $bp_packet = FALSE;
                                    if( $tmp_debug )
                                        print "2-1) false\n";
                                }
                            }
                        }
                        else
                            $bp_packet = TRUE;

                        if( isset( $validate['log-level'] ) )
                        {
                            foreach( $validate['log-level'] as $final_loglevel_check )
                            {
                                if( $tmp_debug )
                                    print "3) log-level: ".$this->logLevel()." |validate: ".$final_loglevel_check."\n";
                                $negate_string = "";
                                if( strpos($final_loglevel_check, '!') !== FALSE )
                                    $negate_string = "!";
                                if( $negate_string.$this->logLevel == $final_loglevel_check )
                                {
                                    $bp_loglevel = FALSE;
                                    if( $tmp_debug )
                                        print "3-0) false\n";
                                    break;
                                }
                                else
                                {
                                    $bp_loglevel = TRUE;
                                    if( $tmp_debug )
                                        print "3-1) true\n";
                                }
                            }
                        }
                        else
                            $bp_loglevel = TRUE;



                        if( $bp_action && $bp_packet && $bp_loglevel )
                            return TRUE;
                        else
                            return FALSE;
                    }
                }
            }
        }


        return null;
    }

    public function spyware_advanced_dns_security_rule_visibility()
    {
        $tmp_debug = false;

        $check_array = $this->spyware_dns_bp_visibility_JSON( "visibility", true);

        if( $tmp_debug )
            print_r( $check_array );
        if( isset( $check_array['action']) )
        {
            foreach( $check_array['action'] as $validate )
            {
                $bp_action = FALSE;
                $bp_packet = FALSE;
                $bp_loglevel = FALSE;

                foreach( $validate['type'] as $name )
                {
                    if( $this->name() == $name )
                    {
                        if( $tmp_debug )
                            print "0) name: ".$name."\n";

                        if( isset( $validate['action'] ) )
                        {
                            foreach( $validate['action'] as $final_action_check )
                            {
                                if( $tmp_debug )
                                    print "1) action: ".$this->action()." |validate: ".$final_action_check."\n";
                                if( $this->action() == $final_action_check )
                                {
                                    $bp_action = TRUE;
                                    if( $tmp_debug )
                                        print "1-0) true\n";
                                    break;
                                }
                                else
                                {
                                    $bp_action = FALSE;
                                    if( $tmp_debug )
                                        print "1-1) false\n";
                                }

                            }
                        }
                        else
                            $bp_action = TRUE;


                        if( isset( $validate['packet-capture'] ) )
                        {
                            foreach( $validate['packet-capture'] as $final_packet_check )
                            {
                                if( $tmp_debug )
                                    print "2) packet: ".$this->packetCapture()." |validate: ".$final_packet_check."\n";
                                if( $this->packetCapture() == $final_packet_check )
                                {
                                    $bp_packet = TRUE;
                                    if( $tmp_debug )
                                        print "2-0) true\n";
                                    break;
                                }
                                else
                                {
                                    $bp_packet = FALSE;
                                    if( $tmp_debug )
                                        print "2-1) false\n";
                                }
                            }
                        }
                        else
                            $bp_packet = TRUE;

                        if( isset( $validate['log-level'] ) )
                        {
                            foreach( $validate['log-level'] as $final_loglevel_check )
                            {
                                if( $tmp_debug )
                                    print "3) log-level: ".$this->logLevel()." |validate: ".$final_loglevel_check."\n";
                                $negate_string = "";
                                if( strpos($final_loglevel_check, '!') !== FALSE )
                                    $negate_string = "!";
                                if( $negate_string.$this->logLevel == $final_loglevel_check )
                                {
                                    $bp_loglevel = FALSE;
                                    if( $tmp_debug )
                                        print "3-0) false\n";
                                    break;
                                }
                                else
                                {
                                    $bp_loglevel = TRUE;
                                    if( $tmp_debug )
                                        print "3-1) true\n";
                                }
                            }
                        }
                        else
                            $bp_loglevel = TRUE;


                        if( $bp_action && $bp_packet && $bp_loglevel )
                            return TRUE;
                        else
                            return FALSE;
                    }
                }
            }
        }


        return null;
    }


    public function spyware_lists_bp_visibility_JSON( $checkType )
    {
        $secprof_type = "spyware";
        $checkArray = array();

        if( $checkType !== "bp" && $checkType !== "visibility" )
            derr( "only 'bp' or 'visibility' argument allowed" );

        ###############################
        $details = PH::getBPjsonFile( );

        if( isset($details[$secprof_type]['lists']) )
        {
            if( $checkType == "bp" )
            {
                if( isset($details[$secprof_type]['lists']['bp']))
                    $checkArray = $details[$secprof_type]['lists']['bp'];
                else
                    mwarning( "this JSON bp/visibility JSON file customised 'bp' -> 'lists' defined correctly for: '".$secprof_type, null, FALSE );
            }
            elseif( $checkType == "visibility")
            {
                if( isset($details[$secprof_type]['lists']['visibility']))
                    $checkArray = $details[$secprof_type]['lists']['visibility'];
                #else
                //until now all settings are visibilty
                #    derr( "this JSON bp/visibility JSON file does not have 'visibility' -> 'dns' defined correctly for: '".$secprof_type, null, FALSE );
            }
        }

        return $checkArray;
    }

    public function spyware_lists_bestpractice()
    {
        $check_array = $this->spyware_lists_bp_visibility_JSON( "bp");

        if( isset( $check_array['action'] ) )
        {
            foreach( $check_array['action'] as $validate )
            {
                $bp_action = FALSE;
                $bp_packet = FALSE;

                foreach( $validate['type'] as $name )
                {
                    if( $this->name() == $name )
                    {
                        #print "0) name: ".$name."\n";
                        foreach( $validate['action'] as $final_action_check )
                        {
                            #print "1) action: ".$this->action()." |validate: ".$final_action_check."\n";
                            if( $this->action() == $final_action_check )
                            {
                                $bp_action = TRUE;
                                #print "1-0) true\n";
                                break;
                            }
                            else
                            {
                                $bp_action = FALSE;
                                #print "1-1) false\n";
                            }

                        }


                        foreach( $validate['packet-capture'] as $final_packet_check )
                        {
                            #print "2) packet: ".$this->packetCapture()." |validate: ".$final_packet_check."\n";
                            if( $this->packetCapture() == $final_packet_check )
                            {
                                $bp_packet = TRUE;
                                #print "2-0) true\n";
                                break;
                            }
                            else
                            {
                                $bp_packet = FALSE;
                                #print "2-1) false\n";
                            }
                        }


                        if( $bp_action && $bp_packet )
                            return TRUE;
                        else
                            return FALSE;
                    }
                }
            }
        }

        return TRUE;
    }

    public function spyware_lists_visibility()
    {
        $check_array = $this->spyware_lists_bp_visibility_JSON( "visibility");

        if( isset( $check_array['action'] ) )
        {
            foreach( $check_array['action'] as $validate )
            {
                $bp_action = FALSE;

                foreach( $validate['type'] as $name )
                {
                    if( $this->name() == $name )
                    {
                        #print "0) name: ".$name."\n";
                        foreach( $validate['action'] as $final_action_check )
                        {
                            $final_action_check = str_replace("!", "", $final_action_check);
                            #print "1) action: ".$this->action()." |validate: ".$final_action_check."\n";
                            if( $this->action() == $final_action_check )
                            {
                                return false;
                                $bp_action = FALSE;
                                #print "1-1) false\n";
                            }
                            else
                            {
                                $bp_action = TRUE;
                                #print "1-0) true\n";
                                break;
                            }
                        }

                        if( $bp_action )
                            return TRUE;
                        else
                            return FALSE;
                    }
                }
            }
        }

        return true;
    }
}


