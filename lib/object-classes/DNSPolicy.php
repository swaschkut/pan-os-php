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

    public function spyware_dns_bp_visibility_JSON( $checkType )
    {
        $secprof_type = "spyware";
        $checkArray = array();

        if( $checkType !== "bp" && $checkType !== "visibility" )
            derr( "only 'bp' or 'visibility' argument allowed" );

        ###############################
        $details = PH::getBPjsonFile( );

        if( isset($details[$secprof_type]['dns']) )
        {
            if( $checkType == "bp" )
            {
                if( isset($details[$secprof_type]['dns']['bp']))
                    $checkArray = $details[$secprof_type]['dns']['bp'];
                else
                    derr( "this JSON bp/visibility JSON file does not have 'bp' -> 'dns' defined correctly for: '".$secprof_type, null, FALSE );
            }
            elseif( $checkType == "visibility")
            {
                if( isset($details[$secprof_type]['dns']['visibility']))
                    $checkArray = $details[$secprof_type]['dns']['visibility'];
                #else
                //until now all settings are visibilty
                #    derr( "this JSON bp/visibility JSON file does not have 'visibility' -> 'dns' defined correctly for: '".$secprof_type, null, FALSE );
            }
        }

        return $checkArray;
    }

    public function spyware_dns_security_rule_bestpractice()
    {
        $check_array = $this->spyware_dns_bp_visibility_JSON( "bp");

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

        /*
        if( ( $this->name() == "pan-dns-sec-malware"
                || $this->name() == "pan-dns-sec-phishing"
            )
            && ( $this->action() != "sinkhole"
            || $this->packetCapture() != "single-packet" )
        )
            return false;
        elseif( ( $this->name() == "pan-dns-sec-cc"
                )
                && ( $this->action() != "sinkhole"
                    || $this->packetCapture() != "extended-capture" )
            )
            return false;
        else
            return true;
        */
        return TRUE;
    }

    public function spyware_dns_security_rule_visibility()
    {
        //every setting is visibility
        return true;
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
                    derr( "this JSON bp/visibility JSON file does not have 'bp' -> 'lists' defined correctly for: '".$secprof_type, null, FALSE );
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

        return TRUE;
    }

    public function spyware_lists_visibility()
    {
        //every setting is visibility
        return true;
    }
}


