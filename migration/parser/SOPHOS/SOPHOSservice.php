<?php



#namespace expedition;


trait SOPHOSservice
{
    private function create_service($srv_name, $srv_value, $srv_protocol, $srv_comment, $name_extension = "")
    {
        if( $name_extension != "" )
        {
            if( $name_extension == "_tcp" )
                $srv_protocol[1] = "tcp";
            elseif( $name_extension == "_udp" )
                $srv_protocol[1] = "udp";
        }

        PH::print_stdout( "name: " . $srv_name . " - value: " . $srv_value . " - prot: " . $srv_protocol[1] );

        $tmp_service = $this->sub->serviceStore->find($srv_name . $name_extension);
        if( $tmp_service == FALSE or $tmp_service == null )
        {
            PH::print_stdout( "create service - name: " . $srv_name . " - value: " . $srv_value . " - prot: " . $srv_protocol[1]);
            $tmp_service = $this->sub->serviceStore->newService($srv_name . $name_extension, $srv_protocol[1], $srv_value);
            $tmp_service->setDescription($srv_comment);
        }

        return $tmp_service;
    }

    private function cleanup_text($policy)
    {
        $srv_value = str_replace(',', "", $policy['dst_high']);
        $srv_value_low = str_replace(',', "", $policy['dst_low']);
        if( $srv_value_low !== $srv_value )
            $srv_value = $srv_value_low . "-" . $srv_value;

        $srv_protocol = explode("/", $policy['_type']);
        $srv_protocol = str_replace(',', "", $srv_protocol);
        $srv_comment = str_replace(',', "", $policy['comment']);
        $srv_comment = str_replace('(', "", $srv_comment);
        $srv_comment = str_replace(')', "", $srv_comment);

        return array("value" => $srv_value, "protocol" => $srv_protocol, "comment" => $srv_comment);
    }

    public function service($master_array)
    {
        if( isset($master_array["service"]) )
        {
            foreach ($master_array['service'] as $policy) {
                $srv_name = str_replace(',', "", $policy['name']);

                if ($policy['_type'] == 'service/group,') {
                    //check seperate import later on
                } elseif ($policy['_type'] == 'service/tcp,') {
                    $srv_policy = $this->cleanup_text($policy);
                    $this->create_service($srv_name, $srv_policy['value'], $srv_policy['protocol'], $srv_policy['comment']);
                } elseif ($policy['_type'] == 'service/udp,') {
                    $srv_policy = $this->cleanup_text($policy);
                    $this->create_service($srv_name, $srv_policy['value'], $srv_policy['protocol'], $srv_policy['comment']);
                } elseif ($policy['_type'] == 'service/tcpudp,') {
                    $srv_policy = $this->cleanup_text($policy);
                    $tmp_service_tcp = $this->create_service($srv_name, $srv_policy['value'], array('1' => "tcp"), $srv_policy['comment'], "_tcp");
                    $tmp_service_udp = $this->create_service($srv_name, $srv_policy['value'], array('1' => "udp"), $srv_policy['comment'], "_udp");

                    $tmp_service_group = $this->sub->serviceStore->find($srv_name);
                    if ($tmp_service_group == FALSE or $tmp_service_group == null) {
                        $tmp_service_group = $this->sub->serviceStore->newServiceGroup($srv_name);
                        if (is_object($tmp_service_tcp))
                            $tmp_service_group->addMember($tmp_service_tcp);
                        else
                            mwarning("not an object can not be added");
                        if (is_object($tmp_service_udp))
                            $tmp_service_group->addMember($tmp_service_udp);
                    }
                } else {
                    PH::print_stdout("|" . $policy['_type'] . "|");
                    print_r($policy);
                }
            }
        }
    }


    public function servicegroup($master_array)
    {
        $missingGroupMembers = array();
        if( isset($master_array["service"]) )
        {
            foreach ($master_array['service'] as $policy)
            {
                $srv_name = str_replace(',', "", $policy['name']);

                if ($policy['_type'] == 'service/group,') {
                    $tmp_service_group = $this->sub->serviceStore->find($srv_name);
                    if ($tmp_service_group == FALSE or $tmp_service_group == null) {
                        $tmp_service_group = $this->sub->serviceStore->newServiceGroup($srv_name);
                    }
                    PH::print_stdout();
                    PH::print_stdout("object found: '" . $tmp_service_group->name() . "'");
                    /** @var ServiceGroup $tmp_service_group */
                    if (!$tmp_service_group->isGroup()) {
                        PH::print_stdout("object is NOT a Group - full part skipped - Service with same name available, please rename");
                        continue;
                    }

                    $tmp_found = FALSE;
                    $src_array = explode(",", $policy['members']);
                    PH::print_stdout("\n- set group members:");
                    foreach ($src_array as $members) {
                        #print "src_ref:".$source."\n";
                        foreach ($master_array['service'] as $master_service) {
                            #print "compare:".$master_address['_ref']."-".$master_address['name']."|\n";
                            if (str_replace(',', "", $master_service['_ref']) == $members) {
                                //search object in addressstore
                                $tmp_name = str_replace(',', "", $master_service['name']);
                                PH::print_stdout("FOUND service: " . $tmp_name . " - " . $members);

                                $tmp_service = $this->sub->serviceStore->find($tmp_name);
                                // add to rule source
                                if ($tmp_service !== FALSE && $tmp_service !== null)
                                    $tmp_service_group->addMember($tmp_service);
                                else {
                                    $missingGroupMembers[$tmp_service_group->name()] = $tmp_name;
                                    mwarning("serviceobject: " . $tmp_name . " not found. check if defined later on");
                                }


                                PH::print_stdout($tmp_name);
                                $tmp_found = TRUE;
                                break;
                            } elseif ($master_service['_ref'] == "REF_NetworkAny") {
                                $tmp_found = TRUE;
                                break;
                            } else {
                                #print "NOT FOUND\n";
                            }
                        }
                        if (!$tmp_found) {
                            mwarning("   - service object not found:" . $members . "\n");
                        }
                    }
                }
            }
        }
        /*
        foreach( $missingGroupMembers as $name => $members )
        {
            $tmp_service_group = $this->sub->serviceStore->find($name);
            foreach( $members as $member_service )
            {
                $tmp_service = $this->sub->serviceStore->find($member_service);
                $tmp_service_group->addMember($tmp_service);
            }
        }
        */
    }
}


