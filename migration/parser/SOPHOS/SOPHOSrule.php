<?php

trait SOPHOSrule
{
    public function rule($master_array, $rulesort)
    {
        PH::print_stdout("**************************************");
        PH::print_stdout( "\nSEC Rule  migration:\n");

        foreach( $rulesort as $rule )
        {
            if( isset($master_array['packetfilter']) )
            {
                foreach( $master_array['packetfilter'] as $policy )
                {

                    #print "NAME:|".$rule."|\n";
                    #print "REF:|".$policy['_ref']."|\n";
                    $rule_ref = str_replace(',', "", $policy['_ref']);
                    if( $rule == $rule_ref )
                    {
                        #print_r( $policy );


                        $name_length = 63;
                        if( strlen($policy['name']) > $name_length )
                        {
                            PH::print_stdout( "\n\nrule name must cut to length " . $name_length . "| new rule name: '" . substr($policy['name'], 0, $name_length - 1) . "'" );
                            $rule_name = substr($policy['name'], 0, $name_length - 1);
                        }
                        else
                        {
                            PH::print_stdout( "\nname: " . $policy['name'] );
                            $rule_name = str_replace(',', "", $policy['name']);
                        }
                        $rule_name = str_replace('(', "", $rule_name);
                        $rule_name = str_replace(')', "", $rule_name);
                        $rule_name = str_replace('+', "", $rule_name);
                        $rule_name = str_replace('Ù', "U", $rule_name);
                        $rule_name = str_replace('ä', "ae", $rule_name);
                        $rule_name = str_replace('@', "et", $rule_name);


                        $rule_name = rtrim($rule_name);


                        $tmp_rule = $this->sub->securityRules->newSecurityRule($rule_name);
                        PH::print_stdout( PH::boldText("generate new Rule:" . $rule_name) );


                        if( strpos($policy['comment'], ",") !== 0 )
                        {
                            //set rule comment
                            PH::print_stdout( "- set comment: " . $policy['comment'] );
                            $rule_comment = str_replace(',', "", $policy['comment']);
                            $rule_comment = str_replace('(', "", $rule_comment);
                            $rule_comment = str_replace(')', "", $rule_comment);
                            $tmp_rule->setDescription($rule_comment);
                        }

                        if( strpos($policy['action'], "accept") !== FALSE )
                        {
                            //set rule action => allow
                            PH::print_stdout( "- set action: " . $policy['action'] );
                            $rule_action = str_replace(',', "", $policy['action']);
                            $tmp_rule->setAction('allow');
                        }
                        else
                        {
                            //set rule action => deny
                            PH::print_stdout( "- set action: " . $policy['action'] );
                            $tmp_rule->setAction('deny');
                        }

                        //for src/dst/service
                        //explode based on ","
                        //foreach entry search relevant

                        $tmp_found = FALSE;
                        $src_array = explode(",", $policy['sources']);
                        PH::print_stdout( "- set sources: " );
                        foreach( $src_array as $source )
                        {
                            #print "src_ref:".$source."\n";
                            foreach( $master_array['network'] as $master_address )
                            {
                                #print "compare:".$master_address['_ref']."-".$master_address['name']."|\n";
                                if( str_replace(',', "", $master_address['_ref']) == $source )
                                {
                                    #print "FOUND address".$master_address['name']."\n";
                                    //search object in addressstore
                                    $tmp_name = str_replace(',', "", $master_address['name']);
                                    $tmp_address = $this->sub->addressStore->findOrCreate($tmp_name);
                                    // add to rule source
                                    $tmp_rule->source->addObject($tmp_address);
                                    PH::print_stdout( $tmp_name );
                                    $tmp_found = TRUE;
                                    break;
                                }
                                elseif( $master_address['_ref'] == "REF_NetworkAny" )
                                {
                                    $tmp_found = TRUE;
                                    break;
                                }
                                else
                                {
                                    #print "NOT FOUND\n";
                                }

                            }
                            if( !$tmp_found )
                            {
                                if( strpos($source, "Any") === FALSE )
                                    mwarning("   - network object not found:" . $source . "\n");
                                else
                                    PH::print_stdout( "ANY" );
                            }
                        }
                        #print "\n";

                        $tmp_found = FALSE;
                        $dst_array = explode(",", $policy['destinations']);
                        PH::print_stdout( "- set destinations: " );
                        foreach( $dst_array as $destination )
                        {
                            #print "dst_ref:".$destination."\n";
                            foreach( $master_array['network'] as $master_address )
                            {
                                #print "compare:".$master_address['_ref']."-".$master_address['name']."|\n";
                                if( str_replace(',', "", $master_address['_ref']) == $destination )
                                {
                                    #print "FOUND address".$master_address['name']."\n";
                                    //search object in addressstore
                                    $tmp_name = str_replace(',', "", $master_address['name']);
                                    $tmp_address = $this->sub->addressStore->findOrCreate($tmp_name);
                                    // add to rule destination
                                    $tmp_rule->destination->addObject($tmp_address);
                                    PH::print_stdout( $tmp_name );
                                    $tmp_found = TRUE;
                                    break;
                                }
                                elseif( $master_address['_ref'] == "REF_NetworkAny" )
                                {
                                    $tmp_found = TRUE;
                                    break;
                                }
                                else
                                {
                                    #print "NOT FOUND\n";
                                }
                            }
                            if( !$tmp_found )
                            {
                                if( strpos($destination, "Any") === FALSE )
                                    mwarning("   - network object not found:" . $destination . "\n");
                                else
                                    PH::print_stdout( "ANY" );
                            }
                        }
                        PH::print_stdout( );

                        $tmp_found = FALSE;
                        $srv_array = explode(",", $policy['services']);
                        PH::print_stdout( "- set services: " );
                        foreach( $srv_array as $service )
                        {
                            #print "srv_ref:".$service."\n";
                            foreach( $master_array['service'] as $master_service )
                            {
                                if( str_replace(',', "", $master_service['_ref']) == $service )
                                {
                                    #print "FOUND service".$master_service['name']."\n";
                                    //search object in servicestore
                                    $tmp_name = str_replace(',', "", $master_service['name']);

                                    $tmp_service = $this->sub->serviceStore->findOrCreate($tmp_name);
                                    // add to rule service
                                    $tmp_rule->services->add($tmp_service);
                                    PH::print_stdout( $tmp_name );
                                    $tmp_found = TRUE;
                                    break;
                                }
                                elseif( $master_service['_ref'] == "REF_ServiceAny" )
                                {
                                    $tmp_found = TRUE;
                                    break;
                                }
                                else
                                {
                                    #print "NOT FOUND\n";
                                }

                            }
                            if( !$tmp_found )
                            {
                                if( strpos($service, "Any") === FALSE )
                                    mwarning("   - service object not found:" . $service . "\n");
                                else
                                    PH::print_stdout( "ANY");
                            }
                        }
                        print "\n";

                        #print "- set tag: ";
                        $tag = $policy['group'];
                        $tag = str_replace(',', "", $tag);
                        #print "tag:|" . $tag . "|\n";
                        if( $tag != "" )
                        {
                            $tmp_tag = $this->sub->tagStore->findOrCreate($tag);
                            $tmp_rule->tags->addTag($tmp_tag);
                            PH::print_stdout( "- set tag: " . $tag );

                        }
                        print "\n";

                        if( $policy['status'] == 'false,' )
                        {
                            $tmp_rule->setDisabled(TRUE);
                            PH::print_stdout( "set rule to disable" );
                        }
                    }
                }
            }

        }
    }


    public function rule_nat($master_array)
    {
        PH::print_stdout("**************************************");
        PH::print_stdout( "\nNAT Rule  migration:\n");

                if (isset($master_array['packetfilter']))
                {

                    $rule_type_array = array();

                    foreach ($master_array['packetfilter'] as $policy)
                    {

                        //Todo: missing stuff:
                        //    [packetfilter/nat] => packetfilter/nat
                        //    [packetfilter/masq] => packetfilter/masq


                        #print "NAME:|".$policy['name']."|\n";
                        #print "REF:|".$policy['_ref']."|\n";
                        #print "TYPE:|".$policy['_type']."\n";
                        $rule_ref = str_replace(',', "", $policy['_ref']);
                        $rule_type = str_replace(',', "", $policy['_type']);


                        if ($rule_type === "packetfilter/packetfilter")
                        {
                            continue;
                            #$tmp_rule = $this->sub->securityRules->newSecurityRule($rule_name);
                            #PH::print_stdout(PH::boldText("generate new SECRule:" . $rule_name));

                        }

                        $name_length = 63;
                        if (strlen($policy['name']) > $name_length) {
                            PH::print_stdout("\n\nrule name must cut to length " . $name_length . "| new rule name: '" . substr($policy['name'], 0, $name_length - 1) . "'");
                            $rule_name = substr($policy['name'], 0, $name_length - 1);
                        } else {
                            PH::print_stdout("\nname: " . $policy['name']);
                            $rule_name = str_replace(',', "", $policy['name']);
                        }
                        $rule_name = str_replace('(', "", $rule_name);
                        $rule_name = str_replace(')', "", $rule_name);
                        $rule_name = str_replace('+', "", $rule_name);
                        $rule_name = str_replace('Ù', "U", $rule_name);
                        $rule_name = str_replace('ä', "ae", $rule_name);
                        $rule_name = str_replace('@', "et", $rule_name);


                        $rule_name = rtrim($rule_name);



                        if ($rule_type === "packetfilter/nat") {
                            if (isset($policy['mode']) && $policy['mode'] == 'dnat,') {
                                /** @var NatRule $tmp_rule */
                                $tmp_rule = $this->sub->natRules->newNATRule($rule_name);
                                PH::print_stdout(PH::boldText("generate new DNAT Rule:" . $rule_name));

                                $dnat_address_ref = str_replace(',', "", $policy['destination_nat_address']);
                                $dnat_service_ref = str_replace(',', "", $policy['destination_nat_service']);

                                $tmp_adr_name = $this->ref_array[$dnat_address_ref];
                                $adr_object = $this->sub->addressStore->find($tmp_adr_name);
                                $tmp_rule->setDNAT($adr_object);
                                if (!empty($dnat_service)) {
                                    $tmp_srv_name = $this->ref_array[$dnat_service_ref];
                                    $srv_object = $this->sub->serviceStore->find($tmp_srv_name);
                                    $tmp_rule->setDNAT($adr_object, $srv_object);
                                }

                                print_r($policy);
                                /*
                                 DNAT
                                Array
                                (
                                    [_locked] => ,
                                    [_ref] => REF_PacNatTcp44FromInter,
                                    [_type] => packetfilter/nat,
                                    [auto_pf_in] => ,
                                    [auto_pfrule] => false,
                                    [comment] => ,
                                    [destination] => REF_NetIntInterAvaya1gbit7,
                                    [destination_nat_address] => REF_NetHosVmwaremdm,
                                    [destination_nat_service] => ,
                                    [group] => VMware-MDM,
                                    [ipsec] => false,
                                    [log] => false,
                                    [mode] => dnat,
                                    [name] => VMware-UAGext from VMware-MDM to Internet Avaya 1Gbit extern [VMware-MDMGW] (Address),
                                    [service] => REF_SerGroVmwareuage,
                                    [source] => REF_NetworkInternet,
                                    [source_nat_address] => ,
                                    [source_nat_service] => ,
                                    [status] => true
                                )
                                 */
                            } elseif (isset($policy['mode']) && $policy['mode'] == 'full,') {
                                /** @var NatRule $tmp_rule */
                                $tmp_rule = $this->sub->natRules->newNATRule($rule_name);
                                PH::print_stdout(PH::boldText("generate new full SNAT and DNAT Rule:" . $rule_name));

                                $snat_address_ref = str_replace(',', "", $policy['source_nat_address']);
                                $snat_service_ref = str_replace(',', "", $policy['source_nat_service']);

                                $dnat_address_ref = str_replace(',', "", $policy['destination_nat_address']);
                                $dnat_service_ref = str_replace(',', "", $policy['destination_nat_service']);


                                $tmp_adr_name = $this->ref_array[$snat_address_ref];
                                $adr_object = $this->sub->addressStore->find($tmp_adr_name);
                                $tmp_rule->changeSourceNAT("dynamic-ip-and-port");
                                $tmp_rule->snathosts->addObject($adr_object);


                                $tmp_adr_name = $this->ref_array[$dnat_address_ref];
                                $adr_object = $this->sub->addressStore->find($tmp_adr_name);
                                $tmp_rule->setDNAT($adr_object);
                                if (!empty($dnat_service)) {
                                    $tmp_srv_name = $this->ref_array[$dnat_service_ref];
                                    $srv_object = $this->sub->serviceStore->find($tmp_srv_name);
                                    $tmp_rule->setDNAT($adr_object, $srv_object);
                                }

                                //NAT
                                /*
                                 rule name must cut to length 63| new rule name: 'VMware-UAGext from VMware-MDM to Internet Avaya 1Gbit extern ['
                                generate new NAT Rule:VMware-UAGext from VMware-MDM to Internet Avaya 1Gbit extern [

                                FULL/SNAT/DNAT
                                (
                                    [_locked] => ,
                                    [_ref] => REF_PacNatGroupS2sOut44,
                                    [_type] => packetfilter/nat,
                                    [auto_pf_in] => ,
                                    [auto_pfrule] => false,
                                    [comment] => NAT (S2S) Zielhost 1 bei Siemens,
                                    [destination] => REF_NetHosNatS2sRemot,
                                    [destination_nat_address] => REF_NetHosSite2Remot1,
                                    [destination_nat_service] => ,
                                    [group] => VPN (S2S) Siemens,
                                    [ipsec] => false,
                                    [log] => true,
                                    [mode] => full,
                                    [name] => Group S2S (out)
                                    [service] => REF_SerGroGroupS2sOut3,
                                    [source] => REF_NetDnsSiemensacu,
                                    [source_nat_address] => REF_NetHosNatSiemens,
                                    [source_nat_service] => ,
                                    [status] => true
                                )
                                 */
                            }
                        } elseif ($rule_type === "packetfilter/masq") {
                            $tmp_rule = $this->sub->natRules->newNATRule($rule_name);
                            PH::print_stdout(PH::boldText("generate new masq NAT Rule:" . $rule_name));


                            /** @var NatRule $tmp_rule */
                            #$tmp_rule->setNatRuleType('ipv4');

                            if (isset($policy['source_nat_interface'])) {
                                $tmp_src_nat_interface = str_replace(',', "", $policy['source_nat_interface']);

                                PH::print_stdout("interface: " . $tmp_src_nat_interface . "\n");


                                $tmp_interface_name = $this->ref_array[$tmp_src_nat_interface];
                                $tmp_rule->changeSourceNAT('dynamic-ip-and-port', $tmp_interface_name);

                            }

                            //MASQ
                            /*
                             name: from Any to Extern 100Mbit,
                            generate new NAT Rule:from Any to Extern 100Mbit
                            Array
                            (
                                [_locked] => ,
                                [_ref] => REF_PacMasFromAnyToExter,
                                [_type] => packetfilter/masq,
                                [additional_address] => ,
                                [additional_address_restore] => ,
                                [comment] => ,
                                [name] => from Any to Extern 100Mbit,
                                [source] => REF_NetworkAny,
                                [source_nat_interface] => REF_IntEthExternNeu,
                                [status] => false
                            )

                             */
                        }


                        if (strpos($policy['comment'], ",") !== 0) {
                            //set rule comment
                            PH::print_stdout("- set comment: " . $policy['comment']);
                            $rule_comment = str_replace(',', "", $policy['comment']);
                            $rule_comment = str_replace('(', "", $rule_comment);
                            $rule_comment = str_replace(')', "", $rule_comment);
                            $tmp_rule->setDescription($rule_comment);
                        }

                        if ($rule_type === "packetfilter/packetfilter") {
                            if (isset($policy['action']) && strpos($policy['action'], "accept") !== FALSE) {
                                //set rule action => allow
                                PH::print_stdout("- set action: " . $policy['action']);
                                $rule_action = str_replace(',', "", $policy['action']);
                                $tmp_rule->setAction('allow');
                            } elseif (isset($policy['action']) && strpos($policy['action'], "reject") !== FALSE) {
                                //set rule action => allow
                                PH::print_stdout("- set action: " . $policy['action']);
                                $rule_action = str_replace(',', "", $policy['action']);
                                $tmp_rule->setAction('deny');
                            } elseif (!isset($policy['action'])) {
                                PH::print_stdout("Rule not action set");
                                print_r($policy);
                                exit();
                            } else {
                                //set rule action => deny
                                PH::print_stdout("- set action: " . $policy['action']);
                                $tmp_rule->setAction('deny');
                            }

                            //for src/dst/service
                            //explode based on ","
                            //foreach entry search relevant
                            if (isset($policy['sources'])) {
                                $tmp_found = FALSE;
                                $src_array = explode(",", $policy['sources']);
                                PH::print_stdout("- set sources: ");
                                foreach ($src_array as $source) {
                                    #print "src_ref:".$source."\n";
                                    foreach ($master_array['network'] as $master_address) {
                                        #print "compare:".$master_address['_ref']."-".$master_address['name']."|\n";
                                        if (str_replace(',', "", $master_address['_ref']) == $source) {
                                            #print "FOUND address".$master_address['name']."\n";
                                            //search object in addressstore
                                            $tmp_name = str_replace(',', "", $master_address['name']);
                                            $tmp_address = $this->sub->addressStore->findOrCreate($tmp_name);
                                            // add to rule source
                                            $tmp_rule->source->addObject($tmp_address);
                                            PH::print_stdout($tmp_name);
                                            $tmp_found = TRUE;
                                            break;
                                        } elseif ($master_address['_ref'] == "REF_NetworkAny") {
                                            $tmp_found = TRUE;
                                            break;
                                        } else {
                                            #print "NOT FOUND\n";
                                        }

                                    }
                                    if (!$tmp_found) {
                                        if (strpos($source, "Any") === FALSE)
                                            mwarning("   - network object not found:" . $source . "\n");
                                        else
                                            PH::print_stdout("ANY");
                                    }
                                }
                                #print "\n";
                            }

                            if (isset($policy['destinations'])) {
                                $tmp_found = FALSE;
                                $dst_array = explode(",", $policy['destinations']);
                                PH::print_stdout("- set destinations: ");
                                foreach ($dst_array as $destination) {
                                    #print "dst_ref:".$destination."\n";
                                    foreach ($master_array['network'] as $master_address) {
                                        #print "compare:".$master_address['_ref']."-".$master_address['name']."|\n";
                                        if (str_replace(',', "", $master_address['_ref']) == $destination) {
                                            #print "FOUND address".$master_address['name']."\n";
                                            //search object in addressstore
                                            $tmp_name = str_replace(',', "", $master_address['name']);
                                            $tmp_address = $this->sub->addressStore->findOrCreate($tmp_name);
                                            // add to rule destination
                                            $tmp_rule->destination->addObject($tmp_address);
                                            PH::print_stdout($tmp_name);
                                            $tmp_found = TRUE;
                                            break;
                                        } elseif ($master_address['_ref'] == "REF_NetworkAny") {
                                            $tmp_found = TRUE;
                                            break;
                                        } else {
                                            #print "NOT FOUND\n";
                                        }
                                    }
                                    if (!$tmp_found) {
                                        if (strpos($destination, "Any") === FALSE)
                                            mwarning("   - network object not found:" . $destination . "\n");
                                        else
                                            PH::print_stdout("ANY");
                                    }
                                }
                                PH::print_stdout();
                            }

                            if (isset($policy['services'])) {
                                $tmp_found = FALSE;
                                $srv_array = explode(",", $policy['services']);
                                PH::print_stdout("- set services: ");
                                foreach ($srv_array as $service) {
                                    #print "srv_ref:".$service."\n";
                                    foreach ($master_array['service'] as $master_service) {
                                        if (str_replace(',', "", $master_service['_ref']) == $service) {
                                            #print "FOUND service".$master_service['name']."\n";
                                            //search object in servicestore
                                            $tmp_name = str_replace(',', "", $master_service['name']);

                                            $tmp_service = $this->sub->serviceStore->findOrCreate($tmp_name);
                                            // add to rule service
                                            $tmp_rule->services->add($tmp_service);
                                            PH::print_stdout($tmp_name);
                                            $tmp_found = TRUE;
                                            break;
                                        } elseif ($master_service['_ref'] == "REF_ServiceAny") {
                                            $tmp_found = TRUE;
                                            break;
                                        } else {
                                            #print "NOT FOUND\n";
                                        }

                                    }
                                    if (!$tmp_found) {
                                        if (strpos($service, "Any") === FALSE)
                                            mwarning("   - service object not found:" . $service . "\n");
                                        else
                                            PH::print_stdout("ANY");
                                    }
                                }
                                print "\n";
                            }
                        }

                        if ($rule_type === "packetfilter/nat" || $rule_type === "packetfilter/masq") {
                            //source
                            if (isset($policy['source'])) {
                                $ref_string = str_replace(',', "", $policy['source']);
                                $ref_obj_name = $this->ref_array[$ref_string];
                                $adr_object = $this->sub->addressStore->find($ref_obj_name);
                                if ($adr_object !== null)
                                    $tmp_rule->source->addObject($adr_object);
                                else
                                    mwarning("   - source object not found:" . $ref_string . "\n", null, false);
                            }
                            //destination
                            if (isset($policy['destination'])) {
                                $ref_string = str_replace(',', "", $policy['destination']);
                                $ref_obj_name = $this->ref_array[$ref_string];
                                $adr_object = $this->sub->addressStore->find($ref_obj_name);
                                if ($adr_object !== null)
                                    $tmp_rule->destination->addObject($adr_object);
                                else
                                    mwarning("   - destination object not found:" . $ref_string . "\n", null, false);
                            }
                            //service
                            if (isset($policy['service']) && !empty($policy['service'])) {
                                if ($policy['service'] !== "REF_ServiceAny,") {
                                    $ref_string = str_replace(',', "", $policy['service']);
                                    $ref_obj_name = $this->ref_array[$ref_string];
                                    $srv_object = $this->sub->serviceStore->find($ref_obj_name);
                                    /** @var NatRule $tmp_rule */
                                    $tmp_rule->setService($srv_object);
                                }

                            }
                        }


                        if (isset($policy['group'])) {
                            #print "- set tag: ";
                            $tag = $policy['group'];
                            $tag = str_replace(',', "", $tag);
                            #print "tag:|" . $tag . "|\n";
                            if ($tag != "") {
                                $tmp_tag = $this->sub->tagStore->findOrCreate($tag);
                                $tmp_rule->tags->addTag($tmp_tag);
                                PH::print_stdout("- set tag: " . $tag);

                            }
                            print "\n";
                        }


                        if ($policy['status'] == 'false,') {
                            $tmp_rule->setDisabled(TRUE);
                            PH::print_stdout("set rule to disable");
                        }
                    }

                    print_r($rule_type_array);
                }
            }

}