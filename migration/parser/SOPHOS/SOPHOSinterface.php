<?php

trait SOPHOSinterface
{
    public function interface( $master_array )
    {
        $ref_names = array();

        PH::print_stdout("**************************************");
        PH::print_stdout( "\nINTERFACE migration:\n");

        if( isset($master_array['itfparams']) )
        {
            foreach( $master_array['itfparams'] as $key => $value )
            {
                //[_type] => itfparams/link_aggregation_group,
                if( $value['_type'] == "itfparams/link_aggregation_group,")
                    continue;
                elseif( $value['_type'] == "itfparams/primary," || $value['_type'] == "itfparams/secondary," )
                {
                    $tmp_array = array();

                    $ref_name = str_replace(',', "", $value['_ref'] );
                    
                    if( isset($value['address']) )
                        $tmp_array[ $ref_name ]['address'] = str_replace(',', "", $value['address']);
                    if( isset($value['netmask']) )
                        $tmp_array[ $ref_name ]['netmask'] = str_replace(',', "", $value['netmask']);
                    if( isset($value['default_gateway_address']) )
                        $tmp_array[ $ref_name ]['default_gateway_address'] = str_replace(',', "", $value['default_gateway_address']);

                    if( isset($value['address6']) )
                        $tmp_array[ $ref_name ]['address6'] = str_replace(',', "", $value['address6']);
                    if( isset($value['netmask6']) )
                        $tmp_array[ $ref_name ]['netmask6'] = str_replace(',', "", $value['netmask6']);

                    if( isset($value['default_gateway_address6']) )
                        $tmp_array[ $ref_name ]['default_gateway_address6'] = str_replace(',', "", $value['default_gateway_address6']);

                    if( isset($value['interface_address']) )
                        $tmp_array[ $ref_name ]['interface_address'] = str_replace(',', "", $value['interface_address']);

                    if( isset($value['interface_broadcast']) )
                        $tmp_array[ $ref_name ]['interface_broadcast'] = str_replace(',', "", $value['interface_broadcast']);
                    if( isset($value['interface_network']) )
                        $tmp_array[ $ref_name ]['interface_network'] = str_replace(',', "", $value['interface_network']);
                    if( isset($value['comment']) )
                        $tmp_array[ $ref_name ]['comment'] = str_replace(',', "", $value['comment']);
                    if( isset($value['name']) )
                        $tmp_array[ $ref_name ]['name'] = str_replace(',', "", $value['name']);

                    if( isset($value['type']) )
                        $tmp_array[ $ref_name ]['type'] = str_replace(',', "", $value['type']);
                    if( isset($value['status']) )
                        $tmp_array[ $ref_name ]['status'] = str_replace(',', "", $value['status']);

                    $this->sub->addressStore->newAddress( $ref_name, "ip-netmask", $tmp_array[ $ref_name ]['address']."/".$tmp_array[ $ref_name ]['netmask'] );

                    $ref_names = array_merge( $ref_names, $tmp_array );
                    #print_r( $tmp_array );
                    /*
                        [_locked] => ,
                        [_ref] => REF_ItfPri10661321292,
                        [_type] => itfparams/primary,
                        [address] => 10.66.132.129,
                        [address6] => ::,
                        [comment] => ,
                        [default_gateway_address] => 0.0.0.0,
                        [default_gateway_address6] => ,
                        [default_gateway_status] => false,
                        [default_gateway_status6] => false,
                        [dhcpv6_rapid_commit] => false,
                        [dns_server_1] => 0.0.0.0,
                        [dns_server_2] => 0.0.0.0,
                        [dns_server_3] => ::,
                        [dns_server_4] => ::,
                        [gateway_type] => static,
                        [gateway_type6] => static,
                        [hostname] => ,
                        [interface_address] => REF_NetIntDmzawAddre4,
                        [interface_broadcast] => REF_NetIntDmzawBroad4,
                        [interface_network] => REF_NetIntDmzawNetwo4,
                        [name] => 10.66.132.129/25 (2),
                        [netmask] => 25,
                        [netmask6] => 0,
                        [pd_address6] => ,
                        [pd_netmask6] => 0,
                        [pd_resolved6] => false,
                        [resolved] => true,
                        [resolved6] => false,
                        [six2four] => false,
                        [type] => static,
                        [type6] => static
                     */

                    /*
                    if( isset($value['address']) )
                    {
                        $itf_addressv4 = str_replace(',', "", $value['address'] );
                        $itf_netmask4 = str_replace(',', "", $value['netmask'] );

                        print "IPv4: ".$itf_addressv4."/".$itf_netmask4."\n";
                    }

                    if( isset($value['address6']) )
                    {
                        $itf_addressv6 = str_replace(',', "", $value['address6'] );
                        $itf_netmask6 = str_replace(',', "", $value['netmask6'] );

                        if( $itf_addressv6 !== "::" && $itf_netmask6 !== "0")
                            print "IPv6: ".$itf_addressv6."/".$itf_netmask6."\n";
                    }
                    */
                }

            }
        }

        #print_r( $ref_names );

        if( isset($master_array['interface']) )
        {
            $itfhw_array = array();

            foreach( $master_array['interface'] as $key => $value )
            {
                if( $value['_type'] === 'interface/ethernet,' )
                {
                    #print_r($value);
                    /*
                    Array
                    (
                        [_locked] => ,
                        [_ref] => REF_IntEthDslavMail0,
                        [_type] => interface/ethernet,
                        [additional_addresses] => REF_ItfSecMobilekkhe,REF_ItfSecSophosmobi2,REF_ItfSecNextcloudd
                        [bandwidth] => 0,
                        [comment] => DSL-redundant LWL/Funkstrecke,
                        [inbandwidth] => 0,
                        [itfhw] => REF_ItfEthEth15A6Intel,
                        [link] => true,
                        [mtu] => 1500,
                        [mtu_auto_discovery] => true,
                        [name] => DSL-Plusnet1,
                        [outbandwidth] => 0,
                        [primary_address] => REF_ItfPri62156254232,
                        [proxyarp] => false,
                        [proxyndp] => false,
                        [status] => true
                    )
                     */

                    $ref_name = str_replace(',', "", $value['_ref'] );

                    $int_name = str_replace(',', "", $value['itfhw']);
                    $this->ref_array[$ref_name] = $int_name;

                    $itfhw_array[$int_name] = $ref_name;


                    /** @var EthernetInterface $newInterface */
                    PH::print_stdout(" - create EthernetInterface: ".$int_name );
                    $newInterface = $this->template->network->ethernetIfStore->newEthernetIf( $int_name, "layer3" );
                    $this->sub->importedInterfaces->addInterface($newInterface);

                    $int_primary = str_replace(',', "", $value['primary_address']);
                    $tmp_address = $ref_names[$int_primary]['address']."/".$ref_names[$int_primary]['netmask'];

                    print "primary_IP_REF:".$int_primary." | address: ".$tmp_address."\n";

                    #print_r( $ref_names[$int_primary] );
                    /*
                         [address] => 10.66.0.9
                        [netmask] => 29
                        [default_gateway_address] => 0.0.0.0
                        [address6] => ::
                        [netmask6] => 0
                        [default_gateway_address6] =>
                        [interface_address] => REF_NetIntTransVpnGwAddre
                        [interface_broadcast] => REF_NetIntTransVpnGwBroad
                        [interface_network] => REF_NetIntTransVpnGwNetwo
                        [comment] =>
                        [name] => 10.65.0.241/29
                        [type] => static
                     */
                    $newInterface->addIPv4Address($tmp_address);
                    if( $ref_names[$int_primary]['address6'] !== "::" && $ref_names[$int_primary]['netmask6'] !== "0" )
                    {
                        $tmp_address6 = $ref_names[$int_primary]['address6']."/".$ref_names[$int_primary]['netmask6'];
                        PH::print_stdout( "IPv6: ".$tmp_address6 );
                        $newInterface->addIPv6Address($tmp_address6);
                    }


                    if( isset($value['default_gateway_address']) )
                    {
                        $int_default_gw = str_replace(',', "", $value['default_gateway_address']);
                        if( $int_default_gw !== "0.0.0.0" )
                        {
                            //Todo: add static default rout to Router "default"

                            //if default route is already available created "default-2"
                            //if default-2 is already available create "default-1+x" if available
                        }
                    }

                    if( isset($value['additional_addresses']) )
                    {
                        $int_additional_string = $value['additional_addresses'];
                        $int_additional_array = explode(',', $int_additional_string);
                        print "additional_IPs_REF:"."";
                        print implode(",", $int_additional_array)."\n";
                        foreach( $int_additional_array as $key_additional_string => $int_additional )
                        {
                            #print_r( $ref_names[$int_additional ] );
                            $tmp_address = $ref_names[$int_additional]['address']."/".$ref_names[$int_additional]['netmask'];
                            PH::print_stdout( "IPv4: ".$tmp_address);
                            $newInterface->addIPv4Address($tmp_address );
                            if( $ref_names[$int_additional]['address6'] !== "::" && $ref_names[$int_additional]['netmask6'] !== "0" )
                            {
                                $tmp_address6 = $ref_names[$int_primary]['address6']."/".$ref_names[$int_primary]['netmask6'];
                                PH::print_stdout( "IPv6: ".$tmp_address6);
                                $newInterface->addIPv6Address($tmp_address6);
                            }

                        }
                    }

                }
                elseif( $value['_type'] === 'interface/vlan,' )
                {
                    $int_name = str_replace(',', "", $value['itfhw']);

                    $this->ref_array[$ref_name] = $int_name;
                    $itfhw_array[$int_name] = $ref_name;

                    /** @var EthernetInterface $newInterface */
                    $MainInterface = $this->template->network->ethernetIfStore->find( $int_name, "layer3" );

                    if( $MainInterface === null )
                    {
                        PH::print_stdout(" - create EthernetInterface: ".$int_name );
                        $MainInterface = $this->template->network->ethernetIfStore->newEthernetIf( $int_name, "layer3" );
                        $this->sub->importedInterfaces->addInterface($newInterface);
                    }
                    PH::print_stdout("found Interface: ".$MainInterface->name());

                    #print_r( $value );
                    /*
                     * [_locked] => ,
                        [_ref] => REF_IntVlaDmzavisusd,
                        [_type] => interface/vlan,
                        [bandwidth] => 0,
                        [comment] => Visus Dirty-PACs,
                        [inbandwidth] => 0,
                        [itfhw] => REF_ItfEthEth10A1Intel,
                        [link] => true,
                        [macvlan] => false,
                        [mtu] => 1500,
                        [mtu_auto_discovery] => true,
                        [name] => TRANS_Visus-DMZ-a,
                        [outbandwidth] => 0,
                        [primary_address] => REF_ItfPri106681330,
                        [proxyarp] => false,
                        [proxyndp] => false,
                        [status] => true,
                        [vlantag] => 811
                     */
                    PH::print_stdout(" - EthernetInterface: ".$MainInterface->name(). " add subinterface: ".$value['vlantag'] );
                    $newInterface = $MainInterface->addSubInterface( $value['vlantag'] );
                    $this->sub->importedInterfaces->addInterface($newInterface);

                    /** @var VirtualSystem $dummy_sub */
                    $dummy_sub = $this->sub;
                    $tmp_zone = $dummy_sub->zoneStore->newZone( "v".$value['vlantag'], "layer3" );
                    $tmp_zone->attachedInterfaces->addInterface($newInterface);

                    $dummy_template = $this->template->network;
                    /** @var NetworkPropertiesContainer $dummy_template*/
                    $tmp_router = $dummy_template->virtualRouterStore->findOrCreate("default");
                    $tmp_router->attachedInterfaces->addInterface($newInterface);



                    $int_primary = str_replace(',', "", $value['primary_address']);
                    print "primary_IP_REF:".$int_primary."\n";
                    $newInterface->addIPv4Address($ref_names[$int_primary]['address']."/".$ref_names[$int_primary]['netmask']);
                    if( $ref_names[$int_primary]['address6'] !== "::" && $ref_names[$int_primary]['netmask6'] !== "0" )
                        $newInterface->addIPv6Address($ref_names[$int_primary]['address6']."/".$ref_names[$int_primary]['netmask6']);

                    if( isset($value['additional_string']) )
                    {
                        $int_additional_string = $value['additional_string'];
                        $int_additional_array = explode(',', $int_additional_string);
                        print "additional_IPs_REF:"."\n";
                        #print_r($int_additional_array);
                        foreach( $int_additional_array as $key_additional_string => $int_additional )
                        {
                            #print_r( $ref_names[$int_additional ] );
                            $newInterface->addIPv4Address($ref_names[$int_additional]['address']."/".$ref_names[$int_additional]['netmask']);
                            if( $ref_names[$int_additional]['address6'] !== "::" && $ref_names[$int_additional]['netmask6'] !== "0" )
                                $newInterface->addIPv6Address($ref_names[$int_primary]['address6']."/".$ref_names[$int_primary]['netmask6']);
                        }
                    }

                }
                elseif( $value['_type'] === 'interface/group,' )
                {
                    //group import????
                    print_r($value);
                    $ref_name = str_replace(',', "", $value['_ref'] );

                    if( isset($value['members']) )
                    {
                        $int_name = str_replace(',', "", $value['members'][0]);
                        $this->ref_array[$ref_name] = $int_name;
                    }
                }
            }

            #print_r($itfhw_array);


        }
    }
}