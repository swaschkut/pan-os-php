<?php

trait SOPHOSroute
{
    public function route( $master_array )
    {
        $ref_names = array();

        PH::print_stdout("**************************************");
        PH::print_stdout( "\nROUTE  migration:\n");


        if( isset($master_array['route']) )
        {

            foreach( $master_array['route'] as $key => $value )
            {
                if( $value['_type'] === "route/static," )
                {
                    #print_r( $value );

                    $route_name = str_replace(',', "", $value['name']);
                    $route_comment = str_replace(',', "", $value['comment']);
                    $route_metric = str_replace(',', "", $value['metric']);

                    //of type ADDRESS/ADDRRESSgroup if type host
                    $route_network = str_replace(',', "", $value['network']);
                    $route_status = str_replace(',', "", $value['status']);

                    //of type ADDRESS/ADDRESSGroup if type host
                    $route_target = str_replace(',', "", $value['target']);

                    //host - itf
                    $route_type = str_replace(',', "", $value['type']);

                    //search virtueal router 'default'
                    if( $route_type === "host" )
                    {
                        if(  $this->useLogicalRouter )
                            $new_router = $this->template->network->logicalRouterStore->findVirtualRouter("default");
                        else
                            $new_router = $this->template->network->virtualRouterStore->findVirtualRouter("default");
                        if( $new_router === null )
                        {
                            if(  $this->useLogicalRouter )
                                $new_router = $this->template->network->logicalRouterStore->newLogicalRouter("default");
                            else
                                $new_router = $this->template->network->virtualRouterStore->newVirtualRouter("default");
                        }


                        $routename = $route_name;

                        if( isset($this->ref_array[$route_target]) )
                            $tmp_route_target_name = $this->ref_array[$route_target];
                        else
                            derr( "ref_name route target: '".$route_target."' - not found" );
                        $obj_ip_gateway = $this->sub->addressStore->find( $tmp_route_target_name );
                        if( $obj_ip_gateway !== null )
                            $ip_gateway = $obj_ip_gateway->value();
                        else
                            derr( "route target: '".$route_target."' - not found" );

                        $metric = $route_metric;

                        if( isset($this->ref_array[$route_network]) )
                            $tmp_route_network_name = $this->ref_array[$route_network];
                        else
                            derr( "ref_name route network: '".$route_network."' - not found" );
                        $obj_route_network = $this->sub->addressStore->find( $tmp_route_network_name );
                        /** @var Address|AddressGroup $obj_route_network*/
                        if( $obj_route_network !== null )
                        {
                            if( $obj_route_network->isAddress() )
                            {
                                $route_network = $obj_route_network->value();
                                if( strpos($route_network, "/") === FALSE )
                                {
                                    $route_network .= "/32";
                                }
                                //------------

                                $xml_interface = "dummy";

                                #if( $ipfamiliy_node->textContent == "IPv4" )
                                $xmlString = "<entry name=\"" . $routename . "\"><nexthop><ip-address>" . $ip_gateway . "</ip-address></nexthop><metric>" . $metric . "</metric>" . $xml_interface . "<destination>" . $route_network . "</destination></entry>";
                                #elseif( $ipfamiliy_node->textContent == "IPv6" )
                                #    $xmlString = "<entry name=\"" . $routename . "\"><nexthop><ipv6-address>" . $ip_gateway . "</ipv6-address></nexthop><metric>" . $metric . "</metric>" . $xml_interface . "<destination>" . $route_network . "</destination></entry>";


                                $newRoute = new StaticRoute('***tmp**', $new_router);
                                $tmpRoute = $newRoute->create_staticroute_from_xml($xmlString);

                                $new_router->addstaticRoute($tmpRoute);
                            }

                            elseif( $obj_route_network->isGroup() )
                            {
                                $members = $obj_route_network->expand(FALSE, $tmp_array, $obj_route_network->owner->owner);
                                foreach( $members as $member )
                                    $resolve[] = $member;


                                foreach( $resolve as $key => $member )
                                {
                                    $routename = $route_name."_".$key;

                                    /** @var Address $member */
                                    if( $member->isAddress() )
                                    {
                                        if( $member->isType_FQDN() )
                                            $route_network = $member->name();
                                        elseif( $member->isType_ipNetmask() )
                                        {
                                            $route_network = $member->value();
                                            if( strpos($route_network, "/") === FALSE )
                                            {
                                                $route_network .= "/32";
                                            }
                                        }

                                    }

                                    elseif( $member->isType_FQDN() )
                                        $route_network = $member->name();
                                    //------------

                                    if( $route_network === "::/0" || $route_network === "0.0.0.0/0" )
                                        continue;

                                    $xml_interface = "dummy";

                                    #if( $ipfamiliy_node->textContent == "IPv4" )
                                    $xmlString = "<entry name=\"" . $routename . "\"><nexthop><ip-address>" . $ip_gateway . "</ip-address></nexthop><metric>" . $metric . "</metric>" . $xml_interface . "<destination>" . $route_network . "</destination></entry>";
                                    #elseif( $ipfamiliy_node->textContent == "IPv6" )
                                    #    $xmlString = "<entry name=\"" . $routename . "\"><nexthop><ipv6-address>" . $ip_gateway . "</ipv6-address></nexthop><metric>" . $metric . "</metric>" . $xml_interface . "<destination>" . $route_network . "</destination></entry>";


                                    $newRoute = new StaticRoute('***tmp**', $new_router);
                                    $tmpRoute = $newRoute->create_staticroute_from_xml($xmlString);

                                    $new_router->addstaticRoute($tmpRoute);
                                }
                            }
                        }

                        else
                            derr( "route network: '".$route_network."' - not found" );



                    }
                }
                elseif( $value['_type'] === "route/policy," )
                {
                    #print_r( $value );
                }

            }

        }
    }
}