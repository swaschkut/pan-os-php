<?php
/**
 * ISC License
 *
 * Copyright (c) 2019, Palo Alto Networks Inc.
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

class NETWORKUTIL extends UTIL
{
    public function utilStart()
    {
        $this->utilInit();

        $this->utilActionFilter();


        $this->location_filter_object();


        $this->time_to_process_objects();


        $this->GlobalFinishAction();

        PH::print_stdout();
        PH::print_stdout( " **** PROCESSED $this->totalObjectsProcessed objects over {$this->totalObjectsOfSelectedStores} available ****" );
        PH::print_stdout();
        PH::print_stdout();

        $this->stats();

        $this->save_our_work(TRUE);

        $runtime = number_format((microtime(TRUE) - $this->runStartTime), 2, '.', '');
        PH::print_stdout( array( 'value' => $runtime, 'type' => "seconds" ), false,'runtime' );

        if( PH::$shadow_json )
        {
            PH::$JSON_OUT['log'] = PH::$JSON_OUTlog;
            //print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );
        }
    }


    public function location_filter_object()
    {
        $sub = null;

        foreach( $this->objectsLocation as $location )
        {
            $locationFound = FALSE;

            if( $this->configType == 'panos' )
            {
                #if( $location == 'shared' || $location == 'any' || $location == 'all' )
                if( $location == 'shared' || $location == 'any' )
                {
                    if( $this->utilType == 'virtualwire' )
                        $this->objectsToProcess[] = Array('store' => $this->pan->network->virtualWireStore, 'objects' => $this->pan->network->virtualWireStore->virtualWires());
                    elseif( $this->utilType == 'interface' )
                        $this->objectsToProcess[] = Array('store' => $this->pan->network, 'objects' => $this->pan->network->getAllInterfaces());
                    elseif( $this->utilType == 'routing' && !$this->pan->_advance_routing_enabled )
                        $this->objectsToProcess[] = Array('store' => $this->pan->network->virtualRouterStore, 'objects' => $this->pan->network->virtualRouterStore->getAll());
                    elseif( $this->utilType == 'routing' && $this->pan->_advance_routing_enabled )
                        $this->objectsToProcess[] = Array('store' => $this->pan->network->logicalRouterStore, 'objects' => $this->pan->network->logicalRouterStore->getAll());
                    elseif( $this->utilType == 'dhcp' )
                        $this->objectsToProcess[] = Array('store' => $this->pan->network->dhcpStore, 'objects' => $this->pan->network->dhcpStore->getAll());
                    elseif( $this->utilType == 'zone' )
                    {
                        //zone store only in vsys available
                    }
                    elseif( $this->utilType == 'certificate' )
                    {
                        $this->objectsToProcess[] = Array('store' => $this->pan->certificateStore, 'objects' => $this->pan->certificateStore->getAll());
                    }
                    elseif( $this->utilType == 'static-route' && !$this->pan->_advance_routing_enabled )
                    {
                        foreach($this->pan->network->virtualRouterStore->getAll() as $vr )
                            $this->objectsToProcess[] = Array('store' => $vr, 'objects' => $vr->staticRoutes());
                    }
                    elseif( $this->utilType == 'static-route' && $this->pan->_advance_routing_enabled )
                    {
                        foreach($this->pan->network->logicalRouterStore->getAll() as $vr )
                            $this->objectsToProcess[] = Array('store' => $vr, 'objects' => $vr->staticRoutes());
                    }
                    elseif( $this->utilType == 'gp-gateway' )
                    {
                        //gpgateway store only in vsys available
                    }
                    elseif( $this->utilType == 'gp-portal' )
                    {
                        //gpportal store only in vsys available
                    }
                    elseif( $this->utilType == 'ike-profile' )
                    {
                        $this->objectsToProcess[] = Array('store' => $this->pan->network->ikeCryptoProfileStore, 'objects' => $this->pan->network->ikeCryptoProfileStore->ikeCryptoProfil());
                    }
                    elseif( $this->utilType == 'ike-gateway' )
                    {
                        $this->objectsToProcess[] = Array('store' => $this->pan->network->ikeGatewayStore, 'objects' => $this->pan->network->ikeGatewayStore->gateways());
                    }
                    elseif( $this->utilType == 'ipsec-profile' )
                    {
                        $this->objectsToProcess[] = Array('store' => $this->pan->network->ipsecCryptoProfileStore, 'objects' => $this->pan->network->ipsecCryptoProfileStore->ipsecCryptoProfil());
                    }
                    elseif( $this->utilType == 'ipsec-tunnel' )
                    {
                        $this->objectsToProcess[] = Array('store' => $this->pan->network->ipsecTunnelStore, 'objects' => $this->pan->network->ipsecTunnelStore->tunnels());
                    }
                    elseif( $this->utilType == 'gre-tunnel' )
                    {
                        $this->objectsToProcess[] = Array('store' => $this->pan->network->greTunnelStore, 'objects' => $this->pan->network->greTunnelStore->tunnels());
                    }
                    elseif( $this->utilType == 'gpgateway-tunnel' )
                    {
                        $this->objectsToProcess[] = Array('store' => $this->pan->network->gpGatewayTunnelStore, 'objects' => $this->pan->network->gpGatewayTunnelStore->tunnels());
                    }

                    $locationFound = TRUE;
                }


                foreach( $this->pan->getVirtualSystems() as $sub )
                {
                    if( isset(PH::$args['loadpanoramapushedconfig']) )
                    {

                        if( ($location == 'any' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                        {
                            if( $this->utilType == 'virtualwire' )
                            {}
                            elseif( $this->utilType == 'interface' )
                            {}
                            elseif( $this->utilType == 'routing' )
                            {}
                            elseif( $this->utilType == 'zone' )
                            {}
                            elseif( $this->utilType == 'dhcp' )
                            {}
                            elseif( $this->utilType == 'certificate' )
                            {}
                            elseif( $this->utilType == 'gp-gateway' )
                            {}
                            elseif( $this->utilType == 'gp-portal' )
                            {}
                            elseif( $this->utilType == 'ike-profile' )
                            {}
                            elseif( $this->utilType == 'ike-gateway' )
                            {}
                            elseif( $this->utilType == 'ipsec-profile' )
                            {}
                            elseif( $this->utilType == 'ipsec-tunnel' )
                            {}

                            $locationFound = TRUE;
                        }
                    }
                    else
                    {
                        if( ($location == 'any' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                        {
                            if( $this->utilType == 'virtualwire' )
                            {}
                            elseif( $this->utilType == 'interface' )
                                $this->objectsToProcess[] = Array('store' => $sub->importedInterfaces, 'objects' => $sub->importedInterfaces->getAll());
                            elseif( $this->utilType == 'routing' )
                            {}
                            elseif( $this->utilType == 'zone' )
                                $this->objectsToProcess[] = array('store' => $sub->zoneStore, 'objects' => $sub->zoneStore->getall());
                            elseif( $this->utilType == 'dhcp' )
                            {}
                            elseif( $this->utilType == 'certificate' )
                                $this->objectsToProcess[] = Array('store' => $sub->certificateStore, 'objects' => $sub->certificateStore->getAll());
                            elseif( $this->utilType == 'gp-gateway' )
                                $this->objectsToProcess[] = array('store' => $sub->GPGatewayStore, 'objects' => $sub->GPGatewayStore->getall());
                            elseif( $this->utilType == 'gp-portal' )
                                $this->objectsToProcess[] = array('store' => $sub->GPPortalStore, 'objects' => $sub->GPPortalStore->getall());
                            elseif( $this->utilType == 'ike-profile' )
                            {}
                            elseif( $this->utilType == 'ike-gateway' )
                            {}
                            elseif( $this->utilType == 'ipsec-profile' )
                            {}
                            elseif( $this->utilType == 'ipsec-tunnel' )
                            {}

                            $locationFound = TRUE;
                        }
                    }

                    self::GlobalInitAction($sub);
                }

                foreach( $this->pan->getSharedGateways() as $sub )
                {
                    if( ($location == 'any' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                    {
                        if( $this->utilType == 'virtualwire' )
                        {}
                        elseif( $this->utilType == 'interface' )
                            $this->objectsToProcess[] = Array('store' => $sub->importedInterfaces, 'objects' => $sub->importedInterfaces->getAll());
                        elseif( $this->utilType == 'routing' )
                        {}
                        elseif( $this->utilType == 'zone' )
                            $this->objectsToProcess[] = array('store' => $sub->zoneStore, 'objects' => $sub->zoneStore->getall());
                        elseif( $this->utilType == 'dhcp' )
                        {}
                        elseif( $this->utilType == 'certificate' )
                            $this->objectsToProcess[] = Array('store' => $sub->certificateStore, 'objects' => $sub->certificateStore->getAll());
                        elseif( $this->utilType == 'gp-gateway' )
                            $this->objectsToProcess[] = array('store' => $sub->GPGatewayStore, 'objects' => $sub->GPGatewayStore->getall());
                        elseif( $this->utilType == 'gp-portal' )
                            $this->objectsToProcess[] = array('store' => $sub->GPPortalStore, 'objects' => $sub->GPPortalStore->getall());
                        elseif( $this->utilType == 'ike-profile' )
                        {}
                        elseif( $this->utilType == 'ike-gateway' )
                        {}
                        elseif( $this->utilType == 'ipsec-profile' )
                        {}
                        elseif( $this->utilType == 'ipsec-tunnel' )
                        {}

                        $locationFound = TRUE;
                    }

                    self::GlobalInitAction($sub);
                }
            }
            else
            {
                if( $this->configType == 'panorama' )
                    $subGroups = $this->pan->getDeviceGroups();
                elseif( $this->configType == 'fawkes' )
                {
                    $subGroups = $this->pan->getContainers();
                    $subGroups2 = $this->pan->getDeviceClouds();

                    $subGroups = array_merge( $subGroups, $subGroups2 );

                    $subGroups2 = $this->pan->getDeviceOnPrems();
                    $subGroups = array_merge( $subGroups, $subGroups2 );

                    $subGroups2 = $this->pan->getSnippets();
                    $subGroups = array_merge( $subGroups, $subGroups2 );
                }

                if( $this->configType == 'panorama' )
                {
                    $mergedTemplateAndStack = $this->pan->templates;
                    $mergedTemplateAndStack = array_merge( $mergedTemplateAndStack, $this->pan->templatestacks );

                    //foreach( $this->pan->templates as $template )
                    foreach( $mergedTemplateAndStack as $template )
                    {
                        if( $this->templateName == 'any' || $this->templateName == $template->name() )
                        {
                            if( $location == 'shared' || $location == 'any'  )
                            {
                                if( $this->utilType == 'virtualwire' )
                                    $this->objectsToProcess[] = Array('store' => $template->deviceConfiguration->network->virtualWireStore, 'objects' => $template->deviceConfiguration->network->virtualWireStore->virtualWires());
                                elseif( $this->utilType == 'interface' )
                                    $this->objectsToProcess[] = Array('store' => $template->deviceConfiguration->network, 'objects' => $template->deviceConfiguration->network->getAllInterfaces());
                                elseif( $this->utilType == 'routing' )
                                    $this->objectsToProcess[] = Array('store' => $template->deviceConfiguration->network->virtualRouterStore, 'objects' => $template->deviceConfiguration->network->virtualRouterStore->getAll());
                                elseif( $this->utilType == 'zone' )
                                {
                                    //zone store only in vsys available
                                }
                                elseif( $this->utilType == 'dhcp' )
                                    $this->objectsToProcess[] = Array('store' => $template->deviceConfiguration->network->dhcpStore, 'objects' => $template->deviceConfiguration->network->dhcpStore->getAll());
                                elseif( $this->utilType == 'certificate' )
                                {
                                    $this->objectsToProcess[] = Array('store' => $template->certificateStore, 'objects' => $template->certificateStore->getAll());
                                }
                                elseif( $this->utilType == 'static-route' )
                                {
                                    foreach($template->deviceConfiguration->network->virtualRouterStore->getAll() as $vr )
                                        $this->objectsToProcess[] = Array('store' => $vr, 'objects' => $vr->staticRoutes());
                                }
                                elseif( $this->utilType == 'gp-gateway' )
                                {
                                    //gpgateway store only in vsys available
                                }
                                elseif( $this->utilType == 'gp-portal' )
                                {
                                    //gpportal store only in vsys available
                                }
                                elseif( $this->utilType == 'ike-profile' )
                                {
                                    $this->objectsToProcess[] = Array('store' => $template->deviceConfiguration->network->ikeCryptoProfileStore, 'objects' => $template->deviceConfiguration->network->ikeCryptoProfileStore->ikeCryptoProfil());
                                }
                                elseif( $this->utilType == 'ike-gateway' )
                                {
                                    $this->objectsToProcess[] = Array('store' => $template->deviceConfiguration->network->ikeGatewayStore, 'objects' => $template->deviceConfiguration->network->ikeGatewayStore->gateways());
                                }
                                elseif( $this->utilType == 'ipsec-profile' )
                                {
                                    $this->objectsToProcess[] = Array('store' => $template->deviceConfiguration->network->ipsecCryptoProfileStore, 'objects' => $template->deviceConfiguration->network->ipsecCryptoProfileStore->ipsecCryptoProfil());
                                }
                                elseif( $this->utilType == 'ipsec-tunnel' )
                                {
                                    $this->objectsToProcess[] = Array('store' => $template->deviceConfiguration->network->ipsecTunnelStore, 'objects' => $template->deviceConfiguration->network->ipsecTunnelStore->tunnels());
                                }
                                elseif( $this->utilType == 'gre-tunnel' )
                                {
                                    $this->objectsToProcess[] = Array('store' => $template->deviceConfiguration->network->greTunnelStore, 'objects' => $template->deviceConfiguration->network->greTunnelStore->tunnels());
                                }
                                elseif( $this->utilType == 'gpgateway-tunnel' )
                                {
                                    $this->objectsToProcess[] = Array('store' => $template->deviceConfiguration->network->gpGatewayTunnelStore, 'objects' => $template->deviceConfiguration->network->gpGatewayTunnelStore->tunnels());
                                }

                                $locationFound = true;
                            }

                            foreach( $template->deviceConfiguration->getVirtualSystems() as $sub )
                            {
                                if( ($location == 'any' || $location == $sub->name()) && !isset($util->objectsToProcess[$sub->name() . '%pre']) )
                                {
                                    if( $this->utilType == 'virtualwire' )
                                    {}
                                    elseif( $this->utilType == 'interface' )
                                        $this->objectsToProcess[] = array('store' => $sub->importedInterfaces, 'objects' => $sub->importedInterfaces->getAll());
                                    elseif( $this->utilType == 'routing' )
                                    {}
                                    elseif( $this->utilType == 'zone' )
                                        $this->objectsToProcess[] = array('store' => $sub->zoneStore, 'objects' => $sub->zoneStore->getall());
                                    elseif( $this->utilType == 'dhcp' )
                                    {}
                                    elseif( $this->utilType == 'certificate' )
                                        $this->objectsToProcess[] = Array('store' => $sub->certificateStore, 'objects' => $sub->certificateStore->getAll());
                                    elseif( $this->utilType == 'gp-gateway' )
                                        $this->objectsToProcess[] = array('store' => $sub->GPGatewayStore, 'objects' => $sub->GPGatewayStore->getall());
                                    elseif( $this->utilType == 'gp-portal' )
                                        $this->objectsToProcess[] = array('store' => $sub->GPPortalStore, 'objects' => $sub->GPPortalStore->getall());

                                    $locationFound = TRUE;
                                }
                            }
                        }

                    }

                    foreach( $this->pan->templatestacks as $templatestack )
                    {
                        if( $this->templateName == 'any' || $this->templateName == $templatestack->name() )
                        {
                            if( $location == 'shared' || $location == 'any' )
                            {
                                if( $this->utilType == 'certificate' )
                                    $this->objectsToProcess[] = Array('store' => $templatestack->certificateStore, 'objects' => $templatestack->certificateStore->getAll());
                            }
                        }
                    }
                }
                else
                {
                    foreach( $subGroups as $sub )
                    {
                        #if( ($location == 'any' || $location == 'all' || $location == $sub->name()) && !isset($ruleStoresToProcess[$sub->name() . '%pre']) )
                        if( ($location == 'any' || $location == $sub->name()) && !isset($ruleStoresToProcess[$sub->name() . '%pre']) )
                        {
                            #if( $this->utilType == 'interface' )
                            #    $this->objectsToProcess[] = Array('store' => $sub->deviceConfiguration->network, 'objects' => $sub->deviceConfiguration->network->getAllInterfaces());

                            /*
                            if( get_class($sub) === "Container" )
                                continue;
                            foreach( $sub->deviceConfiguration->getVirtualSystems() as $vsys )
                                if( $this->utilType == 'certificate' )
                                    $this->objectsToProcess[] = Array('store' => $vsys->certificateStore, 'objects' => $vsys->certificateStore->getAll());
                            */
                        }
                    }
                }


            }

            #if( !$locationFound )
            #    self::locationNotFound($location, $this->configType, $this->pan);
        }
    }

}