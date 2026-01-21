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

trait transfer_template
{

    static public $plugin_cfg_onboarding_entry_nodes = null;
    static public $tpl_config_node  = null;
    static public $tpl_cfg_shared_node  = null;
    static public $tpl_devices_node  = null;
    static public $tpl_config_device_entry_node  = null;
    static public $tpl_config_device_network_node  = null;
    static public $tpl_cfg_network_interface_node  = null;
    static public $tpl_cfg_network_interface_ethernet_node  = null;
    static public $tpl_cfg_network_ike_node  = null;
    static public $tpl_config_device_entry_network_tunnel_node  = null;
    static public $tpl_config_device_entry_network_tunnel_ipsec_node  = null;
    static public $tpl_cfg_network_tunnel_global_protect_gateway_node  = null;

    static public $tpl_cfg_vsys_node  = null;
    static public $tpl_cfg_vsys_entry_node  = null;
    static public $tpl_vsys_gp  = null;

    static public $tpl_gp_gw  = null;
    static public $tpl_gp_portal  = null;

    static public $gp_portal_default  = null;
    static public $tpl_gp_portal_config  = null;

    static public $tpl_cfg_device_config_node = null;
    
    
    
    function template_path_settings( $tpl_cfg, $plugin_xmlroot = null, $mode = "old" )
    {
        if( $plugin_xmlroot != null )
        {
            $tmp = DH::findFirstElement( "onboarding", $plugin_xmlroot );
            if( $tmp !== false )
                self::$plugin_cfg_onboarding_entry_nodes = DH::findFirstElement( "entry", $tmp );
        }

        if( $mode == "old" )
        {
            self::$tpl_config_node = DH::findFirstElement( "config", $tpl_cfg );
            if( self::$tpl_config_node !== false )
            {
                self::$tpl_cfg_shared_node = DH::findFirstElementOrCreate( "shared", self::$tpl_config_node);
                self::$tpl_devices_node = DH::findFirstElement( "devices", self::$tpl_config_node );
                self::$tpl_config_device_entry_node = DH::findFirstElement( "entry", self::$tpl_devices_node );
            }
        }
        else
            self::$tpl_config_device_entry_node =  $tpl_cfg;

        if( self::$tpl_config_device_entry_node !== false && self::$tpl_config_device_entry_node !== null )
        {
            ////////////////////////////////
            //NETWORK section
            self::$tpl_config_device_network_node = DH::findFirstElementOrCreate( "network", self::$tpl_config_device_entry_node );

            self::$tpl_cfg_network_interface_node = DH::findFirstElementOrCreate( "interface", self::$tpl_config_device_network_node );
            self::$tpl_cfg_network_interface_ethernet_node = DH::findFirstElementOrCreate( "ethernet", self::$tpl_cfg_network_interface_node );

            self::$tpl_cfg_network_ike_node = DH::findFirstElementOrCreate( "ike", self::$tpl_config_device_network_node );

            //not needed for RN
            self::$tpl_config_device_entry_network_tunnel_node = DH::findFirstElementOrCreate( "tunnel", self::$tpl_config_device_network_node );
            self::$tpl_config_device_entry_network_tunnel_ipsec_node = DH::findFirstElementOrCreate( "ipsec", self::$tpl_config_device_entry_network_tunnel_node );

            self::$tpl_cfg_network_tunnel_global_protect_gateway_node = DH::findFirstElementOrCreate( "global-protect-gateway", self::$tpl_config_device_entry_network_tunnel_node );


            ////////////////////////////////
            //VSYS section
            self::$tpl_cfg_vsys_node = DH::findFirstElementOrCreate( "vsys", self::$tpl_config_device_entry_node );
            self::$tpl_cfg_vsys_entry_node = DH::findFirstElementOrCreate( "entry", self::$tpl_cfg_vsys_node );
            self::$tpl_vsys_gp = DH::findFirstElementOrCreate( "global-protect", self::$tpl_cfg_vsys_entry_node );

            self::$tpl_gp_gw = DH::findFirstElementOrCreate( "global-protect-gateway", self::$tpl_vsys_gp );
            self::$tpl_gp_portal = DH::findFirstElementOrCreate( "global-protect-portal", self::$tpl_vsys_gp );

            self::$gp_portal_default = DH::findFirstElementByNameAttr( 'entry', 'GlobalProtect_Portal', self::$tpl_gp_portal );


            if( self::$gp_portal_default !== null )
            {
                self::$tpl_gp_portal_config = DH::findFirstElement( "portal-config", self::$gp_portal_default );
            }



            $tmp = DH::findFirstElement( "entry", self::$tpl_gp_portal );
            if( $tmp != null )
                $tmp = DH::findFirstElement( "portal-config", $tmp );




            ////////////////////////////////
            //DEVICECONFIG
            self::$tpl_cfg_device_config_node = DH::findFirstElementOrCreate( "deviceconfig", self::$tpl_config_device_entry_node );
        }
    }


    function stage_shared()
    {
        $tpl_cfg_shared_log_settings_node = DH::findFirstElementOrCreate("log-settings", self::$tpl_cfg_shared_node);

        /*
         * IS THIS ONLY needed in MU section?????
         * */
        $tpl_cfg_shared_log_settings_hipmatch_node = DH::findFirstElementOrCreate("hipmatch", $tpl_cfg_shared_log_settings_node);
        $tpl_cfg_shared_log_settings_hipmatch_match_list_node = DH::findFirstElementOrCreate("match-list", $tpl_cfg_shared_log_settings_hipmatch_node);
        $tpl_cfg_shared_log_settings_hipmatch_match_list_entry_node = DH::findFirstElementByNameAttr('entry', 'userid-gpcs-default', $tpl_cfg_shared_log_settings_hipmatch_match_list_node);
        if( $tpl_cfg_shared_log_settings_hipmatch_match_list_entry_node == null )
        {
            $tmp_node = self::$TPL_HIPMATCH_DEFAULT_MATCH_LIST_ENTRY_CFG;
            $node = $this->panorama_doc->importNode($tmp_node, TRUE);
            $tpl_cfg_shared_log_settings_hipmatch_match_list_node->appendChild($node);
        }


        $tpl_cfg_shared_log_settings_userid_node = DH::findFirstElementOrCreate("userid", $tpl_cfg_shared_log_settings_node);
        $tpl_cfg_shared_log_settings_userid_match_list_node = DH::findFirstElementOrCreate("match-list", $tpl_cfg_shared_log_settings_userid_node);
        $tpl_cfg_shared_log_settings_userid_match_list_entry_node = DH::findFirstElementByNameAttr('entry', 'userid-gpcs-default', $tpl_cfg_shared_log_settings_userid_match_list_node);
        if( $tpl_cfg_shared_log_settings_userid_match_list_entry_node == null )
        {
            $tmp_node = self::$TPL_USERID_DEFAULT_MATCH_LIST_ENTRY_CFG;
            $node = $this->panorama_doc->importNode($tmp_node, TRUE);
            $tpl_cfg_shared_log_settings_userid_match_list_node->appendChild($node);
        }
    }

    function movingSHAREDtoVSYS()
    {
        //Panorama shared to fawkes "SHARED which is devices/entry[@name='localhost.localdomain']/
        #$task_array = array( "authentication-profile", "certificate", "certificate-profile", "ssl-tls-service-profile", "server-profile" );

        /*
         * "authentication-profile", -> vsys
         * "server-profile", -> vsys
         * "local-user-database", -> vsys
         * "certificate-profile", ->vsys
         * "ssl-tls-service-profile", ->vsys
         *
         * "certificate", -> shared
         * "scep", -> shared
         * "ocsp-responder" -> shared
         */

        $task_array = array( "authentication-profile", "authentication-sequence", "certificate", "certificate-profile", "ssl-tls-service-profile", "server-profile", "local-user-database", "scep", "ocsp-responder", "ssl-decrypt", "response-page" );

        foreach( $task_array as $task )
        {
            if( $task == "authentication-profile" || $task == "server-profile" || $task == "certificate-profile" || $task == "ssl-tls-service-profile"  || $task == "local-user-database" || $task == "authentication-sequence" ||  $task == "ssl-decrypt" ||  $task == "response-page" )
                $tpl_cfg_vsys_entry_task_node = DH::findFirstElementOrCreate( $task, self::$tpl_cfg_vsys_entry_node );

            elseif( $task == "certificate" || $task == "scep" || $task == "ocsp-responder" )
                $tpl_cfg_vsys_entry_task_node = DH::findFirstElementOrCreate( $task, self::$tpl_config_device_entry_node );


            //move Panoramam shared to Fawkes shared
            $shared_task_node = DH::findFirstElement( $task, self::$tpl_cfg_shared_node );
            if( $shared_task_node != null )
            {
                foreach( $shared_task_node->childNodes as $entry )
                {
                    if( $entry->nodeType != XML_ELEMENT_NODE )
                        continue;

                    //NO continue; as shared must be always moved to FAWKES shared
                    if( $task == "server-profile" || $task == "local-user-database" )
                    {
                        $tpl_cfg_vsys_entry_server_profile_methode_node = DH::findFirstElementOrCreate( $entry->nodeName, $tpl_cfg_vsys_entry_task_node );
                        foreach( $entry->childNodes as $key => $entry2 )
                        {
                            if( $entry2->nodeType != XML_ELEMENT_NODE )
                                continue;

                            $tmp_node = $entry2->cloneNode( true);

                            $name = DH::findAttribute('name', $tmp_node);
                            if( $name !== FALSE )
                            {
                                $tmp_element = DH::findFirstElementByNameAttr( "entry", $name, $tpl_cfg_vsys_entry_server_profile_methode_node );
                                if( $tmp_element !== FALSE && $tmp_element !== null )
                                    $tpl_cfg_vsys_entry_server_profile_methode_node->removeChild($tmp_element);
                            }

                            $tpl_cfg_vsys_entry_server_profile_methode_node->appendChild($tmp_node);
                        }
                    }
                    else
                    {
                        $tmp_node = $entry->cloneNode( true);


                        $name = DH::findAttribute('name', $tmp_node);
                        if( $name !== FALSE )
                        {
                            $tmp_element = DH::findFirstElementByNameAttr( "entry", $name, $tpl_cfg_vsys_entry_task_node );
                            if( $tmp_element !== FALSE && $tmp_element !== null )
                                $tpl_cfg_vsys_entry_task_node->removeChild($tmp_element);
                        }
                        else
                        {
                            $name = $tmp_node->nodeName;
                            $tmp_element = DH::findFirstElement( $name, $tpl_cfg_vsys_entry_task_node );
                            if( $tmp_element !== FALSE )
                            {
                                #PH::print_stdout( "1###############################" );
                                #self::DEBUGprintDOMDocument( $tmp_node );
                                $tpl_cfg_vsys_entry_task_node->removeChild($tmp_element);
                            }
                        }

                        $tpl_cfg_vsys_entry_task_node->appendChild($tmp_node);
                    }
                }

                //SHARED cleanup
                self::$tpl_cfg_shared_node->removeChild( $shared_task_node );
            }

            //move Panorama VSYS to Fawkes Container SHARED [certificate/scep/ocsp-responder] within Panorama config
            $vsys_task_node = DH::findFirstElement( $task, self::$tpl_cfg_vsys_entry_node );
            if( $vsys_task_node != null )
            {
                foreach( $vsys_task_node->childNodes as $entry )
                {
                    if( $entry->nodeType != XML_ELEMENT_NODE )
                        continue;
                    if( $task == "authentication-profile" || $task == "server-profile" || $task == "certificate-profile" || $task == "ssl-tls-service-profile"  || $task == "local-user-database" || $task == "authentication-sequence" ||  $task == "ssl-decrypt" ||  $task == "response-page" )
                        continue;

                    if( $task != "server-profile" )
                    {
                        $tmp_node = $entry->cloneNode( true);


                        $name = DH::findAttribute('name', $tmp_node);
                        if( $name !== FALSE )
                        {
                            $tmp_element = DH::findFirstElementByNameAttr( "entry", $name, $tpl_cfg_vsys_entry_task_node );
                            if( $tmp_element !== FALSE && $tmp_element !== null )
                                $tpl_cfg_vsys_entry_task_node->removeChild($tmp_element);
                        }
                        else
                        {
                            $name = $tmp_node->nodeName;
                            $tmp_element = DH::findFirstElement( $name, $tpl_cfg_vsys_entry_task_node );
                            if( $tmp_element !== FALSE )
                            {
                                #PH::print_stdout( "2###############################" );
                                #self::DEBUGprintDOMDocument( $tmp_node );
                                $tpl_cfg_vsys_entry_task_node->removeChild($tmp_element);
                            }
                        }


                        $tpl_cfg_vsys_entry_task_node->appendChild($tmp_node);
                    }
                    else
                    {
                        $tpl_cfg_vsys_entry_server_profile_methode_node = DH::findFirstElementOrCreate( $entry->nodeName, $tpl_cfg_vsys_entry_task_node );
                        foreach( $entry->childNodes as $key => $entry2 )
                        {
                            if( $entry2->nodeType != XML_ELEMENT_NODE )
                                continue;

                            $tmp_node = $entry2->cloneNode( true);

                            $name = DH::findAttribute('name', $tmp_node);
                            if( $name !== FALSE )
                            {
                                $tmp_element = DH::findFirstElementByNameAttr( "entry", $name, $tpl_cfg_vsys_entry_server_profile_methode_node );
                                if( $tmp_element !== FALSE && $tmp_element !== null )
                                    $tpl_cfg_vsys_entry_server_profile_methode_node->removeChild($tmp_element);
                            }

                            $tpl_cfg_vsys_entry_server_profile_methode_node->appendChild($tmp_node);
                        }
                    }
                }

                //cleanup Panorama vsys
                if( $task == "certificate" || $task == "scep" || $task == "ocsp-responder" )
                    self::$tpl_cfg_vsys_entry_node->removeChild( $vsys_task_node );
            }
        }


    }

    function findENTRY( &$source_vsys, $add_vsys, $xPath_string = "" )
    {
        $xPathName = $xPath_string;

        foreach( $add_vsys->childNodes as $childNode )
        {
            $xPath_string = $xPathName;
            if( $childNode->nodeType != XML_ELEMENT_NODE )
                continue;


            if( $childNode->nodeName != "entry" || ( $childNode->nodeName == "entry" && $add_vsys->nodeName == "vsys" )  )
            {
                $tmpString = $xPath_string . "/".$childNode->nodeName;

                if( self::hasChild( $childNode ) )
                    self::findENTRY(  $source_vsys, $childNode, $tmpString );
                else
                    self::replace_addNode( $source_vsys, $childNode, $tmpString);
            }
            else
                self::templateReplaceWith( $source_vsys, $childNode, $xPath_string );
        }
    }

    function hasChild($p)
    {
        if( $p->hasChildNodes() )
        {
            foreach( $p->childNodes as $c )
            {
                if( $c->nodeType == XML_ELEMENT_NODE )
                    return TRUE;
            }
        }
        return false;
    }
    function templateReplaceWith( &$source_vsys, $childNode, $xPath_string )
    {
        $name = DH::findAttribute('name', $childNode);
        $xPathName = $xPath_string."/entry[@name='".$name."']";
        #print "check xpath: ".$xPathName."\n";

        ####DEBUG
        #if( $xPathName === "/vsys/entry/authentication-profile/entry[@name='PAN-kerberos']")
            #print "check xpath: ".$xPathName."\n";

        foreach( $childNode->childNodes as $childNode2 )
        {
            if( $childNode2->nodeType != XML_ELEMENT_NODE )
                continue;

            ####DEBUG
            $continuedebug = false;
            #if( $xPathName === "/vsys/entry/authentication-profile/entry[@name='PAN-kerberos']")
            #{
            #    $continuedebug = true;
            #    self::DEBUGprintDOMDocument( $childNode2 );
            #}


            $xPath_string2 = $xPathName . "/" . $childNode2->nodeName;
            $xpath_array = explode("/", $xPath_string2);
            if( $this->print_debug )
                print_r( $xpath_array );
            ####fix for:
            #check xpath: /deviceconfig/system/permitted-ip/entry[@name='10.16.28.90/32']
            #issue was '/' in entry @name
            foreach( $xpath_array as $key => $xpath )
            {
                if( strpos( $xpath, "[" ) !== FALSE && strpos( $xpath, "]" ) === FALSE )
                {
                    if( strpos( $xpath_array[$key+1], "]" ) !== FALSE)
                    {
                        $xpath_array[$key] = $xpath."/".$xpath_array[$key+1];
                        unset($xpath_array[$key+1]);
                        break;
                    }
                }
            }

            $test_search = $source_vsys;
            $test_search2 = null;

            foreach( $xpath_array as $key => $xpath )
            {
                if( $key == 0 )
                    continue;

                $test_search2 = $test_search;

                #if($continuedebug)
                #    print "|".$xpath."\n";
                if( strpos($xpath, "@") === FALSE )
                {
                    $test_search = DH::findFirstElementOrCreate($xpath, $test_search2);
                }
                else
                {
                    $tmp_value = explode("'", $xpath);

                    $tmp_value = $tmp_value[1];

                    $test_search = DH::findFirstElementByNameAttrOrCreate('entry', $tmp_value, $test_search2, $test_search2->ownerDocument);
                    if( $test_search == FALSE )
                        print "not found1: " . $xpath . "\n";
                    else
                    {
                        #if($continuedebug)
                        #    print "found: ".$xpath."\n";
                    }
                }
            }

            $parentNode = $test_search->parentNode;

            //add node to template/devices/dir-sync/entry
            $tmp_node = $childNode2->cloneNode(TRUE);

            if( $tmp_node->hasChildNodes() ){
                if( !$test_search->hasChildNodes() )
                {
                    $parentNode->removeChild($test_search);
                    $parentNode->appendChild( $tmp_node );
                }
                elseif( $test_search->textContent !== $tmp_node->textContent )
                {
                    $tmpsearch = DH::findFirstElement($tmp_node->nodeName, $parentNode);
                    if( $tmpsearch === FALSE )
                    {
                        $parentNode->appendChild( $tmp_node );
                    }
                    else
                    {
                        foreach( $tmp_node->childNodes as $entries2 )
                        {
                            if( $entries2->nodeType != XML_ELEMENT_NODE )
                                continue;

                            $searchNodeName = DH::findFirstElement($entries2->nodeName, $tmpsearch);
                            if( $searchNodeName === FALSE )
                                $tmpsearch->appendChild($entries2);
                            else
                            {
                                if( $entries2->nodeName === "entry" )
                                {
                                    $firstattributename = DH::findAttribute( "name", $entries2 );
                                    $secondattributename = DH::findAttribute( "name", $searchNodeName );
                                    if( $firstattributename === $secondattributename )
                                        $tmpsearch->removeChild($searchNodeName);
                                }
                                else
                                    $tmpsearch->removeChild($searchNodeName);

                                $tmpsearch->appendChild( $entries2 );
                            }
                        }
                    }
                }
            }
        }
    }

    function replace_addNode( &$source_vsys, $childNode, $xPath_string)
    {
        #self::DEBUGprintDOMDocument( $childNode );

        $xpath_array = explode( "/", $xPath_string );
        #print_r( $xpath_array );

        $test_search = $source_vsys;
        $test_search2 = null;

        foreach( $xpath_array as $key => $xpath )
        {
            if( $key == 0 )
                continue;

            $test_search2 = $test_search;

            #print "|".$xpath."\n";
            $test_search = DH::findFirstElementOrCreate( $xpath, $test_search2 );
        }

        $parentNode = $test_search->parentNode;

        //add node to template/devices/dir-sync/entry
        $tmp_node = $childNode->cloneNode( true);


        if( $tmp_node->hasChildNodes() )
        {
            if( !$test_search->hasChildNodes() )
            {
                $parentNode->removeChild($test_search);
                $parentNode->appendChild( $tmp_node );
            }
            elseif( $test_search->textContent !== $tmp_node->textContent )
            {
                $parentNode->removeChild($test_search);
                $parentNode->appendChild( $tmp_node );
            }
        }
    }

    function templateGetDEVICEentry( $template_node )
    {
        $cont_config = DH::findFirstElement('config', $template_node);
        if( $cont_config == false )
            return null;
        $cont_devices = DH::findFirstElementOrCreate( "devices", $cont_config );
        if( $cont_devices == false )
            return null;
        $cont_devices_entry = DH::findFirstElementOrCreate( "entry", $cont_devices );
        if( $cont_devices_entry == false )
            return null;

        return $cont_devices_entry;
    }

    function GPvalidation( $xmlroot )
    {
        $templateName = DH::findAttribute( "name", $xmlroot );

        $Portalvalue = "";
        $GWvalue = "";

        //THIS CHECK IS FOR GP PORTAL AND GW VALIDATE THAT SAME AUTHENTICATION-PROFILE IS USED
        #$this->DEBUGprintDOMDocument( self::$tpl_gp_portal );
        $GPportal_entry = DH::findFirstElement( "entry", self::$tpl_gp_portal );
        if( $GPportal_entry !== false )
        {
            $PortalName = DH::findAttribute( "name", $GPportal_entry );

            $GPportal_config = DH::findFirstElement( "portal-config", $GPportal_entry );
            $GPportal_auth = DH::findFirstElement( "client-auth", $GPportal_config );
            $GPportal_auth_entry = DH::findFirstElement( "entry", $GPportal_auth );
            $GPportal_auth_profil = DH::findFirstElement( "authentication-profile", $GPportal_auth_entry );
            $Portalvalue = $GPportal_auth_profil->textContent;

            #$this->DEBUGprintDOMDocument( $GPportal_auth_profil );
        }


        $GPgw_entry = DH::findFirstElement( "entry", self::$tpl_gp_gw );
        if( $GPgw_entry !== false )
        {
            #$this->DEBUGprintDOMDocument( self::$tpl_gp_gw );
            $GWName = DH::findAttribute( "name", $GPgw_entry );

            $GPgw_auth = DH::findFirstElement( "client-auth", $GPgw_entry );
            $GPgw_auth_entry = DH::findFirstElement( "entry", $GPgw_auth );
            $GPgw_auth_profil = DH::findFirstElement( "authentication-profile", $GPgw_auth_entry );
            $GWvalue = $GPgw_auth_profil->textContent;

            #$this->DEBUGprintDOMDocument( $GPgw_auth_profil );
        }

        if( $GWvalue !== "" && $Portalvalue !== "" )
        {
            if( $GWvalue !== $Portalvalue )
            {
                $this->migration_error( "GlobalProtect migration with different authentication-profile on Portal: '".$PortalName."' and Gateway: '".$GWName."' NOT supported! Template: ".$templateName  );
                if( $this->fixing )
                {
                    $GPgw_auth_entry->removeChild($GPgw_auth_profil);
                    $auth = $GPportal_auth_profil->cloneNode( true );
                    $GPgw_auth_entry->appendChild( $auth );
                }
            }
        }


        //THIS CHECK IS THAT IKE GATEWAY IS NOT USING AUTHENTICATION/CERTIFICATE
        if( self::$tpl_cfg_network_ike_node != null )
        {
            $ike_gateway = DH::findFirstElement( "gateway", self::$tpl_cfg_network_ike_node );
            if( $ike_gateway !== false )
            {
                $gateway_entryLists = $ike_gateway->getElementsByTagName('entry');

                foreach( $gateway_entryLists as $gw_config )
                {
                    $GWName = DH::findAttribute( "name", $gw_config );

                    $ike_gateway_auth = DH::findFirstElement( "authentication", $gw_config );
                    $ike_gateway_auth_cert = DH::findFirstElement( "certificate", $ike_gateway_auth );
                    if( $ike_gateway_auth_cert !== false )
                    {
                        $this->migration_error( "Certificate based IKE Gateway Authentication is not supported! IKE Gateway: " . $GWName . " Template: ".$templateName  );
                        if( $this->fixing )
                        {
                            $ike_gateway_auth->removeChild( $ike_gateway_auth_cert );
                        }
                    }
                }
            }
        }
    }
}