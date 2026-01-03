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

trait fawkes_migration_functions
{

    function stringToXml( $XMLstring )
    {
        $temp_doc = new DOMDocument();
        $temp_doc->loadXML($XMLstring);
        #echo $temp_doc->saveXML();

        $element = DH::firstChildElement( $temp_doc );

        return $element;
    }

    function plugin_remove_dg_temp( $plugin_node )
    {
        if( $plugin_node != null )
        {
            $tmp_dg = DH::findFirstElement('device-group', $plugin_node);
            if( $tmp_dg != null )
                $plugin_node->removeChild($tmp_dg);
            $tmp_temp = DH::findFirstElement('template-stack', $plugin_node);
            if( $tmp_temp != null )
                $plugin_node->removeChild($tmp_temp);
        }
    }

    function getDGTemp( &$plugin_dg_temp, $cloud_service_node, $type_name)
    {
        $dg_node = null;

        if( $cloud_service_node != null )
        {
            $type_node = DH::findFirstElement($type_name, $cloud_service_node);

            if( $type_node != false )
            {
                $dg_node = DH::findFirstElement('device-group', $type_node);
                $temp_stack_node = DH::findFirstElement('template-stack', $type_node);

                if( $dg_node != false )
                {
                    $plugin_dg_temp[ $type_name ]['dg'] = $dg_node->nodeValue;
                    $plugin_dg_temp['DGS'][$dg_node->nodeValue] = $dg_node->nodeValue;
                    $this->parentDGcheck( $plugin_dg_temp, $dg_node->nodeValue );
                }
                else
                {
                    if( $type_name == "mobile-users" )
                        $dg_value = "Mobile_User_Device_Group";

                    elseif( $type_name == "remote-networks" )
                        $dg_value = "Remote_Network_Device_Group";

                    elseif( $type_name == "service-connection" )
                        $dg_value = "Service_Conn_Device_Group";

                    elseif( $type_name == "mobile-users-explicit-proxy" )
                        $dg_value = "Explicit_Proxy_Device_Group";

                    $plugin_dg_temp[ $type_name ]['dg'] = $dg_value;
                    $plugin_dg_temp['DGS'][$dg_value] = $dg_value;
                    $this->parentDGcheck( $plugin_dg_temp, $dg_value );
                }

                if( $temp_stack_node != false )
                    $plugin_dg_temp[ $type_name ]['template-stack'] = $temp_stack_node->nodeValue;
                else
                {
                    if( $type_name == "mobile-users" )
                        $temp_stack_value = "Mobile_User_Template_Stack";

                    elseif( $type_name == "remote-networks" )
                        $temp_stack_value = "Remote_Network_Template_Stack";

                    elseif( $type_name == "service-connection" )
                        $temp_stack_value = "Service_Conn_Template_Stack";

                    elseif( $type_name == "mobile-users-explicit-proxy" )
                        $dg_value = "Explicit_Proxy_Template_Stack";

                    $plugin_dg_temp[ $type_name ]['template-stack'] = $temp_stack_value;
                }
            }
        }
        else
        {
            self::migration_error( "This config does not contain any CloudService PlugIn\n" );
        }

    }

    function parentDGcheck( &$plugin_dg_temp, $dg_value )
    {
        $tmp_DG = $this->pan_panorama->findDeviceGroup( $dg_value );
        foreach( $tmp_DG->parentDeviceGroups() as $parentDeviceGroup )
        {
            if( !isset($plugin_dg_temp['DGS'][$parentDeviceGroup->name()]) )
                $plugin_dg_temp['DGS'][$parentDeviceGroup->name()] = $tmp_DG->name();
            else
            {
                if( $parentDeviceGroup->name() !== "Service_Conn_Device_Group"
                    && $parentDeviceGroup->name() !== "Mobile_User_Device_Group"
                    && $parentDeviceGroup->name() !== "Remote_Network_Device_Group"
                    && $parentDeviceGroup->name() !== "Explicit_Proxy_Device_Group"
                )
                    $plugin_dg_temp['DGS'][$parentDeviceGroup->name()] = $dg_value;
            }
        }
    }

    function getTrustedZones( $cloud_service_node, $type_name )
    {
        $type_node = DH::findFirstElement($type_name, $cloud_service_node);

        $trustZoneNameadded = false;
        $zoneArray = array();
        if( $type_node != null )
        {
            $trustedZones = DH::findFirstElement('trusted-zones', $type_node);
            if( $trustedZones != null )
            {
                foreach( $trustedZones->childNodes as $trustedZone )
                {
                    /** @var DOMElement $childNode */
                    if( $trustedZone->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $this->pluginTrustedZones[$type_name][] = $trustedZone->nodeValue;

                    if( $trustedZone->nodeValue != "clientless-vpn" )
                    {
                        if( !$trustZoneNameadded )
                            $zoneArray[ 'trust' ] = 'trust';
                        $trustedZone->nodeValue = "trust";
                    }
                    else
                        $zoneArray[ 'clientless-vpn' ] = 'clientless-vpn';
                }

                $type_node->removeChild($trustedZones);
                $trustedZones = DH::findFirstElementorCreate('trusted-zones', $type_node);
                foreach( $zoneArray as $zone )
                    DH::createElement($trustedZones, 'member', $zone);
            }
        }

    }

    function pluginRemoveBGP( $cloud_service_node, $type_name )
    {
        $type_node = DH::findFirstElement($type_name, $cloud_service_node);

        if( $type_node != null )
        {
            $onboarding = DH::findFirstElement('onboarding', $type_node);
            if( $onboarding === false )
                return;

            $onboardingLists = $onboarding->getElementsByTagName('entry');
            foreach( $onboardingLists as $entry )
            {
                $protocol = DH::findFirstElement('protocol', $entry);
                $bgp = false;
                if( $protocol != false )
                    $bgp = DH::findFirstElement('bgp', $protocol);
                if( $bgp != false )
                {
                    $bgp_enable = DH::findFirstElement( "enable", $bgp );
                    $peer_as = DH::findFirstElement( "peer-as", $bgp );
                    $peer_ip_address = DH::findFirstElement( "peer-ip-address", $bgp );
                    if( $bgp_enable != false && $peer_ip_address !== false && $peer_as !== false )
                    {
                        $bgp_enable_value = $bgp_enable->textContent;

                        if( $bgp_enable_value == "no" )
                        {
                            #$protocol->removeChild($bgp);
                        }
                    }
                    else
                    {
                        $protocol->removeChild($bgp);
                        $removeProtocol = TRUE;
                        foreach( $protocol->childNodes as $child )
                        {
                            if( $child->nodeType == XML_ELEMENT_NODE )
                                $removeProtocol = FALSE;
                        }
                        if( $removeProtocol )
                            $entry->removeChild($protocol);
                    }
                }

                $bgp_peer = DH::findFirstElement('bgp-peer', $entry);
                if( $bgp_peer != false )
                {
                    $sameAsPrimary = DH::findFirstElement( "same-as-primary", $bgp_peer );
                    $peerIpAddress = DH::findFirstElement( "peer-ip-address", $bgp_peer );

                    if( $sameAsPrimary !== false && $peerIpAddress !== false )
                    {
                        #$entry->removeChild($bgp_peer);
                    }
                    else
                        $entry->removeChild($bgp_peer);

                }
            }

        }
    }

    function move_dir_sync(  $cloud_service_node, $type_name )
    {
        $type_node = DH::findFirstElement($type_name, $cloud_service_node);

        if( $type_name == 'service-connection' )
        {
            $template = $this->pan_panorama->findTemplate( "Service_Conn_Template" );
        }
        elseif( $type_name == 'remote-networks' )
        {
            $template = $this->pan_panorama->findTemplate("Remote_Network_Template");
        }
        elseif( $type_name == 'mobile-users' )
        {
            $template = $this->pan_panorama->findTemplate("Mobile_User_Template");
        }
        elseif( $type_name == 'mobile-users-explicit-proxy' )
        {
            $template = $this->pan_panorama->findTemplate("Explicit_Proxy_Template");
        }

        if( !is_object( $template ) )
            return null;

        $tmp = DH::findFirstElement( 'config', $template->xmlroot );
        if( $tmp === false )
            return;
        $tmp = DH::findFirstElement( 'devices', $tmp );
        if( $tmp === false )
            return;
        $tmp = DH::findFirstElement( 'entry', $tmp );
        if( $tmp === false )
            return;

        if( $type_node != null )
        {
            $dir_sync = DH::findFirstElement('dir-sync', $type_node);
            if( $dir_sync != null )
            {
                $dir_sync_node = DH::findFirstElementOrCreate( 'dir-sync', $tmp );
                $dir_sync_entry_node = DH::findFirstElementOrCreate( 'entry', $dir_sync_node );
                $dir_sync_entry_node->setAttribute('name', $type_name);

                foreach( $dir_sync->childNodes as $node )
                {
                    /** @var DOMElement $childNode */
                    if( $node->nodeType != XML_ELEMENT_NODE )
                        continue;

                    //add node to template/devices/dir-sync/entry
                    $tmp_node = $node->cloneNode( true);
                    $dir_sync_entry_node->appendChild( $tmp_node );
                }

                $type_node->removeChild( $dir_sync );
            }
        }
    }

    function run_util_script ( $type, &$util, $action, $location, $filter = false, $ruletype = "security", $configType = 'panorama' )
    {

        if( $type == "rule" )
            $new_util = new RULEUTIL("custom", array(), array(),"fake-migration-parser");
        else
            $new_util = new UTIL("custom", array(), array(),"fake-migration-parser");

        $new_util->shadow_ignoreInvalidAddressObjects();

        $new_util->configType = $configType;
        $new_util->configInput['type'] = 'file';
        $new_util->configInput['filename'] = "dummy";
        $new_util->configOutput = null;

        $new_util->utilType = $type;

        if( $type == "rule" )
            $new_util->ruleTypes();

        if( $ruletype != null )
        {
            $ruletype_array = explode(",", $ruletype);
            $new_util->ruleTypes = $ruletype_array;
        }


        $new_util->doActions = $action;
        if( $filter != false )
            $new_util->objectsFilter = $filter;
        $new_util->objectsLocation = $location;

        $new_util->pan = $util->pan;


        $new_util->extracting_actions();
        $new_util->createRQuery();
        $new_util->location_filter();
        $new_util->location_filter_object();
        $new_util->time_to_process_objects();
        $new_util->GlobalFinishAction();

        /*
        print "BETWEEN\n";
        foreach( $new_util->pan->deviceGroups as $DG_obj )
        {

            print "DGname: ".$DG_obj->name()."\n";

            print "countSecProfGroup1 - ".count( $DG_obj->securityProfileGroupStore->getAll() )."\n";
            print "countSecProfGroup2 - ".count( $DG_obj->securityProfileGroupStore->all() )."\n";
        }
        */
    }




    function ruleManipulation( $testArray )
    {
        foreach( $testArray as $entry )
        {
            $DGname = $entry[ 'dg' ];
            if( isset( $entry[ 'container' ] ) )
                $ContainerName = $entry[ 'container' ];
            else
                $ContainerName = null;

            if( isset( $entry[ 'cloud' ] ) )
                $CloudDeviceName = $entry[ 'cloud' ];
            else
                $CloudDeviceName = null;

            $stores = $entry[ 'store' ];

            if( $DGname == "shared" )
                $DG_RN = $this->pan_panorama;
            else
                $DG_RN = $this->pan_panorama->findDeviceGroup( $DGname );

            if( $DG_RN === null )
                continue;

            foreach( $stores as $store )
            {
                /** @var DeviceGroup $DG_RN */
                //Todo: DLP and IoT are not supported; where are these configured, Rules?

                foreach( $DG_RN->$store->resultingPreRuleSet() as $rule )
                {
                    $this->handleRule( $rule, $store, $ContainerName, $CloudDeviceName);
                }
                foreach( $DG_RN->$store->resultingPostRuleSet() as $rule )
                {
                    if( $ContainerName != null  )
                        $inPost = true;
                    elseif( $CloudDeviceName != null )
                        $inPost = false;

                    $this->handleRule( $rule, $store, $ContainerName, $CloudDeviceName, $inPost);
                }
            }

        }

    }

    function handleRule( $rule, $store, $ContainerName, $CloudDeviceName, $inPost = FALSE)
    {
        #print "STORE:".$store."\n";
        /**
         * @var SecurityRule|DecryptionRule|AppOverrideRule $rule
         */

        if( $store == "securityRules" || $store == "decryptionRules" || $store == "qosRules" || $store == "appOverrideRules" || $store == "authenticationRules" || $store == "defaultSecurityRules" )
        {
            /*
            [mobile-users] => Array
                    [0] => Mobile-User-Trust
            [remote-networks] => Array
                    [0] => Remote-Trust
             */

            if( !$rule->target_isAny() )
            {
                if( $rule->target_isNegated() )
                {
                    $rule->target_setAny();
                }
                else
                {
                    $rule->target_setAny();
                    $rule->setDisabled( TRUE );

                    //add tag "target_removed"
                    $tmp_tag = $rule->owner->owner->tagStore->findOrCreate( "target_removed" );
                    $rule->tags->addTag( $tmp_tag );
                }
            }

            if( $ContainerName == "Mobile Users Container" || $CloudDeviceName == "Mobile Users" )
            {
                $relevantZoneArray = array();
                if( isset( $this->pluginTrustedZones[ "mobile-users" ] ) )
                    $relevantZoneArray = $this->pluginTrustedZones[ "mobile-users" ];

                $this->rule_zone_manipulation( $rule, $relevantZoneArray );
            }
            elseif( $CloudDeviceName == "Remote Networks" )
            {
                $relevantZoneArray = array();
                if( isset( $this->pluginTrustedZones[ "remote-networks" ] ) )
                    $relevantZoneArray = $this->pluginTrustedZones[ "remote-networks" ];

                $this->rule_zone_manipulation( $rule, $relevantZoneArray );
            }
            elseif( $CloudDeviceName == "Service Connections" )
            {
                //NO trusted Zones for Service Connections
            }
            elseif( $CloudDeviceName == "Explicit Proxy" )
            {
                //check if correct NAME
                //NO trusted Zones for Service Connections
            }

            if( $store == "securityRules" || $store == "decryptionRules" || $store == "authenticationRules" || $store == "defaultSecurityRules" )
            {
                /*
                if( $store == "decryptionRules" || $store == "authenticationRules" )
                {
                    //not implemented yet
                }
                else
                    */
                    if( $rule->logSetting() !== FALSE )
                        $rule->setLogSetting( "Cortex Data Lake"  );
            }


            if( $store == "securityRules" || $store == "defaultSecurityRules" )
            {


                if( !$rule->securityProfileIsBlank() && $rule->securityProfileGroup() == "default" )
                    $rule->setSecurityProfileGroup( "best-practice" );

                $rule->rewriteSecProfXML();
            }
            elseif( $store == "decryptionRules" )
            {
                if( $rule->getDecryptionProfile() == "default" )
                    $rule->setDecryptionProfile( "best-practice" );


                $decrypt_rule_type = DH::findFirstElement( 'type', $rule->xmlroot);
                foreach( $this->decrypt_profile_not_supported as $decrypt_feature )
                {
                    $decrypt_SSH_PROXY = DH::findFirstElement( $decrypt_feature, $decrypt_rule_type);
                    if( $decrypt_SSH_PROXY !== false  )
                    {
                        self::migration_error( "Decryption Rule: ".$rule->name()." TYPE:'".$decrypt_feature."' found - stop migration!" );
                    }
                }

                $decrypt_rule_action = DH::findFirstElement( 'action', $rule->xmlroot);
                $action_found = FALSE;
                foreach( $this->decrypt_rule_action_supported as $decrypt_action )
                {
                    if( $decrypt_action === $decrypt_rule_action->textContent )
                        $action_found = TRUE;
                }
                if( !$action_found  )
                {
                    self::migration_error( "Decryption Rule: ".$rule->name()." ACTION:'".$decrypt_rule_action->textContent."' found - stop migration!" );
                }
            }
        }




        $this->printDebug( $rule->name() );


        $node = $rule->xmlroot;

        if( $ContainerName != null )
        {
            $CONTAINER = $this->pan_fawkes->findContainer( $ContainerName);
            if( $CONTAINER == null )
                $CONTAINER = $this->pan_fawkes->createContainer( $ContainerName, "Prisma Access" );
        }
        elseif( $CloudDeviceName != null )
        {
            $CONTAINER = $this->pan_fawkes->findDeviceCloud( $CloudDeviceName);
            if( $CONTAINER == null )
            {
                if( $CloudDeviceName === "Mobile Users" || $CloudDeviceName === "Mobile Users Explicit Proxy" )
                    $parent = "Mobile Users Container";
                else
                    $parent = "Prisma Access";

                $CONTAINER = $this->pan_fawkes->createDeviceCloud( $CloudDeviceName, $parent );
            }

        }


        if( $store == "securityRules" )
            $newRule = new SecurityRule( $CONTAINER->$store );
        elseif( $store == "decryptionRules" )
            $newRule = new DecryptionRule( $CONTAINER->$store );
        elseif( $store == "appOverrideRules" )
            $newRule = new AppOverrideRule( $CONTAINER->$store );
        elseif( $store == "qosRules" )
            $newRule = new QoSRule( $CONTAINER->$store );
        elseif( $store == "authenticationRules" )
            $newRule = new AuthenticationRule( $CONTAINER->$store );
        elseif( $store == "defaultSecurityRules" )
            $newRule = new DefaultSecurityRule( $CONTAINER->$store );

        $newRule->xmlroot = $this->fawkes_doc->importNode($node, TRUE);
        $newRule->load_from_domxml($newRule->xmlroot);

        $newRule->owner = null;

        $CONTAINER->$store->addRule( $newRule, $inPost );
    }

    function rule_zone_manipulation( $rule, $relevantZoneArray )
    {
        $trustZoneName = "trust";
        $untrustZoneName = "untrust";

        $trustZone = $rule->owner->owner->zoneStore->findOrCreate( "trust" );
        $untrustZone = $rule->owner->owner->zoneStore->findOrCreate( "untrust" );

        $counter = 0;
        foreach( $rule->from->zones() as $zone )
        {
            if( $zone->name() == $trustZoneName || $zone->name() == $untrustZoneName )
                continue;

            #if( $relevantZoneString == $zone->name() )
            if( in_array( $zone->name(), $relevantZoneArray ) )
            {
                $rule->from->addZone( $trustZone );
                $rule->from->removeZone( $zone );
            }
            elseif( $counter == 0 )
            {
                $rule->from->addZone( $untrustZone );
                $rule->from->removeZone( $zone );
                $counter++;
            }
            else
                $rule->from->removeZone( $zone );
        }


        $counter = 0;
        foreach( $rule->to->zones() as $zone )
        {
            if( $zone->name() == $trustZoneName || $zone->name() == $untrustZoneName )
                continue;

            #if( $relevantZoneString == $zone->name() )
            if( in_array( $zone->name(), $relevantZoneArray ) )
            {
                $rule->to->addZone( $trustZone );
                $rule->to->removeZone( $zone );
            }
            elseif( $counter == 0 )
            {
                $rule->to->addZone( $untrustZone );
                $rule->to->removeZone( $zone );
                $counter++;
            }
            else
                $rule->to->removeZone( $zone );
        }
    }

    function printDebug( $text, $additional = "" )
    {
        if( $this->print_debug )
        {
            if( !empty( $additional ) )
                print $additional."\n";

            if( is_array( $text) )
                print_r( $text );
            else
                print $text."\n";
        }

    }


    function migrationSecProf( $tmpProfil, $profile, $DEVICE, $rootDoc, $prefix = "", $tmpxmlroot = null)
    {

        $newProfName = $prefix.$tmpProfil->name();
        if( $tmpProfil->xmlroot == null )
        {
            #$this->printDebug( "NewName: ".$newProfName." - return nothing\n" );
            #$this->DEBUGprintDOMDocument( $tmpProfil->xmlroot );
            //objec from higher level; ignore
            return null;
        }
        $profStore = $profile."Store";
        $fawkes_profile = $DEVICE->$profStore->find( $newProfName );
        //$fawkes_profile = $DEVICE->$profStore->find( $newProfName, null, FALSE );

        if( $fawkes_profile !== null && $tmpProfil->xmlroot !== $fawkes_profile->xmlroot )
        {
            //you can not compare panorama and fawkes migrate part
            #$this->printDebug( "secprof check: ".$fawkes_profile->name() );
            #$this->DEBUGprintDOMDocument( $tmpProfil->xmlroot );
            #$this->DEBUGprintDOMDocument( $fawkes_profile->xmlroot );
            #exit();
        }

        if( $fawkes_profile == null )
        {
            if( $profile == "DecryptionProfile" )
            {
                $fawkes_profile = new DecryptionProfile( $newProfName, $DEVICE->DecryptionProfileStore);


                foreach( $this->decrypt_profile_not_supported as $decrypt_feature )
                {
                    $decrypt_SSH_PROXY = DH::findFirstElement( $decrypt_feature, $tmpProfil->xmlroot);
                    if( $decrypt_SSH_PROXY !== false  )
                    {
                        if( $this->fixing )
                            $tmpProfil->xmlroot->removeChild($decrypt_SSH_PROXY);
                        self::migration_error( "Decryption Profile: ".$newProfName." '".$decrypt_feature."' found - stop migration!" );
                    }
                }
            }


            elseif( $profile == "customURLProfile" )
                $fawkes_profile = new customURLProfile( $newProfName, $DEVICE->customURLProfileStore );

            elseif( $profile == "HipObjectsProfile" )
                $fawkes_profile = new HipObjectsProfile( $newProfName, $DEVICE->HipObjectsProfileStore);

            elseif( $profile == "HipProfilesProfile" )
                $fawkes_profile = new HipProfilesProfile( $newProfName, $DEVICE->HipProfilesProfileStore);

            elseif( $profile == "FileBlockingProfile" )
                $fawkes_profile = new FileBlockingProfile( $newProfName, $DEVICE->FileBlockingProfileStore);

            elseif( $profile == "DataFilteringProfile" )
                $fawkes_profile = new DataFilteringProfile( $newProfName, $DEVICE->DataFilteringProfileStore);

            elseif( $profile == "VulnerabilityProfile" )
                $fawkes_profile = new VulnerabilityProfile( $newProfName, $DEVICE->VulnerabilityProfileStore);

            elseif( $profile == "URLProfile" )
                $fawkes_profile = new URLProfile( $newProfName, $DEVICE->URLProfileStore );

            elseif( $profile == "SaasSecurityProfile" )
                $fawkes_profile = new SaasSecurityProfile( $newProfName, $DEVICE->SaasSecurityProfileStore, true );

            elseif( $profile == "DNSSecurityProfile" )
                $fawkes_profile = new DNSSecurityProfile( $newProfName, $DEVICE->DNSSecurityProfileStore, true);

            elseif( $profile == "VirusAndWildfireProfile" )
                $fawkes_profile = new VirusAndWildfireProfile( $newProfName, $DEVICE->VirusAndWildfireProfileStore);

            elseif( $profile == "AntiSpywareProfile" )
                $fawkes_profile = new AntiSpywareProfile( $newProfName, $DEVICE->AntiSpywareProfileStore);


            $fawkes_profile->owner = null;

            if( $tmpxmlroot === null )
                $node = $rootDoc->importNode($tmpProfil->xmlroot, TRUE);
            else
                $node = $rootDoc->importNode($tmpxmlroot, TRUE);

            if( $profile != "DNSSecurityProfile" && $profile != "SaasSecurityProfile" )
            {
                if( $profile == "URLProfile" )
                    $fawkes_profile->load_from_domxml( $node, false );
                else
                    $fawkes_profile->load_from_domxml( $node );
            }

            $fawkes_profile->setName( $newProfName );
            $DEVICE->$profStore->addSecurityProfile( $fawkes_profile );

            if( $profile == "DNSSecurityProfile" || $profile == "SaasSecurityProfile" )
            {
                $fawkes_profile->xmlroot->appendChild($node);
                $fawkes_profile->load_from_domxml( $node, true );
            }



            //search for threat-exception in
            $threatException = DH::findFirstElement( 'threat-exception', $fawkes_profile->xmlroot);
            if( $threatException !== false  )//&& isset($fawkes_profile->secprof_type)
            {
                $threatExceptionDEVICE = DH::findFirstElementOrCreate( 'threat-exception', $DEVICE->xmlroot);
                $threatExceptionDEVICE_profile = DH::findFirstElementOrCreate( $fawkes_profile->secprof_type, $threatExceptionDEVICE);

                foreach( $threatException->childNodes as $childNode )
                {
                    /** @var DOMElement $childNode */
                    if( $childNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_node = $childNode->cloneNode();

                    $nodeName = DH::findAttribute('name', $childNode);
                    $Nodeexist = DH::findFirstElementByNameAttr( "entry", $nodeName, $threatExceptionDEVICE_profile );
                    if( $Nodeexist === null )
                        $threatExceptionDEVICE_profile->appendChild( $tmp_node );
                }
            }
        }
        else
        {
            //if already migrated earlier in another SecProfGroup, then of course profile is there
            #$this->printDebug( PH::boldText( "PROFILE: ".$newProfName." already available" ), PH::boldText( "#############################################" ) );

            $this->printDebug( "use available profile: ".$newProfName );
        }

        return $fawkes_profile;
    }

    function DLPmigrateSecProf( $tmpXMLProfil, $profile , $DEVICE, $rootDoc, $prefix = "", $tmpxmlroot = null)
    {
        $profile = "DataFilteringProfile";


        $tmpProfil = new DataFilteringProfile("dummy", $DEVICE->DataFilteringProfileStore);
        $tmpProfil->load_from_domxml( $tmpXMLProfil);
        $tmpProfil->owner = null;
        
        $newProfName = $prefix.$tmpProfil->name();
        
        $profStore = $profile."Store";
        $fawkes_profile = $DEVICE->$profStore->find( $newProfName );
        

        if( $fawkes_profile !== null && $tmpProfil->xmlroot !== $fawkes_profile->xmlroot )
        {
            //you can not compare panorama and fawkes migrate part
        }


        if( $fawkes_profile == null )
        {
            $fawkes_profile = new DataFilteringProfile( $newProfName, $DEVICE->DataFilteringProfileStore);

            $this->DLPdatafilteringforDeletion[$newProfName] = $newProfName;

            $fawkes_profile->owner = null;

            if( $tmpxmlroot === null )
                $node = $rootDoc->importNode($tmpProfil->xmlroot, TRUE);
            else
                $node = $rootDoc->importNode($tmpxmlroot, TRUE);

            
            $fawkes_profile->load_from_domxml( $node );

            
            $fawkes_profile->setName( $newProfName );
            $DEVICE->$profStore->addSecurityProfile( $fawkes_profile );

        }
        else
            $this->printDebug( "use available profile: ".$newProfName );


        return $fawkes_profile;
    }

    function remove_empty_node( $temp_devices )
    {
        $dom = new DOMDocument;
        $dom->preserveWhiteSpace = false;
        $dom->formatOutput = true;
        #$dom->loadXML($temp_devices);
        $node = $dom->importNode($temp_devices, true);
        $dom->appendChild($node);

        $elements = $dom->getElementsByTagName('*');
        foreach($elements as $element)
        {
            #if( $element->nodeName == "peer-address" )
            #    print "|->".$element->nodeValue."<-|";

            if ( ! $element->hasChildNodes() OR $element->nodeValue == "" OR trim( $element->nodeValue ) == "" OR $element->nodeValue == null )
            {
                $element->parentNode->removeChild($element);
            }
            #else print "|".$element->nodeValue."|";
        }
        $temp_devices = DH::findFirstElement( "devices", $dom );

        return $temp_devices;
    }

    function DEBUGprintDOMDocument( $node )
    {
        if( $node != null )
        {
            $newdoc = new DOMDocument;
            $node = $newdoc->importNode($node, true);
            $newdoc->appendChild($node);
            print $newdoc->saveXML();
        }

    }

    function printCertificateProfile( $temp_xmlroot, $start = true )
    {
        if( $start )
        {
            $tmp1 = DH::findFirstElement( "config", $temp_xmlroot );
            $tmp2 = DH::findFirstElement( "devices", $tmp1 );
        }
        else
        {
            $tmp2 = $temp_xmlroot;
        }

        $tmp3 = DH::findFirstElement( "entry", $tmp2 );
        $tmp4 = DH::findFirstElement( "vsys", $tmp3 );
        $tmp5 = DH::findFirstElement( "entry", $tmp4 );
        $tmp6 = DH::findFirstElement( "certificate-profile", $tmp5 );

        #$this->DEBUGprintDOMDocument( $tmp6 );
    }

    public function display_migration_counter( $pan, $return_true_false = false )
    {

        $container_all = $pan->findContainer( "All");

        $gpreSecRules = $container_all->securityRules->countPreRules();
        $gpreNatRules = $container_all->natRules->countPreRules();
        $gpreDecryptRules = $container_all->decryptionRules->countPreRules();
        $gpreAppOverrideRules = $container_all->appOverrideRules->countPreRules();
        $gpreCPRules = $container_all->captivePortalRules->countPreRules();
        $gpreAuthRules = $container_all->authenticationRules->countPreRules();
        $gprePbfRules = $container_all->pbfRules->countPreRules();
        $gpreQoSRules = $container_all->qosRules->countPreRules();
        $gpreDoSRules = $container_all->dosRules->countPreRules();

        $gpostSecRules = $container_all->securityRules->countPostRules();
        $gpostNatRules = $container_all->natRules->countPostRules();
        $gpostDecryptRules = $container_all->decryptionRules->countPostRules();
        $gpostAppOverrideRules = $container_all->appOverrideRules->countPostRules();
        $gpostCPRules = $container_all->captivePortalRules->countPostRules();
        $gpostAuthRules = $container_all->authenticationRules->countPostRules();
        $gpostPbfRules = $container_all->pbfRules->countPostRules();
        $gpostQoSRules = $container_all->qosRules->countPostRules();
        $gpostDoSRules = $container_all->dosRules->countPostRules();

        $gnservices = $container_all->serviceStore->countServices();
        $gnservicesUnused = $container_all->serviceStore->countUnusedServices();
        $gnserviceGs = $container_all->serviceStore->countServiceGroups();
        $gnserviceGsUnused = $container_all->serviceStore->countUnusedServiceGroups();
        $gnTmpServices = $container_all->serviceStore->countTmpServices();

        $gnaddresss = $container_all->addressStore->countAddresses();
        $gnaddresssUnused = $container_all->addressStore->countUnusedAddresses();
        $gnaddressGs = $container_all->addressStore->countAddressGroups();
        $gnaddressGsUnused = $container_all->addressStore->countUnusedAddressGroups();
        $gnTmpAddresses = $container_all->addressStore->countTmpAddresses();

        $gTagCount = $container_all->tagStore->count();
        $gTagUnusedCount = $container_all->tagStore->countUnused();

        $gnsecprofgroups = $container_all->securityProfileGroupStore->count();


        $gnsecprofAS = $container_all->AntiSpywareProfileStore->count();
        $gnsecprofVB = $container_all->VulnerabilityProfileStore->count();
        $gnsecprofAVWF = $container_all->VirusAndWildfireProfileStore->count();
        $gnsecprofDNS = $container_all->DNSSecurityProfileStore->count();
        $gnsecprofURL = $container_all->URLProfileStore->count();
        $gnsecprofFB = $container_all->FileBlockingProfileStore->count();
        $gnsecprofDF = $container_all->DataFilteringProfileStore->count();

        $gnsecprofDecr = $container_all->DecryptionProfileStore->count();
        $gnsecprofHipProf = $container_all->HipProfilesProfileStore->count();
        $gnsecprofHipObj = $container_all->HipObjectsProfileStore->count();

        $gnAppCustom = $container_all->appStore->countAppCustom();
        $gnAppFilters = $container_all->appStore->countAppFilters();
        $gnAppGroup = $container_all->appStore->countAppGroups();

        $gScheduleCount = $container_all->scheduleStore->count();

        foreach( $pan->containers as $cur )
        {
            if( $cur->name() == "All" )
                continue;

            $gpreSecRules += $cur->securityRules->countPreRules();
            $gpreNatRules += $cur->natRules->countPreRules();
            $gpreDecryptRules += $cur->decryptionRules->countPreRules();
            $gpreAppOverrideRules += $cur->appOverrideRules->countPreRules();
            $gpreCPRules += $cur->captivePortalRules->countPreRules();
            $gpreAuthRules += $cur->authenticationRules->countPreRules();
            $gprePbfRules += $cur->pbfRules->countPreRules();
            $gpreQoSRules += $cur->qosRules->countPreRules();
            $gpreDoSRules += $cur->dosRules->countPreRules();

            $gpostSecRules += $cur->securityRules->countPostRules();
            $gpostNatRules += $cur->natRules->countPostRules();
            $gpostDecryptRules += $cur->decryptionRules->countPostRules();
            $gpostAppOverrideRules += $cur->appOverrideRules->countPostRules();
            $gpostCPRules += $cur->captivePortalRules->countPostRules();
            $gpostAuthRules += $cur->authenticationRules->countPostRules();
            $gpostPbfRules += $cur->pbfRules->countPostRules();
            $gpostQoSRules += $cur->qosRules->countPostRules();
            $gpostDoSRules += $cur->dosRules->countPostRules();

            $gnservices += $cur->serviceStore->countServices();
            $gnservicesUnused += $cur->serviceStore->countUnusedServices();
            $gnserviceGs += $cur->serviceStore->countServiceGroups();
            $gnserviceGsUnused += $cur->serviceStore->countUnusedServiceGroups();
            $gnTmpServices += $cur->serviceStore->countTmpServices();

            $gnaddresss += $cur->addressStore->countAddresses();
            $gnaddresssUnused += $cur->addressStore->countUnusedAddresses();
            $gnaddressGs += $cur->addressStore->countAddressGroups();
            $gnaddressGsUnused += $cur->addressStore->countUnusedAddressGroups();
            $gnTmpAddresses += $cur->addressStore->countTmpAddresses();

            $gTagCount += $cur->tagStore->count();
            $gTagUnusedCount += $cur->tagStore->countUnused();

            $gnsecprofgroups += $cur->securityProfileGroupStore->count();

            $gnsecprofAS += $cur->AntiSpywareProfileStore->count();
            $gnsecprofVB += $cur->VulnerabilityProfileStore->count();
            $gnsecprofAVWF += $cur->VirusAndWildfireProfileStore->count();
            $gnsecprofDNS += $cur->DNSSecurityProfileStore->count();
            $gnsecprofURL += $cur->URLProfileStore->count();
            $gnsecprofFB += $cur->FileBlockingProfileStore->count();
            $gnsecprofDF += $cur->DataFilteringProfileStore->count();

            $gnsecprofDecr += $cur->DecryptionProfileStore->count();
            $gnsecprofHipProf += $cur->HipProfilesProfileStore->count();
            $gnsecprofHipObj += $cur->HipObjectsProfileStore->count();

            $gnAppCustom += $cur->appStore->countAppCustom();
            $gnAppFilters += $cur->appStore->countAppFilters();
            $gnAppGroup += $cur->appStore->countAppGroups();

            $gScheduleCount += $cur->scheduleStore->count();
        }

        foreach( $pan->clouds as $cur )
        {
            if( $cur->name() == "All" )
                continue;

            $gpreSecRules += $cur->securityRules->count();
            $gpreNatRules += $cur->natRules->count();
            $gpreDecryptRules += $cur->decryptionRules->count();
            $gpreAppOverrideRules += $cur->appOverrideRules->count();
            $gpreCPRules += $cur->captivePortalRules->count();
            $gpreAuthRules += $cur->authenticationRules->count();
            $gprePbfRules += $cur->pbfRules->count();
            $gpreQoSRules += $cur->qosRules->count();
            $gpreDoSRules += $cur->dosRules->count();

            /*
            $gpreSecRules += $cur->securityRules->countPreRules();
            $gpreNatRules += $cur->natRules->countPreRules();
            $gpreDecryptRules += $cur->decryptionRules->countPreRules();
            $gpreAppOverrideRules += $cur->appOverrideRules->countPreRules();
            $gpreCPRules += $cur->captivePortalRules->countPreRules();
            $gpreAuthRules += $cur->authenticationRules->countPreRules();
            $gprePbfRules += $cur->pbfRules->countPreRules();
            $gpreQoSRules += $cur->qosRules->countPreRules();
            $gpreDoSRules += $cur->dosRules->countPreRules();

            $gpostSecRules += $cur->securityRules->countPostRules();
            $gpostNatRules += $cur->natRules->countPostRules();
            $gpostDecryptRules += $cur->decryptionRules->countPostRules();
            $gpostAppOverrideRules += $cur->appOverrideRules->countPostRules();
            $gpostCPRules += $cur->captivePortalRules->countPostRules();
            $gpostAuthRules += $cur->authenticationRules->countPostRules();
            $gpostPbfRules += $cur->pbfRules->countPostRules();
            $gpostQoSRules += $cur->qosRules->countPostRules();
            $gpostDoSRules += $cur->dosRules->countPostRules();
            */

            $gnservices += $cur->serviceStore->countServices();
            $gnservicesUnused += $cur->serviceStore->countUnusedServices();
            $gnserviceGs += $cur->serviceStore->countServiceGroups();
            $gnserviceGsUnused += $cur->serviceStore->countUnusedServiceGroups();
            $gnTmpServices += $cur->serviceStore->countTmpServices();

            $gnaddresss += $cur->addressStore->countAddresses();
            $gnaddresssUnused += $cur->addressStore->countUnusedAddresses();
            $gnaddressGs += $cur->addressStore->countAddressGroups();
            $gnaddressGsUnused += $cur->addressStore->countUnusedAddressGroups();
            $gnTmpAddresses += $cur->addressStore->countTmpAddresses();

            $gTagCount += $cur->tagStore->count();
            $gTagUnusedCount += $cur->tagStore->countUnused();

            $gnsecprofgroups += $cur->securityProfileGroupStore->count();

            $gnsecprofAS += $cur->AntiSpywareProfileStore->count();
            $gnsecprofVB += $cur->VulnerabilityProfileStore->count();
            $gnsecprofAVWF += $cur->VirusAndWildfireProfileStore->count();
            $gnsecprofDNS += $cur->DNSSecurityProfileStore->count();
            $gnsecprofURL += $cur->URLProfileStore->count();
            $gnsecprofFB += $cur->FileBlockingProfileStore->count();
            $gnsecprofDF += $cur->DataFilteringProfileStore->count();

            $gnsecprofDecr += $cur->DecryptionProfileStore->count();
            $gnsecprofHipProf += $cur->HipProfilesProfileStore->count();
            $gnsecprofHipObj += $cur->HipObjectsProfileStore->count();

            $gnAppCustom += $cur->appStore->countAppCustom();
            $gnAppFilters += $cur->appStore->countAppFilters();
            $gnAppGroup += $cur->appStore->countAppGroups();

            $gScheduleCount += $cur->scheduleStore->count();
        }

        $stdoutarray = array();

        $stdoutarray['security rules'] = $gpreSecRules + $gpostSecRules;
        #$stdoutarray['pre security rules'] = $gpreSecRules;
        #$stdoutarray['post security rules'] = $gpostSecRules;

        $stdoutarray['nat rules'] = $gpreNatRules + $gpostNatRules;
        #$stdoutarray['pre nat rules'] = $gpreNatRules;
        #$stdoutarray['post nat rules'] = $gpostNatRules;

        $stdoutarray['qos rules'] = $gpreQoSRules + $gpostQoSRules;
        #$stdoutarray['pre qos rules'] = $gpreQoSRules;
        #$stdoutarray['post qos rules'] = $gpostQoSRules;

        $stdoutarray['pbf rules'] = $gprePbfRules + $gpostPbfRules;
        #$stdoutarray['pre pbf rules'] = $gprePbfRules;
        #$stdoutarray['post pbf rules'] = $gpostPbfRules;

        $stdoutarray['decryption rules'] = $gpreDecryptRules + $gpostDecryptRules;
        #$stdoutarray['pre decryption rules'] = $gpreDecryptRules;
        #$stdoutarray['post decryption rules'] = $gpostDecryptRules;

        $stdoutarray['app-override rules'] = $gpreAppOverrideRules + $gpostAppOverrideRules;
        #$stdoutarray['pre app-override rules'] = $gpreAppOverrideRules;
        #$stdoutarray['post app-override rules'] = $gpostAppOverrideRules;

        ##$stdoutarray['capt-portal rules'] = $gpreCPRules + $gpostCPRules;
        #$stdoutarray['pre capt-portal rules'] = $gpreCPRules;
        #$stdoutarray['post capt-portal rules'] = $gpostCPRules;

        $stdoutarray['authentication rules'] = $gpreAuthRules + $gpostAuthRules;
        #$stdoutarray['pre authentication rules'] = $gpreAuthRules;
        #$stdoutarray['post authentication rules'] = $gpostAuthRules;

        $stdoutarray['dos rules'] = $gpreDoSRules + $gpostDoSRules;
        #$stdoutarray['pre dos rules'] = $gpreDoSRules;
        #$stdoutarray['post dos rules'] = $gpostDoSRules;




        $stdoutarray['address objects'] = $gnaddresss;
        $stdoutarray['addressgroup objects'] = $gnaddressGs;
        $stdoutarray['temporary address objects'] = $gnTmpAddresses;


        $stdoutarray['service objects'] = $gnservices;
        $stdoutarray['servicegroup objects'] = $gnserviceGs;
        $stdoutarray['temporary service objects'] = $gnTmpServices;

        $stdoutarray['tag objects'] = $gTagCount;


        $stdoutarray['securityProfileGroup objects'] = $gnsecprofgroups;

        $stdoutarray['securityProfile Anti-Spyware objects'] = $gnsecprofAS;
        $stdoutarray['securityProfile Vulnerability objects'] = $gnsecprofVB;
        $stdoutarray['securityProfile WildfireAndAnti-Virus objects'] = $gnsecprofAVWF;
        $stdoutarray['securityProfile DNS objects'] = $gnsecprofDNS;
        $stdoutarray['securityProfile URL objects'] = $gnsecprofURL;
        $stdoutarray['securityProfile File-Blocking objects'] = $gnsecprofFB;
        $stdoutarray['securityProfile Data-Filtering objects'] = $gnsecprofDF;

        $stdoutarray['Decryption Profiles'] = $gnsecprofDecr;
        $stdoutarray['HIP Profiles'] = $gnsecprofHipProf;
        $stdoutarray['HIP Objects'] = $gnsecprofHipObj;

        $stdoutarray['App Custom'] = $gnAppCustom;
        $stdoutarray['App Filters'] = $gnAppFilters;
        $stdoutarray['App Groups'] = $gnAppGroup;

        $stdoutarray['schedule objects'] = $gScheduleCount;


        $stdoutarray['zones'] = $pan->zoneStore->count();
        #$stdoutarray['apps'] = $pan->appStore->count();


        $return = array();
        $return[0]['type'] = "all";
        $return[0]['name'] = "fawkes";
        $return[0]['counters'] = $stdoutarray;

        if( $return_true_false )
        {
            return $return;
        }
        else
        {
            #PH::print_stdout( $return );
            PH::print_stdout( $stdoutarray );
        }



    }

    function migration_error( $text )
    {
        if( $this->reporting )
        {
            $this->error = true;
            $this->error_array[] = $text;
        }
        else
        {
            if( !PH::$shadow_json )
            {
                PH::print_stdout("");
                PH::print_stdout("###############################################");
                PH::print_stdout("###############################################");
                PH::print_stdout($text);
                PH::print_stdout("###############################################");
                PH::print_stdout("###############################################");
                PH::print_stdout("");
            }

            derr($text);
        }
    }

    function run_cleanup_script( $argv)
    {
        //cleanup script to remove duplicate address-group members
        $inputFile = "";
        $outputFile= "";
        $shadowJSON = "";

        foreach( $argv as $key => $argument )
        {
            if( strpos( $argument, "in=" ) !== false )
            {
                $inputFile = $argument;
                $inputFile = str_replace( "in=", "", $inputFile);
                $file = basename($inputFile);
                $dirname = dirname($inputFile);
                $tmp_out = explode( ".", $file );
                $outputFile = $dirname."/".$tmp_out[0]."_changed.xml";
                $argv[$key] = "in=".$outputFile;
            }

            if( strpos( $argument, "shadow-json" ) !== false )
                $shadowJSON = "shadow-json";
        }

        $newARGV = array();
        $newARGV[0] = "";
        $newARGV[] = "in=".$inputFile;
        $newARGV[] = "out=".$outputFile;
        $newARGV[] = "shadow-ignoreInvalidAddressObjects";
        if( $shadowJSON !== "" )
            $newARGV[] = "shadow-json";
        $argc = count( $newARGV );

        PH::resetCliArgs( $newARGV);
        $util = new XMLISSUE( "xml-issue", $newARGV, $argc,"xml-issue");

        return $argv;
    }

    public function expliciteProxypredefined( $DEVICE, $rootDoc )
    {
        //created predefined EDL
        $externalList = DH::findFirstElementOrCreate( "external-list", $DEVICE->xmlroot );

        $EDLarray = array();
        $EDLarray[] = array( "PA-SWG-bulletproof-ip-list", "panw-bulletproof-ip-list" );
        $EDLarray[] = array( "PA-SWG-highrisk-ip-list", "panw-highrisk-ip-list" );
        $EDLarray[] = array( "PA-SWG-known-ip-list", "panw-known-ip-list" );

        foreach( $EDLarray as $edl )
        {
            $entry = $rootDoc->createElement('entry');
            $entry->setAttribute('name', $edl[0]);
            $type = DH::findFirstElementOrCreate( "type", $entry );
            $predefinedIP = DH::findFirstElementOrCreate( "predefined-ip", $type );
            $url = DH::findFirstElementOrCreate( "url", $predefinedIP );
            $url->textContent = $edl[1];
            $externalList->appendChild( $entry );
        }


        //create securityProfile
        /** @var SecurityRule $tmp_secrule */
        $tmp_secrule = $DEVICE->securityRules->newSecurityRule("BlockBadIPs");
        //add source all three EDL;
        /** @var DeviceCloud $DEVICE */
        $tmp_addr1 = $DEVICE->addressStore->createTmp( "PA-SWG-bulletproof-ip-list" );
        $tmp_addr2 = $DEVICE->addressStore->createTmp( "PA-SWG-highrisk-ip-list" );
        $tmp_addr3 = $DEVICE->addressStore->createTmp( "PA-SWG-known-ip-list" );

        $tmp_secrule->source->addObject( $tmp_addr1 );
        $tmp_secrule->source->addObject( $tmp_addr2 );
        $tmp_secrule->source->addObject( $tmp_addr3 );
        
        $tmp_secrule->setAction("deny");
    }

    public function migrationSpyware( $DEVICE, $profile, &$fawkes_dnssecurity = null )
    {
        $spyware_xmlroot = $profile->xmlroot;
        $spyware_profile = $profile;

        //$this->DEBUGprintDOMDocument( $spyware_xmlroot );

        $botnet_domain_xmlroot = DH::findFirstElement( 'botnet-domains', $spyware_xmlroot);

        if( $botnet_domain_xmlroot != null )
        {
            $fawkes_dnssecurity = $this->migrationSecProf( $spyware_profile, "DNSSecurityProfile", $DEVICE, $this->fawkes_doc, "", $botnet_domain_xmlroot  );

            $spyware_xmlroot->removeChild( $botnet_domain_xmlroot );
        }


        $fawkes_profile = $this->migrationSecProf( $spyware_profile, "AntiSpywareProfile", $DEVICE, $this->fawkes_doc, "", $spyware_xmlroot  );

        if( $fawkes_dnssecurity === null )
            $fawkes_dnssecurity = $DEVICE->DNSSecurityProfileStore->find( $profile->name() );

        return $fawkes_profile;
    }

    public function migrationURL( $DEVICE, $profile, &$fawkes_saassecurity = null )
    {
        $url_xmlroot = $profile->xmlroot;
        $url_profile = $profile;

        $http_header_insertion_xmlroot = DH::findFirstElement('http-header-insertion', $url_xmlroot);

        if( $http_header_insertion_xmlroot != null )
        {
            $url_xmlroot->removeChild( $http_header_insertion_xmlroot );
            $fawkes_saassecurity = $this->migrationSecProf( $url_profile, "SaasSecurityProfile", $DEVICE, $this->fawkes_doc, "", $http_header_insertion_xmlroot  );
        }

        if( $fawkes_saassecurity === null )
            $fawkes_saassecurity = $DEVICE->SaasSecurityProfileStore->find( $profile->name() );

        $fawkes_profile = $this->migrationSecProf( $profile, "URLProfile", $DEVICE, $this->fawkes_doc, "", $url_xmlroot );

        return $fawkes_profile;
    }

    public function migrationWildfireAddVirusBP( $fawkes_viruswildfire )
    {
        $virusBestPractice = "<entry name=\"best-practice\">
  <decoder>
    <entry name=\"ftp\">
      <action>default</action>
      <wildfire-action>reset-both</wildfire-action>
    </entry>
    <entry name=\"http\">
      <action>default</action>
      <wildfire-action>reset-both</wildfire-action>
    </entry>
    <entry name=\"imap\">
      <action>alert</action>
      <wildfire-action>alert</wildfire-action>
    </entry>
    <entry name=\"pop3\">
      <action>alert</action>
      <wildfire-action>alert</wildfire-action>
    </entry>
    <entry name=\"smb\">
     <action>default</action>
     <wildfire-action>reset-both</wildfire-action>
   </entry>
   <entry name=\"smtp\">
     <action>reset-both</action>
     <wildfire-action>reset-both</wildfire-action>
   </entry>
  </decoder>
</entry>";

        $wildfireBestPractice = "<entry name=\"best-practice\">
        <decoder>
          <entry name=\"ftp\">
            <action>default</action>
            <wildfire-action>default</wildfire-action>
            <mlav-action>default</mlav-action>
          </entry>
          <entry name=\"http\">
            <action>default</action>
            <wildfire-action>default</wildfire-action>
            <mlav-action>default</mlav-action>
          </entry>
          <entry name=\"http2\">
            <action>default</action>
            <wildfire-action>default</wildfire-action>
            <mlav-action>default</mlav-action>
          </entry>
          <entry name=\"imap\">
            <action>default</action>
            <wildfire-action>default</wildfire-action>
            <mlav-action>default</mlav-action>
          </entry>
          <entry name=\"pop3\">
            <action>default</action>
            <wildfire-action>default</wildfire-action>
            <mlav-action>default</mlav-action>
          </entry>
          <entry name=\"smb\">
            <action>default</action>
            <wildfire-action>default</wildfire-action>
            <mlav-action>default</mlav-action>
          </entry>
          <entry name=\"smtp\">
            <action>default</action>
            <wildfire-action>default</wildfire-action>
            <mlav-action>default</mlav-action>
          </entry>
        </decoder>
        <mlav-engine-filebased-enabled>
          <entry name=\"Windows Executables\">
            <mlav-policy-action>disable</mlav-policy-action>
          </entry>
          <entry name=\"PowerShell Script 1\">
            <mlav-policy-action>disable</mlav-policy-action>
          </entry>
          <entry name=\"PowerShell Script 2\">
            <mlav-policy-action>disable</mlav-policy-action>
          </entry>
          <entry name=\"Executable Linked Format\">
            <mlav-policy-action>disable</mlav-policy-action>
          </entry>
        </mlav-engine-filebased-enabled>
        </entry>";

        $newDoc = new DOMDocument();
        #$newDoc->loadXml($virusBestPractice);
        $newDoc->loadXml($wildfireBestPractice);
        $nodeVirusBestPractice = $this->fawkes_doc->importNode($newDoc->documentElement, TRUE);

        $node = $this->fawkes_doc->importNode($nodeVirusBestPractice, TRUE);
        $virus_decoder_node = DH::findFirstElement( "decoder", $node );
        #$this->DEBUGprintDOMDocument($virus_decoder_node);

        $fawkes_av_decoder_node = DH::findFirstElement( "decoder", $fawkes_viruswildfire->xmlroot );

        if( $fawkes_av_decoder_node === false )
            $fawkes_viruswildfire->xmlroot->appendChild($virus_decoder_node);

        $virus_mlav_node = DH::findFirstElement( "mlav-engine-filebased-enabled", $node );
        #$this->DEBUGprintDOMDocument($virus_decoder_node);

        $fawkes_av_mlav_node = DH::findFirstElement( "mlav-engine-filebased-enabled", $fawkes_viruswildfire->xmlroot );

        if( $fawkes_av_mlav_node === false )
            $fawkes_viruswildfire->xmlroot->appendChild($virus_mlav_node);
    }

    public function checkEDLsupport( $node_xml, $DG )
    {
        $EDL_name = DH::findAttribute('name', $node_xml);

        $EDL_type = DH::findFirstElement('type', $node_xml);
        if( $EDL_type != null )
        {
            $EDL_type_imsi = DH::findFirstElement('imsi', $EDL_type);
            if( $EDL_type_imsi != null )
                //"EDL migration of typeis NOT supported!
                $this->migration_error( "EDL migration of type imsi [Subscriber Identity List] NOT supported! ".$EDL_name." in DG: ".$DG );

            $EDL_type_imei = DH::findFirstElement('imei', $EDL_type);
            if( $EDL_type_imei != null )
                $this->migration_error( "EDL migration of type imei [Equipment Identity List] NOT supported! ".$EDL_name." in DG: ".$DG );
        }
    }


    function deleteDisableOverride( &$fawkesDoc )
    {
        $fawkesXMLroot = $fawkesDoc->xmldoc;

        $nodeList = $fawkesXMLroot->getElementsByTagname('disable-override');
        $nodeArray = iterator_to_array($nodeList);

        foreach( $nodeArray as $key => $item )
        {
            $text = DH::elementToPanXPath( $item );
            //print $text."\n";

            $item->parentNode->removeChild($item);
        }
    }
    
    function DLPdatafilteringCleanup( $util_fawkes )
    {
        #$DEVICEName = "Prisma Access";
        $DEVICEName = "All";
        /** @var Container $DEVICE */
        $DEVICE = $util_fawkes->findContainer( $DEVICEName);
        
        foreach( $this->DLPdatafilteringforDeletion as $profile )
        {
            $fawkes_profile = $DEVICE->DataFilteringProfileStore->find( $profile );
            $DEVICE->DataFilteringProfileStore->removeSecurityProfile($fawkes_profile);
        }

    }
}
