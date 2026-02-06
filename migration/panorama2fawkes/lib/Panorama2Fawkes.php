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

/*
 * Todo: DLP migration
 * DG/profiles/dlp-data-profiles
 * DG/profiles/data-objects
 */

include_once 'fawkes_migration_functions.php';

include_once 'transfer_template.php';
include_once 'transfer_rn_template.php';
include_once 'transfer_sn_template.php';
include_once 'transfer_mu_template.php';
include_once 'transfer_ep_template.php';

class Panorama2Fawkes
{
    use fawkes_migration_functions;

    use transfer_template;
    use transfer_rn_template;
    use transfer_sn_template;
    use transfer_mu_template;
    use transfer_ep_template;

    public $print_debug = false;

    public $cloudServicePluginVersion = "1.6.2";

    //FAWKES not supported features
    //ssl-inbound-proxy is supported,
    //https://docs.paloaltonetworks.com/cloud-management/administration/manage-configuration-ngfw-and-prisma-access/security-services/decryption
    public $decrypt_profile_not_supported = array("ssh-proxy", "ssl-inbound-proxy");
    public $decrypt_rule_action_supported = array( "decrypt", "no-decrypt" );


    /** @var PanoramaConf $pan_panorama */
    public $pan_panorama = null;
    /** @var DOMDocument $panorama_doc */
    public $panorama_doc = null;

    /** @var FawkesConf $pan_fawkes */
    public $pan_fawkes = null;
    /** @var DOMDocument $fawkes_doc */
    public $fawkes_doc = null;

    public $pluginTrustedZones = array();

    public $optimisation = false;

    public $migrationCheck = array();

    public $reporting = false;
    public $error = false;
    public $error_array = array();

    public $fixing = false;
    
    public $versionmigration = false;
    
    public $DLPdatafilteringforDeletion = array();

    public $keycheck = true;

    function main( $argv, $argc )
    {
        //in= -> Panorama file
//fawkes= -> FAWKES file;

        $supportedArguments = array();
        $supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'Panorama input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $supportedArguments['fawkes'] = array('niceName' => 'fawkes', 'shortHelp' => 'Fawkes input file. ie: in=config.xml ', 'argDesc' => '[filename]');
        $supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
        $supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $supportedArguments['optimise'] = array('niceName' => 'optimise', 'shortHelp' => 'reduce duplicate objects, delete unused objects, generate IP objects if IP-address are used directly in Policies');

        $supportedArguments['testing'] = array('niceName' => 'testing', 'shortHelp' => 'special argument for unit testing');
        $supportedArguments['reporting'] = array('niceName' => 'reporting', 'shortHelp' => 'error reporting');
        $supportedArguments['fixing'] = array('niceName' => 'fixing', 'shortHelp' => 'config fixing with manipulation');
        
        $supportedArguments['versionmigration'] = array('niceName' => 'versionmigration', 'shortHelp' => 'use python scripts to migrate to a later version');

        $supportedArguments['skipkeycheck'] = array('niceName' => 'skipkeycheck', 'shortHelp' => 'skip validation if keys are send with asterisk *');
        
        $usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=[PANORAMA_config_file] fawkes=[FAWKES_config_file]";


        /**
         * @var UTIL $util_panorama
         */
        PH::resetCliArgs( $argv);
        $util_panorama = new UTIL("custom", $argv, $argc,__FILE__, $supportedArguments, $usageMsg);
        $util_panorama->utilInit();

        if( $util_panorama->configType != 'panorama' )
            derr( "argument 'in=' expect Panorama config file!", null, false);


        if( isset( PH::$args['skipkeycheck'] ) )
        {
            $this->keycheck = false;
        }

        if( $this->keycheck )
        {
            //another validation if load xml doc has string ">********<" included
            $nodeArray = array();

            $nodeArray[] = "password";
            $nodeArray[] = "kerberos-keytab";
            $nodeArray[] = "bind-password";
            $nodeArray[] = "secret";
            $nodeArray[] = "authpwd";
            $nodeArray[] = "privpwd";
            $nodeArray[] = "private-key";
            $nodeArray[] = "authentication-key";
            $nodeArray[] = "secure-proxy-password";
            $nodeArray[] = "key";
            $nodeArray[] = "group-password";
            $nodeArray[] = "secret-access-key";
            $nodeArray[] = "service-account-cred";
            $nodeArray[] = "wmi-password";
            $nodeArray[] = "agent-user-override-key";
            $nodeArray[] = "passcode";
            $nodeArray[] = "uninstall-password";

            foreach( $nodeArray as $element )
            {
                $nodeList = $util_panorama->xmlDoc->getElementsByTagName($element);
                foreach ($nodeList as $entry)
                {
                    if (strpos($entry->nodeValue, "*") !== false)
                    {
                        $text = "all keys include asterisk [*]; please export Panorama running-config.xml correctly. TechSupportFile(TSF) is not working";
                        $this->migration_error( $text );
                    }
                }
            }
        }
        
##########################################
##########################################
        $util_panorama->load_config();
#$util->location_filter();

        $this->pan_panorama = $util_panorama->pan;

        $this->panorama_doc = new DOMDocument();
        $this->panorama_doc = $util_panorama->xmlDoc;


        if( isset( PH::$args['reporting'] ) )
        {
            $this->reporting = true;
        }
        if( isset( PH::$args['fixing'] ) )
        {
            $this->fixing = true;
        }
        if( isset( PH::$args['versionmigration'] ) )
        {
            $this->versionmigration = true;
        }
        ////////////////////////////////////////////////////////////
        ///////migrationCheck - what is supported by FAWKES - false => not supported
        ////////////////////////////////////////////////////////////
        if( isset( PH::$args['testing'] ) )
        {
            $this->migrationCheck['multi-tenant'] = "false";
            $this->migrationCheck['dlp'] = "true";
            $this->migrationCheck['iot'] = "false";
            $this->migrationCheck['sdwan'] = "false";
        }
        else
        {
            $filePath = dirname(__FILE__)."/../tests/migrationCheck.json";

            //request file path from kubernets; no testing possible;
            $fawkes_path = "/opt/features-list/features-list.json";
            if( file_exists( $fawkes_path ) )
                $filePath = $fawkes_path;

            $someJSON = file_get_contents( $filePath );
            // Convert JSON string to Array
            $this->migrationCheck = json_decode($someJSON, TRUE);
        }


        if( isset( PH::$args['optimise'] ) )
        {
            $this->optimisation = true;
        }

        if( !isset(PH::$args['fawkes']) )
        {
            PH::$args['fawkes'] = dirname(__FILE__)."/../fawkes_baseconfig.xml";
        }

        if( isset(PH::$args['fawkes']) )
        {
            $fawkes_file = PH::$args['fawkes'];
            $fawkes_out = PH::$args['out'];

            if( !file_exists( $fawkes_file ) )
                derr("file '{$fawkes_file}' not found");

            #$file_content = file( $file ) or die("Unable to open file!");
            $fawkes = file_get_contents( $fawkes_file) or die("Unable to open file!");


            PH::$args = array();
            PH::$argv = array();
            PH::$argv[0] = $argv[0];
            PH::$argv[0] = "";
            PH::$argv[] = "in=".$fawkes_file;
            PH::$argv[] = "out=" . $fawkes_out;

            $argv = array();
            $argv[] = "panorama-2fawkes.php";
            $argv[] = "in=".$fawkes_file;
            $argv[] = "out=" . $fawkes_out;

            /**
             * @var UTIL $util_fawkes
             */
            $util_fawkes = new UTIL("custom", $argv, $argc, __FILE__);
            $util_fawkes->utilInit();

            $util_fawkes->load_config();


            $this->pan_fawkes = $util_fawkes->pan;

            $this->fawkes_doc = new DOMDocument();
            #$fawkes_doc->loadXML($fawkes);
            $this->fawkes_doc = $util_fawkes->xmlDoc;
            #echo $fawkes_doc->saveXML();

            $container_Prisma_Access = $this->pan_fawkes->findContainer( "Prisma Access");
            if( $container_Prisma_Access === null )
                $container_Prisma_Access = $this->pan_fawkes->createContainer( "Prisma Access", "Prisma Access" );
            #$container_Prisma_Access->display_statistics();

        }

        if( $util_panorama->debugAPI )
        {
            PH::print_stdout( "DEBUGAPI");
            $this->print_debug = true;
        }




        $panorama_xpath = new DOMXPath( $util_panorama->xmlDoc );





////////////////////////////////////////////////////////////
///////PLUGIN
/// ////////////////////////////////////////////////////////////

        $plugin_query = "/config/devices/entry/plugins";

        $entries = $panorama_xpath->query($plugin_query);
        $plugins = $entries->item(0);

        if( $plugins == null )
            self::migration_error( "PLUGin section not found - stop migration!" );

        ///error if DLP plugin is found
        $dlp_node = DH::findFirstElement( "dlp", $plugins );
        if( $dlp_node != false && $this->migrationCheck['dlp'] == "false" )
        {
            self::migration_error( "DLP migration is NOT supported! - DLP found in plugins" );
        }

        $cloud_service_node = DH::findFirstElement( "cloud_services", $plugins );
        if( $cloud_service_node === false  )
        {
            self::migration_error( "cloud_service XML node not found!" );
        }

        $cloud_service_version = DH::findAttribute( "version", $cloud_service_node );
        if( $cloud_service_version !== false )
            $cloud_service_node->setAttribute( "version", $this->cloudServicePluginVersion );


        $multi_tenant_enable = DH::findFirstElement( "multi-tenant-enable", $cloud_service_node );
        $multi_tenent_enable_value = "no";
        if( $multi_tenant_enable != false )
        {
            $multi_tenent_enable_value = $multi_tenant_enable->textContent;

            if( $multi_tenent_enable_value == "no" )
            {
                $cloud_service_node->removeChild( $multi_tenant_enable );

                $multi_tenant = DH::findFirstElement( "multi-tenant", $cloud_service_node );
                if( $multi_tenant != false )
                    $cloud_service_node->removeChild( $multi_tenant );
            }

        }


        //error if multi_tenent_enable YES is found
        if( $multi_tenent_enable_value == 'yes' && $this->migrationCheck['multi-tenant'] == "false" )
        {
            self::migration_error( "Multi-tenant migration is NOT supported!" );
        }

        //check if explicit-proxy is used in panorama
        $explicit_proxy = DH::findFirstElement( "mobile-users-explicit-proxy", $cloud_service_node );
        $explicit_proxy_value = "no";
        if( $explicit_proxy != false )
        {
            $explicit_proxy_user = DH::findFirstElement( "users", $explicit_proxy );
            if( $explicit_proxy_user != false )
                $explicit_proxy_value = "yes";
        }
        $mobile_users = DH::findFirstElement( "mobile-users", $cloud_service_node );
        $mobile_users_value = "no";
        if( $mobile_users != false )
        {
            $mobile_users_value = "yes";
        }

        //Todo: swaschkut 20210726 check if enable no/yes must be done later, due to which setting is found
        //create plugin enable section
        $enable_string = "<enable>
            <mobile-users-explicit-proxy>".$explicit_proxy_value."</mobile-users-explicit-proxy>
            <mobile-users-global-protect>".$mobile_users_value."</mobile-users-global-protect>
          </enable>";
        $doc = new DOMDocument();
        $doc->loadXML($enable_string, XML_PARSE_BIG_LINES);
        $node = DH::findFirstElementOrDie('enable', $doc);

        $node = $this->panorama_doc->importNode($node, true);
        $cloud_service_node->appendChild( $node );

        $pluginFeatureArray = array( 'mobile-users', 'remote-networks', 'service-connection', 'mobile-users-explicit-proxy' );

        $plugin_dg_temp = array();
        $plugin_dg_temp['DGS']['shared'] = 'Prisma Access';

        foreach( $pluginFeatureArray as $feature )
        {
            //move dir-sync to template, do not keep it in plugin
            $this->pluginRemoveBGP(  $cloud_service_node, $feature );

            //move dir-sync to template, do not keep it in plugin
            $this->move_dir_sync(  $cloud_service_node, $feature );

            $this->getDGTemp( $plugin_dg_temp, $cloud_service_node, $feature );
        }

        $this->printDebug( $plugin_dg_temp, "check DG hierarchy" );



        $this->getTrustedZones(  $cloud_service_node, 'mobile-users' );
        $this->getTrustedZones(  $cloud_service_node, 'remote-networks' );
        //no trusted zones for service-connection

        $this->printDebug( $this->pluginTrustedZones, "trusted zones" );


//todo: after storing the values above in VARIABLES, delete entries from $cloud_service_node
//why, Albert mentioned this, but I can still see this in FAWKES config file
//todo: search in FAWKES and load CLOUD_SERVICE_NODE there
//manipluation of <trusted-zones> not needed, Alberts mentioned something, but it is still there in FAWKES

        $tmp_service_conn = DH::findFirstElement('service-connection', $cloud_service_node);
        if( $tmp_service_conn != false )
            $this->plugin_remove_dg_temp( $tmp_service_conn );

        $tmp_mobile_users = DH::findFirstElement('mobile-users', $cloud_service_node);
        if( $tmp_mobile_users != false )
            $this->plugin_remove_dg_temp( $tmp_mobile_users );

        $tmp_remote_networks = DH::findFirstElement('remote-networks', $cloud_service_node);
        if( $tmp_remote_networks != false )
            $this->plugin_remove_dg_temp( $tmp_remote_networks );

        $tmp_mobile_users_explicit_proxy = DH::findFirstElement('mobile-users-explicit-proxy', $cloud_service_node);
        if( $tmp_mobile_users_explicit_proxy != false )
            $this->plugin_remove_dg_temp( $tmp_mobile_users_explicit_proxy );

        $fawkes_plugin_node = $this->fawkes_doc->importNode($cloud_service_node, TRUE);


        $fawkes_config = DH::findFirstElement('config', $this->fawkes_doc);
        $fawkes_devices = DH::findFirstElement('devices', $fawkes_config);
        $fawkes_entry = DH::findFirstElement('entry', $fawkes_devices);
        $fawkes_plugin = DH::findFirstElement('plugins', $fawkes_entry);



        while ($fawkes_plugin->hasChildNodes()) {
            $fawkes_plugin->removeChild($fawkes_plugin->firstChild);
        }

        $fawkes_plugin->appendChild( $fawkes_plugin_node );

        if( $dlp_node != false && $this->migrationCheck['dlp'] == "true" )
        {
            //WHAT is the correct migration approach for DLP
            //- dlp-data-profiles node. They must be moved to config/devices/entry[@name='localhost.localdomain']/container/entry[@name='Prisma Access']/profiles/dlp-data-profiles

            $dlpInternal = DH::findFirstElement("internal", $dlp_node);
            $dlpProfiles = False;
            if( $dlpInternal !== False )
                $dlpProfiles = DH::findFirstElement("dlp-data-profiles", $dlpInternal);
            if( $dlpProfiles !== False )
            {
                #$DEVICEName = "Prisma Access";
                $DEVICEName = "All";
                /** @var Container $DEVICE */
                $DEVICE = $this->pan_fawkes->findContainer( $DEVICEName);
                if( $DEVICE === null )
                    #$DEVICE = $this->pan_fawkes->createContainer( $DEVICEName, "Prisma Access" );
                    $DEVICE = $this->pan_fawkes->createContainer( $DEVICEName, "All" );

                foreach( $dlpProfiles->childNodes as $XMLprofile )
                {
                    /** @var DOMElement $childNode */
                    if( $XMLprofile->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $this->DLPmigrateSecProf($XMLprofile, "DataFilteringProfile", $DEVICE, $this->fawkes_doc  );

                }
            }
        }

////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

        //create all needed Container / Device Cloud

        $DEVICEName = "Mobile Users Container";
        $DEVICE = $this->pan_fawkes->findContainer( $DEVICEName);
        if( $DEVICE === null )
            $DEVICE = $this->pan_fawkes->createContainer( $DEVICEName, "Prisma Access" );

        $DEVICEName = "Mobile Users";
        $DEVICE = $this->pan_fawkes->findDeviceCloud( $DEVICEName);
        if( $DEVICE === null )
            $DEVICE = $this->pan_fawkes->createDeviceCloud( $DEVICEName, "Mobile Users Container" );

        $DEVICEName = "Mobile Users Explicit Proxy";
        $DEVICE = $this->pan_fawkes->findDeviceCloud( $DEVICEName);
        if( $DEVICE === null )
        {
            $DEVICE = $this->pan_fawkes->createDeviceCloud( $DEVICEName, "Mobile Users Container" );
            #$this->expliciteProxypredefined( $DEVICE, $this->fawkes_doc );
        }

        $DEVICEName = "Mobile Users Access Agent";
        $DEVICE = $this->pan_fawkes->findDeviceCloud( $DEVICEName);
        if( $DEVICE === null )
            $DEVICE = $this->pan_fawkes->createDeviceCloud( $DEVICEName, "Mobile Users Container" );


        $DEVICEName = "Remote Networks";
        $DEVICE = $this->pan_fawkes->findDeviceCloud( $DEVICEName);
        if( $DEVICE === null )
        $DEVICE = $this->pan_fawkes->createDeviceCloud( $DEVICEName, "Prisma Access" );


        $DEVICEName = "Service Connections";
        $DEVICE = $this->pan_fawkes->findDeviceCloud( $DEVICEName);
        if( $DEVICE === null )
            $DEVICE = $this->pan_fawkes->createDeviceCloud( $DEVICEName, "Prisma Access" );







        $print_dg_hierarchy = false;
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
///
/// how to check DG hierarchy???
        $DGs = $this->pan_panorama->getDeviceGroups();
        foreach( $DGs as $key =>  $DG )
        {
            if( !isset( $plugin_dg_temp['DGS'][ $DG->name() ] ) )
            {
                //todo: swaschkut 01032021
                //delete DG with all included content

                $ALL = $DG->addressStore->all();
                foreach( $ALL as $obj )
                    $DG->addressStore->remove( $obj );

                $ALL = $DG->serviceStore->all();
                foreach( $ALL as $obj )
                    $DG->serviceStore->remove( $obj );

                $ALL = $DG->tagStore->getAll();
                foreach( $ALL as $obj )
                    $DG->tagStore->removeTag( $obj );

                //TODO:
                // - securityProfileStore/s
                // - securityProfileGroupStore


                $DG->securityRules->removeAll();
                $DG->natRules->removeAll();
                $DG->decryptionRules->removeAll();
                $DG->appOverrideRules->removeAll();


                $DG->captivePortalRules->removeAll();
                $DG->authenticationRules->removeAll();
                $DG->pbfRules->removeAll();
                $DG->qosRules->removeAll();
                $DG->dosRules->removeAll();


                continue;
            }
        }

        $TemplateStacks = $this->pan_panorama->getTemplatesStacks();
        foreach( $TemplateStacks as $key =>  $templateStack )
        {
            /** @var TemplateStack $templateStack */

            if(  $templateStack->name() != "Mobile_User_Template_Stack" &&
                $templateStack->name() != "Remote_Network_Template_Stack" &&
                $templateStack->name() != "Service_Conn_Template_Stack" &&
                $templateStack->name() != "Explicit_Proxy_Template_Stack" )
                continue;

            $this->printDebug( "tempStack: ".$templateStack->name(), "-------------" );

            $used_templates = $templateStack->templates;

            //task description: merging all template information within a template-stack
            $source = null;
            $merged = null;
            $first = true;
            foreach( array_reverse($used_templates) as $key => $template )
            {
                //set template environment


                $this->template_path_settings( $template->xmlroot );

                $this->GPvalidation( $template->xmlroot );

                $this->movingSHAREDtoVSYS();

                #print "key: ".$key." templatename: ".$template->name()."\n";
                if( $first )
                {
                    $source_orig = $this->templateGetDEVICEentry( $template->xmlroot );
                    $source = $source_orig->cloneNode( true);
                    $first = false;
                }
                else
                {
                    $add_orig = $this->templateGetDEVICEentry( $template->xmlroot );
                    $add = $add_orig->cloneNode( true);
                    if( $add !== null )
                        $this->findENTRY( $source, $add, "" );
                }
            }

            //at this stage something is wrong with ipsec_crypto_profile;
            // found this: crypto-profiles/ike-crypto-profiles/ipsec-crypto-profiles 20220330


            //task description: merging previous merged template/template information with config from template-stack
            $this->template_path_settings( $templateStack->xmlroot );
            $this->GPvalidation( $templateStack->xmlroot );
            $this->movingSHAREDtoVSYS();

            $add_orig = $this->templateGetDEVICEentry( $templateStack->xmlroot );
            if( $add_orig !== null )
            {
                $add = $add_orig->cloneNode(TRUE);
                $this->findENTRY($source, $add, "");
            }



            $mergedTemplate = $source;

            if(  $templateStack->name() == "Mobile_User_Template_Stack" )
                $this->migrate_mu_template( $mergedTemplate, $tmp_mobile_users );
            elseif(  $templateStack->name() == "Remote_Network_Template_Stack" )
                $this->migrate_rn_template( $mergedTemplate, $tmp_remote_networks );
            elseif(  $templateStack->name() == "Service_Conn_Template_Stack" )
                $this->migrate_sn_template( $mergedTemplate, $tmp_service_conn );
            elseif(  $templateStack->name() == "Explicit_Proxy_Template_Stack" )
                $this->migrate_ep_template( $mergedTemplate, $tmp_mobile_users_explicit_proxy );



            $DEVICEName = null;
            $DEVICE = null;
            if( $templateStack->name() == "Mobile_User_Template_Stack" )
            {
                /**
                 * @var Container $CONTAINER
                 */
                $DEVICEName = "Mobile Users Container";
                $DEVICE = $this->pan_fawkes->findContainer( $DEVICEName);
                if( $DEVICE === null )
                    $DEVICE = $this->pan_fawkes->createContainer( $DEVICEName, "Prisma Access" );

                $DEVICEName = "Mobile Users";
                $DEVICE = $this->pan_fawkes->findDeviceCloud( $DEVICEName);
                if( $DEVICE === null )
                    $DEVICE = $this->pan_fawkes->createDeviceCloud( $DEVICEName, "Mobile Users Container" );
            }
            elseif(  $templateStack->name() == "Remote_Network_Template_Stack" || $templateStack->name() == "Service_Conn_Template_Stack" )
            {
                if( $templateStack->name() == "Remote_Network_Template_Stack" )
                    $DEVICEName = "Remote Networks";
                elseif( $templateStack->name() == "Service_Conn_Template_Stack" )
                    $DEVICEName = "Service Connections";

                $DEVICE = $this->pan_fawkes->findDeviceCloud( $DEVICEName);
                if( $DEVICE === null )
                    $DEVICE = $this->pan_fawkes->createDeviceCloud( $DEVICEName, "Prisma Access" );
            }
            elseif(  $templateStack->name() == "Explicit_Proxy_Template_Stack" )
            {
                $DEVICEName = "Mobile Users Container";
                $DEVICE = $this->pan_fawkes->findContainer( $DEVICEName);
                if( $DEVICE === null )
                    $DEVICE = $this->pan_fawkes->createContainer( $DEVICEName, "Prisma Access" );

                $DEVICEName = "Mobile Users Explicit Proxy";
                $DEVICE = $this->pan_fawkes->findDeviceCloud( $DEVICEName);
                if( $DEVICE === null )
                {
                    $DEVICE = $this->pan_fawkes->createDeviceCloud( $DEVICEName, "Mobile Users Container" );
                    $this->expliciteProxypredefined( $DEVICE, $this->fawkes_doc );
                }

                $DEVICEName = "Mobile Users Access Agent";
                $DEVICE = $this->pan_fawkes->findDeviceCloud( $DEVICEName);
                if( $DEVICE === null )
                    $DEVICE = $this->pan_fawkes->createDeviceCloud( $DEVICEName, "Mobile Users Container" );

            }

            if( $DEVICE != null )
            {
                $cont_xmlroot = $DEVICE->xmlroot;

                //cleanup existing Container/DeviceCloud XMLnode "devices"
                $cont_devices = DH::findFirstElement( "devices", $cont_xmlroot );
                if( $cont_devices != false )
                    $cont_xmlroot->removeChild( $cont_devices );

                $cont_xmldoc = $DEVICE->owner->xmldoc;
                $node = $cont_xmldoc->importNode($mergedTemplate, true);

                $cont_devices = DH::findFirstElementOrCreate( "devices", $cont_xmlroot );
                $cont_devices->appendChild($node);
            }

            $this->printDebug( "-------------\n" );
        }


////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////


        #$this->run_util_script( "rule", $util_panorama, 'securityprofile-replace-by-Group', 'any' );
        #$this->run_util_script( "rule", $util_panorama, 'securityprofile-replace-by-Group', 'any', false, "defaultsecurity" );
        $this->run_util_script( "rule", $util_panorama, 'securityprofile-replace-by-Group', 'any', false, "security,defaultsecurity" );

        if( $this->optimisation )
        {
            $this->run_util_script( "address", $util_panorama, 'delete', 'any', '(object is.unused.recursive) and (object is.group)');
            $this->run_util_script( "address", $util_panorama, 'delete', 'any', 'object is.unused.recursive');
            $this->run_util_script( "service", $util_panorama, 'delete', 'any', '(object is.unused.recursive) and (object is.group)');
            $this->run_util_script( "service", $util_panorama, 'delete', 'any', 'object is.unused.recursive');
            $this->run_util_script( "tag", $util_panorama, 'delete', 'any', 'object is.unused');

//UTIL create address if used as TMP
            $this->run_util_script( "address", $util_panorama, 'replace-IP-by-MT-like-Object', 'any', 'object is.tmp');

            //Todo: run for all three types XYZ-merger allowmergingwithupperlevel 'location=any'

            $type_array = array( 'address', 'service', 'tag');
            foreach( $type_array as $type )
            {
                //object merger
                $this->run_util_script( $type, $util_panorama, 'move:shared,removeIfMatch', 'any');
                //add prefix to all object, but not in shared
                //move_objects to shared
            }
        }

////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

/// OBJTES migration
///               'tag', 'address', 'address-group', 'service', 'service-group',
//                'application', 'application-filter', 'application-group',
//                'schedule',
//                'region', 'external-list', 'dynamic-user-group',  'authentication-object',
//                'device-object'
/// PROFIL migration:
///
        PH::print_stdout( "" );

        foreach(  $plugin_dg_temp['DGS'] as $key => $DG )
        {
            $DGS_name = $key;
            if( $key === "shared" )
                $DG_obj = $this->pan_panorama;
            else
                $DG_obj = $this->pan_panorama->findDeviceGroup( $key );


            #print "find: ".$DG." in Device or Continainer\n";
            if( $DG === "Mobile_User_Device_Group" )
            {
                $DEVICEName = "Mobile Users Container";
                $DEVICE = $this->pan_fawkes->findContainer( $DEVICEName);
                if( $DEVICE === null )
                    $DEVICE = $this->pan_fawkes->createContainer( $DEVICEName, "Prisma Access" );

                $DEVICEName = "Mobile Users";
                $DEVICE = $this->pan_fawkes->findDeviceCloud( $DEVICEName);
                if( $DEVICE === null )
                    $DEVICE = $this->pan_fawkes->createDeviceCloud( $DEVICEName, "Mobile Users Container" );
            }
            elseif( $DG === "Prisma Access" )
            {
                $DEVICEName = "Prisma Access";
                /** @var Container $DEVICE */
                $DEVICE = $this->pan_fawkes->findContainer( $DEVICEName);
                if( $DEVICE === null )
                    $DEVICE = $this->pan_fawkes->createContainer( $DEVICEName, "Prisma Access" );
            }
            elseif( $DG === "Remote_Network_Device_Group" || $DG === "Service_Conn_Device_Group" )
            {
                if( $DG === "Remote_Network_Device_Group" )
                    $DEVICEName = "Remote Networks";
                elseif( $DG === "Service_Conn_Device_Group" )
                    $DEVICEName = "Service Connections";

                /** @var DeviceCloud $DEVICE */
                $DEVICE = $this->pan_fawkes->findDeviceCloud( $DEVICEName);
                if( $DEVICE === null )
                    $DEVICE = $this->pan_fawkes->createDeviceCloud( $DEVICEName, "Prisma Access" );
            }
            elseif(  $DG == "Explicit_Proxy_Device_Group" )
            {
                $DEVICEName = "Mobile Users Container";
                $DEVICE = $this->pan_fawkes->findContainer( $DEVICEName);
                if( $DEVICE === null )
                    $DEVICE = $this->pan_fawkes->createContainer( $DEVICEName, "Prisma Access" );

                $DEVICEName = "Mobile Users Explicit Proxy";
                $DEVICE = $this->pan_fawkes->findDeviceCloud( $DEVICEName);
                if( $DEVICE === null )
                {
                    $DEVICE = $this->pan_fawkes->createDeviceCloud( $DEVICEName, "Mobile Users Container" );
                    #$this->expliciteProxypredefined( $DEVICE, $this->fawkes_doc );
                }

                $DEVICEName = "Mobile Users Access Agent";
                $DEVICE = $this->pan_fawkes->findDeviceCloud( $DEVICEName);
                if( $DEVICE === null )
                    $DEVICE = $this->pan_fawkes->createDeviceCloud( $DEVICEName, "Mobile Users Container" );

            }


            if( $DEVICE != null )
            {
                $this->printDebug( "Container/DeviceCloud found: ".$DEVICE->name()."\n" );
            }


/// objects migration, shared and all other DG
            $tmp_migration_array = array(
                'tag', 'address', 'address-group', 'service', 'service-group',
                'application', 'application-filter', 'application-group',
                'schedule',

                'region', 'external-list', 'dynamic-user-group',  'authentication-object',

                'threats',

                'device-object'
            );
            //NONE of these elements are really available as objects and can counted well; optimisation needed in Expedition-Converter
            //'region', 'external-list', 'dynamic-user-group',  'authentication-object'

            foreach( $tmp_migration_array as $key2 => $tmp_obj )
            {
                if( $key === "shared" )
                {
                    $panorama_shared = DH::findFirstElementOrCreate( "shared", $DG_obj->xmlroot );
                    $tmp_xmlroot = DH::findFirstElement( $tmp_obj, $panorama_shared);
                }
                else
                    $tmp_xmlroot = DH::findFirstElement( $tmp_obj, $DG_obj->xmlroot);

                if( $tmp_xmlroot != false )
                {
                    //this is to update the objects in memory
                    if( $tmp_obj === "address" )
                        $objStore = "addressStore";
                    elseif( $tmp_obj === "address-group" )
                        $objStore = "addressStore";
                    elseif( $tmp_obj === "service" )
                        $objStore = "serviceStore";
                    elseif( $tmp_obj === "service-group" )
                        $objStore = "serviceStore";
                    elseif( $tmp_obj === "tag" )
                        $objStore = "tagStore";
                    elseif( $tmp_obj === "application" )
                        $objStore = "appStore";
                    elseif( $tmp_obj === "application-filter" )
                        $objStore = "appStore";
                    elseif( $tmp_obj === "application-group" )
                        $objStore = "appStore";
                    elseif( $tmp_obj === "schedule" )
                        $objStore = "scheduleStore";

                    //this is for adding it to the XML document
                    foreach( $tmp_xmlroot->childNodes as $node_xml )
                    {
                        /** @var DOMElement $childNode */
                        if( $node_xml->nodeType != XML_ELEMENT_NODE )
                            continue;


                        if( $tmp_obj == "device-object" && $this->migrationCheck['iot'] == "false" )
                        {
                            self::migration_error( "IoT migration is NOT supported! - 'device-object' found in Panorama Device-Group: ".$DG );
                        }

                        if( $tmp_obj == "external-list" )
                        {
                            $this->checkEDLsupport( $node_xml, $DG );
                        }

                        $fawkes_tmp_xmlroot = DH::findFirstElementorCreate( $tmp_obj, $DEVICE->xmlroot);

                        $node = $this->fawkes_doc->importNode($node_xml, TRUE);
                        $fawkes_tmp_xmlroot->appendChild($node);

                        /*
                         * //Todo: validation check inspecific for appstore not working; others are fine
                        $nodeName = DH::findAttribute( "name", $node_xml );
                        if( isset( $DEVICE->$objStore) )
                        {
                            if( $DEVICE->$objStore->find( $nodeName ) === null )
                            {
                                $node = $this->fawkes_doc->importNode($node_xml, TRUE);
                                $fawkes_tmp_xmlroot->appendChild($node);
                            }
                            else
                            {
                                #print "objectname: ".$nodeName." of Storetype: ".$tmp_obj." already available\n";
                                $tmp_xmlroot->removeChild( $node_xml );
                            }
                        }
                        */
                    }

                    //this is to update the objects in memory
                    if( $tmp_obj === "address" )
                        $DEVICE->addressStore->load_addresses_from_domxml($tmp_xmlroot);
                    elseif( $tmp_obj === "address-group" )
                        $DEVICE->addressStore->load_addressgroups_from_domxml($tmp_xmlroot);
                    elseif( $tmp_obj === "service" )
                        $DEVICE->serviceStore->load_services_from_domxml($tmp_xmlroot);
                    elseif( $tmp_obj === "service-group" )
                        $DEVICE->serviceStore->load_servicegroups_from_domxml($tmp_xmlroot);
                    elseif( $tmp_obj === "tag" )
                    {
                        $root_node = $this->fawkes_doc->importNode($tmp_xmlroot, TRUE);
                        $DEVICE->tagStore->load_from_domxml($root_node);
                    }

                    elseif( $tmp_obj === "application" )
                        $DEVICE->appStore->load_application_custom_from_domxml($tmp_xmlroot);
                    elseif( $tmp_obj === "application-filter" )
                        $DEVICE->appStore->load_application_filter_from_domxml($tmp_xmlroot);
                    elseif( $tmp_obj === "application-group" )
                        $DEVICE->appStore->load_application_group_from_domxml($tmp_xmlroot);

                    elseif( $tmp_obj === "schedule" )
                        $DEVICE->scheduleStore->load_from_domxml($tmp_xmlroot);

                    //Todo: add support for other objects stores to load in memory, to be counted at the end
                    //'application', 'application-filter', 'application-group', // load available, do it, then add counter

                }
            }


            foreach( $DG_obj->customURLProfileStore->getAll() as $tmpProfil)
                $this->migrationSecProf( $tmpProfil, "customURLProfile", $DEVICE, $this->fawkes_doc  );

            foreach( $DG_obj->DecryptionProfileStore->getAll() as $tmpProfil)
                $this->migrationSecProf( $tmpProfil, "DecryptionProfile", $DEVICE, $this->fawkes_doc  );

            foreach( $DG_obj->HipObjectsProfileStore->getAll() as $tmpProfil)
                $this->migrationSecProf( $tmpProfil, "HipObjectsProfile", $DEVICE, $this->fawkes_doc  );

            foreach( $DG_obj->HipProfilesProfileStore->getAll() as $tmpProfil)
                $this->migrationSecProf( $tmpProfil, "HipProfilesProfile", $DEVICE, $this->fawkes_doc  );



            foreach( $DG_obj->FileBlockingProfileStore->getAll() as $profile)
            {
                $refArray = $profile->getReferences();
                if( count( $refArray ) === 0 )
                    $fawkes_profile = $this->migrationSecProf( $profile, "FileBlockingProfile", $DEVICE, $this->fawkes_doc  );
            }
            foreach( $DG_obj->DataFilteringProfileStore->getAll() as $profile)
            {
                $refArray = $profile->getReferences();
                if( count( $refArray ) === 0 )
                    $fawkes_profile = $this->migrationSecProf( $profile, "DataFilteringProfile", $DEVICE, $this->fawkes_doc  );
            }
            foreach( $DG_obj->VulnerabilityProfileStore->getAll() as $profile)
            {
                $refArray = $profile->getReferences();
                if( count( $refArray ) === 0 )
                    $fawkes_profile = $this->migrationSecProf( $profile, "VulnerabilityProfile", $DEVICE, $this->fawkes_doc );
            }
            foreach( $DG_obj->URLProfileStore->getAll() as $profile)
            {
                $refArray = $profile->getReferences();
                if( count( $refArray ) === 0 )
                {
                    $fawkes_profile = $this->migrationURL( $DEVICE, $profile, $fawkes_saassecurity );
                    #$fawkes_profile = $this->migrationSecProf( $profile, "URLProfile", $DEVICE, $this->fawkes_doc );
                }

            }
            foreach( $DG_obj->AntiSpywareProfileStore->getAll() as $profile)
            {
                $refArray = $profile->getReferences();
                if( count( $refArray ) === 0 )
                {
                    $fawkes_profile = $this->migrationSpyware( $DEVICE, $profile, $fawkes_dnssecurity );
                }
            }

            //WILDFIRE
            foreach( $DG_obj->WildfireProfileStore->getAll() as $profile)
            {
                $refArray = $profile->getReferences();
                if( count( $refArray ) === 0 )
                {
                    $fawkes_viruswildfire = $this->migrationSecProf( $profile, "VirusAndWildfireProfile", $DEVICE, $this->fawkes_doc, "", $profile->xmlroot  );

                    $this->migrationWildfireAddVirusBP( $fawkes_viruswildfire );
                }
            }
            //VIRUS
            foreach( $DG_obj->AntiVirusProfileStore->getAll() as $profile)
            {
                $refArray = $profile->getReferences();
                if( count( $refArray ) === 0 )
                {
                    $fawkes_profile = $this->migrationSecProf( $profile, "VirusAndWildfireProfile", $DEVICE, $this->fawkes_doc, "", $profile->xmlroot  );
                }
            }




            /**
             * @var DeviceGroup $DG_obj
             */
            $this->printDebug( "DGname: ".$DG_obj->name() );
            $this->printDebug( "countSecProfGroup - ".count( $DG_obj->securityProfileGroupStore->getAll() ) );

            foreach( $DG_obj->securityProfileGroupStore->getAll() as $secProfGroup )
            {
                /**
                 * @var SecurityProfileGroup $secProfGroup
                 */
                $this->printDebug( PH::boldText( "\nSecProfGroup: ".$secProfGroup->name() ) );


                $fawkes_secprofGroup = $DEVICE->securityProfileGroupStore->find( $secProfGroup->name(), null, FALSE );
                if( $fawkes_secprofGroup === null )
                {
                    $fawkes_secprofGroup = new SecurityProfileGroup( $secProfGroup->name(), $DEVICE->securityProfileGroupStore , TRUE);
                    $fawkes_secprofGroup->owner = null;
                    $DEVICE->securityProfileGroupStore->addSecurityProfileGroup( $fawkes_secprofGroup );
                }




                $virus_xmlroot = null;
                $wildfire_xmlroot = null;
                $spyware_xmlroot = null;

                $virus_profile = null;
                $wildfire_profile = null;
                $spyware_profile = null;

                $fawkes_saassecurity = null;
                $fawkes_dnssecurity = null;

                foreach( $secProfGroup->secprofiles as $key => $profile )
                {
                    if( !empty( $profile ) )
                    {
                        if( is_object( $profile ) )
                        {
                            $this->printDebug( "profName-".$key .": '".$profile->name()."'" );

                            if( $key == "virus" )
                            {
                                //what if default -> best-practice; any specific pre-defined settings
                                $virus_xmlroot = $profile->xmlroot;
                                $virus_profile = $profile;
                            }
                            elseif( $key == "wildfire-analysis" )
                            {
                                //what if default -> best-practice; any specific pre-defined settings
                                $wildfire_xmlroot = $profile->xmlroot;
                                $wildfire_profile = $profile;
                            }
                            elseif( $key == "spyware" )
                            {
                                $spyware_xmlroot = $profile->xmlroot;
                                $spyware_profile = $profile;
                                //search for 'botnet-domain' xml element
                            }
                            elseif( $key == "file-blocking" )
                            {
                                $fawkes_profile = $this->migrationSecProf( $profile, "FileBlockingProfile", $DEVICE, $this->fawkes_doc  );
                                $fawkes_secprofGroup->secprofiles[$key] = $fawkes_profile->name();
                                $this->printDebug( "\nadd to group => '".$fawkes_profile->name()."'" );
                            }
                            elseif( $key == "data-filtering" )
                            {
                                $fawkes_profile = $this->migrationSecProf( $profile, "DataFilteringProfile", $DEVICE, $this->fawkes_doc  );
                                $fawkes_secprofGroup->secprofiles[$key] = $fawkes_profile->name();
                                $this->printDebug( "\nadd to group => '".$fawkes_profile->name()."'" );
                            }
                            elseif( $key == "vulnerability" )
                            {
                                $fawkes_profile = $this->migrationSecProf( $profile, "VulnerabilityProfile", $DEVICE, $this->fawkes_doc );
                                $fawkes_secprofGroup->secprofiles[$key] = $fawkes_profile->name();
                                $this->printDebug( "\nadd to group => '".$fawkes_profile->name()."'" );
                            }
                            elseif( $key == "url-filtering" )
                            {
                                #$fawkes_profile = $this->migrationSecProf( $profile, "URLProfile", $DEVICE, $this->fawkes_doc );
                                $fawkes_profile = $this->migrationURL( $DEVICE, $profile, $fawkes_saassecurity );
                                $fawkes_secprofGroup->secprofiles[$key] = $fawkes_profile->name();

                                if( $fawkes_saassecurity !== null )
                                    $fawkes_secprofGroup->secprofiles['saas-security'] = $fawkes_saassecurity->name();
                                $this->printDebug( "\nadd to group => '".$fawkes_profile->name()."'" );
                            }
                        }
                        elseif( in_array( $profile, $this->DLPdatafilteringforDeletion ) )
                        {
                            if( $key == "data-filtering" )
                            {
                                #$DEVICEName = "Prisma Access";
                                $DEVICEName = "All";
                                /** @var Container $DEVICE */

                                $DEVICE = $this->pan_fawkes->findContainer( $DEVICEName);
                                $fawkes_profile = $DEVICE->DataFilteringProfileStore->find( $profile );
                                $fawkes_secprofGroup->secprofiles[$key] = $fawkes_profile->name();
                                $this->printDebug( "\nadd to group => '".$fawkes_profile->name()."'" );
                            }
                        }
                        else
                        {
                            //assume 'default' must be changed to "best-practice
                            $this->printDebug( "profName-".$key .": '".$profile."'" );

                            if( $profile === 'strict' )
                                $set = 'best-practice-strict';
                            else
                                $set = 'best-practice';

                            if( $key == "virus" || $key == "wildfire-analysis" )
                                $fawkes_secprofGroup->secprofiles['virus-and-wildfire-analysis'] = $set;
                            else
                                $fawkes_secprofGroup->secprofiles[$key] = $set;
                            $this->printDebug( "\nadd to group => ".$set );
                        }
                    }
                }

                $fawkes_viruswildfire = null;

                if( $virus_xmlroot != null || $wildfire_xmlroot != null )
                {
                    if( $virus_xmlroot != null)
                    {
                        if( isset( $fawkes_secprofGroup->secprofiles['virus-and-wildfire-analysis'] ) && $fawkes_secprofGroup->secprofiles['virus-and-wildfire-analysis'] == 'best-practice' )
                        {
                            //Todo: add WF best-practice
                        }

                        $fawkes_viruswildfire = $this->migrationSecProf( $virus_profile, "VirusAndWildfireProfile", $DEVICE, $this->fawkes_doc, "", $virus_xmlroot  );

                        $fawkes_secprofGroup->secprofiles['virus-and-wildfire-analysis'] = $fawkes_viruswildfire->name();
                        $this->printDebug( "\nadd to group => '".$fawkes_viruswildfire->name()."'" );
                    }

                    if( $wildfire_xmlroot != null)
                    {
                        if( isset( $fawkes_secprofGroup->secprofiles['virus-and-wildfire-analysis'] ) && $fawkes_secprofGroup->secprofiles['virus-and-wildfire-analysis'] == 'best-practice' )
                        {
                            //add Virus best-practice??
                        }

                        if( $fawkes_viruswildfire === null )
                        {
                            $fawkes_viruswildfire = $this->migrationSecProf( $wildfire_profile, "VirusAndWildfireProfile", $DEVICE, $this->fawkes_doc, "", $wildfire_xmlroot  );

                            //add virus best practise
                            $this->migrationWildfireAddVirusBP( $fawkes_viruswildfire );

                            $fawkes_secprofGroup->secprofiles['virus-and-wildfire-analysis'] = $fawkes_viruswildfire->name();
                            $this->printDebug( "\nadd to group => '".$fawkes_viruswildfire->name()."'" );
                        }
                        else
                        {
                            //virus part already available;
                            //add wildfire XML part
                            $node = $this->fawkes_doc->importNode($wildfire_xmlroot, TRUE);
                            $wf_rules_node = DH::findFirstElement( "rules", $node );

                            $fawkes_wf_ruls_node = DH::findFirstElement( "rules", $fawkes_viruswildfire->xmlroot );

                            if( $wf_rules_node !== false && $fawkes_wf_ruls_node === false )
                                $fawkes_viruswildfire->xmlroot->appendChild($wf_rules_node);
                        }
                    }
                    else
                    {
                        //what todo if no Wildfire profile is set??? default settings are looking like how?
                    }
                }

                if( $spyware_xmlroot != null)
                {
                    $fawkes_dnssecurity = null;
                    $fawkes_profile = $this->migrationSpyware( $DEVICE, $spyware_profile, $fawkes_dnssecurity );

                    //20220310 check secprof problem
                    if( $fawkes_dnssecurity !== null )
                    {
                        $fawkes_secprofGroup->secprofiles['dns-security'] = $fawkes_dnssecurity->name();
                        $this->printDebug( "\nadd dns-security to group => '".$fawkes_dnssecurity->name()."'" );
                    }
                    else
                    {
                        //$this->DEBUGprintDOMDocument( $spyware_xmlroot );
                        $this->printDebug( "\nno DNS profil migrate - orig name: ".$fawkes_profile->name() );
                    }


                    $fawkes_secprofGroup->secprofiles['spyware'] = $fawkes_profile->name();
                    $this->printDebug( "\nadd spyware to group => '".$fawkes_profile->name()."'" );
                }

                $fawkes_secprofGroup->rewriteXML();
            }

            if( $DG === "Prisma Access" &&  $DGS_name !== "shared" )
            {
                #$ruletype_array = array('security', 'decryption', 'qos', 'appoverride', 'authentication');
                $ruletype_array = array('security', 'decryption', 'qos', 'appoverride');

                foreach( $ruletype_array as $ruletype )
                {
                    $this->run_util_script( "rule", $util_panorama, 'move:shared,pre', $DGS_name, 'rule is.prerule', $ruletype );
                    $this->run_util_script( "rule", $util_panorama, 'move:shared,post', $DGS_name, 'rule is.postrule', $ruletype );
                }
            }
            PH::print_stdout("");
        }

//////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

//copy Rules from DG SN/ RN/ MU
//Service_Conn_Device_Group
//Remote_Network_Device_Group

        $RNruleStores = array( "securityRules", "decryptionRules", "qosRules", "appOverrideRules", "authenticationRules", "defaultSecurityRules" );
        $RNarray = array( 'dg' => "Remote_Network_Device_Group", 'cloud' => "Remote Networks", "store" => $RNruleStores );


        $SNruleStores = array( "qosRules" );
        $SNarray = array( 'dg' => "Service_Conn_Device_Group", 'cloud' => "Service Connections", "store" => $SNruleStores );


        $MUruleStores = array( "securityRules", "decryptionRules", "appOverrideRules", "authenticationRules", "defaultSecurityRules" );
        #$MUarray = array( 'dg' => "Mobile_User_Device_Group", 'container' => "Mobile Users Container", "store" => $MUruleStores );
        $MUarray = array( 'dg' => "Mobile_User_Device_Group", 'cloud' => "Mobile Users", "store" => $MUruleStores );

        $EPruleStores = array( "securityRules", "decryptionRules", "appOverrideRules", "authenticationRules", "defaultSecurityRules" );
        $EParray = array( 'dg' => "Explicit_Proxy_Device_Group", 'cloud' => "Mobile Users Explicit Proxy", "store" => $EPruleStores );

        $sharedruleStores = array( "securityRules", "decryptionRules", "qosRules", "appOverrideRules", "authenticationRules", "defaultSecurityRules" );
        $SHAREDarray = array( 'dg' => "shared", 'container' => "Prisma Access", "store" => $sharedruleStores );

        $testArray = array( $MUarray, $RNarray, $SNarray, $EParray, $SHAREDarray );
        $this->ruleManipulation( $testArray );


        ////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////
        //improvement delete all XML node with name <disable-override>
        //this Panorama feature is NOT supported in FAWKES https://jira-hq.paloaltonetworks.local/browse/DIT-19864 20220311
        $this->deleteDisableOverride( $util_fawkes->pan );

        #$this->DLPdatafilteringCleanup( $util_fawkes->pan );

        ////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////

        if( $this->error )
        {
            $array = array();
            foreach( $this->error_array as $key => $error )
            {
                if( !PH::$shadow_json )
                {
                    PH::print_stdout( "");
                    PH::print_stdout( "###############################################");
                    PH::print_stdout( "###############################################");
                    PH::print_stdout( $error);
                    PH::print_stdout( "###############################################");
                    PH::print_stdout( "###############################################");
                    if( $this->fixing )
                        PH::print_stdout( " - ARGUMENT: fixing was used, the ERROR above is only informational" );
                    else
                        PH::print_stdout( " - ARGUMENT: reporting was used" );
                    PH::print_stdout( "");
                }
                else
                {
                    if( $key == 0 )
                        $array['error'] = $error;
                    else
                    {
                        $array['error'.$key] = $error;
                    }
                }
            }
            if( PH::$shadow_json )
            {
                $JSON_string = json_encode( $array, JSON_PRETTY_PRINT );
                print $JSON_string;
            }
            if( !$this->fixing )
            {
                derr( "this configuration contains errors", null, false );
            }

        }
        
        if( $this->versionmigration )
        {
            $fawkesV3_filename = str_replace( ".xml", "fawkesV3.xml", $util_fawkes->configOutput );
            $filenameOut = $util_fawkes->configOutput;

            $util_fawkes->pan->save_to_file( $fawkesV3_filename );

            if( !PH::$shadow_json )
            {
                PH::print_stdout( "" );
                PH::print_stdout( "migrate fawkes version for file: ".$fawkesV3_filename);
            }

            //run python script
            $pythonScript = "python3 ".dirname(__FILE__)."/../fawkes2fawkes/start.py -i ".$fawkesV3_filename." -o ".$filenameOut;
            if( $this->print_debug )
                $pythonScript .= " -d true";
            exec($pythonScript, $output, $retValue);

            if( $this->print_debug )
            {
                foreach( $output as $line )
                {
                    $string = '   ##  ';
                    $string .= $line;
                    print $string."\n" ;
                }
            }
        }


        // save our work !!!
        if( $util_fawkes->configOutput !== null )
        {
            if( $util_fawkes->configOutput != '/dev/null' )
            {
                if( $this->versionmigration )
                {
                    $fawkesV3_filename = str_replace( ".xml", "fawkesV3.xml", $util_fawkes->configOutput );

                    if( !PH::$shadow_json )
                    {
                        PH::print_stdout( "" );
                        PH::print_stdout( "delete file: ".$fawkesV3_filename );
                        PH::print_stdout( "" );
                    }
                    unlink( $fawkesV3_filename );
                }
                else
                    $util_fawkes->pan->save_to_file( $util_fawkes->configOutput );

                //Todo: also write statistics into JSON file
                //
                #$stat_array = $this->pan_fawkes->display_statistics( true );
                $stat_array = $this->display_migration_counter( $this->pan_fawkes, true);
                $JSON_string = json_encode( $stat_array, JSON_PRETTY_PRINT );

                $JSON_filename = str_replace( ".xml", ".json", $util_fawkes->configOutput );
                file_put_contents(  $JSON_filename, $JSON_string );
            }
        }

    }
}