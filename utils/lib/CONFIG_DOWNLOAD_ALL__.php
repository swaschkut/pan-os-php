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

class CONFIG_DOWNLOAD_ALL__ extends UTIL
{
    public $utilType = null;

    public function utilStart()
    {
        $this->supportedArguments = Array();
        $this->supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
#$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');

        $this->usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml location=vsys1 ".
            "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']\n" .
            "php ".basename(__FILE__)." help          : more help messages\n";

        $this->prepareSupportedArgumentsArray();

        $this->utilInit();

        $this->main();


        
    }

    public function main( )
    {

        $pan = $this->pan;
        $inputConnector = $pan->connector;



        if( $this->configInput['type'] !== 'api' )
            derr('only API connection supported');

########################################################################################################################
        $inputConnector->refreshSystemInfos();

        print "\n\n##########################################\n";

        if( $this->configType == 'panorama' )
        {
            print 'PANORAMA serial: '.$inputConnector->info_serial."\n\n";


            $config_pan_candidate = $inputConnector->getCandidateConfig();
            $config_pan_candidate->save( $inputConnector->info_serial."_PANORAMA.xml" );


########################################################################################################################
            $device_serials = $inputConnector->panorama_getConnectedFirewallsSerials();

            foreach( $device_serials as $child )
            {
                print "##########################################\n";

                $fw_con = $inputConnector->cloneForPanoramaManagedDevice($child['serial']);
                $fw_con->refreshSystemInfos();
                $fw_con->setShowApiCalls($this->debugAPI);

                $this->downloadFWconfig( $fw_con, $child['hostname'] );
            }
        }
        elseif( $this->configType == 'panos' )
        {
            #print 'PANOS serial: '.$inputConnector->info_serial."\n\n";

            $this->downloadFWconfig( $inputConnector, $inputConnector->info_hostname );

            $this->FirewallSpecificDownload( $inputConnector, $inputConnector->info_hostname );
        }

    }

    function downloadFWconfig( $fw_con, $hostname)
    {
        /** @VAR PanAPIConnector $fw_con */
        print 'FIREWALL serial: ' . $fw_con->info_serial . "\n\n";

        $config_candidate = $fw_con->getCandidateConfig();
        ##########SAVE config
        $pan = new PANConf();
        $pan->load_from_domxml($config_candidate);
        $pan->save_to_file($fw_con->info_serial."_".$hostname."_FW.xml");



        $config_pushed = $fw_con->getPanoramaPushedConfig();
        if( $config_pushed !== false )
        {
            //Todo: swaschkut 20250211
            // looks like this is no longer working - check what and with which config version this changed

            #if( $config_pushed->nodeType == XML_DOCUMENT_NODE )
            if( get_class($config_pushed) === "DOMDocument" )
            {
                $first_element = $config_pushed->firstElementChild;
                #$found = DH::findFirstElement('config', $config_pushed);
                $found = DH::findFirstElement('panorama', $first_element);
            }

            if( $found !== false )
            {
                ##########SAVE config
                $pan = new PANConf();
                $pan->load_from_domxml($config_pushed);
                $pan->save_to_file($fw_con->info_serial."_".$hostname."_FW_panorama-pushed.xml");
            }
        }


        //Todo:  this is only Panorama template - merged no object/rule merged!!!!!!
        /*
        $config_merged = $fw_con->getMergedConfig();
        ##########SAVE config
        $pan = new PANConf();
        $pan->load_from_domxml($config_merged);
        $pan->save_to_file($fw_con->info_serial."_".$hostname."_FW_merged_network.xml");
        */

        $config_merged = $fw_con->getMergedConfigFile();
        ##########SAVE config
        if( $config_merged !== false )
        {
            PH::print_stdout("ALL SECRETS are hidden with ASTERISK *******");
            PH::print_stdout("XPATH: /config/*/certificate");
            PH::print_stdout("<private-key>********</private-key>");
            PH::print_stdout("XPATH: /config/*/local-user-database/");
            PH::print_stdout("<phash>********</phash>");
            $pan = new PANConf();
            $pan->load_from_domxml($config_merged);
            $pan->save_to_file($fw_con->info_serial."_".$hostname."_FW_merged-running-config.xml");
        }
    }

    function FirewallSpecificDownload( $directFW_con, $hostname )
    {
        PH::print_stdout("Now saving device-state to file '".$directFW_con->info_serial."_".$hostname."_device_state_cfg.tgz'...");
        $directFW_con->getFirewallDeviceState($directFW_con->info_serial."_".$hostname);

        PH::print_stdout("TSF");
        $directFW_con->getFirewallTechSupportFile($directFW_con->info_serial."_".$hostname);
    }

}