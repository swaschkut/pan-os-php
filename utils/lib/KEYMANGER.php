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

class KEYMANGER extends UTIL
{
    public $utilType = null;


    public function utilStart()
    {
        $this->usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " [delete=hostOrIP] [add=hostOrIP] [test=hostOrIP] [hiddenPW]" .
        "
    Examples:
            
    - php " . basename(__FILE__) . " add=license-apikey 'apikey=[ your personal company license API key account can be found via https://support.paloaltonetworks.com -> Assets -> API key management - only super user can see this ]'
    - php " . basename(__FILE__) . " add=bpa-apikey 'apikey=[ PAN-OS BPA key can be request via: https://customersuccess.paloaltonetworks.com/api-signup/ ]' 
    - php " . basename(__FILE__) . " add=ldap-password 'apikey=[ LDAP password to interact with organisational ldap server ]'
    - php " . basename(__FILE__) . " add=gcp-mysql-password 'apikey=[ mysql password to interact with organisational GCP mysql server ]'
    - php " . basename(__FILE__) . " add=maxmind-licensekey apikey=[ Maxmind license to download Maxmind geo2ip lite database. create free account: https://www.maxmind.com ]
    - php " . basename(__FILE__) . " add=tsg_id{{TSGID}} 'apikey={{CLIENT_ID}}%{{CLIENT_SECRET}}'  | character '%' must be used as separator between client_id and client_secret";

//        pan-os-php type=key-manager add=tsg_id1668544452 'apikey=api-test-swaschkut@1668544451.iam.panserviceaccount.com%6378343f-060e-45ad-9a83-e4273d4a051d'

        $this->prepareSupportedArgumentsArray();
        PH::processCliArgs();

        $this->arg_validation();


        $this->main();


        
    }

    public function main()
    {

        $noArgProvided = TRUE;

        if( isset(PH::$args['nohiddenpw']) )
            $hiddenPW = FALSE;
        else
            $hiddenPW = TRUE;

        if( isset(PH::$args['debugapi']) )
            $debugAPI = TRUE;
        else
            $debugAPI = FALSE;

        if( isset(PH::$args['user']) )
            $cliUSER = PH::$args['user'];
        else
            $cliUSER = null;

        if( isset(PH::$args['pw']) )
            $cliPW = PH::$args['pw'];
        else
            $cliPW = null;


        PH::print_stdout( " - loading keystore from file in user home directory... ");
        PanAPIConnector::loadConnectorsFromUserHome( $debugAPI);


        PH::print_stdout();


        if( isset(PH::$args['delete']) )
        {
            $noArgProvided = FALSE;
            $deleteHost = PH::$args['delete'];

            $string = "requested to delete Host/IP '{$deleteHost}'";
            PH::print_stdout( " - ".$string );
            PH::$JSON_TMP = array();
            PH::$JSON_TMP['header'] = $string;


            if( !is_string($deleteHost) )
                derr("argument of 'delete' must be a string , wrong input provided");

            $foundConnector = FALSE;
            foreach(PanAPIConnector::$savedConnectors as $cIndex => $connector )
            {
                if( $connector->apihost == $deleteHost )
                {
                    $foundConnector = TRUE;
                    $string = "found and deleted";
                    PH::print_stdout( " - ".$string );

                    PH::$JSON_TMP[ $deleteHost ]['name'] = $deleteHost;
                    PH::$JSON_TMP[ $deleteHost ]['status'] = $string;

                    unset(PanAPIConnector::$savedConnectors[$cIndex]);
                    PanAPIConnector::saveConnectorsToUserHome();
                }
            }

            if( !$foundConnector )
            {
                $string = "**WARNING** no host or IP named '{$deleteHost}' was found so it could not be deleted";
                PH::print_stdout( "\n\n ".$string );
                PH::$JSON_TMP[ $deleteHost ]['name'] = $deleteHost;
                PH::$JSON_TMP[ $deleteHost ]['status'] = $string;
            }

            PH::print_stdout( PH::$JSON_TMP, false, 'delete' );
            PH::$JSON_TMP = array();
        }

        if( isset(PH::$args['add']) )
        {
            $noArgProvided = FALSE;
            $addHost = PH::$args['add'];
            $string = "requested to add Host/IP '{$addHost}'";
            PH::print_stdout( " - ".$string );
            PH::$JSON_TMP = array();
            PH::$JSON_TMP['header'] = $string;
            PH::$JSON_TMP[$addHost]['name'] = $addHost;

            if( $addHost == "bpa-apikey" || $addHost == "license-apikey" || $addHost == "ldap-password" || $addHost == "maxmind-licensekey" || $addHost == "gcp-mysql-password" || strpos($addHost, "tsg_id" ) !== FALSE )
            {
                if( strpos($addHost, "tsg_id") !== FALSE )
                {
                    //get tsg_id
                    //get client_id
                    //get client_secret
                    if( !isset(PH::$args['apikey']) )
                    {
                        /*
                        PH::print_stdout( " ** Please enter scope:  {{TSGID}} | without leading 'tsg_id:" );
                        $handle = fopen("php://stdin", "r");
                        $line = fgets($handle);
                        $tsg_id = trim($line);
                        */

                        PH::print_stdout( " ** Please enter client_id" );
                        $handle = fopen("php://stdin", "r");
                        $line = fgets($handle);
                        $client_id = trim($line);

                        PH::print_stdout( " ** Please enter client_secret" );
                        $handle = fopen("php://stdin", "r");
                        $line = fgets($handle);
                        $client_secret = trim($line);

                        #$addHost = "tsg_id".$tsg_id;
                        $key = $client_id."%".$client_secret;
                    }
                    else
                    {
                        #$addHost = "tsg_id".$tsg_id;
                        $key = PH::$args['apikey'];
                    }


                    foreach(PanAPIConnector::$savedConnectors as $cIndex => $connector )
                    {
                        if( $connector->apihost == $addHost )
                            unset(PanAPIConnector::$savedConnectors[$cIndex]);
                    }

                    PanAPIConnector::$savedConnectors[] = new PanAPIConnector($addHost, $key);
                }
                else
                {
                    if( !isset(PH::$args['apikey']) )
                        derr( "argument apikey - must be set to add BPA-/License-APIkey", null, False );

                    foreach(PanAPIConnector::$savedConnectors as $cIndex => $connector )
                    {
                        if( $connector->apihost == $addHost )
                            unset(PanAPIConnector::$savedConnectors[$cIndex]);
                    }

                    PanAPIConnector::$savedConnectors[] = new PanAPIConnector($addHost, PH::$args['apikey']);
                }
                PanAPIConnector::saveConnectorsToUserHome($debugAPI);
            }
            else
            {
                if( !isset(PH::$args['apikey']) )
                    $connector = PanAPIConnector::findOrCreateConnectorFromHost($addHost, null, TRUE, TRUE, $hiddenPW, $debugAPI, $cliUSER, $cliPW);
                else
                    $connector = PanAPIConnector::findOrCreateConnectorFromHost($addHost, PH::$args['apikey']);
            }


            PH::print_stdout( PH::$JSON_TMP, false, 'add' );
            PH::$JSON_TMP = array();
        }

        if( isset(PH::$args['test']) )
        {
            $noArgProvided = FALSE;
            $checkHost = PH::$args['test'];

            PH::$JSON_TMP = array();
            PH::$JSON_TMP['header'] = "requested to test Host/IP";

            if( $checkHost == 'any' || $checkHost == 'all' )
            {
                foreach(PanAPIConnector::$savedConnectors as $connector )
                {
                    $checkHost = $connector->apihost;
                    PH::print_stdout( " - requested to test Host/IP '{$checkHost}'");
                    PH::$JSON_TMP[$checkHost]['name'] = $checkHost;

                    if( $checkHost == "bpa-apikey" || $checkHost == "license-apikey" || $checkHost == "ldap-password" || $checkHost == "maxmind-licensekey" || $addHost == "gcp-mysql-password" )
                    {
                        PH::$JSON_TMP[$checkHost]['status'] = "skipped can not be tested";
                        continue;
                    }

                    PH::enableExceptionSupport();
                    if( strpos($checkHost, "tsg_id") === FALSE )
                    {
                        try
                        {
                            if( !isset(PH::$args['apikey']) )
                                $connector = PanAPIConnector::findOrCreateConnectorFromHost($checkHost, null, TRUE, TRUE, $hiddenPW, $debugAPI , $cliUSER, $cliPW);
                            else
                                $connector = PanAPIConnector::findOrCreateConnectorFromHost($checkHost, PH::$args['apikey'], TRUE, TRUE, TRUE, $debugAPI);

                            if( $debugAPI )
                                $connector->showApiCalls = true;

                            $connector->testConnectivity( $checkHost );
                        } catch(Exception $e)
                        {
                            PH::disableExceptionSupport();
                            $string = "   ***** API Error occured : " . $e->getMessage();
                            PH::$JSON_TMP[$checkHost]['error'] = $string;
                            PH::print_stdout( $string );
                        }
                    }
                    else
                    {
                        try
                        {
                            $TSGid = str_replace( "tsg_id", "", $checkHost);
                            $sase_connector =  new PanSaseAPIConnector($TSGid);

                            $sase_connector->findOrCreateConnectorFromHost($TSGid);

                            if( $debugAPI )
                                $sase_connector->showApiCalls = true;

                            $sase_connector->getAccessToken();
                        } catch(Exception $e)
                        {
                            PH::disableExceptionSupport();
                            $string = "   ***** API Error occured : " . $e->getMessage();
                            PH::$JSON_TMP[$checkHost]['error'] = $string;
                            PH::print_stdout( $string );
                        }


                    }
                    PH::disableExceptionSupport();
                    PH::print_stdout();


                }
            }
            else
            {
                PH::print_stdout( " - requested to test Host/IP '{$checkHost}'");
                PH::$JSON_TMP[$checkHost]['name'] = $checkHost;

                if( $checkHost == "bpa-apikey" || $checkHost == "license-apikey" || $checkHost == "ldap-password" || $checkHost == "maxmind-licensekey" || $checkHost == "gcp-mysql-password" )
                {
                    PH::$JSON_TMP[$checkHost]['status'] = "skipped can not be tested";
                }
                else
                {
                    if( strpos($checkHost, "tsg_id") === FALSE )
                    {
                        if( !isset(PH::$args['apikey']) )
                            $connector = PanAPIConnector::findOrCreateConnectorFromHost($checkHost, null, TRUE, TRUE, $hiddenPW, $debugAPI, $cliUSER, $cliPW);
                        else
                            $connector = PanAPIConnector::findOrCreateConnectorFromHost($checkHost, PH::$args['apikey'], TRUE, TRUE, TRUE, $debugAPI);

                        if( $debugAPI )
                            $connector->showApiCalls = true;

                        $connector->testConnectivity( $checkHost );
                    }
                    else
                    {
                        $TSGid = str_replace( "tsg_id", "", $checkHost);
                        $sase_connector =  new PanSaseAPIConnector($TSGid);

                        $sase_connector->findOrCreateConnectorFromHost($TSGid);

                        if( $debugAPI )
                            $sase_connector->showApiCalls = true;

                        $sase_connector->getAccessToken();
                    }
                }

                PH::print_stdout();
            }
            PH::print_stdout( PH::$JSON_TMP, false, 'test' );
            PH::$JSON_TMP = array();
        }

        $keyCount = count(PanAPIConnector::$savedConnectors);
        $string = "Listing available keys: '[".$keyCount."]'";
        PH::print_stdout( $string );
        PH::$JSON_TMP = array();
        PH::$JSON_TMP['header'] = $string;

        $connectorList = array();
        foreach(PanAPIConnector::$savedConnectors as $connector )
        {
            $connectorList[$connector->apihost] = $connector;
        }
        ksort($connectorList);

        if( $debugAPI )
            print_r($connectorList);

        foreach( $connectorList as $connector )
        {
            $key = $connector->apikey;
            if( strlen($key) > 24 )
                $key = substr($key, 0, 12) . '...' . substr($key, strlen($key) - 12);
            elseif( strlen($key) > 10 )
                $key = substr($key, 0, 5) . '...' . substr($key, strlen($key) - 5);
            $host = str_pad($connector->apihost, 15, ' ', STR_PAD_RIGHT);

            PH::print_stdout( " - Host {$host}: key={$key}");

            PH::$JSON_TMP[$host]['name'] = $host;
            PH::$JSON_TMP[$host]['key'] = $key;

        }
        PH::print_stdout( PH::$JSON_TMP, false, 'api-key' );
        PH::$JSON_TMP = array();

        if( $noArgProvided )
        {
            PH::print_stdout();
            $this->display_usage_and_exit();
        }
    }

    public function supportedArguments()
    {
        $this->supportedArguments[] = array('niceName' => 'delete', 'shortHelp' => 'Clears API key for hostname/IP provided as an argument.', 'argDesc' => '[hostname or IP]');
        $this->supportedArguments[] = array('niceName' => 'add', 'shortHelp' => 'Adds API key for hostname/IP provided as an argument.', 'argDesc' => '[hostname or IP]');
        $this->supportedArguments[] = array('niceName' => 'test', 'shortHelp' => 'Tests API key for hostname/IP provided as an argument.', 'argDesc' => '[hostname or IP]');
        $this->supportedArguments[] = array('niceName' => 'apikey', 'shortHelp' => 'can be used in combination with add argument to use specific API key provided as an argument.', 'argDesc' => '[API Key]');
        $this->supportedArguments[] = array('niceName' => 'nohiddenpw', 'shortHelp' => 'Use this if the entered password should be displayed.');
        $this->supportedArguments[] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments[] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments[] = array('niceName' => 'user', 'shortHelp' => 'can be used in combination with "add" argument to use specific Username provided as an argument.', 'argDesc' => '[USERNAME]');
        $this->supportedArguments[] = array('niceName' => 'pw', 'shortHelp' => 'can be used in combination with "add" argument to use specific Password provided as an argument.', 'argDesc' => '[PASSWORD]');
        $this->supportedArguments[] = array('niceName' => 'shadow-apikeynohidden', 'shortHelp' => 'send API-KEY in clear text via URL. this is needed for all PAN-OS version <9.0 if API mode is used. ');
    }

}