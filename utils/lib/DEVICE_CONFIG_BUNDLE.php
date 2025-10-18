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

class DEVICE_CONFIG_BUNDLE extends UTIL
{
    public $exportcsvFile = null;

    function __construct($utilType, $argv, $argc, $PHP_FILE, $_supportedArguments = array(), $_usageMsg = "")
    {
        #$_usageMsg =  PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=[device-config-bundle.tgz] [playbook=playbook.json] [projectfolder=demo_folder]";;
        #parent::__construct($utilType, $argv, $argc, $PHP_FILE, $_supportedArguments, $_usageMsg);

        $this->utilStart2($argv, $argc);
    }

    public function utilStart2($argv, $argc)
    {
        $tmp_ph = new PH($argv, $argc);
        PH::processCliArgs();
        $this->PHP_FILE = __FILE__;
        //get the in tgz filename
        //validate that it is tgz. not only on filename
        //extract all to projectfolder

        if( isset( PH::$args['playbook'] ) )
            $playbookFile = PH::$args['playbook'];
        else
            $playbookFile = null;

        if( isset( PH::$args['projectfolder'] ) )
            $this->projectFolder = PH::$args['projectfolder'];

        if( $this->projectFolder == null )
            $this->projectFolder = "device-config-bundle";

        if (!file_exists($this->projectFolder))
        {
            mkdir($this->projectFolder, 0777, true);
        }

        $config_filename = PH::$args['in'];

        if( isset(PH::$args['testing']) )
            $testing = true;
        else
            $testing = false;
        if( !$testing )
        {
            //validation if file has .tar.gz
            if( strpos($config_filename, ".tar.gz") === FALSE && strpos($config_filename, ".tgz") === FALSE )
            {
                derr("specified filename with argument 'FILE' is not 'tar.gz' ");
            }
            else
            {
                $srcfile = $config_filename;


                //Todo check if it is better to create this under Tool folder and clean it up at the end

                $destfile = $this->projectFolder . '/test1.tar.gz';

                if( !copy($srcfile, $destfile) )
                {
                    echo "File cannot be copied! \n";
                }
                else
                {
                    #echo "File has been copied!\n";
                }

                //extract into specified folder
                exec('tar -C ' . $this->projectFolder . '/' . ' -zxvf ' . $destfile . ' 2>&1');

                #print "sleep 15 seconds: wait for tar extract complete";
                #sleep(15);
            }
        }


        $file_folder_name = str_replace(".tgz", "", $config_filename);
        $files = glob( $this->projectFolder."/".$file_folder_name."/*" );

        if( $files )
        {
            #PH::print_stdout( "Files with size greater than 0:" );
            #PH::print_stdout( "-------------------------------" );

            foreach( $files as $file )
            {
               if( is_file($file) )
               {
                   $size = filesize($file);

                   if( $size > 0 )
                   {
                       if( $file == null )
                           continue;

                       $checkFilename = basename($file);
                       #PH::print_stdout( $checkFilename );

                       //pan-os-php type=stats shadow-json actions=display-available shadow-json

                       PH::$JSON_OUT = array();
                       PH::$JSON_TMP = array();

                       $PHP_FILE = __FILE__;

                       $arguments = array();
                       $arguments[0] = "";
                       $arguments[1] = "in=".$this->projectFolder."/".$file_folder_name."/".$checkFilename;
                       $arguments[2] = "actions=display-available";
                       $arguments[3] = "projectfolder=".$this->projectFolder."/json";
                       $arguments[4] = "shadow-json";

                       PH::resetCliArgs( $arguments);


                       $tool = "pan-os-php type=stats";
                       PH::print_stdout();
                       PH::print_stdout( PH::boldText( "[ ".$tool. " ".implode( " ", PH::$argv )." ]" ) );
                       PH::print_stdout();

                       $util = PH::callPANOSPHP( "stats", PH::$argv, $argc, $PHP_FILE );

                       $string = json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );

                       $filenameFolder = str_replace(".xml", "", $checkFilename);

                       //store string into tmp file:
                       $tmpJsonFile = $this->projectFolder."/json/".$filenameFolder.".json";
                       file_put_contents($tmpJsonFile, $string);


                       $print_section = false;
                       $first = true;
                       if( isset(PH::$JSON_OUT['statistic']) )
                       {
                           $demo_array = PH::$JSON_OUT['statistic'];

                           foreach( $demo_array[0] as $key => $entry )
                           {
                               if( isset($entry['type']) )
                               {
                                   if( $entry['type'] == "PanoramaConf" || $entry['type'] == "DeviceGroup" )
                                   {
                                       if( $entry['type'] == "PanoramaConf" && $playbookFile != null )
                                       {
                                           PH::$shadow_json = false;

                                           //todo: possible to extend here for BPA playbook JSON file
                                           $arguments = array();
                                           $arguments[0] = "";
                                           $arguments[1] = "in=".$this->projectFolder."/".$file_folder_name."/".$checkFilename;
                                           $arguments[2] = "json=".$playbookFile;
                                           $arguments[3] = "projectfolder=".$this->projectFolder."/playbook";

                                           PH::resetCliArgs( $arguments);


                                           $tool = "pan-os-php type=playbook";
                                           PH::print_stdout();
                                           PH::print_stdout( PH::boldText( "[ ".$tool. " ".implode( " ", PH::$argv )." ]" ) );
                                           PH::print_stdout();

                                           $util = PH::callPANOSPHP( "playbook", PH::$argv, $argc, $PHP_FILE );
                                       }

                                       continue;
                                   }
                                   elseif( $testing )
                                       continue;

                               }

                               if( isset( $entry['type'] ) )
                                   unset( $entry['type'] );
                               if( isset( $entry['statstype'] ) )
                                   unset( $entry['statstype'] );
                               if( isset( $entry['header'] ) )
                                   unset( $entry['header'] );
                               if( isset( $entry['model'] ) )
                                   unset( $entry['model'] );

                               //these are the possible PANconf information from type=stats, combine them the correct type=XYZ
                               $typeArray = array();
                               $typeArray['security rules'] = "rule ruletype=security";
                               $typeArray['nat rules'] = "rule ruletype=nat";
                               $typeArray['qos rules'] = "rule ruletype=qos";
                               $typeArray['pbf rules'] = "rule ruletype=pbf";
                               $typeArray['decryption rules'] = "rule ruletype=decryption";
                               $typeArray['app-override rules'] = "rule ruletype=appoverride";
                               $typeArray['capt-portal rules'] = "rule ruletype=cap";
                               $typeArray['authentication rules'] = "rule ruletype=security";
                               $typeArray['dos rules'] = "rule ruletype=dos";
                               $typeArray['tunnel-inspection rules'] = "rule ruletype=tunnelinspection";
                               $typeArray['default-security rules'] = "rule ruletype=defaultsecurity";
                               $typeArray['network-packet-broker rules'] = "rule ruletype=networkpacketbroker";
                               $typeArray['sdwan rules'] = "rule ruletype=sdwan";


                               $typeArray['address objects'] = "address";
                               $typeArray['addressgroup objects'] = "address";
                               $typeArray['temporary address objects'] = "address";
                               $typeArray['region objects'] = "address";
                               $typeArray['service objects'] = "service";
                               $typeArray['servicegroup objects'] = "service";
                               $typeArray['temporary service objects'] = "service";

                               $typeArray['tag objects'] = "tag";

                               $typeArray['securityProfileGroup objects'] = "securityprofilegroup";
                               $typeArray['Anti-Spyware objects'] = "securityprofile securityprofiletype=spyware";
                               $typeArray['Vulnerability objects'] = "securityprofile securityprofiletype=vulnerability";
                               $typeArray['Antivirus objects'] = "securityprofile securityprofiletype=virus";
                               $typeArray['Wildfire objects'] = "securityprofile securityprofiletype=wildfire-analysis";
                               $typeArray['URL objects'] = "securityprofile securityprofiletype=url-filtering";
                               $typeArray['custom URL objects'] = "securityprofile securityprofiletype=custom-url-category";
                               $typeArray['File-Blocking objects'] = "securityprofile securityprofiletype=file-blocking";
                               $typeArray['Decryption objects'] = null;

                               $typeArray['HipObject objects'] = null;
                               $typeArray['HipProfile objects'] = null;

                               $typeArray['GTP objects'] = null;
                               $typeArray['SCEP objects'] = null;
                               $typeArray['PacketBroker objects'] = null;

                               $typeArray['SDWanErrorCorrection objects'] = null;
                               $typeArray['SDWanPathQuality objects'] = null;
                               $typeArray['SDWanSaasQuality objects'] = null;
                               $typeArray['SDWanTrafficDistribution objects'] = null;
                               $typeArray['DataObjects objects'] = null;


                               $typeArray['certificate objects'] = "certificate";
                               $typeArray['SSL_TLSServiceProfile objects'] = "ssl-tls-service-profile";
                               $typeArray['LogProfile objects'] = "log-profile";
                               $typeArray['zones'] = "zone";;
                               $typeArray['apps'] = "application";;
                               $typeArray['interfaces'] = "interface";
                               $typeArray['sub-interfaces'] = "interface";
                               $typeArray['routing'] = "routing";
                               $typeArray['ZPProfile objects'] = "zone-protection-profile";


                               if( !empty( $entry ) )
                               {
                                   if( $first )
                                   {
                                       print $checkFilename."\n";
                                       $first = false;
                                   }

                                   #print_r(array_keys($entry));
                                   $bug_missing_state_array = array();
                                   foreach( $entry as $key => $value )
                                   {
                                       print $key."\n";

                                       if( isset( $typeArray[$key] ) )
                                       {
                                           $type = $typeArray[$key];

                                           $htmlFilename = $type;
                                           $additional_argument = false;
                                           $tmp_type_array = explode( " ", $type );
                                           if( count( $tmp_type_array ) == 2 )
                                           {
                                               $type = $tmp_type_array[0];
                                               $additional_argument = true;
                                               $additional_argument_string = $tmp_type_array[1];

                                               if( strpos($additional_argument_string, "ruletype=") !== false )
                                                   $htmlFilename = $type."_".str_replace("ruletype=", "", $additional_argument_string);
                                               if( strpos($additional_argument_string, "securityprofiletype=") !== false )
                                                   $htmlFilename = "sp_".str_replace("securityprofiletype=", "", $additional_argument_string);
                                           }

                                           PH::$JSON_OUT = array();
                                           PH::$JSON_TMP = array();
                                           $PHP_FILE = __FILE__;
                                           PH::$shadow_json = false;

                                           $arguments = array();
                                           $arguments[0] = "";
                                           $arguments[1] = "in=".$this->projectFolder."/".$file_folder_name."/".$checkFilename;
                                           $arguments[2] = "actions=exporttoexcel:".$htmlFilename.".html";
                                           $arguments[3] = "projectfolder=".$this->projectFolder."/html/".$filenameFolder;
                                           if( $additional_argument )
                                               $arguments[] = $additional_argument_string;
                                           if( $type == "application" )
                                               $arguments[] = "filter=!(object is.predefined)";

                                           PH::resetCliArgs( $arguments);

                                           $tool = "pan-os-php type=".$type;
                                           PH::print_stdout();
                                           PH::print_stdout( PH::boldText( "[ ".$tool. " ".implode( " ", PH::$argv )." ]" ) );
                                           PH::print_stdout();
                                           $util = PH::callPANOSPHP( $type, PH::$argv, $argc, $PHP_FILE );
                                       }
                                       else
                                       {
                                           $bug_missing_state_array[] = $key;
                                       }

                                   }

                                   //type=html-merger projectfolder
                                   PH::$JSON_OUT = array();
                                   PH::$JSON_TMP = array();
                                   $PHP_FILE = __FILE__;
                                   PH::$shadow_json = false;

                                   //exportCSV=[spreadsheet.xlsx] projectfolder=[DIRECTORY]
                                   $arguments = array();
                                   $arguments[0] = "";
                                   $arguments[1] = "exportcsv=".$filenameFolder.".xls";
                                   $arguments[2] = "projectfolder=".$this->projectFolder."/html/".$filenameFolder;

                                   PH::resetCliArgs( $arguments);

                                   $tool = "pan-os-php type=html-merger";
                                   PH::print_stdout();
                                   PH::print_stdout( PH::boldText( "[ ".$tool. " ".implode( " ", PH::$argv )." ]" ) );
                                   PH::print_stdout();
                                   $util = PH::callPANOSPHP( "html-merger", PH::$argv, $argc, $PHP_FILE );

                                   //move xls file to parent html folder
                                   $orig_file = "/share/".$this->projectFolder."/html/".$filenameFolder."/".$filenameFolder.".xls";
                                   if( file_exists($orig_file) )
                                   {
                                       $rename_file = "/share/".$this->projectFolder."/html/".$filenameFolder.".xls";
                                       rename($orig_file, $rename_file);
                                   }

                                   if( !empty($bug_missing_state_array) )
                                       print_r( $bug_missing_state_array );

                                   $print_section = true;

                               }
                           }
                       }
                       else
                           mwarning( "array 'statistic' not found", null, false );

                        if( $print_section )
                            print "######################\n";

                       PH::$JSON_OUT = array();
                       PH::$JSON_TMP = array();
                   }
               }
            }
        }
        else
            PH::print_stdout( "No files found in the directory." );

        PH::$JSON_OUT = array();
        PH::$JSON_TMP = array();

        $runtime = number_format((microtime(TRUE) - $this->runStartTime), 2, '.', '');
        PH::print_stdout( array( 'value' => $runtime, 'type' => "seconds" ), false,'runtime' );

        if( PH::$shadow_json )
        {
            PH::$JSON_OUT['log'] = PH::$JSON_OUTlog;
            //print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );
        }
    }

    public function supportedArguments()
    {
        parent::supportedArguments();
        #$this->supportedArguments['exportcsv'] = array('niceName' => 'exportCsv', 'shortHelp' => 'export statistics to CSV file using jq', 'argDesc' => 'filename.csv');
        #$this->supportedArguments['json-to-folder'] = array('niceName' => 'Json-To-Folder', 'shortHelp' => 'generate separate JSON files for adoption, visibility, and best-practice statistics for each PanoramaConf and DeviceGroup', 'argDesc' => '/path/to/output/folder');
    }

}