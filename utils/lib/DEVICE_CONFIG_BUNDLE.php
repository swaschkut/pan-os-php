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

    public function utilStart2( $argv, $argc )
    {
        $tmp_ph = new PH($argv, $argc);
        PH::processCliArgs();
        $this->PHP_FILE = __FILE__;
        //get the in tgz filename
        //validate that it is tgz. not only on filename
        //extract all to projectfolder


        if( $this->projectFolder !== null )
            $this->projectFolder = $this->projectFolder;
        else
            $this->projectFolder = "device-config-bundle";

        if (!file_exists($this->projectFolder))
        {
            mkdir($this->projectFolder, 0777, true);
        }

        $config_filename = PH::$args['in'];

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
                       #PH::print_stdout();
                       #PH::print_stdout( PH::boldText( "[ ".$tool. " ".implode( " ", PH::$argv )." ]" ) );
                       #PH::print_stdout();

                       $util = PH::callPANOSPHP( "stats", PH::$argv, $argc, $PHP_FILE );

                       $string = json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );

                       //store string into tmp file:
                       $tmpJsonFile = $this->projectFolder."/json/".$checkFilename.".json";
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

                               if( !empty( $entry ) )
                               {
                                   if( $first )
                                   {
                                       print $checkFilename."\n";
                                       $first = false;
                                   }

                                   print_r(array_keys($entry));

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
        $this->supportedArguments['exportcsv'] = array('niceName' => 'exportCsv', 'shortHelp' => 'export statistics to CSV file using jq', 'argDesc' => 'filename.csv');
        $this->supportedArguments['json-to-folder'] = array('niceName' => 'Json-To-Folder', 'shortHelp' => 'generate separate JSON files for adoption, visibility, and best-practice statistics for each PanoramaConf and DeviceGroup', 'argDesc' => '/path/to/output/folder');
    }

}