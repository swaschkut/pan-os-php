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

class STATSUTIL extends RULEUTIL
{
    public $exportcsvFile = null;

    public $jsonToFolder_string = "";

    function __construct($utilType, $argv, $argc, $PHP_FILE, $_supportedArguments = array(), $_usageMsg = "")
    {
        #PH::print_stdout("argv");
        #print_r($argv);
        #PH::print_stdout("argc");
        #PH::print_stdout($argc);
        #PH::print_stdout("filename");
        #PH::print_stdout($PHP_FILE);

        $_usageMsg =  PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api:://[MGMT-IP] [location=vsys2]";;
        parent::__construct($utilType, $argv, $argc, $PHP_FILE, $_supportedArguments, $_usageMsg);
    }

    public function utilStart()
    {

        $this->utilInit();
        //unique for RULEUTIL
        $this->ruleTypes();

        //no need to do actions on every single rule
        $this->doActions = array();

        $this->createRQuery();
        $this->load_config();
        $this->location_filter();


        $this->location_filter_object();
        $this->time_to_process_objects();

        PH::$args['stats'] = "stats";



        if( isset(PH::$args['json-to-folder']) )
        {
            PH::$args['actions'] = "display-bpa";
            $actions = PH::$args['actions'];
        }
        elseif( isset(PH::$args['actions']) )
        {
            PH::print_stdout( "ACTIONS: ".PH::$args['actions'] );
            $actions = PH::$args['actions'];
        }
        else
        {
            PH::$args['actions'] = "display";
            $actions = PH::$args['actions'];
        }


        PH::$JSON_TMP = array();

        if( !PH::$shadow_loaddghierarchy )
            $this->stats( $this->debugAPI, $actions );
        else
            $this->stats( $this->debugAPI, $actions, $this->location );

        if( PH::$args['actions'] == "display" || PH::$args['actions'] == "display-bpa" || PH::$args['actions'] == "display-available")
            PH::print_stdout(PH::$JSON_TMP, false, "statistic");

        if( PH::$args['actions'] == "trending" )
        {
            $trendingArray = array();
            //load old file

            foreach( PH::$JSON_TMP as $key => $stat )
            {
                if( $stat['statstype'] == "adoption" )
                {
                    $tmpArray = array();

                    $now = new DateTime();
                    $now->format('Y-m-d H:i:s');    // MySQL datetime format
                    $now->getTimestamp();

                    //---------------

                    $tmpArray[$now->getTimestamp()] = $stat['percentage'];
                    print_r( $tmpArray );

                    break;
                }
            }
        }

        if( PH::$args['actions'] == "display-managedfw-serial" || isset(PH::$args['json-to-folder']) )
        {
            if( $this->configType == 'panorama' )
            {
                $AllmanagedFirewall = $this->pan->managedFirewallsStore->getAll();
                $tmp_devices = array();

                foreach( $AllmanagedFirewall as $managedFirewall )
                {
                    if( $managedFirewall->devicegroup == null )
                        $tmp_dg = "---";
                    else
                        $tmp_dg = $managedFirewall->devicegroup;
                    if( $managedFirewall->template_stack == null )
                        $tmp_tstack = "---";
                    else
                        $tmp_tstack = $managedFirewall->template_stack;

                    if( in_array( 'any', $this->objectsLocation) || in_array( $tmp_dg, $this->objectsLocation) )
                    {
                        $tmp_devices[] = array( 'serial' => $managedFirewall->name(), "dg" => $tmp_dg, "template-stack" => $tmp_tstack );
                        PH::print_stdout( " - ".str_pad($managedFirewall->name(),16)." - DG: ".str_pad($tmp_dg,30)." - T-Stack: ".str_pad($tmp_tstack,30) );
                    }

                }

                if( !isset(PH::$args['json-to-folder']) )
                {
                    PH::print_stdout();
                    PH::print_stdout("count: ".count($AllmanagedFirewall));
                }
                elseif( isset(PH::$args['json-to-folder']) )
                {
                    $jsonContent = json_encode($tmp_devices, JSON_PRETTY_PRINT);
                    $this->jsonToFolder_string .= "devices = ".$jsonContent.";";
                }
            }
        }

        if( isset(PH::$args['json-to-folder']) )
        {
            $outputFolder = PH::$args['json-to-folder'];
            if( $outputFolder === TRUE )
                $outputFolder = "json";

            if( $this->projectFolder !== null )
                $outputFolder = $this->projectFolder."/".$outputFolder;

            // Create output folder if it doesn't exist
            if( !is_dir($outputFolder) )
            {
                if( !mkdir($outputFolder, 0755, true) )
                {
                    derr("Failed to create output folder: ".$outputFolder);
                }
                PH::print_stdout( "Created output folder: ".$outputFolder );
            }

            $mainArray = array();
            // Process each statistic entry
            foreach( PH::$JSON_TMP as $key => $stat )
            {
                if( !isset($stat['statstype']) || $stat['statstype'] != "adoption" )
                    continue;

                if( !isset($stat['percentage']) )
                    continue;

                $type = isset($stat['type']) ? $stat['type'] : 'Unknown';

                // Determine the filename prefix
                if( $type == 'PanoramaConf' )
                {
                    if( !PH::$shadow_loaddghierarchy )
                        $filePrefix = "Panorama-full";
                    else
                        $filePrefix = "Panorama-DG-Hierarchy_".$this->location;
                }
                elseif( $type == 'DeviceGroup' )
                {
                    // Extract device group name from header or use a counter
                    $dgName = "DeviceGroup";
                    if( isset($stat['header']) )
                    {
                        // Try to extract name from header like "BP/Visibility Statistics for VSYS 'DG1' | 'xxx'"
                        if( preg_match("/'([^']+)'/", $stat['header'], $matches) )
                        {
                            $dgName = $matches[1];
                            // Strip ANSI escape codes and other non-printable characters
                            $dgName = preg_replace('/\033\[[0-9;]*m/', '', $dgName);
                            $dgName = trim($dgName);
                        }
                    }
                    $filePrefix = $dgName;
                }
                elseif( $type == 'PANConf' )
                {
                    $filePrefix = "Firewall-full";
                }
                elseif( $type == 'VirtualSystem' )
                {
                    $vsysName = "VirtualSystem";
                    if( isset($stat['header']) )
                    {
                        if( preg_match("/'([^']+)'/", $stat['header'], $matches) )
                        {
                            $vsysName = $matches[1];
                            // Strip ANSI escape codes and other non-printable characters
                            $vsysName = preg_replace('/\033\[[0-9;]*m/', '', $vsysName);
                            $vsysName = trim($vsysName);
                        }
                    }
                    $filePrefix = $vsysName;
                }
                else
                {
                    continue;
                }

                // Sanitize filename
                $filePrefix = preg_replace('/[^a-zA-Z0-9_-]/', '_', $filePrefix);

                // Create files for each percentage type
                if( isset($stat['percentage']['adoption']) )
                {
                    $filename = $outputFolder."/".$filePrefix.".adoption.json";
                    $tmp_Array = array();
                    $title = "Overall Adoption";
                    $tmp_Array['title'] = $title;
                    $tmp_Array['info'] = "Adopted";
                    $categoriesArray = array();
                    foreach($stat['percentage']['adoption'] as $name => $info)
                        $categoriesArray[] = array( "name" => $name, "value" => $info['value'], "group" => $info['group'] );

                    $tmp_Array['categories'] = $categoriesArray;
                    $mainArray[$filePrefix."-".$title] = $tmp_Array;
                    #$jsonContent = json_encode($tmp_Array, JSON_PRETTY_PRINT);
                    #file_put_contents($filename, $jsonContent);
                    #PH::print_stdout( " - Created: ".$filename );
                }

                if( isset($stat['percentage']['visibility']) )
                {
                    $filename = $outputFolder."/".$filePrefix.".visibility.json";
                    $tmp_Array = array();
                    $title = "Visibility";
                    $tmp_Array['title'] = $title;
                    $tmp_Array['info'] = "Visible";
                    $categoriesArray = array();
                    foreach($stat['percentage']['visibility'] as $name => $info)
                        $categoriesArray[] = array( "name" => $name, "value" => $info['value'], "group" => $info['group'] );

                    $tmp_Array['categories'] = $categoriesArray;
                    $mainArray[$filePrefix."-".$title] = $tmp_Array;
                    #$jsonContent = json_encode($tmp_Array, JSON_PRETTY_PRINT);
                    #file_put_contents($filename, $jsonContent);
                    #PH::print_stdout( " - Created: ".$filename );
                }

                if( isset($stat['percentage']['best-practice']) )
                {
                    $filename = $outputFolder."/".$filePrefix.".best-practice.json";
                    $tmp_Array = array();
                    $title = "Best Practices";
                    $tmp_Array['title'] = $title;
                    $tmp_Array['info'] = "Best Practice";
                    $categoriesArray = array();
                    foreach($stat['percentage']['best-practice'] as $name => $info)
                        $categoriesArray[] = array( "name" => $name, "value" => $info['value'], "group" => $info['group'] );

                    $tmp_Array['categories'] = $categoriesArray;
                    $mainArray[$filePrefix."-".$title] = $tmp_Array;
                    #$jsonContent = json_encode($tmp_Array, JSON_PRETTY_PRINT);
                    #file_put_contents($filename, $jsonContent);
                    #PH::print_stdout( " - Created: ".$filename );
                }
            }

            $jsonContent = json_encode($mainArray, JSON_PRETTY_PRINT);
            $this->jsonToFolder_string .= "samples = ".$jsonContent.";";
            $filename = $outputFolder."/diagram_data.js";
            file_put_contents($filename, $this->jsonToFolder_string);


            PH::print_stdout();
            PH::print_stdout( "JSON files generated successfully in: ".$outputFolder );
        }

        if( isset(PH::$args['json-to-folder']) && isset(PH::$args['bp-create-diagram']) )
        {

            $filename;
            PH::enableExceptionSupport();
            try
            {
                $cli = "python3 ".dirname(__FILE__)."/../common/html/diagram/create_jpg.py " . $filename . " " . $this->projectFolder;

                exec($cli, $output, $retValue);

                foreach( $output as $line )
                {
                    $string = '   ##  ';
                    $string .= $line;
                    print $string . "\n";
                }
            }
            //catch exception
            catch(Exception $e)
            {
                PH::disableExceptionSupport();
                PH::print_stdout( " ***** an error occured : " . $e->getMessage() );
                PH::print_stdout();
            }
            catch(Error $e)
            {
                PH::disableExceptionSupport();
                PH::print_stdout( " ***** an error occured : " . $e->getMessage() );
                PH::print_stdout();
            }
        }

        if( $this->debugAPI )
        {
            if( isset(PH::$args['json-to-folder']) ) {
                $debugAPI_file = PH::$args['json-to-folder'];
                if ($debugAPI_file === TRUE)
                    $debugAPI_file = "json";

                $debugAPI_file .= "/";
            }
            else
                $debugAPI_file = "";

            if( $this->projectFolder !== null )
                $debugAPI_file = $this->projectFolder."/".$debugAPI_file."/";

            PH::$JSON_TMP = array_values(PH::$JSON_TMP);
            $string = json_encode( PH::$JSON_TMP, JSON_PRETTY_PRINT );

            //store string into tmp file:
            $tmpJsonFile = $debugAPI_file."debugAPI_string.json";
            file_put_contents($tmpJsonFile, $string);
        }

        if( isset(PH::$args['exportcsv'])  )
        {
            $this->exportcsvFile = PH::$args['exportcsv'];

            if( $this->projectFolder !== null )
                $this->exportcsvFile = $this->projectFolder."/".$this->exportcsvFile;

            if( !isset(PH::$args['location']) || (isset(PH::$args['location']) && PH::$args['location'] === 'shared') )
            {}
            elseif( isset(PH::$args['location']) )
            {
                unset( PH::$JSON_TMP[0] );
            }

            foreach( PH::$JSON_TMP as $key => $stat )
            {
                if( $stat['statstype'] == "adoption" )
                    unset( PH::$JSON_TMP[$key] );
            }

            PH::$JSON_TMP = array_values(PH::$JSON_TMP);
            $string = json_encode( PH::$JSON_TMP, JSON_PRETTY_PRINT );

            #$string = json_encode( PH::$JSON_TMP, JSON_PRETTY_PRINT|JSON_FORCE_OBJECT );
            #$string = "[".$string."]";
            #print $string;

            $jqFile = dirname(__FILE__)."/json2csv.jq";

            //store string into tmp file:
            $tmpJsonFile = $this->exportcsvFile."tmp_jq_string.json";
            file_put_contents($tmpJsonFile, $string);

            if( file_exists($this->exportcsvFile) )
                unlink($this->exportcsvFile);

            ##working
            $cli = "jq -rf $jqFile $tmpJsonFile >> ".$this->exportcsvFile;
            #$cli = "echo \"$string\" | jq -rf $jqFile >> ".$this->exportcsvFile;
            exec($cli, $output, $retValue);

            unlink($tmpJsonFile);
        }


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
        $this->supportedArguments['bp-create-diagram'] = array('niceName' => 'BP-create-diagram', 'shortHelp' => 'generate BP jpg diagram based on the JSON files for adoption, visibility, and best-practice statistics for each PanoramaConf and DeviceGroup', 'argDesc' => '');
    }

}