<?php
/**
 * ISC License
 *
 * Copyright (c) 2026, Sven Waschkut - pan-os-php@waschkut.net
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

class PLAYBOOK_VALIDATION__
{

    public $isAPI = false;
    public $debugAPI = false;
    public $debugMemory = false;
    public $outputformatset = false;
    public $subprocessMode = false;
    public $memoryThreshold = 0;

    public $mainLocation = null;

    public $projectFolder = null;
    public $usageMsg = null;
    public $PHP_FILE = "pan-os-php.php type=playbook-validation";

    public $supportedArguments;
    public $outputformatsetFile;

    function __construct( $argv, $argc )
    {



        $this->supportedArguments['type'] = array('niceName' => 'pan-os-php type=');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['debugmemory'] = array('niceName' => 'DebugMemory', 'shortHelp' => 'prints memory usage information after each playbook step');
        $this->supportedArguments['subprocess'] = array('niceName' => 'subprocess', 'shortHelp' => 'run each playbook step as a separate PHP process (slower but uses less memory)');
        $this->supportedArguments['memorythreshold'] = array('niceName' => 'memorythreshold', 'shortHelp' => 'memory threshold in MB before switching to subprocess mode (e.g., memorythreshold=512)', 'argDesc' => 'memorythreshold=MB');
        $this->supportedArguments['outputformatset'] = array('niceName' => 'outputformatset', 'shortHelp' => 'get all PAN-OS set commands about the task the UTIL script is doing. outputformatset=FILENAME -> store set commands in file', 'argDesc' => 'outputformatset');

        $this->supportedArguments['script-validation'] = array('niceName' => 'script-validation');
        $this->supportedArguments['dev'] = array('niceName' => 'run pan-os-php dev related part');
        $this->supportedArguments['beta'] = array('niceName' => 'run pan-os-php beta related beta part');
        $this->supportedArguments['latest'] = array('niceName' => 'run pan-os-php latest related beta part');
        $this->supportedArguments['compare-dev-beta'] = array('niceName' => 'compare XML files from dev and beta folder');
        $this->supportedArguments['compare-latest-dev'] = array('niceName' => 'compare XML files from latest and dev folder');

        $this->supportedArguments['compare-stats-dev-beta'] = array('niceName' => 'compare stats JSON files from dev and beta folder');
        $this->supportedArguments['compare-stats-latest-dev'] = array('niceName' => 'compare stats JSON files from latest and dev folder');

        //stats-not-100
        $this->supportedArguments['stats-not-100'] = array('niceName' => 'search in stats JSON file where percentage value NOT 100; exclud ZPP/APP-ID/User-ID/ServicePort/DataFiltering');

        $this->supportedArguments['generate-sp'] = array('niceName' => 'generate-sp - generate securityprofile HTML overview actions=exportSPtoHTML');
        $this->supportedArguments['generate-sp-only'] = array('niceName' => 'generate-sp-only - in combination with argument dev / beta');

        $this->supportedArguments['generate-stats'] = array('niceName' => 'generate-stats - generate type=stats actions=display-bpa shadow-json - JSON output');
        $this->supportedArguments['generate-stats-only'] = array('niceName' => 'generate-stats-only - in combination with argument dev / beta');

        $this->supportedArguments['tool'] = array('niceName' => 'tool usage: tool=docker-outsite/tool=docker/tool=local');

        $this->supportedArguments['playbook-file'] = array('niceName' => 'define playbook file');
        $this->supportedArguments['bp-setting-file'] = array('niceName' => 'define BP setting file');


        $input = null;
        $output = null;

        $jsonFile = null;
###############################################################################
//PLAYBOOK
###############################################################################
//example of an JSON file syntax
        $visibility_pathString = dirname(__FILE__)."/../api/v1/playbook";
        $predefinedJSONfile = $visibility_pathString."/visibility.json";

        $visibility_pathString = dirname(__FILE__)."/../api/v1/playbook";
        $predefinedJSONfile = $visibility_pathString."/visibility.json";
        $JSONarray = file_get_contents( $predefinedJSONfile );


        $tmp_ph = new PH($argv, $argc);

###############################################################################
//playbook arguments
###############################################################################
        PH::processCliArgs();

        foreach( PH::$args as $index => &$arg )
        {
            if( !isset($this->supportedArguments[$index]) )
            {
                //var_dump($supportedArguments);
                $this->display_error_usage_exit("unsupported argument provided: '$index'");
            }
        }

        $PHP_FILE = __FILE__;

        if( isset(PH::$args['help']) )
        {
            $this->usageMessage();

            exit();
        }




        if( isset(PH::$args['debugapi']) )
            $this->debugAPI = TRUE;

        if( isset(PH::$args['debugmemory']) )
            $this->debugMemory = TRUE;

        if( isset(PH::$args['subprocess']) )
            $this->subprocessMode = TRUE;

        if( isset(PH::$args['memorythreshold']) )
            $this->memoryThreshold = intval(PH::$args['memorythreshold']) * 1024 * 1024; // Convert MB to bytes



        /////////////////////////////////////////////

        $playbook_file = "validation_files/playbook/visibility.json";
        $bp_setting_file = "validation_files/bp_setting/02b_scm_bp_sp_panw.json";


        // Default settings
        $script_validation = false;

        $generate_dev = false;
        $generate_beta = false;
        $generate_latest = false;

        $generate_spr = false;
        $generate_spr_only = false;

        $compare_dev_beta = false;
        $compare_latest_dev = false;

        $compare_stats_not_100 = false;

        $generate_stats = false;
        $generate_stats_only = false;

        $compare_stats_dev_beta = false;
        $compare_stats_latest_dev = false;
//////////////////////////////////////////////////////////////////////////////////////////////////
// CLI Argument Validation
//////////////////////////////////////////////////////////////////////////////////////////////////


        if( isset(PH::$args['script-validation']) )
            $script_validation = true;

        if( isset(PH::$args['dev']) )
            $generate_dev = true;

        if( isset(PH::$args['beta']) )
            $generate_beta = true;

        if( isset(PH::$args['latest']) )
            $generate_latest = true;

        if( isset(PH::$args['compare-dev-beta']) )
            $compare_dev_beta = true;

        if( isset(PH::$args['compare-latest-dev']) )
            $compare_latest_dev = true;


        if( isset(PH::$args['compare-stats-dev-beta']) )
            $compare_stats_dev_beta = true;

        if( isset(PH::$args['compare-stats-latest-dev']) )
            $compare_stats_latest_dev = true;

        if( isset(PH::$args['stats-not-100']) )
            $compare_stats_not_100 = true;

        if( isset(PH::$args['generate-sp']) )
            $generate_spr = true;

        if( isset(PH::$args['generate-sp-only']) )
            $generate_spr_only = true;

        if( isset(PH::$args['generate-stats']) )
            $generate_stats = true;

        if( isset(PH::$args['generate-stats-only']) )
            $generate_stats_only = true;

        if( isset(PH::$args['tool']) )
            $tool = PH::$args['tool'];
        else
            $tool = "docker";

        if( isset(PH::$args['playbook-file']) )
            $playbook_file = PH::$args['playbook-file'];


        if( isset(PH::$args['bp-setting-file']) )
            $bp_setting_file = PH::$args['bp-setting-file'];


//////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

//get all config from origin
        $folderPath = 'origin/*'; // The * matches everything inside

// Get all file paths
        $files = glob($folderPath);

        $validation = array();

        $compare_validation = array();
        $compare_validation['xml'] = null;
        $compare_validation['stats'] = null;
        $compare_validation['percentage'] = null;

        $inline = "   ";
        if( empty($files) )
        {
            print $inline."====================================\n";
            print $inline."NO CONFIG FILES in 'content' FOLDER\n";
            print $inline."====================================\n";

            exit();
        }

        $file_array = array();
        foreach ($files as $file)
        {
            if (is_file($file))
            {
                if( str_contains( basename($file),".xml") )
                {
                    $file_array[] = basename($file);
                    $validation[basename($file)] = $compare_validation;
                }

            }
        }

        if( $script_validation )
            print_r($file_array);




        $command_array = array();
        foreach( $file_array as $config )
        {
            $configname = explode( ".", $config );
            $configname = $configname[0];

            print "\n\n###################################################################\n";
            print "CONFIGNAME: " . $config . "\n\n";

            if( $generate_dev )
                $folder = "dev";
            if( $generate_dev && !$generate_spr_only && !$generate_stats_only && !$compare_stats_not_100 )
            {
                $commands = array();
                print $inline."====================================\n";
                print $inline."DEV\n";
                print $inline."====================================\n";

                //$command = "docker pull swaschkut/pan-os-php:develop";
                //$this->request_CLI_command( $command );


                $folder = "dev";

                if( $tool == "docker-outside" )
                    $panosphp_tool = 'docker run --name panosphp-develop-val --rm -v $PWD:/share -v ~/.panconfkeystore:/home/ubuntu/.panconfkeystore -it swaschkut/pan-os-php:develop';
                elseif( $tool == "docker" )
                    $panosphp_tool = 'php /tools/pan-os-php/utils/pan-os-php.php';
                elseif( $tool == "local" )
                    $panosphp_tool = "pan-os-php";

                $command = $panosphp_tool." type=playbook 'json={$playbook_file}' shadow-bpjsonfile={$bp_setting_file} 'out={$folder}/{$config}' 'in=origin/{$config}' subprocess projectfolder=delete/validation_{$folder}";
                $commands[] = $command;
                $command_array[] = $command;

                #$command = $panosphp_tool . " type=stats shadow-bpjsonfile={$bp_setting_file} actions=display-bpa 'in={$folder}/{$config}' projectfolder={$folder} debugapi shadow-json 2>&1 | tee {$folder}/{$configname}_stats.txt";
                #$commands[] = $command;
                #$command_array[] = $command;

                foreach( $commands as $command )
                {
                    if ($script_validation)
                        print $command . "\n";
                    else
                    {
                        print $inline . $inline . "run CLI command\n";
                        $this->request_CLI_command($command, $config);
                    }
                }
            }

            if( $generate_beta )
                $folder = "beta";
            if( $generate_beta && !$generate_spr_only && !$generate_stats_only && !$compare_stats_not_100 )
            {
                $commands = array();
                print "\n\n";
                print $inline . "====================================\n";
                print $inline . "BETA\n";
                print $inline . "====================================\n";


                //$command = "docker pull swaschkut/pan-os-php:beta";
                //$this->request_CLI_command($command);

                $folder = "beta";


                if( $tool == "docker-outside" )
                    $panosphp_tool = 'docker run --name panosphp-beta-val --rm -v $PWD:/share -v ~/.panconfkeystore:/home/ubuntu/.panconfkeystore -it swaschkut/pan-os-php:beta';
                elseif( $tool == "docker" )
                    $panosphp_tool = 'php /tools/pan-os-php/utils/pan-os-php.php';
                elseif( $tool == "local" )
                    $panosphp_tool = "pan-os-php";

                $command = $panosphp_tool . " type=playbook 'json={$playbook_file}' shadow-bpjsonfile={$bp_setting_file} 'out={$folder}/{$config}' 'in=origin/{$config}' subprocess projectfolder=delete/validation_{$folder}";
                $commands[] = $command;
                $command_array[] = $command;

                #$command = $panosphp_tool . " type=stats shadow-bpjsonfile={$bp_setting_file} actions=display-bpa 'in={$folder}/{$config}' projectfolder={$folder} debugapi shadow-json 2>&1 | tee {$folder}/{$configname}_stats.txt";
                #$commands[] = $command;
                #$command_array[] = $command;

                foreach( $commands as $command )
                {
                    if ($script_validation)
                        print $command . "\n";
                    else
                    {
                        print $inline . $inline . "run CLI command\n";
                        $this->request_CLI_command($command, $config);
                    }
                }
            }

            if( $generate_latest )
                $folder = "latest";
            if( $generate_latest && !$generate_spr_only && !$generate_stats_only && !$compare_stats_not_100 )
            {
                $commands = array();
                print "\n\n";
                print $inline . "====================================\n";
                print $inline . "LATEST\n";
                print $inline . "====================================\n";


                //$command = "docker pull swaschkut/pan-os-php:latest";
                //$this->request_CLI_command($command);

                $folder = "latest";


                if( $tool == "docker-outside" )
                    $panosphp_tool = 'docker run --name panosphp-latest-val --rm -v $PWD:/share -v ~/.panconfkeystore:/home/ubuntu/.panconfkeystore -it swaschkut/pan-os-php:latest';
                elseif( $tool == "docker" )
                    $panosphp_tool = 'php /tools/pan-os-php/utils/pan-os-php.php';
                elseif( $tool == "local" )
                    $panosphp_tool = "pan-os-php";

                $command = $panosphp_tool . " type=playbook 'json={$playbook_file}' shadow-bpjsonfile={$bp_setting_file} 'out={$folder}/{$config}' 'in=origin/{$config}' subprocess projectfolder=delete/validation_{$folder}";
                $commands[] = $command;
                $command_array[] = $command;

                #$command = $panosphp_tool . " type=stats shadow-bpjsonfile={$bp_setting_file} actions=display-bpa 'in={$folder}/{$config}' projectfolder={$folder} debugapi shadow-json 2>&1 | tee {$folder}/{$configname}_stats.txt";
                #$commands[] = $command;
                #$command_array[] = $command;

                foreach( $commands as $command )
                {
                    if ($script_validation)
                        print $command . "\n";
                    else {
                        print $inline . $inline . "run CLI command\n";
                        $this->request_CLI_command($command, $config);
                    }
                }
            }

            //todo:
            //validate if dev and beta folder has all files available

            //validate if all origin config are also available in DEV and BETA, then compare_dev_beta



            if( $generate_spr || $generate_spr_only )
            {
                print "\n\n";
                print $inline."====================================\n";
                print $inline."GENERATE SP\n";
                print $inline."====================================\n";



                if( $tool == "docker" )
                    $panosphp_tool = 'php /tools/pan-os-php/utils/pan-os-php.php';
                elseif( $tool == "local" )
                    $panosphp_tool = "pan-os-php";

                //compare_dev_beta
                if( $generate_beta )
                {
                    if( $tool == "docker-outside" )
                        $panosphp_tool = 'docker run --name panosphp-beta-val --rm -v $PWD:/share -v ~/.panconfkeystore:/home/ubuntu/.panconfkeystore -it swaschkut/pan-os-php:beta';

                    $command = $panosphp_tool." type=securityprofile 'in=beta/{$config}' 'actions=exportSPtoHTML:{$configname}_sp.html' location=any projectfolder=beta 'filter=!(object is.unused) and !(object is.unused.recursive)'";
                }


                if( $generate_dev )
                {
                    if( $tool == "docker-outside" )
                        $panosphp_tool = 'docker run --name panosphp-develop-val --rm -v $PWD:/share -v ~/.panconfkeystore:/home/ubuntu/.panconfkeystore -it swaschkut/pan-os-php:develop';
                    $command = $panosphp_tool." type=securityprofile 'in=dev/{$config}' 'actions=exportSPtoHTML:{$configname}_sp.html' location=any projectfolder=dev 'filter=!(object is.unused) and !(object is.unused.recursive)'";
                }


                if( $generate_latest )
                {
                    if( $tool == "docker-outside" )
                        $panosphp_tool = 'docker run --name panosphp-latest-val --rm -v $PWD:/share -v ~/.panconfkeystore:/home/ubuntu/.panconfkeystore -it swaschkut/pan-os-php:latest';
                    $command = $panosphp_tool." type=securityprofile 'in=dev/{$config}' 'actions=exportSPtoHTML:{$configname}_sp.html' location=any projectfolder=latest 'filter=!(object is.unused) and !(object is.unused.recursive)'";
                }


                if( !$generate_beta && !$generate_dev && !$generate_latest )
                {
                    print "nothing choosen: 'beta' / 'dev' / 'latest' or a combination\n";
                    exit();
                }

                $command_array[] = $command;

                if( $script_validation )
                    print $command."\n";
                else
                {
                    print $inline.$inline."run CLI command\n";
                    $this->compare_command( $command, $config );
                    $this->request_CLI_command($command, $config);
                }

            }


            if( $generate_stats || $generate_stats_only )
            {
                $commands = array();

                print "\n\n";
                print $inline."====================================\n";
                print $inline."GENERATE STATS\n";
                print $inline."====================================\n";


                if( $tool == "docker" )
                    $panosphp_tool = 'php /tools/pan-os-php/utils/pan-os-php.php';
                elseif( $tool == "local" )
                    $panosphp_tool = "pan-os-php";

                //compare_dev_beta
                if( $generate_beta )
                {
                    $folder = "beta";


                    if( $tool == "docker-outside" )
                        $panosphp_tool = 'docker run --name panosphp-beta-val --rm -v $PWD:/share -v ~/.panconfkeystore:/home/ubuntu/.panconfkeystore -it swaschkut/pan-os-php:beta';


                    $command = $panosphp_tool . " type=stats shadow-bpjsonfile={$bp_setting_file} actions=display-bpa 'in={$folder}/{$config}' shadow-json 2>&1 | tee {$folder}/{$configname}_stats.txt";
                    $command_array[] = $command;
                    $commands[] = $command;
                }


                if( $generate_dev )
                {
                    $folder = "dev";

                    if( $tool == "docker-outside" )
                        $panosphp_tool = 'docker run --name panosphp-develop-val --rm -v $PWD:/share -v ~/.panconfkeystore:/home/ubuntu/.panconfkeystore -it swaschkut/pan-os-php:develop';


                    $command = $panosphp_tool . " type=stats shadow-bpjsonfile={$bp_setting_file} actions=display-bpa 'in={$folder}/{$config}' shadow-json 2>&1 | tee {$folder}/{$configname}_stats.txt";
                    $command_array[] = $command;
                    $commands[] = $command;
                }

                if( $generate_latest )
                {
                    $folder = "latest";

                    if( $tool == "docker-outside" )
                        $panosphp_tool = 'docker run --name panosphp-latest-val --rm -v $PWD:/share -v ~/.panconfkeystore:/home/ubuntu/.panconfkeystore -it swaschkut/pan-os-php:latest';


                    $command = $panosphp_tool . " type=stats shadow-bpjsonfile={$bp_setting_file} actions=display-bpa 'in={$folder}/{$config}' shadow-json 2>&1 | tee {$folder}/{$configname}_stats.txt";
                    $command_array[] = $command;
                    $commands[] = $command;
                }

                if( !$generate_beta && !$generate_dev && !$generate_latest )
                {
                    print "nothing choosen: 'beta' / 'dev' / 'latest' or a combination\n";
                    exit();
                }


                foreach( $commands as $command )
                {
                    if ($script_validation)
                        print $command . "\n";
                    else {
                        print $inline . $inline . "run CLI command\n";
                        $this->request_CLI_command($command, $config);
                    }
                }

            }


            /////////////
            /// COMPARE
            //////////////////////////////////////////////////////////
            if( $compare_dev_beta || $compare_latest_dev)
            {
                print "\n\n";
                print $inline."====================================\n";
                print $inline."COMPARE XML\n";
                print $inline."====================================\n";


                if( $tool == "docker-outside" )
                    $panosphp_tool = 'docker run --name panosphp-beta-val --rm -v $PWD:/share -v ~/.panconfkeystore:/home/ubuntu/.panconfkeystore -it swaschkut/pan-os-php:beta';
                elseif( $tool == "docker" )
                    $panosphp_tool = 'php /tools/pan-os-php/utils/pan-os-php.php';
                elseif( $tool == "local" )
                    $panosphp_tool = "pan-os-php";

                if( $compare_dev_beta )
                {
                    //compare_dev_beta
                    $command = $panosphp_tool." type=diff 'file1=dev/{$config}' 'file2=beta/{$config}'";
                    $command_array[] = $command;
                }

                if( $compare_latest_dev )
                {
                    $command = $panosphp_tool." type=diff 'file1=latest/{$config}' 'file2=dev/{$config}'";
                    $command_array[] = $command;
                }


                if( $script_validation )
                    print $command."\n";
                else
                {
                    print $inline.$inline."run CLI command\n";
                    $validation[$config]['xml'] = $this->compare_command( $command, $config );
                }
            }


            if( $compare_stats_dev_beta || $compare_stats_latest_dev )
            {
                print "\n\n";
                print $inline."====================================\n";
                print $inline."COMPARE STATS\n";
                print $inline."====================================\n";

                $compare_stats_array = array();

                $file_dev_beta = array( "file1" => "dev/{$configname}_stats.txt", "file2" => "beta/{$configname}_stats.txt" );
                $file_latest_dev = array( "file1" => "latest/{$configname}_stats.txt", "file2" => "dev/{$configname}_stats.txt" );

                if( $compare_stats_dev_beta )
                    $compare_stats_array[] = $file_dev_beta;

                if( $compare_stats_latest_dev )
                    $compare_stats_array[] = $file_latest_dev;


                foreach( $compare_stats_array as $compare_stats_file )
                {
                    $file1 = $compare_stats_file["file1"];
                    $file2 = $compare_stats_file["file2"];

                    // 1. Check if both files exist and are readable
                    if (!file_exists($file1) || !is_readable($file1)) {
                        die("Error: File 1 does not exist or is not readable: " . $file1);
                    }

                    if (!file_exists($file2) || !is_readable($file2)) {
                        die("Error: File 2 does not exist or is not readable: " . $file2);
                    }

                    // 2. Safely read and decode the files
                    $json1 = json_decode(file_get_contents($file1), true);
                    $json2 = json_decode(file_get_contents($file2), true);

                    // 3. (Optional but recommended) Verify that the JSON itself is valid
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        die("Error parsing JSON data: " . json_last_error_msg());
                    }

                    $statOriginal = $json1['statistic'] ?? null;
                    $statOther = $json2['statistic'] ?? null;

                    //due to header changes in 2.1.57.beta
                    $tmp_array = array();
                    foreach( $statOriginal as $key => $value )
                        $tmp_array[] = $value;
                    $statOriginal = $tmp_array;
                    $tmp_array = array();
                    foreach( $statOther as $key => $value )
                        $tmp_array[] = $value;
                    $statOther = $tmp_array;

                    ////
                    ///
                    // 3. Run the comparison starting strictly on the extracted statistics data
                    $diff = $this->getJsonChangesOnly($statOriginal, $statOther);

                    if( empty($diff) )
                    {
                        $validation[$config]['stats'] = true;
                    }
                    else
                    {
                        // 4. Output results
                        echo json_encode($diff, JSON_PRETTY_PRINT);
                        $validation[$config]['stats'] = false;
                    }

                }
            }

            //statictic -> [0] -> percentag -> visibility
            if( $compare_stats_not_100 )
            {
                $file_array = array();
                if( $generate_beta )
                {
                    $file1 = "beta/{$configname}_stats.txt";
                    $file_array[] = $file1;
                }

                if( $generate_dev )
                {
                    $file1 = "dev/{$configname}_stats.txt";
                    $file_array[] = $file1;
                }

                if( $generate_latest )
                {
                    $file1 = "latest/{$configname}_stats.txt";
                    $file_array[] = $file1;
                }

                foreach( $file_array as $file1 )
                {
                    // 1. Decode the JSON string into a PHP associative array
                    $data = json_decode(file_get_contents($file1), true);

                    $data = $data['statistic'][0][0]['percentage'] ?? null;

                    // 2. Define your exclusion list
                    $exclusions = [
                        'Data Filtering',
                        'App-ID',
                        'User-ID',
                        'Service/Port', // json_decode automatically handles the escaped forward slash
                        'Zone Protection'
                    ];

                    $results = [];

                    // 3. Loop through the visibility items
                    if (isset($data['visibility']))
                    {
                        foreach ($data['visibility'] as $name => $details) {

                            // Condition A: Exclude specific names
                            if (in_array($name, $exclusions)) {
                                continue;
                            }

                            // Condition B: Filter for values that are NOT 100
                            if ($details['value'] !== 100)
                            {
                                // Save matching elements to our results array
                                $results[$name] = $details;
                                $validation[$config]['percentage'] = false;
                            }
                        }
                    }

                    // 4. Output the filtered results
                    print_r($results);
                }
            }

        }

        if( $script_validation )
        {
            print "\n\n";
            print $inline."====================================\n";
            print $inline."ALL COMMANDS:\n";
            print $inline."====================================\n";

            foreach( $command_array as $command )
                print $command."\n\n";
        }


        if( !empty($validation) )
        {
            print "\n\n";
            print $inline."====================================\n";
            print $inline."VALIDATION:\n";
            print $inline."====================================\n";

            foreach( $validation as $config => $compare_type )
            {
                if( $compare_type != null )
                    foreach( $compare_type as $type => $value )
                    {
                        if( $value === false )
                        {
                            print "{$type}: => diff for {$config}\n";
                        }
                    }
            }
        }
    }

    function endOfScript()
    {
    }

    /**
     * Run a playbook step as a subprocess to achieve complete memory cleanup.
     * This spawns a new PHP process for the step, which guarantees all memory
     * is released when the subprocess exits.
     *
     * @param string $script The utility type (e.g., 'rule', 'address', 'device')
     * @param array $arguments The arguments array for the step
     * @param string $PHP_FILE The path to the pan-os-php.php entry point
     */
    function runStepAsSubprocess($script, $arguments, $argc, $PHP_FILE)
    {
        // $PHP_FILE points to PLAYBOOK__.php - we need pan-os-php.php instead
        $panOsPHPFile = dirname(dirname($PHP_FILE)) . '/pan-os-php.php';
        if( !file_exists($panOsPHPFile) )
        {
            // Fallback: try to find it relative to current file
            $panOsPHPFile = dirname(__DIR__) . '/pan-os-php.php';
        }

        // Build the command - redirect stderr to stdout for unified output
        $cmd = 'php ' . escapeshellarg($panOsPHPFile) . ' type=' . escapeshellarg($script);

        // Add all arguments
        foreach( $arguments as $arg )
        {
            if( !empty($arg) )
            {
                $cmd .= " " . escapeshellarg($arg);
            }
        }

        // Redirect stderr to stdout so we get all output in order
        $cmd .= ' 2>&1';

        if( $this->debugMemory )
        {
            PH::print_stdout(" - Running step as subprocess");
        }

        // Use passthru for real-time streaming output
        $returnCode = 0;
        passthru($cmd, $returnCode);

        if( $returnCode !== 0 )
        {
            PH::print_stdout(" ** WARNING: Subprocess exited with code $returnCode");
        }

        $this->display_container_memory_usage($currentContainerTotalMemory, $memMBtotal);
    }


    function get_container_memory_usage(): ?int
    {
        // Path for cgroup v2 (Modern systems, Docker Desktop, newer Linux distros)
        $v2_path = '/sys/fs/cgroup/memory.current';

        // Path for cgroup v1 (Older systems)
        $v1_path = '/sys/fs/cgroup/memory/memory.usage_in_bytes';

        if (file_exists($v2_path)) {
            return (int)trim(file_get_contents($v2_path));
        } elseif (file_exists($v1_path)) {
            return (int)trim(file_get_contents($v1_path));
        }

        return null; // Could not determine
    }

    function display_container_memory_usage( &$currentContainerTotalMemory = 0, &$memMBtotal = 0 ): void
    {
        $currentScriptMemory = memory_get_usage(true);
        $memMB = number_format($currentScriptMemory / 1024 / 1024, 2);
        $currentContainerTotalMemory = $this->get_container_memory_usage();
        if( $currentContainerTotalMemory !== null )
            $memMBtotal = number_format($currentContainerTotalMemory / 1024 / 1024, 2);

        if( $this->debugMemory )
        {
            PH::print_stdout(" - currentScript-Memory=".$memMB." MB");
            if( $currentContainerTotalMemory !== null )
                PH::print_stdout(" - currentTotalContainer-Memory=".$memMBtotal." MB");
        }
    }

    function printCOMMENTS( $string )
    {
        PH::print_stdout();

        $array = explode( "/n", $string );
        foreach( $array as $line )
            PH::print_stdout($line );

        PH::print_stdout();
    }

    public function display_error_usage_exit($msg)
    {
        if( PH::$shadow_json )
            PH::$JSON_OUT['error'] = $msg;
        else
            fwrite(STDERR, PH::boldText("\n**ERROR** ") . $msg . "\n\n");
        $this->display_usage_and_exit(TRUE);
    }

    public function display_usage_and_exit($shortMessage = FALSE)
    {
        if( $this->usageMsg == "" )
            $this->usageMessage();
        else
        {
            PH::print_stdout( $this->usageMsg );
            PH::$JSON_TMP['usage'] = $this->usageMsg;
        }

        PH::print_stdout();
        PH::print_stdout();

        if( !$shortMessage )
        {
            PH::print_stdout( PH::boldText("\nListing available arguments") );
            PH::print_stdout();
            PH::print_stdout();

            ksort($this->supportedArguments);
            foreach( $this->supportedArguments as &$arg )
            {

                PH::$JSON_TMP['arguments'][$arg['niceName']]['name'] = $arg['niceName'];

                $tmp_text = PH::boldText($arg['niceName']);
                if( isset($arg['argDesc']) )
                {
                    $tmp_text .= '=' . $arg['argDesc'] ;
                    PH::$JSON_TMP['arguments'][$arg['niceName']]['argdescription'] = $arg['argDesc'];
                }

                //."=";
                PH::print_stdout( " - " .$tmp_text );
                PH::$JSON_TMP['arguments'][$arg['niceName']]['example'] = $tmp_text;



                if( isset($arg['shortHelp']) )
                {
                    PH::print_stdout( "     " . $arg['shortHelp'] );
                    PH::$JSON_TMP['arguments'][$arg['niceName']]['shorthelp'] = $arg['shortHelp'];
                }


                PH::print_stdout();
            }

            PH::print_stdout( PH::$JSON_TMP, false, 'help' );
            PH::$JSON_TMP = array();


            PH::print_stdout();

        }

        if( PH::$shadow_json )
        {
            PH::$JSON_OUT['log'] = PH::$JSON_OUTlog;
            print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );
            #print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT|JSON_FORCE_OBJECT );
        }
        exit(1);
    }

    public function usageMessage()
    {
        $string = PH::boldText("USAGE: ") . "php " . $this->PHP_FILE . " beta/dev "
            . "[generate-sp/generate-stats/generate-sp-only/generate-stats-only]"
            . "[compare-dev-beta/compare-stats-dev-beta/compare-latest-dev/compare-stats-latest-dev]"
            . "[tool=docker-outside/docker/local]"
            . "[script-validation]"
            . "[playbook-file=custom-pb-file.json]"
            . "[bp-setting-file=custom-bp-set-file.json]"
            . "";


        PH::print_stdout();
        PH::print_stdout( $string );
        PH::print_stdout();

        PH::$JSON_TMP['usage'] = $string;
    }


    function compare_command( $command, $config )
    {
        $ret = $this->request_CLI_command_old($command);
        $counter = $ret["counter"];
        $retValue = $ret["retValue"];
        $diffEqual = $ret["diffEqual"];


        #print "counter: ".$counter."\n";

        //$counter == 11 - if exactly no diff
        #if( $counter > 17 )
        #    derr("DIFF available for file '{$config}' ");

        #if( $retValue != 0 )
        #    derr("CLI exit with error code '{$retValue}'");
        echo "\n";

        return $diffEqual;
    }


    function request_CLI_command_old( $command )
    {
        $diff_equal = false;
        echo " * Executing CLI: {$command}\n";

        $output = array();
        $retValue = 0;

        exec($command, $output, $retValue);

        $counter = 0;
        foreach( $output as $line )
        {
            if( str_contains($line, "- FinalResult:   PASS") )
                $diff_equal = true;
            echo '   ##  ';
            echo $line;
            echo "\n";
            $counter++;
        }

        return array("counter" => $counter, "retValue" => $retValue, "diffEqual" => $diff_equal);
    }


    function request_CLI_command( $command )
    {
        echo " * Executing CLI: {$command}\n";

        // Open the process for reading ('r')
        // We append ' 2>&1' to redirect stderr to stdout so you see errors in real-time too
        $handle = popen($command . ' 2>&1', 'r');

        if ($handle)
        {
            while (!feof($handle))
            {
                // Read one line (up to 4096 bytes)
                $line = fgets($handle);

                // If fgets returns data, print it immediately
                if ($line !== false) {
                    echo '   ##  ' . $line;

                    // Flush the output buffers so it hits the console/browser instantly
                    flush();
                    if (ob_get_level() > 0)
                    {
                        ob_flush();
                    }
                }
            }
            // Close the handle and get the exit code (retValue)
            $retValue = pclose($handle);
        } else {
            echo "Failed to execute command.\n";
        }
    }




    

    /**
     * * Recursively finds keys that exist in $original but have different values in $other.
     * * Ignores any newly added keys.
     * */
    function getJsonChangesOnly(array $original, array $other): array
    {
        $changes = [];

        foreach($original as $key => $value)
        {
            // Ignore if the key doesn't exist in the new payload
            if(!array_key_exists($key, $other)){
                continue;
            }

            if(is_array($value) && is_array($other[$key]))
            {
                $nestedChanges = $this->getJsonChangesOnly($value, $other[$key]);
                if(!empty($nestedChanges))
                {
                    $changes[$key] = $nestedChanges;
                }
            }
            else
            {
                // Validate if the value has really changed
                if($value !== $other[$key])
                {
                    $changes[$key] = [
                        'from' => $value,
                        'to' => $other[$key]
                    ];
                }
            }
        }

        return $changes;
    }
}