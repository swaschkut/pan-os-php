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
        $this->supportedArguments['dev'] = array('niceName' => 'dev');
        $this->supportedArguments['beta'] = array('niceName' => 'beta');
        $this->supportedArguments['compare'] = array('niceName' => 'compare');
        $this->supportedArguments['generate-sp'] = array('niceName' => 'generate-sp');
        $this->supportedArguments['generate-sp-only'] = array('niceName' => 'generate-sp-only');
        $this->supportedArguments['tool'] = array('niceName' => 'tool usage');


        $input = null;
        $output = null;

        $jsonFile = null;
###############################################################################
//PLAYBOOK
###############################################################################
//example of an JSON file syntax
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
            $help_string = PH::boldText("USAGE: ") . "php " . $PHP_FILE . ' in=inputfile.xml out=outputfile.xml [json=JSONfile] [json=$$playbookfolder$$/JSONfile]\n';

            PH::print_stdout( $help_string );

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
        $generate_spr = false;
        $generate_spr_only = false;
        $compare = false; // Changed to false by default so CLI arguments can toggle it on

//////////////////////////////////////////////////////////////////////////////////////////////////
// CLI Argument Validation
//////////////////////////////////////////////////////////////////////////////////////////////////


        if( isset(PH::$args['script-validation']) )
            $script_validation = true;

        if( isset(PH::$args['dev']) )
            $generate_dev = true;

        if( isset(PH::$args['beta']) )
            $generate_beta = true;

        if( isset(PH::$args['compare']) )
            $compare = true;

        if( isset(PH::$args['generate-sp']) )
            $generate_spr = true;

        if( isset(PH::$args['generate-sp-only']) )
            $generate_spr_only = true;

        if( isset(PH::$args['tool']) )
            $tool = PH::$args['tool'];

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

        $file_array = array();
        foreach ($files as $file)
        {
            if (is_file($file))
                $file_array[] = basename($file);

        }

        if( $script_validation )
            print_r($file_array);





        foreach( $file_array as $config )
        {
            $inline = "   ";
            $configname = explode( ".", $config );
            $configname = $configname[0];

            print "\n\n###################################################################\n";
            print "CONFIGNAME: " . $config . "\n\n";

            if( $generate_dev )
                $folder = "dev";
            if( $generate_dev && !$generate_spr_only )
            {
                print $inline."====================================\n";
                print $inline."DEV\n";
                print $inline."====================================\n";

                //$command = "docker pull swaschkut/pan-os-php:develop";
                //$this->request_CLI_command( $command );


                $folder = "dev";
                $panosphp_tool = "pa_docker-panosphp-develop";
                if( $tool == "docker" )
                {
                    $panosphp_tool = 'docker run --name panosphp-develop --rm -v $PWD:/share -v ~/.panconfkeystore:/home/ubuntu/.panconfkeystore -it swaschkut/pan-os-php:develop';
                    $panosphp_tool = 'php /tools/pan-os-php/utils/pan-os-php.php';
                }
                elseif( $tool == "local" )
                    $panosphp_tool = "pan-os-php";

                $command = $panosphp_tool." type=playbook 'json={$playbook_file}' shadow-bpjsonfile={$bp_setting_file} 'out={$folder}/{$config}' 'in=origin/{$config}' subprocess projectfolder=delete/validation_{$folder}";

                if( $script_validation )
                    print $command."\n";
                else
                {
                    print $inline.$inline."run CLI command\n";
                    $this->request_CLI_command( $command, $config );
                }
            }

            if( $generate_beta )
                $folder = "beta";
            if( $generate_beta && !$generate_spr_only )
            {
                print "\n\n";
                print $inline . "====================================\n";
                print $inline . "BETA\n";
                print $inline . "====================================\n";


                //$command = "docker pull swaschkut/pan-os-php:beta";
                //$this->request_CLI_command($command);

                $folder = "beta";

                $panosphp_tool = "pa_docker-panosphp-beta";
                if( $tool == "docker-outside" )
                {
                    $panosphp_tool = 'docker run --name panosphp-beta --rm -v $PWD:/share -v ~/.panconfkeystore:/home/ubuntu/.panconfkeystore -it swaschkut/pan-os-php:beta';
                }
                elseif( $tool == "docker" )
                {
                    $panosphp_tool = 'php /tools/pan-os-php/utils/pan-os-php.php';
                }
                elseif( $tool == "local" )
                    $panosphp_tool = "pan-os-php";

                $command = $panosphp_tool . " type=playbook 'json={$playbook_file}' shadow-bpjsonfile={$bp_setting_file} 'out={$folder}/{$config}' 'in=origin/{$config}' subprocess projectfolder=delete/validation_{$folder}";

                if ($script_validation)
                    print $command . "\n";
                else {
                    print $inline . $inline . "run CLI command\n";
                    $this->request_CLI_command($command, $config);
                }
            }

            //todo:
            //validate if dev and beta folder has all files available

            //validate if all origin config are also available in DEV and BETA, then compare
            if( $compare )
            {
                print "\n\n";
                print $inline."====================================\n";
                print $inline."COMPARE\n";
                print $inline."====================================\n";

                $panosphp_tool = "pa_docker-panosphp-beta";
                if( $tool == "docker-outside" )
                {
                    $panosphp_tool = 'docker run --name panosphp-beta --rm -v $PWD:/share -v ~/.panconfkeystore:/home/ubuntu/.panconfkeystore -it swaschkut/pan-os-php:beta';
                }
                elseif( $tool == "docker" )
                {
                    $panosphp_tool = 'php /tools/pan-os-php/utils/pan-os-php.php';
                }
                elseif( $tool == "local" )
                    $panosphp_tool = "pan-os-php";

                //compare
                $command = $panosphp_tool." type=diff 'file1=dev/{$config}' 'file2=beta/{$config}'";

                if( $script_validation )
                    print $command."\n";
                else
                {
                    print $inline.$inline."run CLI command\n";
                    $this->compare_command( $command, $config );
                }
            }

            if( $generate_spr || $generate_spr_only )
            {
                print "\n\n";
                print $inline."====================================\n";
                print $inline."GENERATE SP\n";
                print $inline."====================================\n";

                $panosphp_tool = "pa_docker-panosphp-beta";
                if( $tool == "docker-outside" )
                {
                    $panosphp_tool = 'docker run --name panosphp-beta --rm -v $PWD:/share -v ~/.panconfkeystore:/home/ubuntu/.panconfkeystore -it swaschkut/pan-os-php:beta';
                }
                if( $tool == "docker" )
                {
                    $panosphp_tool = 'php /tools/pan-os-php/utils/pan-os-php.php';
                }
                elseif( $tool == "local" )
                    $panosphp_tool = "pan-os-php";

                //compare
                if( $generate_beta )
                    $command = $panosphp_tool." type=securityprofile 'in=beta/{$config}' 'actions=exportSPtoHTML:sp_{$configname}_beta.html' projectfolder={$folder}";
                elseif( $generate_dev )
                    $command = $panosphp_tool." type=securityprofile 'in=dev/{$config}' 'actions=exportSPtoHTML:sp_{$configname}_dev.html' projectfolder={$folder}";
                else
                {
                    print "nothing choosen: 'beta' or 'dev'\n";
                    exit();
                }

                if( $script_validation )
                    print $command."\n";
                else
                {
                    print $inline.$inline."run CLI command\n";
                    $this->compare_command( $command, $config );
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
        $string = PH::boldText("USAGE: ") . "php " . $this->PHP_FILE . " in=inputfile.xml out=outputfile.xml location=any|shared|sub " .
            "json=PLAYBOOK.json projectfolder=DIRECTORY\n";


        PH::print_stdout( $string );
        PH::$JSON_TMP['usage'] = $string;
    }


    function compare_command( $command, $config )
    {
        $ret = $this->request_CLI_command_old($command);
        $counter = $ret["counter"];
        $retValue = $ret["retValue"];


        #print "counter: ".$counter."\n";

        //$counter == 11 - if exactly no diff
        #if( $counter > 17 )
        #    derr("DIFF available for file '{$config}' ");

        #if( $retValue != 0 )
        #    derr("CLI exit with error code '{$retValue}'");
        echo "\n";
    }


    function request_CLI_command_old( $command )
    {
        echo " * Executing CLI: {$command}\n";

        $output = array();
        $retValue = 0;

        exec($command, $output, $retValue);

        $counter = 0;
        foreach( $output as $line )
        {
            echo '   ##  ';
            echo $line;
            echo "\n";
            $counter++;
        }

        return array("counter" => $counter, "retValue" => $retValue);
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
}