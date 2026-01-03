<?php

/*
 USAGE;
php qa_sport_check.php in=panorama.xml fawkes=migrated_fawkes-configv27.xml
 */

require_once("lib/pan_php_framework.php");
require_once ( "utils/lib/UTIL.php");


$print_debug = false;

/** @var PanoramaConf $pan_panorama */
$pan_panorama = null;
/** @var DOMDocument $panorama_doc */
$panorama_doc = null;

/** @var FawkesConf $pan_fawkes */
$pan_fawkes = null;
/** @var DOMDocument $fawkes_doc */
$fawkes_doc = null;


PH::print_stdout();
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout();

PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );

$displayAttributeName = false;

$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'Panorama input file. ie: in=config.xml  ', 'argDesc' => '[filename]');
$supportedArguments['fawkes'] = Array('niceName' => 'fawkes', 'shortHelp' => 'FAWKES input file. ie: fawkes=config.xml  ', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');


$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=PANORAMAconfig.xml ".
    "\"fawkes=FAWKESconfig.xml\n".
    "php ".basename(__FILE__)." help          : more help messages\n";
##############

$util_panorama = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
$util_panorama->utilInit();

##########################################
##########################################

$util_panorama->load_config();
#$util->location_filter();

$pan_panorama = $util_panorama->pan;

$panorama_doc = new DOMDocument();
$panorama_doc = $util_panorama->xmlDoc;

########################################################################################################################
PH::print_stdout();
PH::print_stdout( "   *******************************");
PH::print_stdout();


if( !isset( PH::$args['fawkes'] ) )
    $util_panorama->display_error_usage_exit('"fawkes" argument is not set: example "fawkes=FAWKESconfig.xml');
else
{
    if( isset(PH::$args['fawkes']) )
    {
        $fawkes_file = PH::$args['fawkes'];
        $fawkes_out = PH::$args['out'];

        if( !file_exists($fawkes_file) )
            derr("file '{$fawkes_file}' not found");

        #$file_content = file( $file ) or die("Unable to open file!");
        $fawkes = file_get_contents($fawkes_file) or die("Unable to open file!");


        PH::$args = array();
        PH::$argv = array();
        PH::$argv[0] = $argv[0];
        PH::$argv[0] = "";
        PH::$argv[] = "in=" . $fawkes_file;
        PH::$argv[] = "out=" . $fawkes_out;

        $argv = array();
        $argv[] = "panorama-2fawkes.php";
        $argv[] = "in=" . $fawkes_file;
        $argv[] = "out=" . $fawkes_out;

        /**
         * @var UTIL $util_fawkes
         */
        $util_fawkes = new UTIL("custom", $argv, $argc, __FILE__);
        $util_fawkes->utilInit();

        $util_fawkes->load_config();


        $pan_fawkes = $util_fawkes->pan;

        $fawkes_doc = new DOMDocument();
        #$fawkes_doc->loadXML($fawkes);
        $fawkes_doc = $util_fawkes->xmlDoc;
        #echo $fawkes_doc->saveXML();
    }

    if( $util_panorama->debugAPI )
    {
        PH::print_stdout("DEBUGAPI");
        $print_debug = TRUE;
    }
}


########################################################################################################################
PH::print_stdout();
PH::print_stdout( "   *******************************");
PH::print_stdout( "start here to do spot check");
PH::print_stdout();
//START writing here

//PANORAMA
//$pan_panorama; PanoramaConf
//$panorama_doc; XMLdoc


//FAWKES
//$pan_fawkes; FAWKESconf
//$fawkes_doc; XMLdoc


//Mobile User Authentication-Profile
$panoramaXpath = "";
//check first Mobile User Template-stack
// store xpath
// get all templates
// store from all templates the xpath


$fawkesXpath = "/config/devices/entry[@name='localhost.localdomain']/device/cloud/entry[@name='Mobile Users']/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/authentication-profile";







//use class
#PH::print_stdout(PH::$JSON_TMP, false, "serials");
PH::$JSON_TMP = array();

#$util->save_our_work(TRUE);

#$util->endOfScript();

PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
########################################################################################################################
