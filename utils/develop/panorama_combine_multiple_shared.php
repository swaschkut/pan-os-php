<?php

// load PAN-OS-PHP library
require_once("lib/pan_php_framework.php");
require_once "utils/lib/UTIL.php";


PH::print_stdout();
PH::print_stdout("*********** START OF SCRIPT ".basename(__FILE__)." ************" );
PH::print_stdout();


$supportedArguments = array();
//PREDEFINED arguments:
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'in=filename.xml | api. ie: in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['location'] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');

$supportedArguments['loadpanoramapushedconfig'] = array('niceName' => 'loadPanoramaPushedConfig', 'shortHelp' => 'load Panorama pushed config from the firewall to take in account panorama objects and rules');
$supportedArguments['apitimeout'] = array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to anwer, increase this value (default=60)');

$supportedArguments['shadow-disableoutputformatting'] = array('niceName' => 'shadow-disableoutputformatting', 'shortHelp' => 'XML output in offline config is not in cleaned PHP DOMDocument structure');
$supportedArguments['shadow-enablexmlduplicatesdeletion']= array('niceName' => 'shadow-enablexmlduplicatesdeletion', 'shortHelp' => 'if duplicate objects are available, keep only one object of the same name');
$supportedArguments['shadow-ignoreinvalidaddressobjects']= array('niceName' => 'shadow-ignoreinvalidaddressobjects', 'shortHelp' => 'PAN-OS allow to have invalid address objects available, like object without value or type');
$supportedArguments['shadow-apikeynohidden'] = array('niceName' => 'shadow-apikeynohidden', 'shortHelp' => 'send API-KEY in clear text via URL. this is needed for all PAN-OS version <9.0 if API mode is used. ');
$supportedArguments['shadow-apikeynosave']= array('niceName' => 'shadow-apikeynosave', 'shortHelp' => 'do not store API key in .panconfkeystore file');
$supportedArguments['shadow-displaycurlrequest']= array('niceName' => 'shadow-displaycurlrequest', 'shortHelp' => 'display curl information if running in API mode');
$supportedArguments['shadow-reducexml']= array('niceName' => 'shadow-reducexml', 'shortHelp' => 'store reduced XML, without newline and remove blank characters in offline mode');
$supportedArguments['shadow-json']= array('niceName' => 'shadow-json', 'shortHelp' => 'BETA command to display output on stdout not in text but in JSON format');

//YOUR OWN arguments if needed
$supportedArguments['argument1'] = array('niceName' => 'ARGUMENT1', 'shortHelp' => 'an argument you like to use in your script');
$supportedArguments['optional_argument2'] = array('niceName' => 'Optional_Argument2', 'shortHelp' => 'an argument you like to define here');


$usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=api:://[MGMT-IP] argument1 [optional_argument2]";


$util = new UTIL("custom", $argv, $argc,__FILE__, $supportedArguments, $usageMsg );

$util->utilInit();

$util->load_config();
$util->location_filter();


/** @var PANConf|PanoramaConf $pan */
$pan = $util->pan;


/** @var VirtualSystem|DeviceGroup $sub */
$sub = $util->sub;

/** @var string $location */
$location = $util->location;

/** @var boolean $apiMode */
$apiMode = $util->apiMode;

/** @var array $args */
$args = PH::$args;

PH::print_stdout();
PH::print_stdout( "    **********     **********" );
PH::print_stdout();

/*********************************
 * *
 * *  START WRITING YOUR CODE HERE
 * *
 * * List of available variables:
 *
 * * $pan : PANConf or PanoramaConf object
 * * $location : string with location name or undefined if not provided on CLI
 * * $sub : DeviceGroup or VirtualSystem found after looking from cli 'location' argument
 * * $apiMode : if config file was downloaded from API directly
 * * $args : array with all CLI arguments processed by PAN-OS-PHP
 * *
 */

PH::print_stdout( "copy shared DG from multiple Panorama config files into a new Panorama config");

//define all Panorama files
//empty one
//how to flexible read all possible panorama files?

$file_array = array();
$file_array[] = "panorama1.xml";
$file_array[] = "panorama2.xml";
$file_array[] = "panorama3.xml";




foreach( $file_array as  $key =>  $filename )
{
    //read Panorama file
    //- get XML
    //- search xpath /config/shared
    //- based on how many files, create DGx
    //- add all child from /config/shared to DGx
    $xmlDoc = new DOMDocument();
    PH::print_stdout( " - Reading XML file from disk... ".$filename );
    if( !$xmlDoc->load($filename, XML_PARSE_BIG_LINES) )
        derr("error while reading xml config file");

    $xpath = "/config/shared";
    $xpathResult = DH::findXPath( $xpath, $xmlDoc);
    PH::print_stdout( "   * XPATH: ".$xpath );

    $tmpSTring = $key + 1;
    $DG = $pan->createDeviceGroup( "DG".(string)$tmpSTring );

    foreach( $xpathResult as $xpath )
    {
        foreach( $xpath->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $tmpNode = $pan->xmlroot->ownerDocument->importNode($node, TRUE);
            $nodeName = $tmpNode->nodeName;

            #$allowedImport = array("address", "address-group", "service", "service-group", "tag");
            #if( in_array( $nodeName, $allowedImport) )
            #{
                $nodeElement = DH::findFirstElement( $nodeName, $DG->xmlroot );
                if( $nodeElement !== FALSE )
                    $DG->xmlroot->removeChild($nodeElement);
                $DG->xmlroot->appendChild( $tmpNode );
            #}
        }
    }
}

$util->save_our_work();
PH::print_stdout();
PH::print_stdout( "************* END OF SCRIPT ".basename(__FILE__)." ************" );
PH::print_stdout();

