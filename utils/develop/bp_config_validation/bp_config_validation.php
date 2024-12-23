<?php

// load PAN-OS-PHP library
require_once("../../../lib/pan_php_framework.php");
require_once "../../../utils/lib/UTIL.php";


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
$supportedArguments['actions'] = array('niceName' => 'actions', 'shortHelp' => 'supported parts: "display", "implement"');

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


$actions = "display";
if( isset(PH::$args['actions'])  )
{
    $actions = PH::$args['actions'];
}

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


///////////////////////////////////////////////////////////
//load json file for validation
$jsonFile = "validate_xpath.json";

////////////
// Read the JSON file
$json = file_get_contents( $jsonFile );

// Check if the file was read successfully
if ($json === false) {
    die('Error reading the JSON file');
}

// Decode the JSON file
$json_data = json_decode($json, true);

// Check if the JSON was decoded successfully
if ($json_data === null) {
    die('Error decoding the JSON file');
}

#print_r($json_data);
$spreadSheetArray = array();
foreach( $json_data as $check_entry)
{
    if( $check_entry['check'] == "false" )
        continue;

    if( $pan->isFirewall() )
    {
        if( strpos( $check_entry['xpath'], "mgt-config" ) !== FALSE )
            $mainXpath = "/config";
        elseif( strpos( $check_entry['xpath'], "setting" ) === 0 )
            $mainXpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig";
        else
            $mainXpath = "/config/devices/entry[@name='localhost.localdomain']";
    }
    elseif( $pan->isPanorama() )
    {
        //different checks needed:
            //check against specific Template
                //all firewall settings are also template relevant

            //check against main Panorama config
            //which values are only relevant to main Panoroama config??
    }
    else
    {
        derr( "Config Type: ".get_class( $pan )." not supported yet for BP config check" );
    }

    $xpath1 = $mainXpath."/".$check_entry['xpath'];
    if( $actions == "display" )
        PH::print_stdout( "check xpath: '".$xpath1."'" );


    $tmp_spreadsheet['xpath'] = $xpath1;
    //$pan->xmlroot
    $doc1Root = DH::findXPathSingleEntry($xpath1, $pan->xmldoc);
    if( $doc1Root )
    {
        #DH::DEBUGprintDOMDocument( $doc1Root );
        if( $actions == "display" )
        {
            PH::print_stdout("     -              : '".$doc1Root->textContent."'");
            PH::print_stdout("     - compare value: '".$check_entry['value']."'");
        }


        $tmp_spreadsheet['value'] = $doc1Root->textContent;
        $tmp_spreadsheet['compare'] = $check_entry['value'];
    }
    else
    {
        if( $actions == "display" )
        {
            PH::print_stdout("     - xpath - NOT set - missing");
            PH::print_stdout("     - compare value: '".$check_entry['value']."'");
        }

        $tmp_spreadsheet['value'] = "N/A";
        $tmp_spreadsheet['compare'] = $check_entry['value'];
    }

    if( $actions == "display" )
        PH::print_stdout();


    $string1 = trim(preg_replace('/\s+/', ' ', $tmp_spreadsheet['value']));
    $string1 = str_replace( "  ", " ", $string1);
    $string2 = trim(preg_replace('/\s+/', ' ', $tmp_spreadsheet['compare']));
    if( $string1 !== $string2 )
    {
        $spreadSheetArray[] = $tmp_spreadsheet;
    }
    else
    {
        if( $actions == "compare" )
            $spreadSheetArray[] = $tmp_spreadsheet;
    }

}
////////////////////////////////////////////////////////////////////////////////////


if( $actions == "implement" )
{
    foreach( $spreadSheetArray as $implement_item)
    {
        //actual value
        $implement_item['value'];

        if( $implement_item['value'] == "N/A" )
        {
            $implement_item['compare'];

            $implement_item['xpath'];

            if( $apiMode )
            {

                $tmp_xpath_Array = explode( "/", $implement_item['xpath'] );
                $lastEntry = array_pop($tmp_xpath_Array);
                $finalXpath = implode("/", $tmp_xpath_Array);

                $tmpElement = "<".$lastEntry.">".$implement_item['compare']."</".$lastEntry.">";

                $pan->connector->sendSetRequest( $finalXpath, $tmpElement );
            }
            else
            {
                $doc1Root = DH::findXPathSingleEntry($implement_item['xpath'], $pan->xmlroot);
                if( !$doc1Root )
                {
                    $xpath_array = explode( "/", $implement_item['xpath'] );

                    $node = $pan->xmlroot;
                    foreach( $xpath_array as $key => $item )
                    {
                        if( $key == 0 )
                            continue;
                        //xmlroot is already /config
                        elseif( $item == "config" )
                            continue;

                        if( strpos($item, "@name") !== FALSE )
                        {
                            $tmp = explode("[", $item);
                            $nodeName = $tmp[0];

                            $nameatrribute = explode( "[@name='", $item);
                            $attribute = $nameatrribute[1];
                            $attribute = substr_replace($attribute, '', -2);

                            $node = DH::findFirstElementByNameAttrOrCreate( $nodeName,  $attribute, $node, $pan->xmldoc );
                            DH::DEBUGprintDOMDocument($node);
                        }
                        else
                        {
                            $node = DH::findFirstElementOrCreate( $item,  $node );
                            DH::DEBUGprintDOMDocument($node);
                        }

                    }


                    $doc1Root = DH::findXPathSingleEntry($implement_item['xpath'], $pan->xmlroot);
                    $doc1Root->textContent = $implement_item['compare'];
                }
                else
                {
                    DH::DEBUGprintDOMDocument($doc1Root);
                    $doc1Root->textContent = $implement_item['compare'];
                }



            }
        }
        else
        {
            //if values differ
        }

    }
}











////////////////////////////////////////////////////////////////////////////////////

$headers = '<th>ID</th><th>value</th><th>compare</th><th>Xpath</th>';

#print_r($spreadSheetArray);

$lines = '';

$count = 0;

foreach( $spreadSheetArray as $object )
{
    $count++;

    if( $count % 2 == 1 )
        $lines .= "<tr>\n";
    else
        $lines .= "<tr bgcolor=\"#DDDDDD\">";

    $lines .= encloseFunction( (string)$count );



    $lines .= encloseFunction($object['value']);

    $lines .= encloseFunction($object['compare']);

    $lines .= encloseFunction($object['xpath']);

    $lines .= "</tr>\n";

}

$content = file_get_contents(dirname(__FILE__) . '/../../common/html/export-template.html');
$content = str_replace('%TableHeaders%', $headers, $content);

$content = str_replace('%lines%', $lines, $content);

$jscontent = file_get_contents(dirname(__FILE__) . '/../../common/html/jquery.min.js');
$jscontent .= "\n";
$jscontent .= file_get_contents(dirname(__FILE__) . '/../../common/html/jquery.stickytableheaders.min.js');
$jscontent .= "\n\$('table').stickyTableHeaders();\n";

$content = str_replace('%JSCONTENT%', $jscontent, $content);

$filename = "bp_config_check.html";
file_put_contents($filename, $content);



//////////////////

$util->save_our_work();
PH::print_stdout();
PH::print_stdout( "************* END OF SCRIPT ".basename(__FILE__)." ************" );
PH::print_stdout();

function encloseFunction( $value, $nowrap = TRUE )
{
    if( $value == NULL )
        $output = "---";
    elseif( is_string($value) )
        $output = htmlspecialchars($value);
    elseif( is_array($value) )
    {
        $output = '';
        $first = TRUE;
        foreach( $value as $subValue )
        {
            if( !$first )
            {
                $output .= '<br />';
            }
            else
                $first = FALSE;

            if( is_string($subValue) || is_numeric($subValue) )
                $output .= htmlspecialchars($subValue);
            elseif( is_object($subValue) )
                $output .= htmlspecialchars($subValue->name());
            else
                $output .= "";
        }
    }
    elseif( is_object($value) )
    {
        $output = htmlspecialchars( $value->name() );
    }
    else
        derr('TYPE: '.gettype($value).' unsupported', null, false);

    if( $nowrap )
        return '<td style="white-space: nowrap">' . $output . '</td>';

    return '<td>' . $output . '</td>';
}