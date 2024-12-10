<?php
/**
 * ISC License
 *
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


//TODO:
//display output not only export
//bring in filter which software version /greater as / lower as
//aso

print "\n***********************************************\n";
print "************ INVENTORY-EXPORT UTILITY ****************\n\n";


set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../../lib/pan_php_framework.php";




function display_usage_and_exit($shortMessage = false)
{
    global $argv;
    print PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml location=vsys1 ".
        "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']\n";
    print "php ".basename(__FILE__)." help          : more help messages\n";


    if( !$shortMessage )
    {
        print PH::boldText("\nListing available arguments\n\n");

        global $supportedArguments;

        ksort($supportedArguments);
        foreach( $supportedArguments as &$arg )
        {
            print " - ".PH::boldText($arg['niceName']);
            if( isset( $arg['argDesc']))
                print '='.$arg['argDesc'];
            //."=";
            if( isset($arg['shortHelp']))
                print "\n     ".$arg['shortHelp'];
            print "\n\n";
        }

        print "\n\n";
    }

    exit(1);
}

function display_error_usage_exit($msg)
{
    fwrite(STDERR, PH::boldText("\n**ERROR** ").$msg."\n\n");
    display_usage_and_exit(true);
}



print "\n";

$configType = null;
$configInput = null;
$configOutput = null;
$doActions = null;
$dryRun = false;
$objectslocation = 'shared';
$objectsFilter = null;
$errorMessage = '';
$debugAPI = false;



$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = Array('niceName' => 'location', 'shortHelp' => 'specify if you want to limit your query to a VSYS. By default location=vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['loadpanoramapushedconfig'] = Array('niceName' => 'loadPanoramaPushedConfig', 'shortHelp' => 'load Panorama pushed config from the firewall to take in account panorama objects and rules' );
$supportedArguments['folder'] = Array('niceName' => 'folder', 'shortHelp' => 'specify the folder where the offline files should be saved');


PH::processCliArgs();

foreach ( PH::$args as $index => &$arg )
{
    if( !isset($supportedArguments[$index]) )
    {
        //var_dump($supportedArguments);
        display_error_usage_exit("unsupported argument provided: '$index'");
    }
}

if( isset(PH::$args['help']) )
{
    display_usage_and_exit();
}


if( ! isset(PH::$args['in']) )
    display_error_usage_exit('"in" is missing from arguments');
$configInput = PH::$args['in'];
if( !is_string($configInput) || strlen($configInput) < 1 )
    display_error_usage_exit('"in" argument is not a valid string');

if(isset(PH::$args['out']) )
{
    $configOutput = PH::$args['out'];
    if (!is_string($configOutput) || strlen($configOutput) < 1)
        display_error_usage_exit('"out" argument is not a valid string');
}

if( isset(PH::$args['debugapi'])  )
{
    $debugAPI = true;
}

if( isset(PH::$args['folder'])  )
{
    $offline_folder = PH::$args['folder'];
}


################
//
// What kind of config input do we have.
//     File or API ?
//
// <editor-fold desc="  ****  input method validation and PANOS vs Panorama auto-detect  ****" defaultstate="collapsed" >
$configInput = PH::processIOMethod($configInput, true);
$xmlDoc1 = null;

if( $configInput['status'] == 'fail' )
{
    fwrite(STDERR, "\n\n**ERROR** " . $configInput['msg'] . "\n\n");exit(1);
}

if( $configInput['type'] == 'file' )
{
    if( !file_exists($configInput['filename']) )
        derr("file '{$configInput['filename']}' not found");

    $xmlDoc1 = new DOMDocument();
    if( ! $xmlDoc1->load($configInput['filename']) )
        derr("error while reading xml config file");

}
elseif ( $configInput['type'] == 'api'  )
{

    if($debugAPI)
        $configInput['connector']->setShowApiCalls(true);
    print " - Downloading config from API... ";

    if( isset(PH::$args['loadpanoramapushedconfig']) )
    {
        print " - 'loadPanoramaPushedConfig' was requested, downloading it through API...";
        $xmlDoc1 = $configInput['connector']->getPanoramaPushedConfig();
    }
    else
    {
        $xmlDoc1 = $configInput['connector']->getCandidateConfig();

    }
    #$hostname = $configInput['connector']->info_hostname;

    #$xmlDoc1->save( $offline_folder."/orig/".$hostname."_prod_new.xml" );

    print "OK!\n";

}
else
    derr('not supported yet');

//
// Determine if PANOS or Panorama
//
$xpathResult1 = DH::findXPath('/config/devices/entry/vsys', $xmlDoc1);
if( $xpathResult1 === FALSE )
    derr('XPath error happened');
if( $xpathResult1->length <1 )
{
    $xpathResult1 = DH::findXPath('/panorama', $xmlDoc1);
    if( $xpathResult1->length <1 )
        $configType = 'panorama';
    else
        $configType = 'pushed_panorama';
}
else
    $configType = 'panos';
unset($xpathResult1);

print " - Detected platform type is '{$configType}'\n";

############## actual not used

if( $configType == 'panos' )
    $pan = new PANConf();
elseif( $configType == 'panorama' )
    $pan = new PanoramaConf();



if( $configInput['type'] == 'api' )
    $pan->connector = $configInput['connector'];






// </editor-fold>

################


//
// Location provided in CLI ?
//
if( isset(PH::$args['location'])  )
{
    $objectslocation = PH::$args['location'];
    if( !is_string($objectslocation) || strlen($objectslocation) < 1 )
        display_error_usage_exit('"location" argument is not a valid string');
}
else
{
    if( $configType == 'panos' )
    {
        print " - No 'location' provided so using default ='vsys1'\n";
        $objectslocation = 'vsys1';
    }
    elseif( $configType == 'panorama' )
    {
        print " - No 'location' provided so using default ='shared'\n";
        $objectslocation = 'shared';
    }
    elseif( $configType == 'pushed_panorama' )
    {
        print " - No 'location' provided so using default ='vsys1'\n";
        $objectslocation = 'vsys1';
    }
}



##########################################
##########################################

if( $configType != 'panorama' || $configInput['type'] != 'api' )
{
    derr( "only Panorama in API mode is allowed!" );
}


$filename = 'inventory_sw.xls';


$configRoot = $pan->connector->sendOpRequest( '<show><devices><all></all></devices></show>' );

/*
#TMP
$doc = new DOMDocument();
$doc->load('sw.xml');
$configRoot = $doc;
$response = $configRoot;


$configRoot = DH::findFirstElement('response', $configRoot);
if( $configRoot === FALSE )
    derr("<result> was not found", $response);
*/





$configRoot = DH::findFirstElement('result', $configRoot);
if( $configRoot === FALSE )
    derr("<result> was not found", $configRoot);

$configRoot = DH::findFirstElement('devices', $configRoot);
if( $configRoot === FALSE )
    derr("<config> was not found", $configRoot);


#var_dump( $configRoot );


$device_array = array();

foreach( $configRoot->childNodes as $entry )
{
    if( $entry->nodeType != XML_ELEMENT_NODE )
        continue;

    foreach( $entry->childNodes as $node )
    {
        if( $node->nodeType != XML_ELEMENT_NODE )
            continue;


        if( $node->nodeName == "serial" ||  $node->nodeName == "serial-no" )
        {
            #print $node->nodeName." : ".$node->textContent."\n";
            $serial_no = $node->textContent;
            $device_array[ $serial_no ][ $node->nodeName ] = $serial_no;
        }
        else
        {
            #print "counter: ".count( $node->childNodes )."\n";
            if( count( $node->childNodes ) == 1 )
            {
                #print $node->nodeName." : ".$node->textContent."\n";
                $tmp_node = $node->textContent;
                $device_array[ $serial_no ][ $node->nodeName ] = $tmp_node;
            }
            else
            {
                #$tmp_node = $node->textContent;
                #$device_array[ $serial_no ][ $node->nodeName ] = $tmp_node;

                foreach( $node->childNodes as $child )
                {
                    $tmp_node = $child->textContent;
                    $device_array[ $serial_no ][ $child->nodeName ] = $tmp_node;
                }
                #derr( $node->nodeName."has childes" );
            }


        }
    }
}




$fields = array();
foreach( $device_array as $index => &$array )
{
    foreach( $array as $key => $value )
        $fields[$key] = $key;
}


foreach( $device_array as $index => &$array )
{
    foreach( $fields as $key => $value )
    {
        if( !isset( $array[$key] ) )
            $array[$key] = "not set";
    }
}



#print_r( $device_array );




$lines = '';

$count = 0;
if( !empty($device_array) )
{
    foreach ($device_array as $device)
    {
        $count++;

        /** @var SecurityRule|NatRule $rule */
        if ($count % 2 == 1)
            $lines .= "<tr>\n";
        else
            $lines .= "<tr bgcolor=\"#DDDDDD\">";

        foreach($fields as $fieldName => $fieldID )
        {
            $lines .= "<td>".$device[$fieldID]."</td>";
        }


        $lines .= "</tr>\n";

    }
}




$tableHeaders = '';
foreach($fields as $fName => $value )
    $tableHeaders .= "<th>{$fName}</th>\n";

$content = file_get_contents(dirname(__FILE__).'/../common/html-export-template.html');


$content = str_replace('%TableHeaders%', $tableHeaders, $content);

$content = str_replace('%lines%', $lines, $content);

$jscontent =  file_get_contents(dirname(__FILE__).'/../common/jquery-1.11.js');
$jscontent .= "\n";
$jscontent .= file_get_contents(dirname(__FILE__).'/../common/jquery.stickytableheaders.min.js');
$jscontent .= "\n\$('table').stickyTableHeaders();\n";

$content = str_replace('%JSCONTENT%', $jscontent, $content);

file_put_contents($filename, $content);






print "\n\n************ END OF INVENTORY-EXPORT UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";
