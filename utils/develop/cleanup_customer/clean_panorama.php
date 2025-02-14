<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
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


set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../../utils/lib/UTIL.php";

PH::print_stdout();
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout();


PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );


$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = Array('niceName' => 'location', 'shortHelp' => 'specify if you want to limit your query to a VSYS. By default location=vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['loadpanoramapushedconfig'] = Array('niceName' => 'loadPanoramaPushedConfig', 'shortHelp' => 'load Panorama pushed config from the firewall to take in account panorama objects and rules' );
$supportedArguments['folder'] = Array('niceName' => 'folder', 'shortHelp' => 'specify the folder where the offline files should be saved');
$supportedArguments['namenodelete'] = Array('niceName' => 'NameNoDelete', 'shortHelp' => 'specify all DG/Templates as string which should not delete, regex search is implemented: test is keeping DG-test and Temp-test');

$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml location=vsys1 ".
    "\n".
    "php ".basename(__FILE__)." help          : more help messages\n";
##############


##########################################
##########################################

$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();


##########################################
##########################################
if( !isset( PH::$args['namenodelete'] ) )
    $util->display_error_usage_exit('"namenodelete" argument is not set');
else
    $NameNotDelete = explode(",", PH::$args['namenodelete']);

##########################################
##########################################

$util->load_config();
#$util->location_filter();

$pan = $util->pan;
$connector = $pan->connector;


///////////////////////////////////////////////////////

//Todo: start with offline; API mode to download later on

//todo: load into XMLDomdocument
//delete based on specific xpath, or keep xpath, decision needed

$xpathToDelete = array();
$xpathToDelete[] = "/config/mgt-config";
$xpathToDelete[] = "/config/shared";
$xpathToDelete[] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig";
$xpathToDelete[] = "/config/devices/entry[@name='localhost.localdomain']/template-stack";
$xpathToDelete[] = "/config/devices/entry[@name='localhost.localdomain']/log-collector";
$xpathToDelete[] = "/config/devices/entry[@name='localhost.localdomain']/log-collector-group";
$xpathToDelete[] = "/config/panorama";

##############################################


foreach(  $xpathToDelete as $xpath )
{
    PH::print_stdout("delete Xpath: ".$xpath);
    $xpathResult = DH::findXPath( $xpath, $util->xmlDoc);

    $removeNode = $xpathResult[0];
    #DH::DEBUGprintDOMDocument($removeNode);
    $removeNode->parentNode->removeChild($removeNode);
}




$xpathToKeep = array();
$xpathToKeep[] = "/config/devices/entry[@name='localhost.localdomain']/template";
$xpathToKeep[] = "/config/devices/entry[@name='localhost.localdomain']/device-group";

foreach(  $xpathToKeep as $xpath )
{

    $xpathResult = DH::findXPath( $xpath, $util->xmlDoc);

    $removeNode = $xpathResult[0];
    #DH::DEBUGprintDOMDocument($removeNode);
    PH::print_stdout("check Xpath: ".$xpath);
    $divs = iterator_to_array($removeNode->childNodes);
    foreach( $divs as $child )
    {
        /** @var DOMElement $node */
            if ($child->nodeType != XML_ELEMENT_NODE)
                continue;

        $name = DH::findAttribute("name",$child);
        $delete = true;
        foreach( $NameNotDelete as $notDeleteName )
        {
            if( strpos($name,$notDeleteName) !== false )
                $delete = false;
        }
        if( $delete )
        {
            PH::print_stdout("remove NAME: ". $name);
            $removeNode->removeChild($child);
        }
    }
}

#DH::debugprintDOMDocument($util->xmlDoc->documentElement);
##############################################

PH::print_stdout();

// save our work !!!
$util->save_our_work();


PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
