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

require_once("lib/pan_php_framework.php");
require_once("utils/lib/UTIL.php");

PH::print_stdout();
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout();

PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );

$displayAttributeName = false;

$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1 or location={DGname}:excludeMaindg [only childDGs of {DGname}] or location={DGname}:includechilddgs [{DGname} + all childDGs]', 'argDesc' => 'sub1[,sub2]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');


$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml ".
    "php ".basename(__FILE__)." help          : more help messages\n";
##############

$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();

##########################################
##########################################



$util->load_config();
$util->location_filter();

$pan = $util->pan;
$connector = $pan->connector;


########################################################################################################################

###########
#DISPLAY
###########
$actions = "display";
$ciscoFilter = "Demo-Tenant";


//////////////////////////////
$vsys = $util->objectsLocation[0];

$DG = $pan->findDeviceGroup($vsys);
if( $DG == null )
    derr("DG: ".$vsys." not found");

$cmd = '<show><tag><limit>100</limit><start-point>1</start-point></tag></show>';

$params = array();

$params['type'] = 'op';
$params['cmd'] = &$cmd;
$params['vsys'] = $vsys;

$response = $connector->sendRequest($params);

$cursor = DH::findXPathSingleEntryOrDie('/response/result', $response);

$epg_Array = array();
$headerArray = array();
foreach( $cursor->childNodes as $child )
{
    if( $child->nodeType != XML_ELEMENT_NODE )
        continue;

    #DH::DEBUGprintDOMDocument($child);
    $entry = DH::findAttribute("name", $child);
    $epg_Array[] =  $entry;

    $explode = explode( ".", $entry );
    foreach( $explode as $key => $part )
    {
        if( isset( $headerArray[$part] ) )
        {
            $headerArray[$part] ++;
        }
        else
        {
            if( !is_numeric($part) )
                $headerArray[$part] = 1;
        }

    }
}



$filterArray = array();

foreach( $epg_Array as $entry )
{
    if( strpos( $entry, $ciscoFilter ) != FALSE )
    {
        $filterArray[] = $entry;
    }
}

if( $actions == 'display' || $actions == "create" )
{
    $maxCount = count($epg_Array);
    foreach( $headerArray as $key => $entry )
    {
        #remove all entries which are not available less than three times
        if( $entry < 3 )
            unset($headerArray[$key]);

        #remove all EPG part name if available on all entries
        elseif( intval($entry) == intval($maxCount) )
            unset($headerArray[$key]);
    }

    PH::print_stdout( "possible EPG :" );
    print_r($headerArray);


    PH::print_stdout();
    PH::print_stdout( "all available EPG :" );
    print_r($epg_Array);


    PH::print_stdout( "filtered by : '".$ciscoFilter."'");
    print_r($filterArray);
}

if( $actions == "create" )
{
    foreach( $filterArray as $filtervalue )
    {
        $pos = strpos( $filtervalue, $ciscoFilter );
        $name = substr( $filtervalue, $pos+strlen($ciscoFilter)+1 );

        PH::print_stdout( "next step, create dynamic address group with name: ".$name." and filter: ".$filtervalue );


        $dynAddrGroup = $DG->addressStore->find($name);
        if( $dynAddrGroup == null )
        {
            $dynAddrGroup = $DG->addressStore->newAddressGroupDynamic( $name );
            $dynAddrGroup->addFilter($filtervalue);

            $dynAddrGroup->API_sync();
        }
        else
            mwarning( "address object with name: ".$name." is already available", null, false );
    }
}



########################################################################################################################



PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
########################################################################################################################
