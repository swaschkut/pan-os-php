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


###################################################################################
###################################################################################
//Todo: possible to bring this in via argument
//CUSTOM variables for the script



###################################################################################
###################################################################################

print "\n***********************************************\n";
print "************ renaming none valid PAN-OS characters UTILITY ****************\n\n";


require_once("lib/pan_php_framework.php");
require_once("utils/lib/UTIL.php");

$file = null;

$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['file'] = array('niceName' => 'XML', 'shortHelp' => 'Watchguard Config file in XML format');
$supportedArguments['location'] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');


$usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=api:://[MGMT-IP] file=[csv_text file] [out=]";

function strip_wrong_chars($str)
{
    //not possible to replace it in general
    $chars = array("'", "ä", "ö", "ü", "Ä" , "Ö", "Ü", "+", "#", "*", "?", ",", ";", ":", "(", ")", "[", "]", "\r\n", "\n", "\r", "\t", "\0", "\x0B", "/");


    foreach( $chars as $char )
    {
        if( $char === "ä" )
            $str = str_replace($char, "ae", $str);
        elseif( $char === "ö" )
            $str = str_replace($char, "oe", $str);
        elseif( $char === "ü" )
            $str = str_replace($char, "ue", $str);
        elseif( $char === "Ä" )
            $str = str_replace($char, "Ae", $str);
        elseif( $char === "Ö" )
            $str = str_replace($char, "Oe", $str);
        elseif( $char === "Ü" )
            $str = str_replace($char, "Ue", $str);
        else
            $str = str_replace($char, "", $str);
    }


    #return preg_replace('/\s+/',' ',$str);
    return $str;
}


$util = new UTIL("custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg);
$util->utilInit();

##########################################
##########################################


$util->load_config();
$util->location_filter();

$pan = $util->pan;

/** @var PanoramaConf|PANConf|BuckbeakConf|FawkesConf $v */
if ($util->configType == 'panos')
{
    // Did we find VSYS1 ?
    $v = $pan->findVirtualSystem($util->objectsLocation[0]);
    if ($v === null)
        derr($util->objectsLocation[0] . " was not found ? Exit\n");
}
elseif ($util->configType == 'panorama')
{
    $v = $pan->findDeviceGroup($util->objectsLocation[0]);
    if ($v == null)
        $v = $pan->createDeviceGroup($util->objectsLocation[0]);

    derr( "Panorama config file is not yet supported" );
}
elseif ($util->configType == 'fawkes')
{
    $v = $pan->findContainer($util->objectsLocation[0]);
    if ($v == null)
        $v = $pan->createContainer($util->objectsLocation[0]);

    derr( "Strata cloud manager config file is not yet supported" );
}


##########################################

//get all Service / Service-groups objects and rename it
$tmpVsyses = $pan->getVirtualSystems();

foreach( $tmpVsyses as $vsys )
{
    $tmp_services = $vsys->serviceStore->all();
    foreach( $tmp_services as $object)
    {
        $oldName = $object->name();
        $newName = strip_wrong_chars($oldName);

        if( $oldName !==  $newName )
            $object->setName($newName);
    }

//get all address / address-groups rename it
    $tmp_addresses = $vsys->addressStore->all();
    foreach( $tmp_addresses as $object)
    {
        $oldName = $object->name();
        $newName = strip_wrong_chars($oldName);

        if( $oldName !==  $newName  && $object !== null )
            $object->setName($newName);
    }

//get all rules rename it
    $tmp_rules = $vsys->securityRules->rules();
    foreach ( $tmp_rules as $object)
    {
        $oldName = $object->name();
        $newName = strip_wrong_chars($oldName);

        if( $oldName !==  $newName )
            $object->setName($newName);
    }
}


##################################################################

print "\n\n\n";

$util->save_our_work();

print "\n\n************ END OF renaming characters UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";