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
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');

$supportedArguments['location'] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');


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

/** @var DeviceGroup $deviceGroup */
$deviceGroup = $util->sub;

########################################################################################################################
$DAG_name_prefix = "DAG_";

#used static tag objects to create DAG
$tag_array = $deviceGroup->tagStore->all("(name regex /EPG/)");


//Todo: 20240420 swaschkut - how to get ACI tags and create DAG from there??????
foreach( $tag_array as $key => $tag )
{
    $objDAG = $deviceGroup->addressStore->newAddressGroupDynamic( $DAG_name_prefix.$tag->name() );

    $objDAG->addFilter($tag->name());

    if( $util->apiMode )
        $objDAG->API_sync();
}


########################################################################################################################
### CREATE Rules based on Dynamic Address Groups
########################################################################################################################
$zone = "ZONE_NAME";

$DAG_array = $deviceGroup->addressStore->all("(object is.group) and (object is.dynamic) and (name regex /".$DAG_name_prefix."/)");

$DAG_array_copy = $DAG_array;

foreach( $DAG_array as $key1 => $object1 )
{
    unset( $DAG_array_copy[$key1] );
    foreach( $DAG_array_copy as  $key2 => $object2 )
    {
        PH::print_stdout( "create Rule: ". $object1->name() ." -> ". $object2->name());

        $rule1_name = "ACI-".$object1->name()."_".$object2->name();

        $check_rule1_name = $rule1 = $deviceGroup->securityRules->find($rule1_name);
        if( !$check_rule1_name )
        {
            $rule1 = $deviceGroup->securityRules->newSecurityRule( $rule1_name );
            $rule1->source->addObject($object1);
            $rule1->destination->addObject($object2);

            $obj_Zone = $deviceGroup->zoneStore->findOrCreate($zone);
            $rule1->from->addZone($obj_Zone);
            $rule1->to->addZone($obj_Zone);

            #$rule->API_sync();
        }
        else
            mwarning( "- rule: '".$rule1_name."' already avaialble", null, false);

        PH::print_stdout("----------------");

        PH::print_stdout( "create Rule2: ". $object2->name() ." -> ". $object1->name());

        $rule2_name = "ACI-".$object2->name()."_".$object1->name();
        $check_rule2_name = $deviceGroup->securityRules->find($rule2_name);
        if( !$check_rule2_name )
        {
            $rule2 = $deviceGroup->securityRules->newSecurityRule( $rule2_name );
            $rule2->source->addObject($object2);
            $rule2->destination->addObject($object1);

            $obj_Zone = $deviceGroup->zoneStore->findOrCreate($zone);
            $rule2->from->addZone($obj_Zone);
            $rule2->to->addZone($obj_Zone);

            #$rule2->API_sync();
        }
        else
            mwarning( "- rule: '".$rule2_name."' already avaialble", null, false);

        PH::print_stdout("----------------");

        PH::print_stdout("===============================================================");
    }
}

if( $util->apiMode )
    $deviceGroup->securityRules->API_sync();

########################################################################################################################



PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
########################################################################################################################
