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
$supportedArguments['actions'] = array('niceName' => 'Actions', 'shortHelp' => 'displaying or creating Cisco ACI EPG information. ie: actions=display / actions=create / actions=decommission', 'argDesc' => 'action:arg1[,arg2]');
$supportedArguments['location'] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1 or location={DGname}:excludeMaindg [only childDGs of {DGname}] or location={DGname}:includechilddgs [{DGname} + all childDGs]', 'argDesc' => 'sub1[,sub2]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');

$supportedArguments['epg-filter'] = array('niceName' => 'EPG-Filter', 'shortHelp' => 'filter Cisco ACI Fabric available EPG', 'argDesc' => '[NAME]');
$supportedArguments['zone-from-to'] = array('niceName' => 'Zone-From-To', 'shortHelp' => 'zone Name to be used as From and To for newly create Cisco ACI EPG rules', 'argDesc' => '[ZONENAME]');

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
/** @var PanAPIConnector $connector */
$connector = $pan->connector;


########################################################################################################################
########################################################################################################################

function ruleNameFunction( $addrGroup1, $addrGroup2, $key1, $key2)
{
    //rule name max 64 characters
    $name = $addrGroup1->name() ." to ".$addrGroup2->name();
    $name = "EPG-".$key1."_to_".$key2;

    return $name;
}

########################################################################################################################

//validate if Panorama API mode is used
if( !$util->apiMode )
    derr( "Panorama API Mode is needed", null, false );


########################################################################################################################
/*
//download plugin
//&type=op
//&cmd=<request><plugins><download><file>cisco-3.0.1</file></download></plugins></request>
$cmd = "<request><plugins><download><file>cisco-3.0.1</file></download></plugins></request>";
$params['type'] = 'op';
$params['cmd'] = &$cmd;

$response = $connector->sendRequest($params);
$cursor = DH::findXPathSingleEntryOrDie('/response', $response);
DH::DEBUGprintDOMDocument($cursor);

$jobID = $connector->getJobID($response);
$response = $connector->waitForJobFinished($jobID);
$cursor = DH::findXPathSingleEntryOrDie('/response', $response);
DH::DEBUGprintDOMDocument($cursor);


//install plugin
$cmd = "<request><plugins><install>cisco-3.0.1</install></plugins></request>";
$params['type'] = 'op';
$params['cmd'] = &$cmd;

$response = $connector->sendRequest($params);
$jobID = $connector->getJobID($response);
$response = $connector->waitForJobFinished($jobID);
$cursor = DH::findXPathSingleEntryOrDie('/response', $response);
DH::DEBUGprintDOMDocument($cursor);
*/

/*
set plugins cisco notify-group ACIlab device-group CiscoACI
set plugins cisco aci-fabric test-Adrian APIC-IP 10.100.99.14
set plugins cisco aci-fabric test-Adrian client-username apic#fallback\\Demo-Tenant-CP-User
set plugins cisco aci-fabric test-Adrian password -AQ==h3hVZ4BHp5leeCQ2DDRvapXsj+Y=mXDyIbM7/lLBMzMXDI4qJQ==
set plugins cisco monitoring-definition test-adrian aci-fabric test-Adrian
set plugins cisco monitoring-definition test-adrian notify-group ACIlab
*/

exit();
########################################################################################################################
//validate if Cisco ACI plugin is installed

$cmd = "<show><plugins><cisco><status></status></cisco></plugins></show>";
$params['type'] = 'op';
$params['cmd'] = &$cmd;

#$response = $connector->sendRequest($params);
$response = $connector->sendJobRequest($params);
$cursor = DH::findXPathSingleEntryOrDie('/response/result', $response);

PH::print_stdout();
PH::print_stdout("########################################################");
if( !DH::hasChild($cursor) )
    derr( "Panorama Cisco ACI Plugin not installed", null, false );
else
{
    PH::print_stdout("CISCO ACI-fabric - actual status:");
    $cursor = DH::findFirstElement( "result", $cursor);
    DH::DEBUGprintDOMDocument($cursor);
}


//if result/result/pass -> available
//if empty -> not installed


########################################################################################################################
//display plugin configuration
PH::print_stdout();
PH::print_stdout("########################################################");
$xpath = "/config/devices/entry[@name='localhost.localdomain']/plugins/cisco";
$xpathResult = DH::findXPath( $xpath, $util->xmlDoc);
PH::print_stdout("CISCO ACI-fabric - available configuration:");
DH::DEBUGprintDOMDocument($xpathResult[0]);

$notify = DH::findFirstElement("notify-group", $xpathResult[0]);
$entry = DH::findFirstElement("entry", $notify);
$devicegroup = DH::findFirstElement("device-group", $entry);
$member = DH::findFirstElement("member", $devicegroup);
PH::print_stdout("---------------");
PH::print_stdout("'location=".$member->textContent."'");
PH::print_stdout("---------------");
PH::print_stdout("########################################################");

########################################################################################################################
########################################################################################################################

if( !isset(PH::$args['actions']) || strtolower(PH::$args['actions']) == 'display' )
    $actions = 'display';
elseif( strtolower(PH::$args['actions']) == 'create' )
    $actions = 'create';
elseif( strtolower(PH::$args['actions']) == 'decommission' )
    $actions = 'decommission';
else
    derr( "argument: 'actions=".strtolower(PH::$args['actions'])."' - is not supported. supported actions=display/create/decommission", null, false );

if( isset(PH::$args['epg-filter']) )
    $ciscoFilter = PH::$args['epg-filter'];
else
    $ciscoFilter = "";

if( isset(PH::$args['zone-from-to']) )
    $zoneName = PH::$args['zone-from-to'];

//////////////////////////////
if( !isset(PH::$args['location']) )
    derr( "argument: 'location=".$member->textContent."' - not set; please check above which DeviceGroup is configured in notify group", null, false);

$vsys = $util->objectsLocation[0];
if( $vsys == "" )
    derr( "no argument 'location=' provided. This is needed to filter specific DeviceGroup information.", null, false);

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


    PH::print_stdout();
    PH::print_stdout("########################################################");
    PH::print_stdout( "all available EPG :" );
    print_r($epg_Array);

    PH::print_stdout();
    PH::print_stdout("########################################################");
    PH::print_stdout( "suggested EPG-Filter :" );
    print_r($headerArray);
    PH::print_stdout("---------------");
    PH::print_stdout("'epg-filter='");
    PH::print_stdout("---------------");

    if( isset(PH::$args['epg-filter']) )
    {
        PH::print_stdout();
        PH::print_stdout("########################################################");
        PH::print_stdout( "filtered by : '".$ciscoFilter."'");
        print_r($filterArray);
    }


    PH::print_stdout();
    PH::print_stdout("########################################################");
}

if( $actions == "create" or $actions == "decommission" )
{
    $addressGroupObjects = array();
    $ruleArray = array();
    foreach( $filterArray as $filtervalue )
    {
        $pos = strpos( $filtervalue, $ciscoFilter );
        $name = substr( $filtervalue, $pos+strlen($ciscoFilter)+1 );

        $dynAddrGroup = $DG->addressStore->find($name);
        if( $actions == "create" )
        {
            PH::print_stdout( "- create dynamic address group with name: '".PH::boldText($name)."' and filter: '".$filtervalue."'" );
            if( $dynAddrGroup == null )
            {
                $dynAddrGroup = $DG->addressStore->newAddressGroupDynamic( $name );
                $dynAddrGroup->addFilter($filtervalue);

                $dynAddrGroup->API_sync();
            }
            else
                mwarning( "- address object with name: ".$name." is already available", null, false );
        }

        $addressGroupObjects[] = $dynAddrGroup;
    }


    if( isset(PH::$args['zone-from-to']) )
        $zoneObject = $DG->zoneStore->findOrCreate($zoneName);
    else
        derr( "no argument: 'zone-from-to=[ZONENAME]' - found. Rules can not create", null, false );


    PH::print_stdout();
    PH::print_stdout("########################################################");
    $tmp_ObjectArray = $addressGroupObjects;
    $counter = 0;
    foreach( $addressGroupObjects as $key => $addressGroup )
    {
        $secondTMPArray = $tmp_ObjectArray;
        unset( $secondTMPArray[$key] );
        foreach( $secondTMPArray as $key2 => $secondAddressGroup )
        {
            $name = ruleNameFunction($addressGroup, $secondAddressGroup, $key, $key2);

            if( $actions == "create" )
            {
                PH::print_stdout("- create Rule: '" . PH::boldText($name)."'" );
            }


            $rule = $DG->securityRules->find($name);
            if( $actions == "create" )
            {
                if ($rule == null )
                {
                    /** @var SecurityRule $rule */
                    $rule = $DG->securityRules->newSecurityRule($name);

                    if (isset(PH::$args['zone-from-to']))
                        $rule->from->addZone($zoneObject);
                    $rule->source->addObject($addressGroup);

                    if (isset(PH::$args['zone-from-to']))
                        $rule->to->addZone($zoneObject);
                    $rule->destination->addObject($secondAddressGroup);

                    $rule->API_sync();
                    $counter++;
                }
                else
                {
                    mwarning("- Rulename: " . $name . " is already available", null, false);
                    if (!$rule->from->hasZone($zoneObject))
                        PH::print_stdout("from zone object: " . $zoneObject->name() . " not set");

                    if (!$rule->source->has($addressGroup))
                        PH::print_stdout("source object: " . $addressGroup->name() . " not set");

                    if (!$rule->to->hasZone($zoneObject))
                        PH::print_stdout("to zone object: " . $zoneObject->name() . " not set");

                    if (!$rule->destination->has($secondAddressGroup))
                        PH::print_stdout("destination object: " . $addressGroup->name() . " not set");
                }
            }

            $ruleArray[] = $rule;
        }
    }
    if( $actions == "create" )
    {
        PH::print_stdout("########################################################");
        PH::print_stdout();
        PH::print_stdout($counter." Rules created");
        PH::print_stdout();
        PH::print_stdout("########################################################");
    }


    if( $actions == "decommission" )
    {
        //delete all from $ruleArray
        #$ruleArray
        PH::print_stdout();
        PH::print_stdout("########################################################");
        foreach( $ruleArray as $rule )
        {
            if( $rule != null )
            {
                PH::print_stdout( "- remove Rule: '".$rule->name()."'");
                $rule->owner->API_remove($rule);
            }

        }

        //delete all addressGroups from
        #$addressGroupObjects;
        PH::print_stdout();
        PH::print_stdout("########################################################");
        foreach( $addressGroupObjects as $dynAddrObj )
        {
            if( $dynAddrObj != null )
            {
                PH::print_stdout( "- remove dyn AddressGroup: '".$dynAddrObj->name()."'");
                $dynAddrObj->owner->API_remove($dynAddrObj);
            }
        }
    }
}



########################################################################################################################



PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
########################################################################################################################
