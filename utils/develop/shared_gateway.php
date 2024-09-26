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

PH::print_stdout( "migrate Shared-Gateways to vsys");

//Todo: new vsysID can not be on a higher ID as supported on HW/virtuell device
$vsys_number = 8;
foreach( $pan->getSharedGateways() as $key => $sharedGateway)
{
    $vsys_number++;

    PH::print_stdout(" - Shared-Gateway NAME: ".$sharedGateway->name());

    PH::print_stdout( " - create vsys: ".$vsys_number);
    $vsys = $pan->createVirtualSystem($vsys_number);

    $clone = $sharedGateway->xmlroot->cloneNode(true);

    $name = DH::findAttribute('name', $clone);
    $clone->setAttribute("name", "vsys".$vsys_number);


    DH::clearDomNodeChilds($vsys->xmlroot);


    PH::print_stdout( " - clone Shared-Gateways config into VSYS: 'vsys".$vsys_number."'");
    DH::copyChildElementsToNewParentNode($clone, $vsys->xmlroot);
    $vsys->load_from_domxml($vsys->xmlroot);

    PH::print_stdout( " - delete Shared-Gateway: ".$sharedGateway->name());
    $pan->removeSharedGateway( $sharedGateway );



    ############################
    #$new_vsys = $pan->findVirtualSystem("vsys".$vsys_number);

    PH::print_stdout();
    PH::print_stdout("--------------------");
    PH::print_stdout( " - create missing SecurityRules in 'vsys".$vsys_number."'");
    $zones = $vsys->zoneStore->getAll();
    foreach( $zones as $zone1 )
    {
        foreach( $zones as $zone2 )
        {
            if( $zone1->name() == $zone2->name() )
                continue;

            #if( $zone1->name() == "Internet" || $zone2->name() == "Internet" )
            #{
                $rule_name = $zone1->name()."-".$zone2->name();
                PH::print_stdout("  - create new Rule: ".$rule_name);
                $tmp_rule = $vsys->securityRules->newSecurityRule( $rule_name );

                $tmp_rule->to->addZone($zone1);
                $tmp_rule->from->addZone($zone2);
            #}
        }
    }
    PH::print_stdout();
    ############################
    //find all zones in complete config file, of type external where member is shared-gateway name
    //- replace this shared-gateway name with new vsys name

    foreach( $pan->getVirtualSystems() as $key => $virtualSystem)
    {
        /** @var VirtualSystem $virtualSystem */

        $zones = $virtualSystem->zoneStore->getAll();
        foreach( $zones as $zone1 )
        {
            $externalVsys = $zone1->getExternalVsys();
            if ( $externalVsys !== null && $externalVsys == $sharedGateway->name() )
            {
                PH::print_stdout("--------------------");
                PH::print_stdout( " - for zone: ".$zone1->name()." - owner: ".$zone1->owner->owner->name()." set new external vsys: '".$vsys->name()."'");
                $zone1->setExternalVsys($vsys);

                PH::print_stdout( " - for VSYS: ".$virtualSystem->name()." set new visible vsys: '".$vsys->name()."'");
                $virtualSystem->setVisibleVsys($vsys->name());
                PH::print_stdout( " - for VSYS: ".$vsys->name()." set new visible vsys: '".$virtualSystem->name()."'");
                $vsys->setVisibleVsys($virtualSystem->name());
            }
        }
    }

    PH::print_stdout();

    ############################

    $vsys_number++;
}


$util->save_our_work();
PH::print_stdout();
PH::print_stdout( "************* END OF SCRIPT ".basename(__FILE__)." ************" );
PH::print_stdout();

