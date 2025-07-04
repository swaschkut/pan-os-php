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


/*
example CSV File:
"","Name","Tags","Type","Source Zone","Source Address","Source User","Source Device","Destination Zone","Destination Address","Destination Device","Application","Service","Action","Profile","Options","Rule Usage Hit Count","Rule Usage Last Hit","Rule Usage First Hit","Rule Usage Apps Seen","Days With No New Apps","Modified","Created"
"1","test","none","universal","any","1.2.3.4","any","any","any","5.6.7.8","any","any","tcp_443","Allow","Profile Group: Alert-Only","Traffic log sent at session end;Log Forwarding Profile setting: default-1","0","-","-","-","-","0","0"
"2","intrazone-default","none","intrazone","any","any","any","any","(intrazone)","any","any","any","any","Allow","Profile Group: Alert-Only","Traffic log sent at session end;Log Forwarding Profile setting: default-1","0","-","-","-","-","-","-"
"3","interzone-default","none","interzone","any","any","any","any","any","any","any","any","any","Deny","none","Traffic log sent at session end;Log Forwarding Profile setting: default-1","0","-","-","-","-","-","-"
 */
//Todo:
//until now only working for importing Security Rule
//define CSV info to correctly import
set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../utils/lib/UTIL.php";

$createObjects = FALSE;

$actions = null;

$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['actions'] = array('niceName' => 'Actions', 'shortHelp' => 'displaying or importing CSV info. ie: actions=display / actions=import', 'argDesc' => 'action:arg1[,arg2]');
$supportedArguments['csv'] = array('niceName' => 'CSV', 'shortHelp' => 'CSV file with HEADER');
$supportedArguments['location'] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');

$usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=api:://[MGMT-IP] [cycleconnectedFirewalls] [actions=display]";

PH::print_stdout();
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout();

$util = new UTIL("custom", $argv, $argc,__FILE__, $supportedArguments, $usageMsg);
$util->utilInit();

##########################################
##########################################


if( !isset(PH::$args['actions']) || strtolower(PH::$args['actions']) == 'display' )
    $actions = 'display';
elseif( strtolower(PH::$args['actions']) == 'import' )
    $actions = 'import';


if( isset(PH::$args['csv']) )
    $csvfile = PH::$args['csv'];
else
    derr("argument csv not set");


##########################################


$util->load_config();
$util->location_filter();

$pan = $util->pan;

if( $actions == "import" )
{
    $errormsg = "";


    $stringarray = CsvParser::parseFile($csvfile, $errormsg);

    if( $stringarray !== FALSE )
    {

        foreach( $stringarray as $rule )
        {
            #print_r($rule);
            #print_r( array_keys( $rule ) );

            if( $util->configType == "panorama" )
            {
                if( isset($rule['Name']) )
                {
                    //Todo is it not better to define the DG location via script start as argument?
                    //$util->objectsLocation
                    #$rule_location = $pan->findDeviceGroup( $rule['Location']);

                    $rule_location = $pan->findDeviceGroup($util->objectsLocation[0]);
                    if( $rule_location === null )
                    {
                        $rule_location = $pan->createDeviceGroup($util->objectsLocation[0]);
                        #derr("DG: ".$rule['Location']." was not found ? Exit\n");
                    }
                }
                else
                    derr("this script expect in CSV HEADER a field called 'Location' to get the Panorama DG Name from");
            }
            else
            {
                $rule_location = $pan->findVirtualSystem($util->objectsLocation[0]);
                if( $rule_location === null )
                {
                    derr($util->objectsLocation[0] . " vsys1 was not found ? Exit\n");
                }
            }

            $secrule = null;

            if( isset($rule['Name']) )
            {
                $rulename = $rule['Name'];

                if( $rulename == "intrazone-default" || $rulename == "interzone-default" )
                {
                    mwarning("SecurityRule: " . $rulename . " is a reserved name, skip adding ", null, FALSE);
                    continue;
                }

                $secrule = $rule_location->securityRules->find($rulename);
                if( $secrule != null )
                {
                    mwarning("SecurityRule: " . $rulename . " is already available, skip adding ", null, FALSE);
                    continue;
                }

                $secrule = $rule_location->securityRules->newSecurityRule($rulename);
                PH::print_stdout( "");
                PH::print_stdout(  " * create SecurityRule: " . $rulename );

            }

            else
                derr("this script expect in CSV HEADER a field called 'Name' to get the Rulename from");


            if( $secrule !== null )
            {
                if( isset($rule['Tags']) )
                {
                    $name = $rule['Tags'];
                    $name_array = explode(";", $name);
                    foreach( $name_array as $name )
                    {
                        if( $name != "" )
                        {
                            $tmp_tag = $rule_location->tagStore->find($name);
                            if( $tmp_tag == null )
                            {
                                if( $createObjects )
                                {
                                    $tmp_tag = $rule_location->tagStore->findorCreate($name);
                                    if( $util->configInput['type'] == 'api' )
                                        $tmp_tag->API_sync();
                                }
                                mwarning("TAG: '" . $name . "' not found", null, FALSE);
                            }

                            if( $tmp_tag != null )
                            {
                                PH::print_stdout(  "  - add Tag: " . $name );
                                $secrule->tags->addTag($tmp_tag);
                            }
                        }
                    }
                }


                //[Type] => universal
                if( isset($rule['Type']) )
                {
                    if( $rule['Type'] == "universal" )
                    {
                        //do nothing
                    }
                    else
                        $secrule->setType($rule['Type']);
                }


                //[Source Zone] => any
                if( isset($rule['Source Zone']) )
                {
                    $name = $rule['Source Zone'];
                    $name_array = explode(";", $name);
                    foreach( $name_array as $name )
                    {
                        if( $name == "any" )
                        {
                            PH::print_stdout(  "   - from Zone set ANY" );
                            $secrule->from->setAny();
                        }
                        else
                        {
                            $tmp_from_zone = $rule_location->zoneStore->find($name);
                            if( $tmp_from_zone == null )
                            {
                                if( $createObjects )
                                {
                                    if( $util->configType == 'panos' )
                                    {
                                        $tmp_from_zone = $rule_location->zoneStore->newZone($name, "layer3");
                                        if( $util->configInput['type'] == 'api' )
                                            $tmp_from_zone->API_sync();
                                    }
                                    else
                                        $tmp_from_zone = $rule_location->zoneStore->findorCreate($name);
                                }
                                mwarning("Zone: " . $name . " not found", null, FALSE);
                            }

                            if( $tmp_from_zone != null )
                            {
                                PH::print_stdout(  "   - add from Zone: " . $name );
                                $secrule->from->addZone($tmp_from_zone);
                            }
                        }
                    }
                }

                //[Source Address] => old-12.45.123.149
                if( isset($rule['Source Address']) )
                {
                    $name = $rule['Source Address'];
                    $name_array = explode(";", $name);
                    foreach( $name_array as $name )
                    {
                        if( $name == "any" )
                        {
                            PH::print_stdout(  "   - source set ANY" );
                            $secrule->source->setAny();
                        }
                        else
                        {
                            $tmp_address = $rule_location->addressStore->find($name);

                            if( $tmp_address == null )
                            {
                                if( $createObjects )
                                {
                                    $tmp_address = $rule_location->addressStore->newAddress($name, "ip-netmask", "1.1.1.1/32");
                                    if( $util->configInput['type'] == 'api' )
                                        $tmp_address->API_sync();
                                }
                                mwarning("address object: " . $name . " not found", null, FALSE);
                            }

                            if( $tmp_address != null )
                            {
                                PH::print_stdout(  "   - source add: " . $name );
                                $secrule->source->addObject($tmp_address);
                            }
                        }
                    }
                }


                //[Destination Zone] => any
                if( isset($rule['Destination Zone']) )
                {
                    $name = $rule['Destination Zone'];
                    $name_array = explode(";", $name);
                    foreach( $name_array as $name )
                    {
                        if( $name == "any" )
                        {
                            PH::print_stdout(  "   - to Zone set ANY" );
                            $secrule->to->setAny();
                        }
                        else
                        {
                            $tmp_to_zone = $rule_location->zoneStore->find($name);
                            if( $tmp_to_zone == null )
                            {
                                if( $createObjects )
                                {
                                    if( $util->configType == 'panos' )
                                    {
                                        $tmp_to_zone = $rule_location->zoneStore->newZone($name, "layer3");
                                        if( $util->configInput['type'] == 'api' )
                                            $tmp_to_zone->API_sync();
                                    }
                                    else
                                        $tmp_from_zone = $rule_location->zoneStore->findorCreate($name);
                                }
                                mwarning("Zone: " . $name . " not found", null, FALSE);
                            }
                            if( $tmp_to_zone != null )
                            {
                                PH::print_stdout(  "   - add to Zone: " . $name );
                                $secrule->to->addZone($tmp_to_zone);
                            }
                        }
                    }
                }

                //[Destination Address] => gcp-10.54.25.57
                if( isset($rule['Destination Address']) )
                {
                    $name = $rule['Destination Address'];

                    $name_array = explode(";", $name);
                    foreach( $name_array as $name )
                    {
                        if( $name == "any" )
                        {
                            PH::print_stdout(  "   - destination set ANY" );
                            $secrule->destination->setAny();
                        }
                        else
                        {
                            $tmp_address = $rule_location->addressStore->find($name);

                            if( $tmp_address == null )
                            {
                                if( $createObjects )
                                {
                                    $tmp_address = $rule_location->addressStore->newAddress($name, "ip-netmask", "1.1.1.1/32");
                                    if( $util->configInput['type'] == 'api' )
                                        $tmp_address->API_sync();
                                }
                                mwarning("address object: " . $name . " not found", null, FALSE);
                            }
                            if( $tmp_address != null )
                            {
                                PH::print_stdout(  "   - destination add: " . $name );
                                $secrule->destination->addObject($tmp_address);
                            }
                        }
                    }

                }

                //[Application] => any
                //[Service] => application-default
                if( isset($rule['Service']) )
                {
                    $name = $rule['Service'];
                    $name_array = explode(";", $name);
                    foreach( $name_array as $name )
                    {
                        if( $name != "any" && $name != "application-default" )
                        {
                            $tmp_service = $rule_location->serviceStore->find($name);

                            if( $tmp_service == null )
                            {
                                mwarning("service object: " . $name . " not found", null, FALSE);
                            }
                            else
                            {
                                PH::print_stdout(  "   - service add: " . $name );
                                $secrule->services->add($tmp_service);
                            }
                        }
                        elseif( $name == "any" )
                        {
                            PH::print_stdout(  "   - service set any" );
                            $secrule->services->setAny();
                        }

                        elseif( $name == "application-default" )
                        {
                            PH::print_stdout(  "   - service set application-default" );
                            $secrule->services->setApplicationDefault();
                        }

                    }
                }

                if( isset($rule['Application']) )
                {
                    //application add
                    $name = $rule['Application'];
                    $name_array = explode(";", $name);
                    foreach( $name_array as $name )
                    {
                        if( $name != "any" )
                        {
                            $tmp_app = $pan->appStore->find($name);

                            if( $tmp_app == null )
                            {
                                mwarning("appID: '" . $name . "' not found\n", null, FALSE);
                            }
                            else
                            {
                                PH::print_stdout(  "   - appID add: " . $name );
                                $secrule->apps->addApp($tmp_app);
                            }
                        }
                        #elseif( $name == "any" )

                    }
                }


                //[Action] => allow

                if( isset($rule['Action']) )
                {
                    $name = $rule['Action'];
                    PH::print_stdout(  "   - add Rule action to: " . $name );
                    $secrule->setAction($name);
                }


                //[Profile] => none
                if( isset($rule['Profile']) )
                {
                    $name = $rule['Profile'];

                    if( $name != "none" )
                    {
                        PH::print_stdout(  " * add security profile group: " . $name );
                        $secrule->setSecurityProfileGroup($name);
                    }
                }

                //[Options] => Traffic log sent at session end
                if( isset($rule['Options']) )
                {
                    $name = $rule['Options'];

                    if( $name == "Traffic log sent at session end" )
                    {
                        //default
                    }
                    else
                    {
                        //Todo: implementation needed
                        mwarning("'Options' setting: " . $name . " not supported yet", null, FALSE);
                    }
                }


                //#######################################################################################
                //#######################################################################################
                //#######################################################################################
                //TODO: IMPLEMENTATION NEEDED
                //[Source User] => any
                if( isset($rule['Source User']) )
                {
                    $name = $rule['Source User'];
                    if( $name != "any" )
                    {
                        //Todo: implementation needed
                        mwarning("'Source User' - not supported yet");
                    }

                }
                //[Source HIP Profile] => any

                if( isset($rule['Source HIP Profile']) )
                {
                    $name = $rule['Source HIP Profile'];
                    if( $name != "any" )
                    {
                        //Todo: implementation needed
                        mwarning("'Source HIP Profile' - not supported yet");
                    }
                }
                //#######################################################################################
                //#######################################################################################
                //#######################################################################################


                if( $util->configInput['type'] == 'api' )
                    $secrule->API_sync();
            }
        }
    }

    else
    {
        derr($errormsg);
    }
}


##########################################
##########################################

$util->save_our_work();
$util->endOfScript();

PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();