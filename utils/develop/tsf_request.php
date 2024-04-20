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
require_once ( "utils/lib/UTIL.php");

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


$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml ".
    "php ".basename(__FILE__)." help          : more help messages\n";
##############

$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();

##########################################
##########################################

#$util->load_config();
#$util->location_filter();

$pan = $util->pan;
$connector = $pan->connector;


########################################################################################################################

/*
<request><tech-support><dump/></tech-support></request>
*/

if(  $util->pan->isPanorama() )
{
    $firewallSerials = $connector->panorama_getConnectedFirewallsSerials();

    $panoramaMGMTip = $connector->info_mgmtip;

    foreach( $firewallSerials as $fw )
    {
        $argv = array();
        $argc = array();
        PH::$args = array();
        PH::$argv = array();

        $argv[0] = "test";
        //must be fixed value from above $panoramaMGMTip, if not ->refreshSystemInfos later on is updating to FW MGMT IP
        $argv[] = "in=api://".$fw['serial']."@".$panoramaMGMTip."/merged-config";

        PH::print_stdout( "--------------------------------------------------------------------------------" );

        try
        {
            #PH::resetCliArgs( $argv );
            $util2 = new UTIL("custom", $argv, $argc, __FILE__);
            $util2->useException();
            $util2->utilInit();
            
        }
        catch(Exception $e)
        {
            PH::print_stdout("          ***** API Error occured : ".$e->getMessage() );

            $array[ $fw['serial'] ][ "error" ]['name'] = "error";
            $array[ $fw['serial'] ][ "error" ]['ip'] = "connection";

            PH::print_stdout();
            PH::print_stdout( $fw['serial'].",error,connection" );
            PH::print_stdout( "--------------------------------------------------------------------------------" );
        }
    }
}
elseif( $util->pan->isFirewall() )
{
    #$mgmt
    #ssh_connector($fw);
    $query = '<request><tech-support><dump/></tech-support></request>';
    $output = $connector->sendOpRequest($query);

    print $output->textContent;
}

########################################################################################################################






$util->save_our_work();

PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
########################################################################################################################
