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

###########
#DISPLAY
###########

//Todo: check if this is needed before:
//https://pan.dev/access/api/prisma-access-config/post-sse-config-v-1-enable/

$accessToken =  $connector->getAccessToken();
$folder = "Service Connections";

//https://pan.dev/access/api/prisma-access-config/get-sse-config-v-1-shared-infrastructure-settings/
$type = "shared-infrastructure-settings";
$jsonArray = $connector->getResource( $accessToken, $type, $folder );

print_r($jsonArray);

/*
//respones
//Todo: 20240326 check what is needed for first setup
Array
(
    [folder] => Service Connections
    [infra_bgp_as] => 65534
    [infrastructure_subnet] => 10.212.251.0/24
    [tunnel_monitor_ip_address] => 10.212.251.254
    [captive_portal_redirect_ip_address] => 10.212.251.254
    [loopback_ips] => Array
        (
            [0] => 10.212.251.3
        )

    [egress_ip_notification_url] => Array
        (
            [msg] => Array
                (
                    [@status] => success
                    [@code] => 19
                    [result] => Array
                        (
                            [total-count] => 1
                            [url] =>
                        )

                )

        )

    [api_key] => ABCDE..........
)

 */
//////////////////////////////


/////////////////////////////




########################################################################################################################



PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
########################################################################################################################
