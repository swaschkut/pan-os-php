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

//https://pan.dev/scm/api/config/sase/setup/list-folders/

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

/* @var PanSCMAPIConnector $connector */


//curl -L 'https://api.strata.paloaltonetworks.com/config/setup/v1/folders' \
//-H 'Accept: application/json' \
//-H 'Authorization: Bearer <token>'

$url_config = "/config/security/v1/url-access-profiles?folder=All";
///config/mobile-agent/v1/tunnel-profiles
//validation:
//$connector->url_api = "https://api.strata.paloaltonetworks.com";

//$limit and $offset are running into 'Access denied
$MUjsonArray = $connector->getResourceURL( $url_config);
print_r($MUjsonArray);




/*

 Array
(
    [0] => Array
        (
                     [1] => Array
                (
                    [name] => {name}
                    [folder] => Mobile Users
                    [authentication_override] => Array
                        (
                            [accept_cookie] => Array
                                (
                                    [cookie_lifetime] => Array
                                        (
                                            [lifetime_in_hours] => 24
                                        )
                                )
                            [cookie_encrypt_decrypt_cert] => Authentication Cookie Cert
                            [generate_cookie] => 1
                        )

                    [source_user] => Array
                        (
                            [0] => any
                        )

                    [os] => Array
                        (
                            [0] => any
                        )

                    [split_tunneling] => Array
                        (
                            [exclude_applications] => Array
                                (
                                    [0] => C:\Program Files\WindowsApps\*\ms-teams.exe
                                )

                            [exclude_domains] => Array
                                (
                                    [list] => Array
                                        (
                                            [0] => Array
                                                (
                                                    [name] => *.domain.xyz
                                                )
                                        )
                                )
                            [exclude_access_route] => Array
                                (
                                    [0] => {IP-range/host}
                                )
                        )
                )
        )
)
 */

########################################################################################################################



PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
########################################################################################################################
