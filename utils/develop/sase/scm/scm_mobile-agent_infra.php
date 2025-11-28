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

$url_config = "/config/mobile-agent/v1/infrastructure-settings?folder=Mobile Users";

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
            [id] => xyz
            [name] => {e.g. sase-domain.gpcloudservice.com}
            [folder] => Mobile Users
            [dns_servers] => Array
                (
                    [0] => Array
                        (
                            [name] => worldwide
                            [primary_public_dns] => Array
                                (
                                    [dns_server] => {IP-addrress}
                                )

                            [secondary_public_dns] => Array
                                (
                                    [dns_server] => {IP-addrress}
                                )

                            [dns_suffix] => Array
                                (
                                    [0] => {domain.local}
                                    [1] => harding.no
                                )

                        )

                )

            [ip_pools] => Array
                (
                    [0] => Array
                        (
                            [name] => worldwide
                            [ip_pool] => Array
                                (
                                    [0] => 10.209.192.0/18
                                )

                        )

                    [1] => Array
                        (
                            [name] => emea
                            [ip_pool] => Array
                                (
                                    [0] => 10.209.0.0/18
                                )

                        )

                    [2] => Array
                        (
                            [name] => americas
                            [ip_pool] => Array
                                (
                                    [0] => 10.209.64.0/18
                                )

                        )

                    [3] => Array
                        (
                            [name] => apac
                            [ip_pool] => Array
                                (
                                    [0] => 10.209.128.0/18
                                )

                        )

                )

            [region_ipv6] => Array
                (
                    [region] => Array
                        (
                            [0] => Array
                                (
                                    [name] => americas
                                )

                            [1] => Array
                                (
                                    [name] => europe
                                )

                            [2] => Array
                                (
                                    [name] => apac
                                )

                        )

                )

            [enable_wins] => Array
                (
                    [no] => Array
                        (
                        )

                )

            [deployment] => Array
                (
                    [region] => Array
                        (
                            [0] => Array
                                (
                                    [name] => europe
                                    [locations] => Array
                                        (
                                            [0] => austria
                                            [1] => eu-central-1
                                            [2] => germany-south
                                            [3] => germany-north
                                            [4] => italy
                                            [5] => netherlands-central
                                            [6] => eu-west-2
                                            [7] => eu-west-3
                                            [8] => spain-central
                                            [9] => portugal
                                            [10] => spain-east
                                            [11] => bulgaria
                                            [12] => czech-republic
                                            [13] => slovakia
                                            [14] => croatia
                                            [15] => slovenia
                                            [16] => hungary
                                            [17] => romania
                                            [18] => poland
                                            [19] => denmark
                                            [20] => norway
                                            [21] => finland
                                            [22] => eu-west-1
                                            [23] => sweden
                                            [24] => uae
                                            [25] => qatar
                                        )

                                )

                            [1] => Array
                                (
                                    [name] => americas
                                    [locations] => Array
                                        (
                                            [0] => ca-central-1
                                            [1] => canada-central
                                            [2] => us-northeast
                                            [3] => us-east-1
                                            [4] => us-southeast
                                            [5] => us-south
                                            [6] => us-east-2
                                            [7] => us-west-3
                                            [8] => us-west-201
                                            [9] => us-west-1
                                            [10] => us-west-2
                                            [11] => canada-west
                                            [12] => brazil-east
                                            [13] => brazil-central
                                            [14] => argentina
                                            [15] => sa-east-1
                                        )

                                )

                            [2] => Array
                                (
                                    [name] => apac
                                    [locations] => Array
                                        (
                                            [0] => ap-southeast-1
                                            [1] => india-south
                                            [2] => vietnam
                                            [3] => hong-kong
                                        )

                                )

                        )

                )

            [portal_hostname] => Array
                (
                    [custom_domain] => Array
                        (
                            [ssl_tls_service_profile] => muCustomDomainSSLProfile
                            [hostname] => {hostname eg. sase.domain.com}
                            [cname] => {e.g. sase-domain}
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
