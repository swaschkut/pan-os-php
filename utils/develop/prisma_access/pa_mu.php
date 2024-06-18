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


$accessToken =  $connector->getAccessToken();
$folder = "Mobile Users";


$type = "mobile-agent/agent-profiles";
$MUjsonArray = $connector->getResource( $accessToken, $type, $folder );
#print_r($MUjsonArray);
/*
Array
(
    [data] => Array
        (
            [0] => Array
                (
                    [name] => DEFAULT
                    [folder] => Mobile Users
                    [gateways] => Array
                        (
                            [external] => Array
                                (
                                    [list] => Array
                                        (
                                            [0] => Array
                                                (
                                                    [name] => Prisma Access
                                                    [fqdn] => gpcloudservice.com
                                                    [priority_rule] => Array
                                                        (
                                                            [0] => Array
                                                                (
                                                                    [name] => Any
                                                                    [priority] => 1
                                                                )

                                                        )

                                                    [manual] => 1
                                                )

                                        )

                                )

                        )

                    [gp_app_config] => Array
                        (
                            [config] => Array
                                (
                                    [0] => Array
                                        (
                                            [name] => connect-method
                                            [value] => Array
                                                (
                                                    [0] => user-logon
                                                )

                                        )

                                    [1] => Array
                                        (
                                            [name] => agent-user-override
                                            [value] => Array
                                                (
                                                    [0] => allowed
                                                )

                                        )

                                    [2] => Array
                                        (
                                            [name] => uninstall
                                            [value] => Array
                                                (
                                                    [0] => allowed
                                                )

                                        )

                                    [3] => Array
                                        (
                                            [name] => client-upgrade
                                            [value] => Array
                                                (
                                                    [0] => prompt
                                                )

                                        )

                                    [4] => Array
                                        (
                                            [name] => can-change-portal
                                            [value] => Array
                                                (
                                                    [0] => yes
                                                )

                                        )

                                )

                        )

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

                    [hip_collection] => Array
                        (
                            [collect_hip_data] => 1
                        )

                    [source_user] => Array
                        (
                            [0] => any
                        )

                    [os] => Array
                        (
                            [0] => any
                        )

                )

        )

    [offset] => 0
    [total] => 1
    [limit] => 200
)
 */


$type = "mobile-agent/global-settings";
$MUjsonArray = $connector->getResource( $accessToken, $type, $folder );
#print_r($MUjsonArray);
/*
Array
(
    [agent_version] => 6.2.2
    [manual_gateway] => Array
        (
        )

)

 */

$type = "mobile-agent/infrastructure-settings";
$MUjsonArray = $connector->getResource( $accessToken, $type, $folder );
#print_r($MUjsonArray);
/*
Array
(
    [0] => Array
        (
            [id] => 1d7cc28b-5e6d-41ae-8c8c-4cc890e8b7d7
            [name] => Bnt-swd.gpcloudservice.com
            [dns_servers] => Array
                (
                    [0] => Array
                        (
                            [name] => worldwide
                        )

                )

            [ip_pools] => Array
                (
                    [0] => Array
                        (
                            [name] => worldwide
                            [ip_pool] => Array
                                (
                                    [0] => 10.212.252.0/23
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

            [portal_hostname] => Array
                (
                    [default_domain] => Array
                        (
                            [hostname] => Bnt-swd
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
                                            [0] => eu-central-1
                                        )

                                )

                        )

                )

        )

)
 */

$type = "mobile-agent/locations";
$MUjsonArray = $connector->getResource( $accessToken, $type, $folder );
#print_r($MUjsonArray);
/*
Array
(
    [region] => Array
        (
            [0] => Array
                (
                    [name] => europe
                    [locations] => Array
                        (
                            [0] => eu-central-1
                        )
                )
        )
)
 */


$type = "mobile-agent/tunnel-profiles";
$MUjsonArray = $connector->getResource( $accessToken, $type, $folder );

#print_r($MUjsonArray);
/*
Array
(
    [data] => Array
        (
            [0] => Array
                (
                    [name] => DEFAULT
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

                )

        )

    [offset] => 0
    [total] => 1
    [limit] => 200
)

 */

$type = "locations";
$MUjsonArray = $connector->getResource( $accessToken, $type, $folder );

#print_r($MUjsonArray);
/*
Array
(
    [0] => Array
        (
            [value] => canada-central
            [display] => Canada Central
            [continent] => North America
            [latitude] => 43.6487
            [longitude] => -79.38545
            [region] => northamerica-northeast2
            [aggregate_region] => canada-central-toronto
        )

    [1] => Array
        (
            [value] => ca-central-1
            [display] => Canada East
            [continent] => North America
            [latitude] => 46.81274
            [longitude] => -71.21931
            [region] => ca-central-1
            [aggregate_region] => canada-central
        )

    [2] => Array
        (
            [value] => canada-west
            [display] => Canada West
            [continent] => North America
            [latitude] => 49.26039
            [longitude] => -123.11336
            [region] => us-west1
            [aggregate_region] => us-northwest
        )

    [3] => Array
        (
            [value] => costa-rica
            [display] => Costa Rica
            [continent] => North America
            [latitude] => 9.9281
            [longitude] => -84.0907
            [region] => us-east1
            [aggregate_region] => us-southeast
        )

    [4] => Array
        (
            [value] => guatemala
            [display] => Guatemala
            [continent] => North America
            [latitude] => 14.628434
            [longitude] => -90.522713
            [region] => us-east4
            [aggregate_region] => us-east
        )

    [5] => Array
        (
            [value] => mexico-central
            [display] => Mexico Central
            [continent] => North America
            [latitude] => 19.43195
            [longitude] => -99.13315
            [region] => us-south1
            [aggregate_region] => us-south
        )

    [6] => Array
        (
            [value] => mexico-west
            [display] => Mexico West
            [continent] => North America
            [latitude] => 20.68758
            [longitude] => -103.35104
            [region] => us-south1
            [aggregate_region] => us-south
        )

    [7] => Array
        (
            [value] => panama
            [display] => Panama
            [continent] => North America
            [latitude] => 8.95242
            [longitude] => -79.53538
            [region] => us-east1
            [aggregate_region] => us-southeast
        )

    [8] => Array
        (
            [value] => us-east-2
            [display] => US Central
            [continent] => North America
            [latitude] => 39.7392
            [longitude] => -104.9903
            [region] => us-east-2
            [aggregate_region] => us-central
        )

    [9] => Array
        (
            [value] => us-west-3
            [display] => US Central West
            [continent] => North America
            [latitude] => 40.76078
            [longitude] => -111.89105
            [region] => us-west3
            [aggregate_region] => us-central-west
        )

    [10] => Array
        (
            [value] => us-east-1
            [display] => US East
            [continent] => North America
            [latitude] => 37.45244
            [longitude] => -76.41686
            [region] => us-east-1
            [aggregate_region] => us-east
        )

    [11] => Array
        (
            [value] => us-northeast
            [display] => US Northeast
            [continent] => North America
            [latitude] => 40.71455
            [longitude] => -74.00714
            [region] => us-east4
            [aggregate_region] => us-east
        )

    [12] => Array
        (
            [value] => us-west-2
            [display] => US Northwest
            [continent] => North America
            [latitude] => 43.8041
            [longitude] => -120.5542
            [region] => us-west-2
            [aggregate_region] => us-northwest
        )

    [13] => Array
        (
            [value] => us-south
            [display] => US South
            [continent] => North America
            [latitude] => 29.76059
            [longitude] => -95.36968
            [region] => us-south1
            [aggregate_region] => us-south
        )

    [14] => Array
        (
            [value] => us-southeast
            [display] => US Southeast
            [continent] => North America
            [latitude] => 33.74832
            [longitude] => -84.39111
            [region] => us-east1
            [aggregate_region] => us-southeast
        )

    [15] => Array
        (
            [value] => us-west-201
            [display] => US Southwest
            [continent] => North America
            [latitude] => 34.0522
            [longitude] => -118.2437
            [region] => us-west2
            [aggregate_region] => us-southwest
        )

    [16] => Array
        (
            [value] => us-west-1
            [display] => US West
            [continent] => North America
            [latitude] => 37.7749
            [longitude] => -122.4194
            [region] => us-west-1
            [aggregate_region] => us-southwest
        )

    [17] => Array
        (
            [value] => us-east-1-chicago
            [display] => US-Central (Chicago)**
            [continent] => North America
            [latitude] => 41.8781
            [longitude] => -87.6298
            [region] => us-east-1
            [aggregate_region] => us-east-chicago
        )

    [18] => Array
        (
            [value] => us-east-1-miami
            [display] => US-Southeast (Miami)**
            [continent] => North America
            [latitude] => 25.7617
            [longitude] => -80.1918
            [region] => us-east-1
            [aggregate_region] => us-east-miami
        )

    [19] => Array
        (
            [value] => argentina
            [display] => Argentina
            [continent] => South America
            [latitude] => -34.6085
            [longitude] => -58.37344
            [region] => southamerica-west1
            [aggregate_region] => south-america-west
        )

    [20] => Array
        (
            [value] => bolivia
            [display] => Bolivia
            [continent] => South America
            [latitude] => -17.78368
            [longitude] => -63.18041
            [region] => southamerica-west1
            [aggregate_region] => south-america-west
        )

    [21] => Array
        (
            [value] => brazil-central
            [display] => Brazil Central
            [continent] => South America
            [latitude] => -12.8534
            [longitude] => -50.42
            [region] => southamerica-east1
            [aggregate_region] => south-america-east
        )

    [22] => Array
        (
            [value] => brazil-east
            [display] => Brazil East
            [continent] => South America
            [latitude] => -14.2725
            [longitude] => -40.0598
            [region] => southamerica-east1
            [aggregate_region] => south-america-east
        )

    [23] => Array
        (
            [value] => sa-east-1
            [display] => Brazil South
            [continent] => South America
            [latitude] => -25.2335
            [longitude] => -51.4825
            [region] => sa-east-1
            [aggregate_region] => south-america-east
        )

    [24] => Array
        (
            [value] => chile
            [display] => Chile
            [continent] => South America
            [latitude] => -33.43722
            [longitude] => -70.65002
            [region] => southamerica-west1
            [aggregate_region] => south-america-west
        )

    [25] => Array
        (
            [value] => columbia
            [display] => Colombia
            [continent] => South America
            [latitude] => 4.61496
            [longitude] => -74.06941
            [region] => us-east1
            [aggregate_region] => us-southeast
        )

    [26] => Array
        (
            [value] => ecuador
            [display] => Ecuador
            [continent] => South America
            [latitude] => -2.1596
            [longitude] => -79.9283
            [region] => us-east1
            [aggregate_region] => us-southeast
        )

    [27] => Array
        (
            [value] => paraguay
            [display] => Paraguay
            [continent] => South America
            [latitude] => -25.29738
            [longitude] => -57.62775
            [region] => southamerica-east1
            [aggregate_region] => south-america-east
        )

    [28] => Array
        (
            [value] => peru
            [display] => Peru
            [continent] => South America
            [latitude] => -12.05613
            [longitude] => -77.0268
            [region] => southamerica-west1
            [aggregate_region] => south-america-west
        )

    [29] => Array
        (
            [value] => us-east-1-lima
            [display] => South America West (Lima)**
            [continent] => South America
            [latitude] => -10.05613
            [longitude] => -75.0268
            [region] => us-east-1
            [aggregate_region] => us-east-lima
        )

    [30] => Array
        (
            [value] => uruguay
            [display] => Uruguay
            [continent] => South America
            [latitude] => -34.901113
            [longitude] => -56.164531
            [region] => southamerica-west1
            [aggregate_region] => south-america-west
        )

    [31] => Array
        (
            [value] => venezuela
            [display] => Venezuela
            [continent] => South America
            [latitude] => 10.50556
            [longitude] => -66.91771
            [region] => southamerica-east1
            [aggregate_region] => south-america-east
        )

    [32] => Array
        (
            [value] => andorra
            [display] => Andorra
            [continent] => Europe
            [latitude] => 42.7903
            [longitude] => 1.2708
            [region] => europe-southwest1
            [aggregate_region] => europe-southwest
        )

    [33] => Array
        (
            [value] => austria
            [display] => Austria
            [continent] => Europe
            [latitude] => 48.20263
            [longitude] => 14.36843
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [34] => Array
        (
            [value] => belarus
            [display] => Belarus
            [continent] => Europe
            [latitude] => 53.90376
            [longitude] => 27.56544
            [region] => europe-north1
            [aggregate_region] => europe-north
        )

    [35] => Array
        (
            [value] => belgium
            [display] => Belgium
            [continent] => Europe
            [latitude] => 50.84439
            [longitude] => 4.35609
            [region] => europe-west1
            [aggregate_region] => belgium
        )

    [36] => Array
        (
            [value] => bulgaria
            [display] => Bulgaria
            [continent] => Europe
            [latitude] => 42.69719
            [longitude] => 23.32431
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [37] => Array
        (
            [value] => croatia
            [display] => Croatia
            [continent] => Europe
            [latitude] => 45.80724
            [longitude] => 15.96757
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [38] => Array
        (
            [value] => czech-republic
            [display] => Czech Republic
            [continent] => Europe
            [latitude] => 50.07913
            [longitude] => 14.43303
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [39] => Array
        (
            [value] => denmark
            [display] => Denmark
            [continent] => Europe
            [latitude] => 55.67567
            [longitude] => 12.56756
            [region] => europe-west4
            [aggregate_region] => europe-west
        )

    [40] => Array
        (
            [value] => finland
            [display] => Finland
            [continent] => Europe
            [latitude] => 60.7137
            [longitude] => 23.6057
            [region] => europe-north1
            [aggregate_region] => europe-north
        )

    [41] => Array
        (
            [value] => eu-west-3
            [display] => France North
            [continent] => Europe
            [latitude] => 48.85718
            [longitude] => 2.34141
            [region] => eu-west-3
            [aggregate_region] => france-north
        )

    [42] => Array
        (
            [value] => france-south
            [display] => France South
            [continent] => Europe
            [latitude] => 43.29337
            [longitude] => 5.0131
            [region] => europe-west9
            [aggregate_region] => europe-northwest-paris
        )

    [43] => Array
        (
            [value] => eu-central-1
            [display] => Germany Central
            [continent] => Europe
            [latitude] => 50.11208
            [longitude] => 8.68342
            [region] => eu-central-1
            [aggregate_region] => europe-central
        )

    [44] => Array
        (
            [value] => germany-north
            [display] => Germany North
            [continent] => Europe
            [latitude] => 53.55375
            [longitude] => 9.99183
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [45] => Array
        (
            [value] => germany-south
            [display] => Germany South
            [continent] => Europe
            [latitude] => 48.13642
            [longitude] => 11.57755
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [46] => Array
        (
            [value] => ghana
            [display] => Ghana
            [continent] => Europe
            [latitude] => 5.614818
            [longitude] => -0.205874
            [region] => europe-west2
            [aggregate_region] => europe-northwest
        )

    [47] => Array
        (
            [value] => greece
            [display] => Greece
            [continent] => Europe
            [latitude] => 37.7704
            [longitude] => 22.1101
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [48] => Array
        (
            [value] => hungary
            [display] => Hungary
            [continent] => Europe
            [latitude] => 47.49973
            [longitude] => 19.05508
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [49] => Array
        (
            [value] => eu-west-1
            [display] => Ireland
            [continent] => Europe
            [latitude] => 53.1424
            [longitude] => -7.6921
            [region] => eu-west-1
            [aggregate_region] => ireland
        )

    [50] => Array
        (
            [value] => italy
            [display] => Italy
            [continent] => Europe
            [latitude] => 45.46796
            [longitude] => 9.18178
            [region] => europe-west8
            [aggregate_region] => europe-south
        )

    [51] => Array
        (
            [value] => latvia
            [display] => Latvia
            [continent] => Europe
            [latitude] => 56.946285
            [longitude] => 24.105078
            [region] => europe-west1
            [aggregate_region] => belgium
        )

    [52] => Array
        (
            [value] => liechtenstein
            [display] => Liechtenstein
            [continent] => Europe
            [latitude] => 47.16785
            [longitude] => 9.51115
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [53] => Array
        (
            [value] => lithuania
            [display] => Lithuania
            [continent] => Europe
            [latitude] => 54.69063
            [longitude] => 25.26981
            [region] => europe-north1
            [aggregate_region] => europe-north
        )

    [54] => Array
        (
            [value] => luxembourg
            [display] => Luxembourg
            [continent] => Europe
            [latitude] => 49.6096
            [longitude] => 6.12969
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [55] => Array
        (
            [value] => moldova
            [display] => Moldova
            [continent] => Europe
            [latitude] => 47.0246
            [longitude] => 28.83243
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [56] => Array
        (
            [value] => monaco
            [display] => Monaco
            [continent] => Europe
            [latitude] => 43.73287
            [longitude] => 7.01754
            [region] => europe-west8
            [aggregate_region] => europe-south
        )

    [57] => Array
        (
            [value] => netherlands-central
            [display] => Netherlands Central
            [continent] => Europe
            [latitude] => 52.36994
            [longitude] => 5.90788
            [region] => europe-west4
            [aggregate_region] => europe-west
        )

    [58] => Array
        (
            [value] => netherlands-south
            [display] => Netherlands South
            [continent] => Europe
            [latitude] => 51.92283
            [longitude] => 4.47848
            [region] => europe-west4
            [aggregate_region] => europe-west
        )

    [59] => Array
        (
            [value] => norway
            [display] => Norway
            [continent] => Europe
            [latitude] => 59.91234
            [longitude] => 10.75
            [region] => europe-north1
            [aggregate_region] => europe-north
        )

    [60] => Array
        (
            [value] => poland
            [display] => Poland
            [continent] => Europe
            [latitude] => 52.2356
            [longitude] => 21.01038
            [region] => europe-central2
            [aggregate_region] => europe-central-warsaw
        )

    [61] => Array
        (
            [value] => portugal
            [display] => Portugal
            [continent] => Europe
            [latitude] => 39.3151
            [longitude] => -7.5041
            [region] => europe-southwest1
            [aggregate_region] => europe-southwest
        )

    [62] => Array
        (
            [value] => romania
            [display] => Romania
            [continent] => Europe
            [latitude] => 44.4343
            [longitude] => 26.10298
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [63] => Array
        (
            [value] => russia-central
            [display] => Russia Central
            [continent] => Europe
            [latitude] => 55.75697
            [longitude] => 37.61502
            [region] => europe-north1
            [aggregate_region] => europe-north
        )

    [64] => Array
        (
            [value] => russia-northwest
            [display] => Russia Northwest
            [continent] => Europe
            [latitude] => 59.93318
            [longitude] => 30.30605
            [region] => europe-north1
            [aggregate_region] => europe-north
        )

    [65] => Array
        (
            [value] => slovakia
            [display] => Slovakia
            [continent] => Europe
            [latitude] => 49.04924
            [longitude] => 17.10699
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [66] => Array
        (
            [value] => slovenia
            [display] => Slovenia
            [continent] => Europe
            [latitude] => 46.05063
            [longitude] => 14.50283
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [67] => Array
        (
            [value] => spain-central
            [display] => Spain Central
            [continent] => Europe
            [latitude] => 40.41956
            [longitude] => -3.69196
            [region] => europe-southwest1
            [aggregate_region] => europe-southwest
        )

    [68] => Array
        (
            [value] => spain-east
            [display] => Spain East
            [continent] => Europe
            [latitude] => 39.3668
            [longitude] => -1.2965
            [region] => europe-southwest1
            [aggregate_region] => europe-southwest
        )

    [69] => Array
        (
            [value] => sweden
            [display] => Sweden
            [continent] => Europe
            [latitude] => 59.0582
            [longitude] => 16.0916
            [region] => eu-north-1
            [aggregate_region] => europe-north-stockholm
        )

    [70] => Array
        (
            [value] => switzerland
            [display] => Switzerland
            [continent] => Europe
            [latitude] => 45.37708
            [longitude] => 7.53956
            [region] => europe-west6
            [aggregate_region] => switzerland
        )

    [71] => Array
        (
            [value] => uganda
            [display] => Uganda
            [continent] => Europe
            [latitude] => 0.347596
            [longitude] => 32.58252
            [region] => europe-west6
            [aggregate_region] => switzerland
        )

    [72] => Array
        (
            [value] => eu-west-2
            [display] => UK
            [continent] => Europe
            [latitude] => 51.50643
            [longitude] => -0.12721
            [region] => eu-west-2
            [aggregate_region] => europe-northwest
        )

    [73] => Array
        (
            [value] => ukraine
            [display] => Ukraine
            [continent] => Europe
            [latitude] => 50.45057
            [longitude] => 30.52428
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [74] => Array
        (
            [value] => uzbekistan
            [display] => Uzbekistan
            [continent] => Europe
            [latitude] => 41.9768
            [longitude] => 62.2374
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [75] => Array
        (
            [value] => me-south-1
            [display] => Bahrain
            [continent] => Middle East
            [latitude] => 26.0667
            [longitude] => 50.5577
            [region] => me-south-1
            [aggregate_region] => bahrain
        )

    [76] => Array
        (
            [value] => egypt
            [display] => Egypt
            [continent] => Middle East
            [latitude] => 30.04993
            [longitude] => 31.2486
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [77] => Array
        (
            [value] => israel
            [display] => Israel
            [continent] => Middle East
            [latitude] => 30.04993
            [longitude] => 36.3786
            [region] => me-west1
            [aggregate_region] => middle-east-west
        )

    [78] => Array
        (
            [value] => jordan
            [display] => Jordan
            [continent] => Middle East
            [latitude] => 30.0993
            [longitude] => 37.7411
            [region] => europe-west8
            [aggregate_region] => europe-south
        )

    [79] => Array
        (
            [value] => kuwait
            [display] => Kuwait
            [continent] => Middle East
            [latitude] => 29.09426
            [longitude] => 48.07602
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [80] => Array
        (
            [value] => qatar
            [display] => Qatar
            [continent] => Middle East
            [latitude] => 25.2861
            [longitude] => 51.5348
            [region] => me-central1
            [aggregate_region] => me-central-qatar
        )

    [81] => Array
        (
            [value] => saudi-arabia
            [display] => Saudi Arabia
            [continent] => Middle East
            [latitude] => 24.68218
            [longitude] => 46.68719
            [region] => me-central2
            [aggregate_region] => me-central-saudi-arabia
        )

    [82] => Array
        (
            [value] => turkey
            [display] => Turkey
            [continent] => Middle East
            [latitude] => 41.06071
            [longitude] => 28.98772
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [83] => Array
        (
            [value] => uae
            [display] => United Arab Emirates
            [continent] => Middle East
            [latitude] => 25.12175
            [longitude] => 56.33399
            [region] => me-central-1
            [aggregate_region] => me-central-uae
        )

    [84] => Array
        (
            [value] => kenya
            [display] => Kenya
            [continent] => Africa
            [latitude] => -2.0783
            [longitude] => 38.707
            [region] => europe-west8
            [aggregate_region] => europe-south
        )

    [85] => Array
        (
            [value] => nigeria
            [display] => Nigeria
            [continent] => Africa
            [latitude] => 7.5939
            [longitude] => 6.0819
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [86] => Array
        (
            [value] => nigeria-los
            [display] => Nigeria (Lagos)**
            [continent] => Africa
            [latitude] => 9.5939
            [longitude] => 8.0819
            [region] => af-south-1
            [aggregate_region] => nigeria-los
        )

    [87] => Array
        (
            [value] => senegal
            [display] => Senegal
            [continent] => Africa
            [latitude] => -17.467686
            [longitude] => 14.716677
            [region] => europe-west1
            [aggregate_region] => belgium
        )

    [88] => Array
        (
            [value] => south-africa-central
            [display] => South Africa Central
            [continent] => Africa
            [latitude] => -27.033
            [longitude] => 26.8094
            [region] => europe-west3
            [aggregate_region] => europe-central
        )

    [89] => Array
        (
            [value] => south-africa-west
            [display] => South Africa West
            [continent] => Africa
            [latitude] => -32.0775
            [longitude] => 19.455
            [region] => af-south-1
            [aggregate_region] => south-africa-west
        )

    [90] => Array
        (
            [value] => bangladesh
            [display] => Bangladesh
            [continent] => Asia
            [latitude] => 23.71321
            [longitude] => 90.39957
            [region] => asia-south1
            [aggregate_region] => asia-south
        )

    [91] => Array
        (
            [value] => cambodia
            [display] => Cambodia
            [continent] => Asia
            [latitude] => 11.55251
            [longitude] => 104.87901
            [region] => asia-southeast1
            [aggregate_region] => asia-southeast
        )

    [92] => Array
        (
            [value] => hong-kong
            [display] => Hong Kong
            [continent] => Asia
            [latitude] => 22.27831
            [longitude] => 114.1604
            [region] => asia-east2
            [aggregate_region] => hong-kong
        )

    [93] => Array
        (
            [value] => india-north
            [display] => India North
            [continent] => Asia
            [latitude] => 28.63096
            [longitude] => 77.21728
            [region] => asia-south2
            [aggregate_region] => india-north
        )

    [94] => Array
        (
            [value] => india-south
            [display] => India South
            [continent] => Asia
            [latitude] => 13.08363
            [longitude] => 80.28252
            [region] => asia-south1
            [aggregate_region] => asia-south
        )

    [95] => Array
        (
            [value] => ap-south-1
            [display] => India West
            [continent] => Asia
            [latitude] => 18.94017
            [longitude] => 72.83486
            [region] => ap-south-1
            [aggregate_region] => asia-south
        )

    [96] => Array
        (
            [value] => indonesia
            [display] => Indonesia
            [continent] => Asia
            [latitude] => -6.17148
            [longitude] => 106.82649
            [region] => asia-southeast2
            [aggregate_region] => asia-southeast-indonesia
        )

    [97] => Array
        (
            [value] => kazakhstan
            [display] => Kazakhstan
            [continent] => Asia
            [latitude] => 51.169392
            [longitude] => 71.449074
            [region] => europe-north1
            [aggregate_region] => europe-north
        )

    [98] => Array
        (
            [value] => malaysia
            [display] => Malaysia
            [continent] => Asia
            [latitude] => 3.1479
            [longitude] => 101.69405
            [region] => asia-southeast1
            [aggregate_region] => asia-southeast
        )

    [99] => Array
        (
            [value] => myanmar
            [display] => Myanmar
            [continent] => Asia
            [latitude] => 16.88214
            [longitude] => 96.13263
            [region] => asia-southeast1
            [aggregate_region] => asia-southeast
        )

    [100] => Array
        (
            [value] => pakistan-south
            [display] => Pakistan South
            [continent] => Asia
            [latitude] => 24.89612
            [longitude] => 66.99931
            [region] => asia-south1
            [aggregate_region] => asia-south
        )

    [101] => Array
        (
            [value] => pakistan-west
            [display] => Pakistan West
            [continent] => Asia
            [latitude] => 31.53944
            [longitude] => 74.30348
            [region] => asia-south1
            [aggregate_region] => asia-south
        )

    [102] => Array
        (
            [value] => pakistan-west-2
            [display] => Pakistan West (II)
            [continent] => Asia
            [latitude] => 30.55083
            [longitude] => 73.39083
            [region] => asia-southeast1
            [aggregate_region] => asia-southeast
        )

    [103] => Array
        (
            [value] => papua-new-guinea
            [display] => Papua New Guinea
            [continent] => Asia
            [latitude] => -5.0746
            [longitude] => 139.0623
            [region] => australia-southeast1
            [aggregate_region] => australia-southeast
        )

    [104] => Array
        (
            [value] => philippines
            [display] => Philippines
            [continent] => Asia
            [latitude] => 14.64766
            [longitude] => 121.05151
            [region] => asia-southeast1
            [aggregate_region] => asia-southeast
        )

    [105] => Array
        (
            [value] => ap-southeast-1
            [display] => Singapore
            [continent] => Asia
            [latitude] => 1.29019
            [longitude] => 103.85199
            [region] => ap-southeast-1
            [aggregate_region] => asia-southeast
        )

    [106] => Array
        (
            [value] => ap-northeast-2
            [display] => South Korea
            [continent] => Asia
            [latitude] => 37.55886
            [longitude] => 126.99989
            [region] => ap-northeast-2
            [aggregate_region] => south-korea
        )

    [107] => Array
        (
            [value] => srilanka
            [display] => Sri Lanka
            [continent] => Asia
            [latitude] => 6.9271
            [longitude] => 79.8612
            [region] => asia-southeast1
            [aggregate_region] => asia-southeast
        )

    [108] => Array
        (
            [value] => taiwan
            [display] => Taiwan
            [continent] => Asia
            [latitude] => 25.01193
            [longitude] => 121.46562
            [region] => asia-east1
            [aggregate_region] => taiwan
        )

    [109] => Array
        (
            [value] => thailand
            [display] => Thailand
            [continent] => Asia
            [latitude] => 13.75337
            [longitude] => 100.50483
            [region] => asia-southeast1
            [aggregate_region] => asia-southeast
        )

    [110] => Array
        (
            [value] => vietnam
            [display] => Vietnam
            [continent] => Asia
            [latitude] => 11.9856
            [longitude] => 107.7515
            [region] => asia-southeast1
            [aggregate_region] => asia-southeast
        )

    [111] => Array
        (
            [value] => ap-northeast-1
            [display] => Japan Central
            [continent] => Japan
            [latitude] => 35.68409
            [longitude] => 139.80885
            [region] => ap-northeast-1
            [aggregate_region] => asia-northeast
        )

    [112] => Array
        (
            [value] => japan-south
            [display] => Japan South
            [continent] => Japan
            [latitude] => 35.9237
            [longitude] => 137.2446
            [region] => asia-northeast2
            [aggregate_region] => japan-south
        )

    [113] => Array
        (
            [value] => australia-east
            [display] => Australia East
            [continent] => ANZ
            [latitude] => -24.6938
            [longitude] => 150.4588
            [region] => australia-southeast1
            [aggregate_region] => australia-southeast
        )

    [114] => Array
        (
            [value] => australia-south
            [display] => Australia South
            [continent] => ANZ
            [latitude] => -36.6954
            [longitude] => 145.0526
            [region] => australia-southeast2
            [aggregate_region] => australia-south
        )

    [115] => Array
        (
            [value] => ap-southeast-2
            [display] => Australia Southeast
            [continent] => ANZ
            [latitude] => -32.6346
            [longitude] => 148.8175
            [region] => ap-southeast-2
            [aggregate_region] => australia-southeast
        )

    [116] => Array
        (
            [value] => au-west-perth
            [display] => Australia West (Perth)**
            [continent] => ANZ
            [latitude] => -31.953512
            [longitude] => 115.857048
            [region] => ap-southeast-2
            [aggregate_region] => au-west-perth
        )

    [117] => Array
        (
            [value] => new-zealand
            [display] => New Zealand
            [continent] => ANZ
            [latitude] => -37.85232
            [longitude] => 174.76389
            [region] => australia-southeast1
            [aggregate_region] => australia-southeast
        )

    [118] => Array
        (
            [value] => new-zealand-akl
            [display] => New Zealand (Auckland)**
            [continent] => ANZ
            [latitude] => -37.65232
            [longitude] => 176.76389
            [region] => ap-southeast-2
            [aggregate_region] => au-west-auckland
        )

)


 */


$type = "mobile-agent/agent-versions";
$MUjsonArray = $connector->getResource( $accessToken, $type, $folder );
print_r($MUjsonArray);
/*
Array
(
    [agent_versions] => Array
        (
            [0] => 6.2.2 (activated)
            [1] => 6.2.1
            [2] => 6.2.0
            [3] => 6.1.4
            [4] => 6.1.3
            [5] => 6.1.2
            [6] => 6.1.1
            [7] => 6.0.8
            [8] => 6.0.7
            [9] => 5.1.12
        )

)
 */


$type = "mobile-agent/authentication-settings";
$MUjsonArray = $connector->getResource( $accessToken, $type, $folder );
print_r($MUjsonArray);
/*
Array
(
    [data] => Array
        (
            [0] => Array
                (
                    [name] => DEFAULT
                    [folder] => Mobile Users
                    [os] => Any
                    [authentication_profile] => Local Users
                    [authentication_message] => Enter login credentials
                )

        )
    [offset] => 0
    [total] => 1
    [limit] => 200
)
 */


$type = "mobile-agent/enable";
$MUjsonArray = $connector->getResource( $accessToken, $type, $folder );
print_r($MUjsonArray);
/*
Array
(
    [enabled] => 1
)
 */
########################################################################################################################



PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
########################################################################################################################
