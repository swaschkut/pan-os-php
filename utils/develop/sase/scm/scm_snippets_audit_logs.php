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

$url_config = "/config/setup/v1/snippet-audit-logs";

//$limit and $offset are running into 'Access denied
$MUjsonArray = $connector->getResourceURL( $url_config );
print_r($MUjsonArray);

/*
Array
(
    [data] => Array
        (
            [0] => Array
                (
                    [id] => c61ae484-ac16-4a9b-9a09-fad91a47783f
                    [name] => ngfw-shared
                    [parent] => All
                    [snippets] => Array
                        (
                            [0] => Auto-VPN-Default-Snippet
                        )

                    [type] => container
                )

            [1] => Array
                (
                    [display_name] => Colo Connect
                    [id] => 15204760-24b9-40f0-9ced-83d3d4b0c25d
                    [name] => Colo Connect
                    [parent] => Prisma Access
                    [type] => cloud
                )

            [2] => Array
                (
                    [display_name] => Remote Networks
                    [id] => c9bc5fcc-1246-4153-89ad-0604462b4797
                    [name] => Remote Networks
                    [parent] => Prisma Access
                    [type] => cloud
                )

            [3] => Array
                (
                    [display_name] => Service Connections
                    [id] => d881f30f-f62c-4a02-aa92-f0dc2a12c5cb
                    [name] => Service Connections
                    [parent] => Prisma Access
                    [type] => cloud
                )

            [4] => Array
                (
                    [display_name] => Mobile Users
                    [id] => 27d7a633-8028-441c-8d80-5a02f5787a7b
                    [name] => Mobile Users
                    [parent] => Mobile Users Container
                    [type] => cloud
                )

            [5] => Array
                (
                    [display_name] => Mobile Users Explicit Proxy
                    [id] => d77c7ccc-8c82-47d8-8e01-98a645b79ca3
                    [name] => Mobile Users Explicit Proxy
                    [parent] => Mobile Users Container
                    [snippets] => Array
                        (
                            [0] => proxy
                        )

                    [type] => cloud
                )

            [6] => Array
                (
                    [id] => 5979da4b-e369-432f-9582-78d7b2ed958f
                    [name] => Mobile Users Container
                    [parent] => Prisma Access
                    [snippets] => Array
                        (
                            [0] => Internet-Access-Best-Practice
                        )

                    [type] => container
                )

            [7] => Array
                (
                    [id] => aa5689c8-0691-41f6-b93a-5642b8c819e6
                    [name] => Prisma Access
                    [parent] => All
                    [snippets] => Array
                        (
                            [0] => optional-default
                            [1] => office365
                            [2] => rbi
                            [3] => saas-tenant-restrictions
                        )

                    [type] => container
                )

            [8] => Array
                (
                    [display_name] => Global
                    [id] => 93d985ac-153f-4818-a086-c1996c724b51
                    [name] => All
                    [parent] =>
                    [snippets] => Array
                        (
                            [0] => default
                            [1] => SAAS-Inline-Pol-Recommendation
                            [2] => Web-Security-Default
                            [3] => hip-default
                            [4] => dlp-predefined-snippet
                            [5] => OlliS-Test
                        )

                    [type] => container
                )

        )

    [limit] => 200
    [offset] => 0
    [total] => 9
)

 */

########################################################################################################################



PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
########################################################################################################################
