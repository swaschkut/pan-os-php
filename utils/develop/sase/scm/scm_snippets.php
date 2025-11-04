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

$url_config = "/config/setup/v1/snippets";

//$limit and $offset are running into 'Access denied
$MUjsonArray = $connector->getResourceURL( $url_config, null, null, 5, null, 0 );
print_r($MUjsonArray);

/*
Array
(
    [data] => Array
        (
            [0] => Array
                (
                    [id] => cd4e425c-e0f8-44a8-8a98-b883d457eec1
                    [name] => predefined-snippet
                )

            [1] => Array
                (
                    [id] => d3ff8509-91ff-4e4d-a291-43015acd420a
                    [name] => default
                    [display_name] => Global-Default
                    [description] => Snippet for global default configutation settings
                    [type] => predefined
                )

            [2] => Array
                (
                    [id] => 144df401-2c53-4a61-8ecd-b311f1ee50f9
                    [name] => optional-default
                    [display_name] => Recommended-Best-Practice
                    [description] => Snippet for recommended security best practice configuration rules
                    [type] => predefined
                )

            [3] => Array
                (
                    [id] => e6fa075d-68e0-4196-9f2b-6d9669a73ed2
                    [name] => office365
                    [display_name] => O365-Best-Practice
                    [description] => Snippet for recommended configuration to safely enable O365
                    [type] => predefined
                )

            [4] => Array
                (
                    [id] => 07acbb77-f76e-46b0-a6de-8c6c5e08f924
                    [name] => proxy
                    [display_name] => Explicit-Proxy-Best-Practice
                    [description] => Snippet for recommended configuration for Explicit Proxy
                    [type] => predefined
                )

            [5] => Array
                (
                    [id] => 201e4eff-f091-4e67-97f5-ca31d66c735c
                    [name] => rbi
                    [display_name] => Enable-RBI
                    [description] => Snippet to enable RBI integrations with supported vendors
                    [type] => predefined
                )

            [6] => Array
                (
                    [id] => 6d2345af-2952-4892-bb6b-435634bc08ca
                    [name] => saas-tenant-restrictions
                    [display_name] => SaaS-Enterprise-Controls
                    [description] => Snippet for configuring tenant restrictions for Enterprise access to well known SaaS applications
                    [type] => predefined
                )

            [7] => Array
                (
                    [id] => 55f56751-269e-462e-9c1b-8161ab8c5639
                    [name] => Auto-VPN-Default-Snippet
                    [description] => Snippet for default configuration required for Auto VPN - Read Only
                    [type] => readonly
                )

            [8] => Array
                (
                    [id] => ebec1a40-9c66-4658-9252-5571216c1cd6
                    [name] => ZTP-Default-Snippet
                    [display_name] => ZTP-Default
                    [description] => Snippet for the default configuration required for Zero Touch Provisioning
                    [type] => predefined
                )

            [9] => Array
                (
                    [id] => 6a785fba-a5d2-44a7-842e-d6068b683ee7
                    [name] => Web-Security-Default
                    [display_name] => Internet-Security-Default
                    [type] => predefined
                )

            [10] => Array
                (
                    [id] => 731258d8-552d-4206-9ae4-656422b5ad08
                    [name] => Gen-AI-Best-Practice
                    [description] => Recommended configuration for securing Gen AI App access
                    [type] => predefined
                )

            [11] => Array
                (
                    [id] => 95a65b08-8323-4101-b8b3-23376208bfd1
                    [name] => app-tagging
                    [display_name] => Application-Tagging
                    [description] => Snippet to help enforce the admin controlled Application tagging from Insights
                    [type] => predefined
                )

            [12] => Array
                (
                    [id] => 01022df0-f6c7-4594-933d-0f4a236cbbab
                    [name] => hip-default
                    [display_name] => HIP-Default
                    [description] => Snippet for default HIP objects and profiles - Read Only
                    [type] => readonly
                )

            [13] => Array
                (
                    [id] => dd9d4621-5da5-41c2-a60c-d9255976b5f1
                    [name] => dlp-predefined-snippet
                    [type] => predefined
                )

            [14] => Array
                (
                    [id] => f88deb41-f7d4-4229-b025-d2f64f063597
                    [name] => SAAS-Inline-Pol-Recommendation
                    [type] => predefined
                )

            [15] => Array
                (
                    [id] => 356e0f8b-4308-4e8b-91fa-dcd7002181bd
                    [name] => Internet-Access-Best-Practice
                    [type] => predefined
                )

            [16] => Array
                (
                    [id] => a88d2abb-eb6e-4041-8ac3-0cb442352a60
                    [name] => DNS-Best-Practice
                    [display_name] => DNS-Best-Practice
                    [type] => predefined
                )

            [17] => Array
                (
                    [id] => a9403448-9b06-4a7a-a9a6-c73e156ee4bc
                    [name] => AIRS-SLR-AWS-Default
                    [description] => Snippet for the default configuration required for AI-Runtime AWS Security Lifecycle Review
                    [type] => predefined
                )

            [18] => Array
                (
                    [id] => 3e3c7c39-1072-469d-bf90-f57674fa7069
                    [name] => OlliS-Test
                    [enable_prefix] =>
                )

            [19] => Array
                (
                    [id] => 31f97b54-7071-45f9-9008-6753e605d2e6
                    [name] => Test-EDF-Parent
                    [enable_prefix] =>
                )

            [20] => Array
                (
                    [id] => 89a915c7-23ea-4e13-a179-6fd01d8ce032
                    [name] => Test-EDF-Parent2
                    [enable_prefix] =>
                )

            [21] => Array
                (
                    [id] => e6efa67f-d3f8-43a8-9f25-00ee65b18761
                    [name] => AIRS-Best-Practice
                    [description] => Configuration for AIRS with best practice AI profile
                    [type] => predefined
                )

            [22] => Array
                (
                    [id] => cb7d3431-9447-4bf0-9cd7-628c4c366431
                    [name] => GCP-VM-Default
                    [description] => Configuration for VM based dual arm GCP deployments
                    [type] => predefined
                )

            [23] => Array
                (
                    [id] => 5b7dc7ac-895f-40c8-83c2-fc692e237bbc
                    [name] => Azure-VM-Default
                    [description] => Configuration for VM based dual arm Azure deployments
                    [type] => predefined
                )

            [24] => Array
                (
                    [id] => 63980f4e-e134-4362-b492-618566775a84
                    [name] => AWS-VM-Single-Arm-Default
                    [description] => Configuration for VM based single arm AWS deployments
                    [type] => predefined
                )

            [25] => Array
                (
                    [id] => 116e2f27-c681-4161-b6bd-5b4cf0fb0318
                    [name] => AWS-VM-Dual-Arm-Default
                    [description] => Configuration for VM based dual arm AWS deployments
                    [type] => predefined
                )

        )

    [offset] => 0
    [total] => 26
    [limit] => 200
)

 */

########################################################################################################################



PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
########################################################################################################################
