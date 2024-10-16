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


function encloseFunction( $value, $nowrap = TRUE )
{
    if( $value == NULL )
        $output = "---";
    elseif( is_string($value) )
        $output = htmlspecialchars($value);
    elseif( is_array($value) )
    {
        $output = '';
        $first = TRUE;
        foreach( $value as $subValue )
        {
            if( !$first )
            {
                $output .= '<br />';
            }
            else
                $first = FALSE;

            if( is_string($subValue) || is_numeric($subValue) )
                $output .= htmlspecialchars($subValue);
            elseif( is_object($subValue) )
                $output .= htmlspecialchars($subValue->name());
            else
                $output .= "";
        }
    }
    elseif( is_object($value) )
    {
        $output = htmlspecialchars( $value->name() );
    }
    else
        derr('TYPE: '.gettype($value).' unsupported', null, false);

    if( $nowrap )
        return '<td style="white-space: nowrap">' . $output . '</td>';

    return '<td>' . $output . '</td>';
}


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

$util->load_config();
$util->location_filter();

$pan = $util->pan;
$connector = $pan->connector;


########################################################################################################################

$req = '<type><threat>'.
'<sortby>repeatcnt</sortby>'.
'<group-by>rule_uuid</group-by>'.
'<aggregate-by><member>rule</member><member>threatid</member></aggregate-by>'.
'<values><member>repeatcnt</member></values></threat></type>'.
'<period>last-7-days</period><topn>100</topn><topm>25</topm><caption>app-id-change</caption>'.
'<query>(category-of-threatid eq app-id-change)</query>';


$apiArgs = Array();
$apiArgs['type'] = 'report';
$apiArgs['reporttype'] = 'dynamic';
$apiArgs['reportname'] = 'custom-dynamic-report';
$apiArgs['async'] = 'yes';
$apiArgs['cmd'] = $req;

$ret = $connector->getReport($apiArgs);

#print_r($ret);

/*
Array
(
    [0] => Array
        (
            [rule_uuid] => 4b5fa950-d29a-4743-ae64-51d06555c175
            [rule] => client-vpn to inet
            [threatid] => Modified From ssl web-browsing To ms-teams
            [tid] => 547661
            [repeatcnt] => 404
        )
    [1] => Array
        (
            [rule_uuid] => 4b5fa950-d29a-4743-ae64-51d06555c175
            [rule] => client-vpn to inet
            [threatid] => New From ssl web-browsing To coveo
            [tid] => 547830
            [repeatcnt] => 22
        )
    [2] => Array
        (
            [rule_uuid] => 4dde418f-93be-437c-8949-590ee3031f05
            [rule] => dmz dmz
            [threatid] => Modified From ssl web-browsing To ms-teams
            [tid] => 547661
            [repeatcnt] => 2
        )
)
 */
########################################################################################################################
//go through each report entry
//get rule app-id information, check if any -> do nothing
//if rule app-id is not any -> display which app-id must be added

PH::print_stdout();
PH::print_stdout("-------------------------");

$filename = "app-id-change.html";

$headers = '<th>ID</th><th>Rule</th><th>threatid</th><th>actual Rule set to APP-ID</th><th>APP-ID to add</th>';

$lines = '';
$count = 0;

foreach( $ret as $appidInfo )
{
    //this is working for local policy if script is running against Firewall
    $vsys = $pan->findVirtualSystem("vsys1");
    $rule = $vsys->securityRules->findByUUID( $appidInfo['rule_uuid'] );

    $ruleAppAny = $rule->apps->isAny();

    $explode = explode(" To ", $appidInfo['threatid']);

    $count++;

    /** @var Tag $object */
    if( $count % 2 == 1 )
        $lines .= "<tr>\n";
    else
        $lines .= "<tr bgcolor=\"#DDDDDD\">";

    $lines .= encloseFunction( (string)$count );

    $lines .= encloseFunction( $appidInfo['rule'] );
    $lines .= encloseFunction( $appidInfo['threatid'] );

    if( !$ruleAppAny )
    {
        $app_string = "";
        $array_count = 1;
        foreach($rule->apps->apps() as $key => $app)
        {
            $array_count++;
            $app_string .= $app->name();
            if( $array_count < count($rule->apps->apps()) )
                $app_string .= ",";
        }
        $lines .= encloseFunction($app_string);

        $lines .= encloseFunction($explode[1]);
    }
    else
    {
        $lines .= encloseFunction( "any" );
        $lines .= encloseFunction( "" );
    }

    $lines .= "</tr>\n";
}


########################################################################################################################



$content = file_get_contents(dirname(__FILE__) . '/../common/html/export-template.html');
$content = str_replace('%TableHeaders%', $headers, $content);

$content = str_replace('%lines%', $lines, $content);

$jscontent = file_get_contents(dirname(__FILE__) . '/../common/html/jquery.min.js');
$jscontent .= "\n";
$jscontent .= file_get_contents(dirname(__FILE__) . '/../common/html/jquery.stickytableheaders.min.js');
$jscontent .= "\n\$('table').stickyTableHeaders();\n";

$content = str_replace('%JSCONTENT%', $jscontent, $content);

file_put_contents($filename, $content);


########################################################################################################################


PH::print_stdout();


$util->save_our_work();

PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
########################################################################################################################
