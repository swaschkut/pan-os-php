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


set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../../utils/lib/UTIL.php";

PH::print_stdout();
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout();


PH::print_stdout( "PAN-OS-PHP version: ".PH::frameworkVersion() );


$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = Array('niceName' => 'location', 'shortHelp' => 'specify if you want to limit your query to a VSYS. By default location=vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['loadpanoramapushedconfig'] = Array('niceName' => 'loadPanoramaPushedConfig', 'shortHelp' => 'load Panorama pushed config from the firewall to take in account panorama objects and rules' );

$supportedArguments['cert_name'] = Array('niceName' => 'cert_name', 'shortHelp' => 'this message');
$supportedArguments['cert_filename'] = Array('niceName' => 'cert_filename', 'shortHelp' => 'this message');
$supportedArguments['cert_format'] = Array('niceName' => 'cert_format', 'shortHelp' => 'this message');
$supportedArguments['cert_password'] = Array('niceName' => 'cert_password', 'shortHelp' => 'this message');

$supportedArguments['template'] = Array('niceName' => 'template', 'shortHelp' => 'this message');
$supportedArguments['vsys'] = Array('niceName' => 'vsys', 'shortHelp' => 'this message');


$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml location=vsys1 ".
    "\n".
    "php ".basename(__FILE__)." help          : more help messages\n";
##############

$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();

##########################################
##########################################

$util->load_config();
#$util->location_filter();

$pan = $util->pan;
$connector = $pan->connector;


///////////////////////////////////////////////////////

$appsToPutInRule = Array("lwapp","snmp","ldap","ipsec","xdmcp","pcanywhere","portmapper","dtls","rmcp","ssh","rip","echo","nfs","radius","unknown-tcp","quic","websocket","unknown-udp","http-proxy","daytime","traceroute","mssql-mon","web-browsing","tftp","kerberos","dns","vnc-http","netbios-ns","ms-ds-smb","discard","dhcp","soap","netbios-dg","ntp","sip","l2tp","lpd");

$dummyArray = Array();
foreach ($appsToPutInRule as $app)
{
    $dummyArray[$app] = $app;
}
$appsToPutInRule = $dummyArray;

foreach( $appsToPutInRule as $app )
{
    PH::print_stdout("  - $app");
    $appObject = $pan->appStore->find($app);
    if( $appObject !== null )
    {
        $explicits = $appObject->calculateDependencies();
        if( count($explicits) > 0 )
        {
            PH::print_stdout("    - " . PH::list_to_string($explicits));
            foreach( $explicits as $explicit )
            {
                $appsToPutInRule[$explicit->name()] = $explicit->name();
            }

        }
    }
}

print_r($appsToPutInRule);

##############################################

PH::print_stdout();

// save our work !!!
$util->save_our_work();


PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
