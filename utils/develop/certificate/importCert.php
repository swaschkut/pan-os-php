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

//php ...../importCert.php in=api://MGMT-IP debugapi cert_name=dummy1234 cert_format=pem cert_password=dummy1234 template=mkk-gn-int vsys=vsys1 cert_filename=cert_dummy1234.pem


if( !isset( PH::$args['cert_name'] ) )
    $util->display_error_usage_exit('"cert_name" argument is not set');
else
    $certName = PH::$args['cert_name'];


if( !isset( PH::$args['cert_filename'] ) )
    $util->display_error_usage_exit('"cert_filename" argument is not set');
else
    $certFileName = PH::$args['cert_filename'];

if( !isset( PH::$args['cert_format'] ) )
    $util->display_error_usage_exit('"cert_format" argument is not set');
else
    $certFileFormat = PH::$args['cert_format'];


if( isset( PH::$args['cert_password'] ) )
    $certPassword = PH::$args['cert_password'];
else
    $certPassword = null;


if( isset( PH::$args['template'] ) )
    $template = PH::$args['template'];
else
    $template = null;

if( isset( PH::$args['vsys'] ) )
    $vsys = PH::$args['vsys'];
else
    $vsys = "vsys1";


if( $util->configInput['type'] == 'api' )
{
    $response = $pan->API_uploadCertificate($certFileName, $certName, $certFileFormat, $certPassword, $template, $vsys);
}

else
    derr( "this script is working only in API mode\n" );

##############################################

PH::print_stdout();

// save our work !!!
$util->save_our_work();


PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
