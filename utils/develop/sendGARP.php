<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
 * Copyright (c) 2019, Palo Alto Networks Inc.
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



###################################################################################
###################################################################################

print "\n***********************************************\n";
print "************ gratuitous ARP UTILITY ****************\n\n";

$offline_config_test = false;
$user = "";
$password = "";

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../utils/lib/UTIL.php";

require_once dirname(__FILE__)."/../../phpseclib/Net/SSH2.php";
require_once dirname(__FILE__)."/../../phpseclib/Crypt/RSA.php";



$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['test'] = Array('niceName' => 'test', 'shortHelp' => 'command to test against offline config file');
$supportedArguments['user'] = array('niceName' => 'user', 'shortHelp' => 'can be used in combination with "add" argument to use specific Username provided as an argument.', 'argDesc' => '[USERNAME]');
$supportedArguments['pw'] = array('niceName' => 'pw', 'shortHelp' => 'can be used in combination with "add" argument to use specific Password provided as an argument.', 'argDesc' => '[PASSWORD]');

$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api:://[MGMT-IP] file=[csv_text file] [out=]";

PH::processCliArgs();

if( isset(PH::$args['test']) )
    $offline_config_test = true;

if( isset(PH::$args['in']) )
{
    $configInput = PH::$args['in'];

    if( strpos( $configInput, "api://" ) === false && !$offline_config_test )
        derr( "only PAN-OS API connection is supported" );

    $configInput = str_replace( "api://", "", $configInput);
}
else
    derr( "argument 'in' is needed" );

if( isset(PH::$args['user']) )
    $user = PH::$args['user'];
else
{
    if( !$offline_config_test )
        derr( "argument 'user' is needed" );
}

if( isset(PH::$args['pw']) )
    $password = PH::$args['pw'];
else
{
    if( !$offline_config_test )
        derr( "argument 'pw' is needed" );
}


$argv2 = array();
PH::$args = array();
PH::$argv = array();
$argv2[] = "key-manager";
$argv2[] = "add=".$configInput;
$argv2[] = "user=".$user;
$argv2[] = "pw=".$password;
$argc2 = count($argv2);

if( !$offline_config_test )
    $util = new KEYMANGER( "key-manager", $argv2, $argc2, __FILE__ );

PH::$args = array();
PH::$argv = array();



$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments );
$util->utilInit();
$util->load_config();

if( !$util->pan->isFirewall() )
    derr( "only PAN-OS FW is supported" );

if( !$util->apiMode && !$offline_config_test )
    derr( "only PAN-OS API connection is supported" );

$inputConnector = $util->pan->connector;



#$cmd = "<show><interface>all</interface></show>";
#$response = $inputConnector->sendOpRequest( $cmd );
##$xmlDoc = new DOMDocument();
##$xmlDoc->loadXML($response);
##echo $response->saveXML();

$interfaces = $util->pan->network->getAllInterfaces();
$commands = array();
$interfaceIP = array();
$ipRangeInt = array();

foreach($interfaces as $int)
{
    /** @var EthernetInterface $int */
    $name = $int->name();

    #print "CLASS: ".get_class( $int )."\n";
    if( get_class( $int ) !== "EthernetInterface" )
        continue;

    if( $int->type() === "layer3" )
        $ips = $int->getLayer3IPAddresses();
    else
        $ips = array();

    foreach( $ips as $key => $ip )
    {
        $intIP = explode("/",$ip );
        $intIP = $intIP[0];

        if( $key == 0)
        {
            $interfaceIP[ $name ] = $intIP;
        }
        $ipRangeInt[$ip] = $name;

        $commands[] = "test arp gratuitous ip ".$intIP." interface ".$name;
    }
}


//get all vsys
$vsyss = $util->pan->getVirtualSystems();

foreach( $vsyss as $vsys )
{
    //Todo: get DNAT DST ip from NAT rule
    $natDNATrules = $vsys->natRules->rules( '(dnat is.set)' );
    foreach( $natDNATrules as $rule )
    {
        #print "NAME: ".$rule->name()."\n";

        $TO = $rule->to->getAll();
        #print "Zone to: ".$TO[0]->name()."\n";

        $DST = $rule->destination->getAll();
        if( count( $DST ) == 1)
        {
            #print "DST: ".$DST[0]->name()."\n";
            #print "IP: ".$DST[0]->value()."\n";

            $dstIP = $DST[0]->value();

            #print_r( $ipRangeInt );
            foreach( $ipRangeInt as $key => $intName )
            {

                $IP_network = explode( "/", $key);

                $network = cidr::cidr2network($IP_network[0], $IP_network[1]);


                if( cidr::cidr_match( $DST[0]->value(), $network, $IP_network[1] ) )
                    $commands[] = "test arp gratuitous ip ".$dstIP." interface ".$intName;
            }
        }

    }
}


if( !$offline_config_test )
{
    $cmd = "<show><arp><entry name = 'all'/></arp></show>";
    $response = $inputConnector->sendOpRequest( $cmd );
#$xmlDoc = new DOMDocument();
#$xmlDoc->loadXML($response);
#echo $response->saveXML();

    $result = DH::findFirstElement( "result", $response);
    $entries = DH::findFirstElement( "entries", $result);
    foreach( $entries->childNodes as $entry )
    {
        if( $entry->nodeType != XML_ELEMENT_NODE )
            continue;

        $ip = DH::findFirstElement( "ip", $entry);
        $interface = DH::findFirstElement( "interface", $entry);

        $intIP = $interfaceIP[ $interface->textContent ];
        $intIP = explode("/",$intIP );
        $intIP = $intIP[0];

        $commands[] = "ping source ".$intIP." count 2 host ".$ip->textContent;
    }
}
else
{
    PH::print_stdout( "" );
    PH::print_stdout( "ping commands can not be prepared in offline" );
    PH::print_stdout( "" );
}


PH::print_stdout( "" );
PH::print_stdout( "Display the commands like to send to the FW:");
PH::print_stdout( "" );

foreach( $commands as $command )
    PH::print_stdout( $command );



##############################################
##############################################
PH::print_stdout( "" );
$output_string = "";
if( !$offline_config_test )
    $ssh = new RUNSSH( $configInput, $user, $password, $commands, $output_string );

print $output_string;
##############################################
##############################################
