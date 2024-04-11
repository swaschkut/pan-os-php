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
$folder = "Service Connections";


$type = "bgp-routing";
$SNjsonArray = $connector->getResource( $accessToken, $type, $folder );
#print_r($SNjsonArray);
/*
Array
(
    [folder] => Service Connections
    [outbound_routes_for_services] => Array
        (
        )

    [accept_route_over_SC] =>
)
 */

$type = "service-connections";
$SNjsonArray = $connector->getResource( $accessToken, $type, $folder );

$type = "ipsec-tunnels";
$IPsecTunneljsonArray = $connector->getResource( $accessToken, $type, $folder );

$type = "ipsec-crypto-profiles";
$IPsecCryptojsonArray = $connector->getResource( $accessToken, $type, $folder );

$type = "ike-gateways";
$IKEgw_jsonArray = $connector->getResource( $accessToken, $type, $folder );

$type = "ike-crypto-profiles";
$IKECryptojsonArray = $connector->getResource( $accessToken, $type, $folder );

//////////////////////////////

function getSASEarrayName($array, $name)
{
    foreach($array['data'] as $entry)
    {
        if( $entry['name'] == $name )
            return $entry;
    }

    return array();
}

//////////////////////////////

print( "#########################################\n");
print( "## SERVICE CONNECTION ##\n" );
print_r($SNjsonArray['data']);

foreach( $SNjsonArray['data'] as $SNentry )
{
    $IPsecTunnel_Name = $SNentry['ipsec_tunnel'];
    #print $IPsecTunnel_Name."\n";

    $SN_IPsec_Tunnel = getSASEarrayName($IPsecTunneljsonArray, $IPsecTunnel_Name);
    print( "#########################################\n");
    print( "## IPSEC TUNNEL ##\n" );
    print_r($SN_IPsec_Tunnel);


    $SN_IPsecCrypto_profile_name = $SN_IPsec_Tunnel['auto_key']['ipsec_crypto_profile'];
    #print $SN_IPsecCrypto_profile_name."\n";
    $SN_IPsecCrypto_profile = getSASEarrayName($IPsecCryptojsonArray, $SN_IPsecCrypto_profile_name);
    print( "#########################################\n");
    print( "## IPSEC CRYPTO PROFIL ##\n" );
    print_r($SN_IPsecCrypto_profile);


    $SN_IKE_gateway_name = $SN_IPsec_Tunnel['auto_key']['ike_gateway']['0']['name'];
    #print $SN_IKE_gateway_name."\n";
    $SN_IKE_gateway = getSASEarrayName($IKEgw_jsonArray, $SN_IKE_gateway_name);
    print( "#########################################\n");
    print( "## IKE GATEWAY ##\n" );
    print_r($SN_IKE_gateway);


    $SN_IKECrypto_profile_name = $SN_IKE_gateway['protocol']['ikev1']['ike_crypto_profile'];
    #print $SN_IKECrypto_profile_name."\n";
    $SN_IKE_Crypto_Profile = getSASEarrayName($IKECryptojsonArray, $SN_IKECrypto_profile_name);
    print( "#########################################\n");
    print( "## IKE CRYPTO PROFIL ##\n" );
    print_r($SN_IKE_Crypto_Profile);


}


//Todo: 20240326 swaschkut: get log date for SN tunnel

########################################################################################################################



PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
########################################################################################################################
