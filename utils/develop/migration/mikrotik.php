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


###################################################################################
###################################################################################
//Todo: possible to bring this in via argument
//CUSTOM variables for the script


$print = false;

###################################################################################
###################################################################################

print "\n***********************************************\n";
print "************ Mikrotik UTILITY ****************\n\n";

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../../utils/lib/UTIL.php";
#require_once("lib/pan_php_framework.php");
#require_once ( "utils/lib/UTIL.php");


$file = null;

$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['file'] = Array('niceName' => 'FILE', 'shortHelp' => 'BlueCoat config file, export via CLI: ""');
$supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['loadxmlfromfile'] = Array('niceName' => 'loadxmlfromfile', 'shortHelp' => 'do not load from memory, load from newly generated XML file during execution');


$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=[PAN-OS base config file] file=[PULSE xml config file] [out=]";


function strip_hidden_chars($str)
{
    $chars = array("\r\n", "\n", "\r", "\t", "\0", "\x0B");

    $str = str_replace($chars,"",$str);

    #return preg_replace('/\s+/',' ',$str);
    return $str;
}

if( !isset(PH::$args['in'])  )
    PH::$args['in'] = dirname(__FILE__)."/panos_baseconfig.xml";


$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();

##########################################
##########################################

if( isset(PH::$args['file'])  )
    $file = PH::$args['file'];
else
    derr( "argument file not set" );



$util->load_config();
#$util->location_filter();
#$location = $util->objectsLocation[0];


$location = $util->objectsLocation;

$pan = $util->pan;


print "location: ".$location."\n";

if( $util->configType == 'panos' )
{
    // Did we find VSYS1 ?
    $v = $pan->findVirtualSystem( $location );
    if( $v === null )
        derr( $util->$location." was not found ? Exit\n");
}
elseif( $util->configType == 'panorama' )
{
    $v = $pan->findDeviceGroup( $location );
    if( $v == null )
        $v = $pan->createDeviceGroup( $location );
}
elseif( $util->configType == 'fawkes' )
{
    $v = $pan->findContainer( $location );
    if( $v == null )
        $v = $pan->createContainer( $location );
}


##########################################

//read file to string
$filename = $file;




$addressObjectArray = array();
$addressMissingObjects = array();

$serviceObjectArray = array();
$serviceMissingObjects = array();

$userObjectArray = array();
$userMissingObjects = array();

$policyGroupObjectArray = array();
$policyGroupMissingObjects = array();

$missingURL = array();


#######################################################




// 2. Process the file
$data = parseMikroTikConfig($filename);

// 3. Output the result
print_r($data);

/**
 * Main Parsing Logic
 */

print_r( array_keys($data) );
/*
 [0] => interface bridge
    [1] => interface ethernet
    [2] => interface vlan
    [3] => interface vrrp
    [4] => interface wireless security-profiles
    [5] => ip ipsec profile
    [6] => ip ipsec peer
    [7] => ip ipsec proposal
    [8] => routing bgp instance
    [9] => routing ospf area
    [10] => routing ospf instance
    [11] => snmp community
    [12] => system logging action
    [13] => user group
    [14] => interface bridge port
    [15] => ip neighbor discovery-settings
    [16] => ip address
    [17] => ip dns
    [18] => ip firewall address-list
    [19] => ip firewall filter
    [20] => ip firewall mangle
    [21] => ip firewall nat
    [22] => ip firewall raw
    [23] => ip firewall service-port
    [24] => ip ipsec identity
    [25] => ip ipsec policy
    [26] => ip route
    [27] => ip route rule
    [28] => ip route vrf
    [29] => ip service
    [30] => radius
    [31] => radius incoming
    [32] => routing bgp network
    [33] => routing bgp peer
    [34] => routing filter
    [35] => routing ospf interface
    [36] => routing ospf network
    [37] => snmp
    [38] => system clock
    [39] => system identity
    [40] => system logging
    [41] => system note
    [42] => system ntp client
    [43] => system package update
    [44] => system scheduler
    [45] => system script
    [46] => tool bandwidth-server
    [47] => tool sniffer
    [48] => user aaa
 */

//========create interfaces
//interface ethernet
/*
[0] => Array
    (
        [[] => 1
        [find] => 1
        [default-name] => ether1
        []] => 1
        [comment] => MANAGEMENT
    )

[1] => Array
    (
        [[] => 1
        [find] => 1
        [default-name] => sfp-sfpplus1
        []] => 1
        [advertise] => 10000M-full
        [comment] => INTERNET MIKROTIK-PE1_DTG
    )
 */
//interface vlan
/*
[0] => Array
    (
        [comment] => LLI-TO-STX
        [interface] => sfp-sfpplus1
        [name] => LLI-STX
        [vlan-id] => 1025
    )
 */

//=====add ip address to interfaces
//ip address
/*
[0] => Array
    (
        [address] => 10.50.101.2/24
        [comment] => MANAGEMENT
        [interface] => ether1
        [network] => 10.50.101.0
    )
 */


//address objects and address group
//ip firewall address-list
address_migration( $data, $v, $print );

//==========
//ip firewall filter
//-> use dst-port to create service objects
sec_rule_migration( $data, $v, $print, 'ip firewall filter', 'filter_' );

//ip firewall mangle
//ip firewall nat
nat_rule_migration( $data, $v, $print );

//ip firewall raw
sec_rule_migration( $data, $v, $print, 'ip firewall raw', 'raw_' );

//==========
//ip route
//routing bgp network
//routing filter


#######################################################

function nat_rule_migration( $data, $v, $print )
{
    foreach( $data['ip firewall nat'] as $k => $rule )
    {
        foreach ($rule as $array_key => $info)
        {
            $test_array_keys[$array_key] = $array_key;
            if ($array_key == 'action') {
                $actions_array[$info] = $info;
            }


            if ($array_key == 'protocol') {
                $protocol_array[$info] = $info;
            }
        }
        print_r( $rule );

        if( $rule['chain'] == "dstnat" )
        {
            /** @var VirtualSystem $v */
            PH::print_stdout("-------");
            $name = $v->natRules->findAvailableName("dnat"."Rule");

            /** @var NatRule $natrule */
            $natrule = $v->natRules->newNatRule($name );
            PH::print_stdout(" - create Rule: ".$name);

            $dstObj = $v->addressStore->find($rule['dst-address']);
            if($dstObj == null)
                $dstObj = $v->addressStore->newAddress($rule['dst-address'], "ip-netmask", $rule['dst-address']);

            $natrule->destination->addObject($dstObj);
            PH::print_stdout("  - add dst Obj: ".$dstObj->name());

            $dnatObj = $v->addressStore->find($rule['to-addresses']);
            if($dnatObj == null)
                $dnatObj = $v->addressStore->newAddress($rule['to-addresses'], "ip-netmask", $rule['to-addresses']);

            $natrule->setDNAT($dnatObj);
            PH::print_stdout("  - set DNAT Obj: ".$dnatObj->name());

            if( isset($rule['comment']) )
            {
                $natrule->setDescription($rule['comment']);
                PH::print_stdout("  - set Comment: ".$rule['comment']);
            }


            if( isset($rule['protocol']) )
            {
                if( isset($rule['dst-port']) && isset($rule['to-ports']) )
                {
                    $srvObj = $v->serviceStore->find($rule['protocol']."_".$rule['dst-port']);
                    if($srvObj == null)
                        $srvObj = $v->serviceStore->newService($rule['protocol']."_".$rule['dst-port'], $rule['protocol'], $rule['dst-port']);
                    $natrule->setService($srvObj);
                    PH::print_stdout("  - set Service: ".$srvObj->name());

                    $dsrvObj = $v->serviceStore->find($rule['protocol']."_".$rule['to-ports']);
                    if($dsrvObj == null)
                        $dsrvObj = $v->serviceStore->newService($rule['protocol']."_".$rule['to-ports'], $rule['protocol'], $rule['to-ports']);
                    $natrule->setDNAT($dnatObj, $rule['to-ports']);
                    PH::print_stdout("  - set DNATService: ".$rule['to-ports']);
                }
            }
            /*
            Array
            (
                [action] => netmap
                [chain] => dstnat
                [comment] => NAT 1-1 www.telma.km - GAL
                [dst-address] => 102.16.24.5
                [to-addresses] => 10.246.251.35
            )
            Array
            (
                [action] => dst-nat
                [chain] => dstnat
                [comment] => trainingcenter - icmp - GAL
                [dst-address] => 154.126.32.228
                [protocol] => icmp
                [to-addresses] => 10.246.251.31
            )
            Array
            (
                [action] => dst-nat
                [chain] => dstnat
                [comment] => trainingcenter - 443 - GAL
                [dst-address] => 154.126.32.228
                [dst-port] => 443
                [protocol] => tcp
                [to-addresses] => 10.246.251.31
                [to-ports] => 443
            )

             */
        }
        elseif( $rule['chain'] == "srcnat" )
        {
            /*
             * Array
            (
                [action] => netmap
                [chain] => srcnat
                [comment] => NAT1-1 cb2wrct.mvola.km - GAL
                [src-address] => 10.246.251.36
                [to-addresses] => 102.16.24.2
            )

             */

            PH::print_stdout("-------");
            $name = $v->natRules->findAvailableName("snat"."Rule");

            /** @var NatRule $natrule */
            $natrule = $v->natRules->newNatRule($name );
            PH::print_stdout(" - create Rule: ".$name);
            print_r($rule);

            if( isset($rule['src-address']) )
            {
                $srcObj = $v->addressStore->find($rule['src-address']);
                if($srcObj == null)
                    $srcObj = $v->addressStore->newAddress($rule['src-address'], "ip-netmask", $rule['src-address']);

                $natrule->source->addObject($srcObj);
                PH::print_stdout("  - add src Obj: ".$srcObj->name());
            }


            if( isset($rule['to-addresses']) )
            {
                $sNatObj = $v->addressStore->find($rule['to-addresses']);
                if($sNatObj == null)
                    $sNatObj = $v->addressStore->newAddress($rule['to-addresses'], "ip-netmask", $rule['to-addresses']);

                $natrule->snathosts->addObject($sNatObj);
                $natrule->changeSourceNAT( "static-ip" );
                PH::print_stdout("  - set SNAT Obj: ".$sNatObj->name());

            }

            if( isset($rule['comment']) )
            {
                $natrule->setDescription($rule['comment']);
                PH::print_stdout("  - set Comment: ".$rule['comment']);
            }

        }
    }
}

function sec_rule_migration( $data, $v, $print, $ruletype, $rule_prefix = "" )
{
    /** @var VirtualSystem $v*/
    $test_array_keys = array();
    $actions_array = array();
    $protocol_array = array();
    /*
      [action] => action
        [chain] => chain
        [comment] => comment
        [dst-address] => dst-address
        [src-address-list] => src-address-list
        [dst-address-list] => dst-address-list
        [src-address] => src-address
        [address-list] => address-list
        [address-list-timeout] => address-list-timeout
        [protocol] => protocol
        [psd] => psd
        [tcp-flags] => tcp-flags
        [connection-mark] => connection-mark
        [dst-port] => dst-port
        [in-interface] => in-interface
        [disabled] => disabled
     */
    //available actions:
    /*
    [accept] => accept
    [add-src-to-address-list] => add-src-to-address-list
    [add-dst-to-address-list] => add-dst-to-address-list
    [drop] => drop
     */
    foreach( $data[$ruletype] as $k => $rule )
    {
        foreach( $rule as $array_key => $info )
        {
            $test_array_keys[$array_key] = $array_key;
            if( $array_key == 'action' )
            {
                $actions_array[$info] = $info;
            }


            if( $array_key == 'protocol' )
            {
                $protocol_array[$info] = $info;
            }
        }


        if( $rule['action'] == "add-src-to-address-list" || $rule['action'] == "add-dst-to-address-list" )
            continue;

        if( $rule['chain'] == "input" )
            continue;

        PH::print_stdout("-------");
        $name = $v->securityRules->findAvailableName($rule_prefix."Rule");
        $tmpRule = $v->securityRules->newSecurityRule($name );
        PH::print_stdout(" - create Rule: ".$name);

        if( $rule['action'] == "drop" )
        {
            PH::print_stdout( "  - set to drop");
            $tmpRule->setAction("drop");
        }


        if( isset($rule['disabled']) )
        {
            if( $rule['disabled'] == "yes" )
            {
                $tmpRule->setDisabled(true);
                PH::print_stdout( "  - set to disabled");
            }

        }
        if( isset($rule['comment']) )
        {
            $tmpRule->setDescription($rule['comment']);
            PH::print_stdout( "  - add description: ".$rule['comment']);
        }



        if( isset($rule['dst-address']) )
        {
            $addressObj = $v->addressStore->find( $rule['dst-address'] );
            if( $addressObj == null )
            {
                $addressObj = $v->addressStore->newAddress( $rule['dst-address'], "ip-netmask", $rule['dst-address'] );
            }
        }
        elseif( isset($rule['dst-address-list']) )
        {
            $dst_obj_name = $rule['dst-address-list'];
            if( strpos($dst_obj_name, "!") !== false )
            {
                $dst_obj_name = str_replace("!", "", $dst_obj_name);
                $tmpRule->setDestinationIsNegated(true);
                PH::print_stdout( "  - destination is negated ");
            }

            $addressObj = $v->addressStore->find( $dst_obj_name );
        }

        if( $addressObj !== null )
        {
            $tmpRule->destination->addObject( $addressObj );
            PH::print_stdout("  - add destination: ".$addressObj->name());
        }




        if( isset($rule['src-address']) )
        {
            $addressObj = $v->addressStore->find( $rule['src-address'] );
            if( $addressObj == null )
            {
                $addressObj = $v->addressStore->newAddress( $rule['src-address'], "ip-netmask", $rule['src-address'] );
            }
        }
        elseif( isset($rule['src-address-list']) )
        {
            $source_obj_name = $rule['src-address-list'];
            if( strpos($source_obj_name, "!") !== false )
            {
                $source_obj_name = str_replace("!", "", $source_obj_name);
                $tmpRule->setSourceIsNegated(true);
                PH::print_stdout( "  - source is negated ");
            }

            $addressObj = $v->addressStore->find( $source_obj_name );

        }

        if( $addressObj !== null )
        {
            $tmpRule->source->addObject( $addressObj );
            PH::print_stdout("  - add source: ".$addressObj->name());
        }


        if( isset($rule['protocol']) )
        {
            if( $rule['protocol'] == "tcp" || $rule['protocol'] == "udp" )
            {
                PH::print_stdout("  - protocol: ".$rule['protocol']);
                //dst-port
                if( isset($rule['dst-port']) )
                {
                    $srv_name = str_replace(",", "_", $rule['dst-port']);
                    $tmpSrv = $v->serviceStore->find( $rule['protocol']."_".$srv_name );
                    if( $tmpSrv == null )
                        $tmpSrv = $v->serviceStore->newService( $rule['protocol']."_".$srv_name, $rule['protocol'], $rule['dst-port'] );

                    $tmpRule->services->add( $tmpSrv );
                    PH::print_stdout("  - add service: ".$rule['protocol']."_".$srv_name);
                }
            }
            else
            {
                //something like app-id migration
            }
        }

        #print_r( $rule );
    }

    #print_r( $test_array_keys);
    #print_r( $actions_array);
    #print_r( $protocol_array);
}

function address_migration( $data, $v, $print ): void
{
/*
 [0] => Array
    (
        [address] => 10.40.0.0/30
        [disabled] => yes
        [list] => ipblock1
    )
 */
    foreach( $data['ip firewall address-list'] as $address )
    {
        $name = str_replace("/","m",$address['address']);

        $tmp_address_grp = $v->addressStore->find($address['list']);
        if( $tmp_address_grp == null )
        {
            $tmp_address_grp = $v->addressStore->newAddressGroup( $address['list'] );
        }

        $tmp_address = $v->addressStore->find($name);
        if( $tmp_address == null )
        {
            $string_split = explode("/",$address['address']);
            if( filter_var($string_split[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE
                || filter_var($string_split[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE  )
            {
                #print "create NAME: ".$name." - url: ".$url."\n";
                if( $print )
                    print "- create address: ".$name." -type: ip-netmask -value: ".$address['address']."\n";
                $tmp_address = $v->addressStore->newAddress($name, 'ip-netmask', $address['address']);
            }
            else
            {
                if( $print )
                    print "- create address: ".$name." -type: fqdn -value: ".$address['address']."\n";
                $tmp_address = $v->addressStore->newAddress($name, 'fqdn', $address['address']);
            }
        }
        $tmp_address_grp->addMember($tmp_address);
    }
}

function parseMikroTikConfig($filePath) {
    $config = [];
    $currentSection = '';
    $lines = file($filePath, FILE_IGNORE_NEW_LINES);

    $buffer = "";
    $processedLines = [];

    // Step A: Join lines ending with "\"
    foreach ($lines as $line) {
        $trimmedLine = trim($line);
        if (str_ends_with($trimmedLine, '\\')) {
            $buffer .= substr($trimmedLine, 0, -1);
            continue;
        } else {
            $buffer .= $trimmedLine;
            if ($buffer !== "") {
                $processedLines[] = $buffer;
            }
            $buffer = "";
        }
    }

    // Step B: Build the Array
    foreach ($processedLines as $line) {
        if (str_starts_with($line, '#')) continue;

        // New Section (e.g., /ip address)
        if (str_starts_with($line, '/')) {
            $currentSection = trim(substr($line, 1));
            continue;
        }

        // Parse Action (add or set)
        if (preg_match('/^(add|set|edit)\s+(.*)$/', $line, $matches)) {
            $attributesRaw = $matches[2];
            $item = parseAttributes($attributesRaw);
            $config[$currentSection][] = $item;
        }
    }

    return $config;
}

/**
 * Regex Helper to split key=value pairs
 */
function parseAttributes($string) {
    $attributes = [];
    // This regex handles: key=value, key="value with spaces", and [ find ... ]
    $pattern = '/(\S+)=("[^"]*"|\[[^\]]*\]|\S+)|(\S+)/';
    preg_match_all($pattern, $string, $matches, PREG_SET_ORDER);

    foreach ($matches as $match) {
        if (isset($match[1]) && $match[1] !== "") {
            $key = $match[1];
            $val = trim($match[2], '"');
            $attributes[$key] = $val;
        } else {
            // Standalone flags (like 'disabled' or 'passive')
            $attributes[$match[0]] = true;
        }
    }
    return $attributes;
}

function print_xml_info( $appx3, $print = false )
{
    $appName3 = $appx3->nodeName;

    if( $print )
        print "|13:|" . $appName3 . "\n";

    $newdoc = new DOMDocument;
    $node = $newdoc->importNode($appx3, TRUE);
    $newdoc->appendChild($node);
    $html = $newdoc->saveHTML();

    if( $print )
        print "|" . $html . "|\n";
}


function truncate_names($longString) {
    global $source;
    $variable = strlen($longString);

    if ($variable < 63) {
        return $longString;
    } else {
        $separator = '';
        $separatorlength = strlen($separator);
        $maxlength = 63 - $separatorlength;
        $start = $maxlength;
        $trunc = strlen($longString) - $maxlength;
        $salida = substr_replace($longString, $separator, $start, $trunc);

        if ($salida != $longString) {
            //Todo: swaschkut - xml attribute adding needed
            #add_log('warning', 'Names Normalization', 'Object Name exceeded >63 chars Original:' . $longString . ' NewName:' . $salida, $source, 'No Action Required');
        }
        return $salida;
    }
}

function normalizeNames($nameToNormalize) {
    $nameToNormalize = trim($nameToNormalize);
    //$nameToNormalize = preg_replace('/(.*) (&#x2013;) (.*)/i', '$0 --> $1 - $3', $nameToNormalize);
    //$nameToNormalize = preg_replace("/&#x2013;/", "-", $nameToNormalize);
    $nameToNormalize = preg_replace("/[\/]+/", "_", $nameToNormalize);
    $nameToNormalize = preg_replace("/[^a-zA-Z0-9-_. ]+/", "", $nameToNormalize);
    $nameToNormalize = preg_replace("/[\s]+/", " ", $nameToNormalize);

    $nameToNormalize = preg_replace("/^[-]+/", "", $nameToNormalize);
    $nameToNormalize = preg_replace("/^[_]+/", "", $nameToNormalize);

    $nameToNormalize = preg_replace('/\(|\)/','',$nameToNormalize);

    return $nameToNormalize;
}

function find_string_between($line, $needle1, $needle2 = "--END--")
{
    $needle_length = strlen($needle1);
    $pos1 = strpos($line, $needle1);

    if( $needle2 !== "--END--" )
        $pos2 = strpos($line, $needle2);
    else
        $pos2 = strlen($line);

    $finding = substr($line, $pos1 + $needle_length, $pos2 - ($pos1 + $needle_length));

    return $finding;
}

##################################################################

/*

$configInput = array();
$configInput['type'] = 'file';
$configInput['filename'] = $util->configInput;

CONVERTER::rule_merging( $v, $configInput, true, false, false, "tag", array( "1", "3" ) );
*/

print "\n\n\n";

$util->save_our_work();

print "\n\n************ END OF TMG UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";

