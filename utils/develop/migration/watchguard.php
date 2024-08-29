<?php

/**
 * ISC License
 *
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

//BOTH PROFILES MUST BE available if API
$log_profile = "Logging to Panorama";
$secprofgroup_name = "SecDev_Security Profile_NAWAH";


###################################################################################
###################################################################################

print "\n***********************************************\n";
print "************ Watchguard UTILITY ****************\n\n";


require_once("lib/pan_php_framework.php");
require_once("utils/lib/UTIL.php");

$file = null;

$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['file'] = array('niceName' => 'XML', 'shortHelp' => 'Watchguard Config file in XML format');
$supportedArguments['location'] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');


$usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=api:://[MGMT-IP] file=[csv_text file] [out=]";

function strip_hidden_chars($str)
{
    $chars = array("\r\n", "\n", "\r", "\t", "\0", "\x0B");

    $str = str_replace($chars, "", $str);

    #return preg_replace('/\s+/',' ',$str);
    return $str;
}


$util = new UTIL("custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg);
$util->utilInit();

##########################################
##########################################

if (isset(PH::$args['file']))
    $file = PH::$args['file'];
else
    derr("argument file not set");


$util->load_config();
$util->location_filter();

$pan = $util->pan;

/** @var PanoramaConf|PANConf|BuckbeakConf|FawkesConf $v */
if ($util->configType == 'panos')
{
    // Did we find VSYS1 ?
    $v = $pan->findVirtualSystem($util->objectsLocation[0]);
    if ($v === null)
        derr($util->objectsLocation[0] . " was not found ? Exit\n");
}
elseif ($util->configType == 'panorama')
{
    $v = $pan->findDeviceGroup($util->objectsLocation[0]);
    if ($v == null)
        $v = $pan->createDeviceGroup($util->objectsLocation[0]);
}
elseif ($util->configType == 'fawkes')
{
    $v = $pan->findContainer($util->objectsLocation[0]);
    if ($v == null)
        $v = $pan->createContainer($util->objectsLocation[0]);
}


##########################################

//Todo: read XML file:
$xml = new DOMDocument;
$xml->load($file);


$addressObjectArray = array();
$addressMissingObjects = array();

$serviceObjectArray = array();
$serviceMissingObjects = array();

$userObjectArray = array();
$userMissingObjects = array();

$policyGroupObjectArray = array();
$policyGroupMissingObjects = array();

$missingURL = array();


#DH::DEBUGprintDOMDocument($xml->firstChild);

$XMLroot = $xml->documentElement;

/*
foreach( $xml->firstChild->childNodes as $node)
{
    if ($node->nodeType != XML_ELEMENT_NODE) continue;
    print $node->nodeName . "\n";
}
/*
product-grade
rs-version
using-cpm-profile
for-version
xml-purpose
base-model
account-list
system-parameters
address-group-list
service-list
traffic-mgmt-list
nat-list
l2tp-list
ipsec-proposal-list
ipsec-action-list
ike-action-list
ike-policy-list
ike-policy-group-list
schedule-list
policy-list
ras-user-group-list
radius-conf-list
ras-user-list
ras-domain-item-list
ras-server-group-list
proxy-action-list
proxy-helper-list
apps-block-profile-list
alias-list
app-action-list
dlp-sensor-list
dlp-custom-rule-list
logon-banner
device-group-list
device-list
auth-group-list
auth-domain-list
interface-list
alarm-action-list
signature-update
probe-list
load-balance-list
user-group-list
sslvpn-list
one-to-one-nat-list
dnat-list
abs-policy-list
abs-muvpn-list
abs-ipsec-action-list
policy-view
policy-tag-list
policy-filter-list
gateway-wireless-controller
geolocation-blocking
threat-correlation
tigerpaw
tls-profile-list
https-exception-override-list
webblocker-global-exception-list
clientless-vpn
vpn-portal
sdwan-action-list
revision-history
 */

//address-group-list

//service-list

//interface-list
//alias-list -> is using interface-list -> could be migrate to Zone???
//policy-list -> is using alias-list


///profile/interface-list/interface/if-item-list/item/physical-if/if-dev-name
$xml_interface_list = DH::findFirstElementOrCreate('interface-list', $XMLroot );
watchguard_getInterface($pan, $v, $xml_interface_list);


$xml_system_parameters = DH::findFirstElementOrCreate('system-parameters', $XMLroot );
$xml_route = DH::findFirstElementOrCreate('route', $xml_system_parameters );
watchguard_getRoute($pan, $xml_route);


// <abs-ipsec-action-list>
$xml_abs_ipsec_action_list = DH::findFirstElementOrCreate('abs-ipsec-action-list', $XMLroot );
watchguard_getIPsecAction($pan, $v, $xml_abs_ipsec_action_list);
#exit();


$xml_Address = DH::findFirstElementOrCreate('address-group-list', $XMLroot );
watchguard_getAddress( $v, $xml_Address );

$xml_Service = DH::findFirstElementOrCreate('service-list', $XMLroot );
watchguard_getService( $v, $xml_Service );

#policy-list is not of interest
#$xml_Policy = DH::findFirstElementOrCreate('policy-list', $XMLroot );

#read alist first into array
$alias_array = array();
$xml_alias = DH::findFirstElementOrCreate('alias-list', $XMLroot );
watchguard_alias($v, $xml_alias, $alias_array);

#print_r( $alias_array );

#read nat first into array
$nat_array = array();
$xml_alias = DH::findFirstElementOrCreate('nat-list', $XMLroot );
watchguard_nat($v, $xml_alias, $nat_array);

#print_r( $nat_array );

$xml_Policy = DH::findFirstElementOrCreate('abs-policy-list', $XMLroot );
watchguard_getPolicy( $v, $xml_Policy, $alias_array, $nat_array );


#######################################################




function print_xml_info($appx3, $print = false)
{
    $appName3 = $appx3->nodeName;

    if ($print)
        print "|13:|" . $appName3 . "\n";

    $newdoc = new DOMDocument;
    $node = $newdoc->importNode($appx3, TRUE);
    $newdoc->appendChild($node);
    $html = $newdoc->saveHTML();

    if ($print)
        print "|" . $html . "|\n";
}


function truncate_names($longString)
{
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

function normalizeNames($nameToNormalize)
{
    $nameToNormalize = trim($nameToNormalize);
    //$nameToNormalize = preg_replace('/(.*) (&#x2013;) (.*)/i', '$0 --> $1 - $3', $nameToNormalize);
    //$nameToNormalize = preg_replace("/&#x2013;/", "-", $nameToNormalize);
    $nameToNormalize = preg_replace("/[\/]+/", "_", $nameToNormalize);
    $nameToNormalize = preg_replace("/[^a-zA-Z0-9-_. ]+/", "", $nameToNormalize);
    $nameToNormalize = preg_replace("/[\s]+/", " ", $nameToNormalize);

    $nameToNormalize = preg_replace("/^[-]+/", "", $nameToNormalize);
    $nameToNormalize = preg_replace("/^[_]+/", "", $nameToNormalize);

    $nameToNormalize = preg_replace('/\(|\)/', '', $nameToNormalize);

    return $nameToNormalize;
}


function watchguard_getAddress($v, $xml)
{
    /** @var PANConf $v */
    #DH::DEBUGprintDOMDocument($xml);
    foreach( $xml->childNodes as $node) {
        if ($node->nodeType != XML_ELEMENT_NODE) continue;

        DH::DEBUGprintDOMDocument($node);
        /*
        <address-group>
         <name>xphone-Server.2.snat</name>
         <description/>
         <property>16</property>
         <addr-group-member>
          <member>
           <type>1</type>
           <host-ip-addr>10.10.2.224</host-ip-addr>
          </member>
         </addr-group-member>
        </address-group>
         */

        $name = DH::findFirstElement('name', $node);
        print "name: '" . $name->textContent . "'\n";

        $address_array = array();
        $address_array['address'] = array();
        $address_array['domain'] = array();
        $address_array['ip-network-addr'] = array();
        $address_array['range'] = array();

        $xml_addr_group_member = DH::findFirstElement('addr-group-member', $node);
        if( $xml_addr_group_member == False )
        {
            DH::DEBUGprintDOMDocument( $node );
            continue;
        }

        $counter = 1;
        foreach ($xml_addr_group_member->childNodes as $member)
        {
            if ($member->nodeType != XML_ELEMENT_NODE) continue;

            $xml_host_ip_addr = DH::findFirstElement('host-ip-addr', $member);
            $xml_domain = DH::findFirstElement('domain', $member);
            $xml_ip_network_addr = DH::findFirstElement('ip-network-addr', $member);
            $xml_start_ip_addr = DH::findFirstElement('start-ip-addr', $member);
            /*
                <start-ip-addr>10.3.100.1</start-ip-addr>
                <end-ip-addr>10.3.100.254</end-ip-addr>
             */
            if ($xml_host_ip_addr != False)
            {
                print "  * " . $xml_host_ip_addr->textContent . "\n";

                $address_array['address'][$xml_host_ip_addr->textContent] = $xml_host_ip_addr->textContent;
            }
            elseif ($xml_domain != False)
            {
                $address_array['domain'][$xml_domain->textContent] = $xml_domain->textContent;
            }
            elseif ($xml_ip_network_addr != False)
            {
                $xml_ip_mask = DH::findFirstElement('ip-mask', $member);
                $address_array['ip-network-addr'][$xml_ip_network_addr->textContent] = $xml_ip_mask->textContent;
            }
            elseif ($xml_start_ip_addr != False)
            {
                #<end-ip-addr>10.3.100.254</end-ip-addr>
                $xml_end_ip_addr = DH::findFirstElement('end-ip-addr', $member);
                $string = $xml_start_ip_addr->textContent."-".$xml_end_ip_addr->textContent;
                $address_array['range'][$string] = $string;
            }
            else
            {
                DH::DEBUGprintDOMDocument($member);
            }
        }

        if( count( $address_array['address'] ) > 0 )
        {
            if( count( $address_array['address'] ) == 1 )
            {
                foreach( $address_array['address'] as $address )
                {
                    $new_address = $v->addressStore->newAddress( $name->textContent, "ip-netmask", $address);
                }

            }
            else
            {
                $new_addressGroup = $v->addressStore->newAddressGroup( $name->textContent);
                foreach( $address_array['address'] as $address )
                {
                    $new_address = $v->addressStore->find($address);
                    if( $new_address == null )
                        $new_address = $v->addressStore->newAddress( $address, "ip-netmask", $address);
                    $new_addressGroup->addMember($new_address);
                }
            }
        }
        elseif( count( $address_array['ip-network-addr'] ) > 0 )
        {
            if( count( $address_array['ip-network-addr'] ) == 1 )
            {
                foreach( $address_array['ip-network-addr'] as $address => $mask )
                {

                    $ipv4_mask = CIDR::netmask2cidr($mask);

                    $new_address = $v->addressStore->newAddress( $name->textContent, "ip-netmask", $address."/".$ipv4_mask);
                }

            }
        }
        elseif( count( $address_array['domain'] ) > 0 )
        {
            if( count( $address_array['domain'] ) == 1 )
            {
                foreach( $address_array['domain'] as $address => $mask )
                {
                    $description = "";
                    //Todo: 20240627 - value with * must be handled differently
                    if( strpos( $address, "*" ) !== False )
                    {
                        $description = $address;
                        $address = str_replace( "*.", "", $address );
                    }

                    $new_address = $v->addressStore->newAddress( $name->textContent, "fqdn", $address);
                    $new_address->setDescription($description);
                }

            }
        }
        elseif( count( $address_array['range'] ) > 0 )
        {
            if( count( $address_array['range'] ) == 1 )
            {
                foreach( $address_array['range'] as $address => $address )
                {
                    $description = "";
                    $new_address = $v->addressStore->newAddress( $name->textContent, "ip-range", $address);
                    $new_address->setDescription($description);
                }

            }
        }
    }
}

function watchguard_getService($v, $xml)
{
    /** @var PANConf $v */
    #DH::DEBUGprintDOMDocument($xml);
    foreach( $xml->childNodes as $node)
    {
        if ($node->nodeType != XML_ELEMENT_NODE) continue;

        #DH::DEBUGprintDOMDocument($node);
        /*
            <service>
             <name>Any</name>
             <description>Any service</description>
             <property>4</property>
             <proxy-type/>
             <service-item>
              <member>
               <type>1</type>
               <protocol>0</protocol>
               <server-port>0</server-port>
              </member>
             </service-item>
             <idle-timeout>0</idle-timeout>
            </service>
         */
        $type = "not set";
        $protocol = "not set";
        $port = "not set";


        $name = DH::findFirstElement('name', $node);
        print "name: '".$name->textContent."'\n";
        #$new_service = $v->serviceStore->newService($name->textContent, "tcp", "12000");

        $service_array = array();

        $xml_service_item = DH::findFirstElement('service-item', $node);
        $counter = 1;
        foreach($xml_service_item->childNodes as $member)
        {
            if ($member->nodeType != XML_ELEMENT_NODE) continue;

            $xml_type = DH::findFirstElement('type', $member);
            if( $xml_type != False )
            {
                $type = $xml_type->textContent;
            }

            $xml_protocol = DH::findFirstElement('protocol', $member);
            if( $xml_protocol != False )
            {
                $protocol = $xml_protocol->textContent;
            }

            $xml_port = DH::findFirstElement('server-port', $member);
            if( $xml_port == False )
            {
                #<icmp-type>128</icmp-type>
                #<icmp-code>0</icmp-code>
                $icmp_type = DH::findFirstElement('icmp-type', $member);
                if( $icmp_type != False )
                {
                    $icmp_code = DH::findFirstElement('icmp-code', $member);
                    #Todo: valdiation needed as icmp is not possible in PAN-OS service
                    $port = "ICMP";
                }
                else
                {
                    $start_server = DH::findFirstElement('start-server-port', $member);
                    $end_server = DH::findFirstElement('end-server-port', $member);
                    //<start-server-port>50000</start-server-port>
                    //<end-server-port>59999</end-server-port>
                    $port = $start_server->textContent."-".$end_server->textContent;
                }
            }
            elseif( $xml_port != False )
            {
                $port = $xml_port->textContent;
            }



            #print "  * type: ".$type." - protocol: ".$protocol." - port: ".$port."\n";
            /*
            if( $protocol == 6 )
                $protocol = "tcp";
            elseif( $protocol == 17 )
                $protocol = "udp";
            else
                mwarning( "migration part needed", null, False );
            */

            if( !isset($service_array[$protocol]) )
                $service_array[$protocol] = array();

            if( $port !== "ICMP" )
                $service_array[$protocol][$port] = $port;

            /*
            if( $protocol == "tcp" || $protocol == "udp" )
            {
                if ($counter == 1) {
                    $new_service->setProtocol($protocol);
                    $new_service->setDestPort($port);
                } else
                {
                    if ($new_service->protocol() == $protocol)
                    {
                        $new_service->setDestPort($new_service->getDestPort() . "," . $port);
                    }
                    else
                    {
                        $grp_name = $new_service->name();
                        //search if other service name is already available
                        $new_service2 = $v->serviceStore->find($new_service->name() . "_" . $protocol);
                        if ($new_service2 == False)
                        {
                            $new_service2 = $v->serviceStore->newService($new_service->name() . "_" . strtoupper($protocol), $protocol, $port);

                            $new_service->setName($new_service->name()."_".strtoupper($new_service->protocol() ));

                            $grp_obj = $v->serviceStore->newServiceGroup($grp_name);

                        }
                        else
                        {
                            $new_service2->setDestPort($new_service->getDestPort() . "," . $port);
                            $grp_obj = $v->serviceStore->find($grp_name);
                        }


                        $grp_obj->addMember($new_service);
                        $grp_obj->addMember($new_service2);
                        #mwarning("different protocol, create service-group and add both TCP and UDP service. or validation if app-id", null, False);
                    }

                }
            }
            */

            $counter++;
        }

        print_r($service_array);
        print count($service_array)."\n";
        if( count($service_array) == 1)
        {
            foreach( $service_array as $protocol => $ports )
            {
                if( $protocol != 6 && $protocol != 17 )
                    continue;

                if( $protocol == 6 )
                    $protocol = "tcp";
                elseif( $protocol == 17 )
                    $protocol = "udp";
                else
                    $protocol = "tcp";

                $new_service = $v->serviceStore->newService($name->textContent, $protocol, "99999");
                $counter = 1;
                foreach($ports as $port)
                {
                    if( $counter == 1 )
                    {
                        $new_service->setDestPort($port);
                    }
                    else
                        $new_service->setDestPort( $new_service->getDestPort().",".$port);
                    $counter++;
                }
            }
        }
        else
        {

            $tcp_service = null;
            $udp_service = null;
            //create group
            foreach( $service_array as $protocol => $ports )
            {
                if( $protocol != 6 && $protocol != 17 )
                    continue;

                if( $protocol == 6 )
                    $protocol = "tcp";
                elseif( $protocol == 17 )
                    $protocol = "udp";
                else
                    $protocol = "tcp";

                $new_service = $v->serviceStore->newService($name->textContent."_".strtoupper($protocol), $protocol, "12000");

                $counter = 1;
                foreach($ports as $port)
                {
                    if( $counter == 1 )
                    {
                        $new_service->setDestPort($port);
                    }
                    else
                        $new_service->setDestPort( $new_service->getDestPort().",".$port);
                    $counter++;
                }

                if( $protocol == "tcp" )
                    $tcp_service = $new_service;
                elseif( $protocol == "udp" )
                    $udp_service = $new_service;
            }

            $new_serviceGroup = $v->serviceStore->newServiceGroup($name->textContent);
            if( $tcp_service != null )
                $new_serviceGroup->addMember($tcp_service);
            if( $udp_service != null )
                $new_serviceGroup->addMember($udp_service);
        }
    }
}

function add_from_alias_list( $v, $alias_array, $alias )
{

    if( isset($alias_array[$alias]) )
    {
        foreach( $alias_array[$alias] as $array )
        {
            if( isset( $array['address'] ) )
                $search = $array['address'];
            elseif( isset( $array['alias'] ) )
                $search = $array['alias'];

            $object = $v->addressStore->find($search);
            if( $object == null )
            {
                $object = add_from_alias_list( $v, $alias_array, $search );
            }

            return $object;
        }
    }

    return null;
}
function add_zone_from_alias_list( $v, $alias_array, $alias )
{
    if( isset($alias_array[$alias]) )
    {
        foreach( $alias_array[$alias] as $array )
        {
            if(isset($array['interface']))
            {
                $zone_obj = $v->zoneStore->find($array['interface']);
                if( $zone_obj !== null )
                    return $zone_obj;
            }
            elseif( isset($array['alias']) )
            {
                if( isset($alias_array[$array['alias']][0]['interface']) )
                {
                    $search = $alias_array[$array['alias']][0]['interface'];
                    $zone_obj = $v->zoneStore->find($search);
                    if( $zone_obj !== null )
                        return $zone_obj;
                }
            }
        }
    }

    #if(strpos($alias, "Medlinq_Remote.in") !== False)
    #    exit();

    return null;
}
function watchguard_getPolicy($v, $xml, $alias_array, $nat_array)
{
    $not_found = array();

    /** @var VirtualSystem $v */
    #DH::DEBUGprintDOMDocument($xml);
    foreach ($xml->childNodes as $node)
    {
        if ($node->nodeType != XML_ELEMENT_NODE) continue;

        $type = DH::findFirstElement('type', $node);
        $name = DH::findFirstElement('name', $node);

        if( $type->textContent != "Firewall" )
            continue;
        if( strpos( $name->textContent, "Firebox") !== False )
            continue;

        PH::print_stdout();
        PH::print_stdout("--------------------------");

        #DH::DEBUGprintDOMDocument($node);

        $rule_name = $name->textContent;
        print "name: '".$rule_name."'\n";

        /** @var SecurityRule $new_secRule */
        $new_secRule = $v->securityRules->newSecurityRule($rule_name);

        $description = DH::findFirstElement('description', $node);
        print "description: '".$description->textContent."'\n";
        $new_secRule->setDescription($description->textContent);

        $service = DH::findFirstElement('service', $node);

        $service_obj = $v->serviceStore->find($service->textContent);
        if($service_obj != False && $service_obj->name() !== "Any" && $service->textContent !== "Any")
        {
            print "service: '".$service->textContent."'\n";
            $new_secRule->services->add($service_obj);
        }
        elseif($service->textContent !== "Any")
            derr("service obj not found");

        ################
        $from = DH::findFirstElement('from-alias-list', $node);
        #DH::DEBUGprintDOMDocument($from);
        foreach ($from->childNodes as $from_alias)
        {
            if ($from_alias->nodeType != XML_ELEMENT_NODE) continue;

            //Todo: validation if alias is already available in addressStore
            #print "alias to search: '".$from_alias->textContent."'\n";

            $object_from_add = add_from_alias_list($v, $alias_array, $from_alias->textContent);
            if( $object_from_add !== null && $object_from_add->name() !== "Any" )
            {
                PH::print_stdout("add src address obj: ".$object_from_add->name());
                $new_secRule->source->addObject($object_from_add);
            }
            elseif( $object_from_add->name() !== "Any" )
            #else
            {
                mwarning( "object: ".$from_alias->textContent." not found" );
                $not_found[$rule_name]['from'][] = $from_alias->textContent;
                #derr( "object: '".$from_alias->textContent."' not found" );
            }

            ################

            $zone_from_add = add_zone_from_alias_list($v, $alias_array, $from_alias->textContent);
            if( $zone_from_add !== null && $zone_from_add->name() != "Any")
            {
                PH::print_stdout("add from zone: ".$zone_from_add->name());
                $new_secRule->from->addZone($zone_from_add);
            }
        }

        ################
        $to = DH::findFirstElement('to-alias-list', $node);
        foreach ($to->childNodes as $to_alias)
        {
            if ($to_alias->nodeType != XML_ELEMENT_NODE) continue;

            //Todo: validation if alias is already available in addressStore
            #print "alias to search: '".$to_alias->textContent."'\n";

            $object_to_add = add_from_alias_list($v, $alias_array, $to_alias->textContent);
            if( $object_to_add !== null && $object_to_add->name() !== "Any" )
            {
                PH::print_stdout("add dst address obj: ".$object_to_add->name());
                $new_secRule->destination->addObject($object_to_add);
            }
            elseif( $object_to_add->name() !== "Any" )
            #else
            {
                mwarning( "object: ".$to_alias->textContent." not found" );
                $not_found[$rule_name]['to'][] = $to_alias->textContent;
                #derr( "object: '".$to_alias->textContent."' not found" );
            }

            #################

            $zone_to_add = add_zone_from_alias_list($v, $alias_array, $to_alias->textContent);
            if( $zone_to_add !== null && $zone_to_add->name() != "Any")
            {
                PH::print_stdout("add to zone: ".$zone_to_add->name());
                $new_secRule->to->addZone($zone_to_add);
            }
        }


        $schedule = DH::findFirstElement('schedule', $node);
        if( $schedule != FALSE )
        {
            print "schedule: '".$schedule->textContent."'\n";
            if( $schedule->textContent != "Always On" && $schedule->textContent != "" )
            {
                mwarning( "find schedule object", null, False );
            }
        }

        $enable = DH::findFirstElement('enable', $node);
        if( $enable != FALSE )
        {
            #print "enable: '".$enable->textContent."'\n";
            if( $enable->textContent == 0 )
            {
                PH::print_stdout(" - Rule is disabled");
                $new_secRule->setDisabled(true);
            }
        }


        $policy_nat = DH::findFirstElement('policy-nat', $node);
        if( $policy_nat != FALSE )
        {
            if( $policy_nat->textContent != "" )
            {
                //create NAT Rule:
                /** @var VirtualSystem $v */
                $new_natRule = $v->natRules->newNatRule($new_secRule->name());

                foreach ($new_secRule->from->getAll() as $obj)
                    $new_natRule->from->addZone($obj);
                foreach ($new_secRule->source->getAll() as $obj)
                    $new_natRule->source->addObject($obj);

                foreach ($new_secRule->to->getAll() as $obj)
                {
                    $new_secRule->to->removeZone($obj, true, true);

                    $new_natRule->to->addZone($obj);
                }
                $dmz_zone = $v->zoneStore->find("DMZ");
                if($dmz_zone == null)
                    $dmz_zone = $v->zoneStore->newZone("DMZ", "layer3");
                $new_secRule->to->addZone($dmz_zone);

                foreach ($new_secRule->destination->getAll() as $obj)
                    $new_natRule->destination->addObject($obj);

                foreach ($new_secRule->services->getAll() as $obj)
                    $new_natRule->setService($obj);

                //get information for $policy_nat->textContent in NAT_array
                //add NAT_array['add-name'] as destination-nat to $new_natRule
                if( isset($nat_array[$policy_nat->textContent]) )
                {
                    $dnat_obj = $v->addressStore->find($nat_array[$policy_nat->textContent]['addr_name']);
                    $new_natRule->setDNAT($dnat_obj);

                }
            }
        }


        #DH::DEBUGprintDOMDocument($node);
        /*
        <policy>
         <name>Unhandled External Packet-00</name>
         <description>Policy added on 18.03.09 15:30.</description>
         <property>32</property>
         <service>Any</service>
         <firewall>2</firewall>
         <reject-action>1</reject-action>
         <from-alias-list>
          <alias>Unhandled External Packe.1.from</alias>
         </from-alias-list>
         <to-alias-list>
          <alias>Unhandled External Packet.1.to</alias>
         </to-alias-list>
         <proxy/>
         <traffic-mgmt/>
         <qos-marking>
          <marking-field>0</marking-field>
          <marking-method>
           <marking-type>0</marking-type>
          </marking-method>
          <priority-method>0</priority-method>
         </qos-marking>
         <nat/>
         <schedule>Always On</schedule>
         <connection-rate>0</connection-rate>
         <connection-rate-alarm/>
         <log>1</log>
         <log-for-report>0</log-for-report>
         <enable>1</enable>
         <idle-timeout>0</idle-timeout>
         <user-firewall>0</user-firewall>
         <ips-monitor-enabled>0</ips-monitor-enabled>
         <alarm/>
         <send-tcp-reset>1</send-tcp-reset>
         <policy-routing/>
         <using-global-sticky-setting>1</using-global-sticky-setting>
         <policy-sticky-timer>0</policy-sticky-timer>
         <global-1to1-nat>1</global-1to1-nat>
         <global-dnat>1</global-dnat>
         <geo-action>Global</geo-action>
         <geo-deny-page>1</geo-deny-page>
         <tor-block-enabled>1</tor-block-enabled>
        </policy>
         */
    }

    if( !empty( $not_found ) )
    {
        print_r($not_found);
        mwarning( "the above rules does have from/to parts which are not available" );
    }

}

function watchguard_alias($v, $xml, &$alias_array)
{
    /** @var VirtualSystem $v */
    #DH::DEBUGprintDOMDocument($xml);
    foreach ($xml->childNodes as $node)
    {
        if ($node->nodeType != XML_ELEMENT_NODE) continue;


        #DH::DEBUGprintDOMDocument($node);
        /*
        <alias>
         <name>Any</name>
         <description>All traffic</description>
         <property>4</property>
         <alias-member-list>
          <alias-member>
           <type>1</type>
           <user>Any</user>
           <address>Any</address>
           <interface>Any</interface>
          </alias-member>
         </alias-member-list>
        </alias>
         */

        $name_xml = DH::findFirstElement('name', $node);
        $name = $name_xml->textContent;
        $alias_member_list = DH::findFirstElement('alias-member-list', $node);
        foreach ($alias_member_list->childNodes as $node2)
        {
            if ($node2->nodeType != XML_ELEMENT_NODE)
                continue;

            $tmp_array = array();

            $address_xml = DH::findFirstElement('address', $node2);
            if( $address_xml == False )
            {
                $address_xml = DH::findFirstElement('alias-name', $node2);
                $address = $address_xml->textContent;
                $tmp_array['alias'] = $address;
            }
            else
            {
                $address = $address_xml->textContent;
                print "alias: ".$name." value: ".$address."\n";
                $tmp_array['address'] = $address;
            }


            $interface_xml = DH::findFirstElement('interface', $node2);
            if( $interface_xml !== False )
            {
                #DH::DEBUGprintDOMDocument($interface_xml);
                #&& $interface_xml->textContent !== ""
                $tmp_array['interface'] = $interface_xml->textContent;
                print "alias: ".$name." interface: ".$interface_xml->textContent."\n";
                //check if zone is already available if not create
                $zone_obj = $v->zoneStore->find($interface_xml->textContent);
                if( $zone_obj ==  null  )
                {
                    $zone_obj = $v->zoneStore->newZone($interface_xml->textContent,"layer3");
                }
            }

            $alias_array[$name][] = $tmp_array;
            #exit();
        }
    }
}

function watchguard_nat($v, $xml, &$nat_array)
{
    /** @var VirtualSystem $v */
    #DH::DEBUGprintDOMDocument($xml);
    foreach ($xml->childNodes as $node)
    {
        if ($node->nodeType != XML_ELEMENT_NODE) continue;


        #DH::DEBUGprintDOMDocument($node);
        /*
         <nat-list>
            <nat>
               <name>BAS</name>
                   <property>0</property>
                   <type>7</type>
                   <algorithm>0</algorithm>
                   <proxy-arp>0</proxy-arp>
                   <nat-item>
                    <member>
                     <addr-type>4</addr-type>
                     <port>0</port>
                     <ext-addr-name>BAS.1.snat</ext-addr-name>
                     <interface>Any-External</interface>
                     <addr-name>BAS.2.snat</addr-name>
                    </member>
                   </nat-item>
            </nat>
         */

        $name_xml = DH::findFirstElement('name', $node);
        $name = $name_xml->textContent;
        $nat_item = DH::findFirstElement('nat-item', $node);
        if( $nat_item != false )
            foreach ($nat_item->childNodes as $node2)
            {
                if ($node2->nodeType != XML_ELEMENT_NODE)continue;

                $ext_addr_name_XML = DH::findFirstElement('ext-addr-name', $node2);
                if( $ext_addr_name_XML != false )
                {
                    $ext_addr_name = $ext_addr_name_XML->textContent;
                    $nat_array[$name]['ext_addr_name'] = $ext_addr_name;
                }

                $interface_XML = DH::findFirstElement('interface', $node2);
                if( $interface_XML !== False )
                {
                    $interface = $interface_XML->textContent;
                    $nat_array[$name]['interface'] = $interface;
                }


                $addr_name_XML = DH::findFirstElement('addr-name', $node2);
                if( $addr_name_XML !== False )
                {
                    $addr_name = $addr_name_XML->textContent;
                    $nat_array[$name]['addr_name'] = $addr_name;
                }





            }

    }
}

function watchguard_getRoute($pan, $xml)
{
    /** @var PANConf $pan */
    #DH::DEBUGprintDOMDocument($xml);

    /** @var VirtualRouter $v_router */
    $vr_name = "default";

    $tmp_vr = $pan->network->virtualRouterStore->findVirtualRouter($vr_name);
    if( $tmp_vr === null )
    {
        $tmp_vr = $pan->network->virtualRouterStore->newVirtualRouter($vr_name);
    }

    foreach ($xml->childNodes as $node)
    {
        if ($node->nodeType != XML_ELEMENT_NODE) continue;

        #DH::DEBUGprintDOMDocument($node);

        /*
        <route-entry>
         <dest-address>172.30.4.0</dest-address>
         <mask>255.255.252.0</mask>
         <gateway-ip>10.254.1.42</gateway-ip>
         <port-type>-1</port-type>
         <distance>1</distance>
         <metric>1</metric>
         <card-id>0</card-id>
        </route-entry>
         */


        $xml_interface = "";

        $xml_mask = DH::findFirstElement('mask', $node);
        $mask = $xml_mask->textContent;
        $cidr_mask = CIDR::netmask2cidr($mask);
        // to CIDR


        $xml_gateway_ip = DH::findFirstElement('gateway-ip', $node);
        $ip_gateway = $xml_gateway_ip->textContent;


        $tmp_interface = $pan->network->getAllInterfaces();
        $errMesg = '';
        $query = new RQuery('interface');
        if( $query->parseFromString("ipv4 includes ".$ip_gateway, $errMsg) === FALSE )
            derr("error while parsing query: {$errMesg}");

        $res = array();
        foreach( $tmp_interface as $interface )
        {
            $queryContext['object'] = $interface;
            if( $query->matchSingleObject($queryContext) )
                $res[] = $interface;
        }
        if( count($res) == 1 )
        {
            $xml_interface = "<interface>" . $res[0]->name() . "</interface>";
            $tmp_vr->attachedInterfaces->addInterface($res[0]);
        }



        $xml_metric = DH::findFirstElement('metric', $node);
        $metric = $xml_metric->textContent;

        $xml_dest_address = DH::findFirstElement('dest-address', $node);
        $route_network = $xml_dest_address->textContent;

        $routename = $route_network."m".$cidr_mask;

        #if( $ip_version == "v4" )
        $xmlString = "<entry name=\"" . $routename . "\"><nexthop><ip-address>" . $ip_gateway . "</ip-address></nexthop><metric>" . $metric . "</metric>" . $xml_interface . "<destination>" . $route_network."/".$cidr_mask . "</destination></entry>";
        #elseif( $ip_version == "v6" )
        #    $xmlString = "<entry name=\"" . $routename . "\"><nexthop><ipv6-address>" . $ip_gateway . "</ipv6-address></nexthop><metric>" . $metric . "</metric>" . $xml_interface . "<destination>" . $route_network . "</destination></entry>";

        $newRoute = new StaticRoute('***tmp**', $tmp_vr);
        $tmpRoute = $newRoute->create_staticroute_from_xml($xmlString);


        $tmp_vr->addstaticRoute($tmpRoute);
    }
}

function watchguard_getInterface($pan, $v, $xml)
{
    /** @var PANConf $pan */

    /** @var VirtualSystem $v */
    #DH::DEBUGprintDOMDocument($xml);

    /** @var VirtualRouter $v_router */
    $vr_name = "default";
    /*
    $tmp_vr = $pan->network->virtualRouterStore->findVirtualRouter($vr_name);
    if ($tmp_vr === null) {
        $tmp_vr = $pan->network->virtualRouterStore->newVirtualRouter($vr_name);
    }
    */

    foreach ($xml->childNodes as $node)
    {
        if ($node->nodeType != XML_ELEMENT_NODE) continue;

        #DH::DEBUGprintDOMDocument($node);

        $xml_name = DH::findFirstElement('name', $node);
        $name = $xml_name->textContent;

        if( strpos( $name, "Optional" ) !== FALSE )
        {
            continue;
        }

        $xml_if_item_list = DH::findFirstElement('if-item-list', $node);

        if( $xml_if_item_list !== FALSE )
        {
            $xml_item = DH::findFirstElement('item', $xml_if_item_list);
            $xml_item_type = DH::findFirstElement('item-type', $xml_item);

            $xml_physical_if = DH::findFirstElement('physical-if', $xml_item);
            if( $xml_physical_if !== FALSE )
            {
                $xml_if_dev_name = DH::findFirstElement('if-dev-name', $xml_physical_if);
                $if_dev_name = $xml_if_dev_name->textContent;
                #PH::print_stdout();
                #PH::print_stdout("NAME: ".$name);
                #PH::print_stdout( $if_dev_name );
                #DH::DEBUGprintDOMDocument($node);

                /*
                 * <physical-if>
                    <if-num>15</if-num>
                    <if-dev-name>eth15</if-dev-name>
                    <enabled>1</enabled>
                    <if-property>1</if-property>
                    <ip-node-type>IP4_ONLY</ip-node-type>
                    <ip>10.254.1.41</ip>
                    <netmask>255.255.255.252</netmask>
                    <swap-if>
                     <has-hardware-port>1</has-hardware-port>
                     <module-type>0</module-type>
                    </swap-if>

                 */

                $xml_ip = DH::findFirstElement('ip', $xml_physical_if);
                $ip = $xml_ip->textContent;
                $xml_netmask = DH::findFirstElement('netmask', $xml_physical_if);
                $netmask = $xml_netmask->textContent;
                $cidr_netmask = CIDR::netmask2cidr($netmask);


                $int_number = str_replace("eth", "", $if_dev_name);

                $tmp_interface = $pan->network->ethernetIfStore->newEthernetIf("ethernet1/".$int_number+1);

                $tmp_interface->addIPv4Address( $ip."/".$cidr_netmask );

                //add ip address to interface

                $v->importedInterfaces->addInterface($tmp_interface);

                $tmp_zone = $v->zoneStore->newZone( $name, 'layer3' );
                $tmp_zone->attachedInterfaces->addInterface($tmp_interface);

                //default-gateway
                $xml_default_gateway = DH::findFirstElement('default-gateway', $xml_physical_if);
                if( $xml_default_gateway !== false )
                {
                    $vr_name = "default";
                    $tmp_vr = $pan->network->virtualRouterStore->findVirtualRouter($vr_name);
                    if( $tmp_vr === null )
                    {
                        $tmp_vr = $pan->network->virtualRouterStore->newVirtualRouter($vr_name);
                    }

                    $routename = "default_".str_replace("/", "_", $tmp_interface->name());
                    $default_gateway = $xml_default_gateway->textContent;
                    $ip_gateway = $default_gateway;
                    $route_network = "0.0.0.0";
                    $cidr_mask = 0;
                    $metric = "1";

                    $xml_interface = "<interface>" . $tmp_interface->name() . "</interface>";

                    $xmlString = "<entry name=\"" . $routename . "\"><nexthop><ip-address>" . $ip_gateway . "</ip-address></nexthop><metric>" . $metric . "</metric>" . $xml_interface . "<destination>" . $route_network."/".$cidr_mask . "</destination></entry>";
                    #elseif( $ip_version == "v6" )
                    #    $xmlString = "<entry name=\"" . $routename . "\"><nexthop><ipv6-address>" . $ip_gateway . "</ipv6-address></nexthop><metric>" . $metric . "</metric>" . $xml_interface . "<destination>" . $route_network . "</destination></entry>";

                    $newRoute = new StaticRoute('***tmp**', $tmp_vr);
                    $tmpRoute = $newRoute->create_staticroute_from_xml($xmlString);


                    $tmp_vr->addstaticRoute($tmpRoute);

                    $tmp_vr->attachedInterfaces->addInterface($tmp_interface);
                }
            }
        }
    }


    function watchguard_getIPsecAction($pan, $v, $xml)
    {
        /** @var PANConf $pan */
        $tmp_interface = $pan->network->tunnelIfStore->newTunnelIf("tunnel.1");
        $v->importedInterfaces->addInterface($tmp_interface);



        /** @var VirtualSystem $v */
        #DH::DEBUGprintDOMDocument($xml);

        /** @var VirtualRouter $v_router */
        $vr_name = "default";

        foreach ($xml->childNodes as $node)
        {
            if ($node->nodeType != XML_ELEMENT_NODE) continue;

            #DH::DEBUGprintDOMDocument($node);

            $xml_name = DH::findFirstElement('name', $node);
            $name = $xml_name->textContent;

            #PH::print_stdout("NAME: ".$name);
            /*
             * <abs-ipsec-action>
                 <name>Klinikum_Peine</name>
                 <description/>
                 <property>0</property>
                 <enabled>1</enabled>
                 <ike-policy>Klinikum Peine</ike-policy>
                 <ipsec-action>Klinikum_Peine</ipsec-action>
                 <local-remote-pair-list>
                  <local-remote-pair>
                   <local-addr>
                    <type>Host IP</type>
                    <value>10.10.1.79</value>
                   </local-addr>
                   <direction>bi-directional</direction>
                   <remote-addr>
                    <type>Host Range</type>
                    <value>10.195.197.1-10.195.198.254</value>
                   </remote-addr>
                   <one-to-one-nat-enabled>false</one-to-one-nat-enabled>
                   <dnat-enabled>false</dnat-enabled>
                   <dnat-src-ip>0.0.0.0</dnat-src-ip>
                   <nat-action/>
                  </local-remote-pair>
                  <local-remote-pair>
                   <local-addr>
                    <type>Host IP</type>
                    <value>10.10.2.28</value>
                   </local-addr>
                   <direction>bi-directional</direction>
                   <remote-addr>
                    <type>Host Range</type>
                    <value>10.195.197.1-10.195.198.254</value>
                   </remote-addr>
                   <one-to-one-nat-enabled>false</one-to-one-nat-enabled>
                   <dnat-enabled>false</dnat-enabled>
                   <dnat-src-ip>0.0.0.0</dnat-src-ip>
                   <nat-action/>
                  </local-remote-pair>
                  <local-remote-pair>
                   <local-addr>
                    <type>Host IP</type>
                    <value>10.10.2.36</value>
                   </local-addr>
                   <direction>bi-directional</direction>
                   <remote-addr>
                    <type>Host Range</type>
                    <value>10.195.197.1-10.195.198.254</value>
                   </remote-addr>
                   <one-to-one-nat-enabled>false</one-to-one-nat-enabled>
                   <dnat-enabled>false</dnat-enabled>
                   <dnat-src-ip>0.0.0.0</dnat-src-ip>
                   <nat-action/>
                  </local-remote-pair>
                  <local-remote-pair>
                   <local-addr>
                    <type>Host Range</type>
                    <value>10.10.2.113-10.10.2.114</value>
                   </local-addr>
                   <direction>bi-directional</direction>
                   <remote-addr>
                    <type>Host Range</type>
                    <value>10.195.197.1-10.195.198.254</value>
                   </remote-addr>
                   <one-to-one-nat-enabled>false</one-to-one-nat-enabled>
                   <dnat-enabled>false</dnat-enabled>
                   <dnat-src-ip>0.0.0.0</dnat-src-ip>
                   <nat-action/>
                  </local-remote-pair>
                 </local-remote-pair-list>
                 <allow-all-traffic>0</allow-all-traffic>
                </abs-ipsec-action>
             */

            //local-remote-pair-list>
            $xml_local_remote_pair_list = DH::findFirstElement('local-remote-pair-list', $node);

            $remote_addr_array = array();
            foreach ($xml_local_remote_pair_list->childNodes as $node2)
            {
                if ($node2->nodeType != XML_ELEMENT_NODE) continue;

                #DH::DEBUGprintDOMDocument($node2);
                /*
                 *<local-remote-pair>
                   <local-addr>
                    <type>Host Range</type>
                    <value>10.10.2.113-10.10.2.114</value>
                   </local-addr>
                   <direction>bi-directional</direction>
                   <remote-addr>
                    <type>Host Range</type>
                    <value>10.195.197.1-10.195.198.254</value>
                   </remote-addr>
                   <one-to-one-nat-enabled>false</one-to-one-nat-enabled>
                   <dnat-enabled>false</dnat-enabled>
                   <dnat-src-ip>0.0.0.0</dnat-src-ip>
                   <nat-action/>
                  </local-remote-pair>
                 */

                $xml_local_addr = DH::findFirstElement('local-addr', $node2);
                $xml_local_addr_value = DH::findFirstElement('value', $xml_local_addr);
                #PH::print_stdout("  * local-addr-value: ". $xml_local_addr_value->textContent);


                $xml_remote_addr = DH::findFirstElement('remote-addr', $node2);
                $xml_remote_addr_value = DH::findFirstElement('value', $xml_remote_addr);
                #PH::print_stdout("  * remote-addr-value: ". $xml_remote_addr_value->textContent);

                $destination = $xml_remote_addr_value->textContent;
                if( strpos($destination, "/") === FALSE )
                    $destination = $destination."/32";

                $route_name = str_replace("/", "m", $destination)."_".$name;
                $route_name = substr($route_name, 0, 31);

                $remote_addr_array[$route_name] = $destination;
            }

            #print_r($remote_addr_array);


            foreach( $remote_addr_array as $name => $destination )
            {

                if( strpos($destination, "-") === FALSE )
                {
                    $vr_name = "default";
                    $tmp_vr = $pan->network->virtualRouterStore->findVirtualRouter($vr_name);
                    if ($tmp_vr === null) {
                        $tmp_vr = $pan->network->virtualRouterStore->newVirtualRouter($vr_name);
                    }


                    $routename = $name;

                    $ip_gateway = "10.10.10.10";
                    $metric = "1";

                    $xml_interface = "";
                    $xml_interface = "<interface>tunnel.1</interface>";
                    $xml_next_hope = "<nexthop><ip-address>" . $ip_gateway . "</ip-address></nexthop>";
                    $xml_next_hope = "";

                    $xmlString = "<entry name=\"" . $routename . "\">".$xml_next_hope."<metric>" . $metric . "</metric>" . $xml_interface . "<destination>" . $destination . "</destination></entry>";

                    $newRoute = new StaticRoute('***tmp**', $tmp_vr);
                    $tmpRoute = $newRoute->create_staticroute_from_xml($xmlString);


                    $tmp_vr->addstaticRoute($tmpRoute);

                    $tmp_vr->attachedInterfaces->addInterface($tmp_interface);
                }
                else
                {
                    PH::print_stdout("Static Route can not be installed | ".$name." - ".$destination);
                }
            }

        }
    }
}
##################################################################


/*
foreach( $addressObjectArray as $storagename => $object )
{
    print "Storagename: ".$storagename. " - Name: ".$object->name()."\n";
}
*/

print "\n\n\n";

$util->save_our_work();

print "\n\n************ END OF Watchguard UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";
