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

$xml_Address = DH::findFirstElementOrCreate('address-group-list', $XMLroot );
watchguard_getAddress( $v, $xml_Address );

$xml_Service = DH::findFirstElementOrCreate('service-list', $XMLroot );
watchguard_getService( $v, $xml_Service );

$xml_Policy = DH::findFirstElementOrCreate('policy-list', $XMLroot );
watchguard_getPolicy( $v, $xml_Policy );


#######################################################
//FIND OBJECTS


/*Todo: are these objects also needed?
*
 * $xml = DH::findFirstElementOrCreate('fpc4:Root', $xml );
$xml = DH::findFirstElementOrCreate('fpc4:fpc4:Enterprise', $xml );
 */

/*
$xml = DH::findFirstElementOrCreate('fpc4:Root', $xml);
$xml = DH::findFirstElementOrCreate('fpc4:Arrays', $xml);
$xml = DH::findFirstElementOrCreate('fpc4:Array', $xml);

foreach ($xml->childNodes as $appx)
{
    if ($appx->nodeType != XML_ELEMENT_NODE) continue;




}


print "\n\n\n";
print "MISSING addressObjects:\n";
print_r($addressMissingObjects);

print "MISSING serviceObjects:\n";
print_r($serviceMissingObjects);

print "MISSING usrObjects:\n";
print_r($userMissingObjects);

print "MISSING policyGroup Objects:\n";
print_r($policyGroupMissingObjects);

*/



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

function watchguard_getPolicy($v, $xml)
{
    /** @var PANConf $v */
    #DH::DEBUGprintDOMDocument($xml);
    foreach ($xml->childNodes as $node)
    {
        if ($node->nodeType != XML_ELEMENT_NODE) continue;

        PH::print_stdout();
        PH::print_stdout("--------------------------");

        $name = DH::findFirstElement('name', $node);
        $rule_name = $name->textContent;
        print "name: '".$rule_name."'\n";
        /** @var SecurityRule $new_secRule */
        $new_secRule = $v->securityRules->newSecurityRule($rule_name);

        $description = DH::findFirstElement('description', $node);
        print "description: '".$description->textContent."'\n";

        $service = DH::findFirstElement('service', $node);
        print "service: '".$service->textContent."'\n";
        ################
        $from = DH::findFirstElement('from-alias-list', $node);
        $from_array = array();
        foreach ($from->childNodes as $from_alias)
        {
            if ($from_alias->nodeType != XML_ELEMENT_NODE) continue;
            $from_array[] = $from_alias->textContent;
            //Todo: validation if alias is already available in addressStore
            $object = $v->addressStore->find($from_alias->textContent);
            if( $object == null )
            {
                derr( "object: ".$from_alias->textContent." not found" );
            }
        }
        print_r($from_array);
        ################
        $to = DH::findFirstElement('to-alias-list', $node);
        $to_array = array();
        foreach ($to->childNodes as $to_alias)
        {
            if ($to_alias->nodeType != XML_ELEMENT_NODE) continue;
            $to_array[] = $to_alias->textContent;
            //Todo: validation if alias is already available in addressStore
            $object = $v->addressStore->find($to_alias->textContent);
            if( $object == null )
            {
                derr( "object: ".$to_alias->textContent." not found" );
            }
        }
        print_r($to_array);

        $schedule = DH::findFirstElement('schedule', $node);
        print "schedule: '".$schedule->textContent."'\n";
        if( $schedule->textContent != "Always On" && $schedule->textContent != "" )
        {
            mwarning( "find schedule object", null, False );
        }
        $enable = DH::findFirstElement('enable', $node);
        #print "enable: '".$enable->textContent."'\n";
        if( $enable->textContent == 0 )
        {
            PH::print_stdout(" - Rule is disabled");
            $new_secRule->setDisabled(true);
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
