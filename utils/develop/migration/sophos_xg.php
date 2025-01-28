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
print "************ Sophos XG UTILITY ****************\n\n";


require_once(dirname(__FILE__)."/../../../lib/pan_php_framework.php");
require_once(dirname(__FILE__)."/../../../utils/lib/UTIL.php");

$file = null;
$directory = null;

$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['file'] = array('niceName' => 'XML', 'shortHelp' => 'Watchguard Config file in XML format');
$supportedArguments['directory'] = array('niceName' => 'directory', 'shortHelp' => 'directory where the Sophos XG XML files are places');
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
    #derr("argument file not set");
    mwarning("argument file not set");




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

    derr( "Panorama config file is not yet supported" );
}
elseif ($util->configType == 'fawkes')
{
    $v = $pan->findContainer($util->objectsLocation[0]);
    if ($v == null)
        $v = $pan->createContainer($util->objectsLocation[0]);

    derr( "Strata cloud manager config file is not yet supported" );
}


##########################################

//Todo: read XML file:
#$xml = new DOMDocument;
#$xml->load($file);


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

#$XMLroot = $xml->documentElement;





//Todo: read/display all files from directory:
// argument:
if (isset(PH::$args['directory']))
    $directory = PH::$args['directory'];
else
    derr("argument directory not set");

$scanned_directory = array_diff(scandir($directory), array('..', '.'));

foreach ($scanned_directory as $filename)
{
    #PH::print_stdout("FILENAME: ".$filename);

    $xml = new DOMDocument;
    $xml->load($directory."/".$filename);
    #$xml->loadXML(file_get_contents($filename));


    $XMLroot = $xml->documentElement;

    if( strpos($filename, 'objects-ip.xml') !== false )
    {
        sophos_xg_objectsIP($v, $XMLroot);
    }
    if( strpos($filename, 'objects-ipgroup') !== false )
    {
        sophos_xg_objectsIPGROUP($v, $XMLroot);
    }
    elseif( strpos($filename, 'objects-fqdn') !== false )
    {
        sophos_xg_objectsFQDN($v, $XMLroot);
    }
    elseif( strpos($filename, 'objects-service.xml') !== false )
    {
        sophos_xg_objectsSERVICE($v, $XMLroot);
    }
    elseif( strpos($filename, 'objects-servicegroup') !== false )
    {
        sophos_xg_objectsSERVICEGROUP($v, $XMLroot);
    }
    elseif( strpos($filename, 'network-interfaces') !== false )
    {
        sophos_xg_networkINTERFACES($v, $XMLroot);
    }
    elseif( strpos($filename, 'network-lags') !== false )
    {
        //Todo: is this finalised???
        sophos_xg_networkLAGS($v, $XMLroot);
    }
    elseif( strpos($filename, 'objects-mac') !== false )
    {
        //Todo: is this of interest?
        /*
         *   <MACHost transactionid="">
                <Name>T2-Client-SBE-Wifi-08:71:90:A1:1B:7F</Name>
                <Type>MACAddress</Type>
                <MACAddress>08:71:90:A1:1B:7F</MACAddress>
              </MACHost>
         */
    }
    elseif( strpos($filename, 'network-vlans') !== false )
    {
        sophos_xg_networkVLANS($v, $XMLroot);
    }
    elseif( strpos($filename, 'network-zones') !== false )
    {
        //Todo: swaschkut 20250124 implementation needed
        /*
          <Zone transactionid="">
            <Name>LAN</Name>
            <Type>LAN</Type>
            <Description/>
            <ApplianceAccess>
              <AdminServices>
                <HTTPS>Enable</HTTPS>
                <SSH>Enable</SSH>
              </AdminServices>
              <AuthenticationServices>
                <ClientAuthentication>Enable</ClientAuthentication>
                <CaptivePortal>Enable</CaptivePortal>
                <RadiusSSO>Enable</RadiusSSO>
                <ChromebookSSO>Enable</ChromebookSSO>
              </AuthenticationServices>
              <NetworkServices>
                <DNS>Enable</DNS>
                <Ping>Enable</Ping>
              </NetworkServices>
              <OtherServices>
                <WebProxy>Enable</WebProxy>
                <SSLVPN>Enable</SSLVPN>
                <UserPortal>Enable</UserPortal>
                <WirelessProtection>Enable</WirelessProtection>
                <SMTPRelay>Enable</SMTPRelay>
                <SNMP>Enable</SNMP>
              </OtherServices>
            </ApplianceAccess>
          </Zone>
         */
    }
    elseif( strpos($filename, 'routes-static') !== false )
    {
        sophos_xg_routeSTATIC($v, $XMLroot);
    }
    elseif( strpos($filename, 'rules-firewall') !== false )
    {
        sophos_xg_rulesFIREWALL($v, $XMLroot);
    }

}



#######################################################

function sophos_xg_objectsIP( $v, $XMLroot)
{
    /** @var VirtualSystem $v */

    foreach ($XMLroot->childNodes as $child)
    {
        /** @var DOMElement $node */
        if( $child->nodeType != XML_ELEMENT_NODE )
            continue;

        if( $child->nodeName != 'IPHost' )
            continue;
        //IPHost

        /*
         * <IPHost transactionid="">
         <Name>VPN-SVA-T1-VD-10.143.65.0_24</Name>
         <IPFamily>IPv4</IPFamily>
         <HostType>Network</HostType>
         <IPAddress>10.143.65.0</IPAddress>
         <Subnet>255.255.255.0</Subnet>
        </IPHost>
         */
        $name_node = DH::findFirstElement( 'Name', $child);
        $name = normalizeNames($name_node->textContent);

        $ipfamiliy_node = DH::findFirstElement( 'IPFamily', $child);
        $hosttype_node = DH::findFirstElement( 'HostType', $child);

        $ipaddress_node = DH::findFirstElement( 'IPAddress', $child);
        $subnet_node = DH::findFirstElement( 'Subnet', $child);

        $listofipaddresses_node = DH::findFirstElement( 'ListOfIPAddresses', $child);

        $startipaddress_node = DH::findFirstElement( 'StartIPAddress', $child);
        $endipaddress_node = DH::findFirstElement( 'EndIPAddress', $child);

        if( $ipfamiliy_node->textContent != "IPv4" )
        {
            //should work seamless
        }

        if( $hosttype_node->textContent == "System Host" )
        {
            continue;
        }
        elseif( $hosttype_node->textContent == "IP" )
        {
            if( $ipaddress_node !== FALSE )
            {
                $new_address = $v->addressStore->newAddress( $name, "ip-netmask", $ipaddress_node->textContent);
            }
            else
                mwarning( "Sophos object not a valid System Host object", null, false );
        }
        elseif( $hosttype_node->textContent == "Network" )
        {
            if( $ipaddress_node !== FALSE && $subnet_node !== FALSE )
            {
                $subnetmask = CIDR::netmask2cidr($subnet_node->textContent);
                $new_address = $v->addressStore->newAddress( $name, "ip-netmask", $ipaddress_node->textContent."/".$subnetmask);
            }
            else
                mwarning( "Sophos object not a valid Network object", null, false );
        }
        elseif( $hosttype_node->textContent == "IPList" )
        {
            if( $listofipaddresses_node !== FALSE )
            {
                //create address group
                $tmp_addressgroup = $v->addressStore->newAddressGroup($name);

                $addressArray = explode(",", $listofipaddresses_node->textContent);
                foreach( $addressArray as $address )
                {
                    $new_address = $v->addressStore->find($address);
                    if( $new_address === null )
                        $new_address = $v->addressStore->newAddress( $address, "ip-netmask", $address);

                    $tmp_addressgroup->addMember($new_address);
                }
            }
        }
        elseif( $hosttype_node->textContent == "IPRange" )
        {
            if( $startipaddress_node !== FALSE && $endipaddress_node !== FALSE )
            {
                $new_address = $v->addressStore->find($name);
                if( $new_address === null )
                    $new_address = $v->addressStore->newAddress( $name, "ip-range", $startipaddress_node->textContent."-".$endipaddress_node->textContent);
            }

            else
                mwarning( "Sophos object not a valid IPRange", null, false );
        }
        else
        {
            PH::print_stdout($hosttype_node->textContent);
            DH::DEBUGprintDOMDocument($child);
            mwarning( "not implemented yet" );
            #exit();
        }
    }
}

function sophos_xg_objectsIPGROUP( $v, $XMLroot)
{
    /** @var VirtualSystem $v */

    foreach ($XMLroot->childNodes as $child)
    {
        /** @var DOMElement $node */
        if ($child->nodeType != XML_ELEMENT_NODE)
            continue;

        if ($child->nodeName != 'IPHostGroup')
            continue;


        $name_node = DH::findFirstElement( 'Name', $child);
        $name = normalizeNames($name_node->textContent);

        $tmpGroup = $v->addressStore->newAddressGroup($name);

        $hostList_node = DH::findFirstElement( 'HostList', $child);
        if( $hostList_node !== FALSE )
        {
            foreach( $hostList_node->childNodes as $host )
            {
                /** @var DOMElement $node */
                if ($host->nodeType != XML_ELEMENT_NODE)
                    continue;

                $obj_name = normalizeNames($host->textContent);
                $tmp_adr = $v->addressStore->find($obj_name);
                if($tmp_adr !== null)
                    $tmpGroup->addMember($tmp_adr);
                else
                {
                    mwarning( "adr object: $obj_name not found", null, false );
                }
            }
        }
        /*
         *   <IPHostGroup transactionid="">
            <Name>LAN Group IGZ Falkenberg</Name>
            <Description/>
            <HostList>
              <Host>LAN IGZ-L Geb1 192.168.191.0/24</Host>
              <Host>LAN IGZ-L Server 192.168.181.0/24</Host>
              <Host>LAN IGZ-L Transfer 192.168.180.0/24</Host>
            </HostList>
            <IPFamily>IPv4</IPFamily>
          </IPHostGroup>
         */
    }
}

function sophos_xg_objectsSERVICE( $v, $XMLroot)
{
    /** @var VirtualSystem $v */

    foreach ($XMLroot->childNodes as $child)
    {
        $tmp_servicegroup = null;

        /** @var DOMElement $node */
        if( $child->nodeType != XML_ELEMENT_NODE )
            continue;

        if( $child->nodeName != 'Services' )
            continue;

        $name_node = DH::findFirstElement( 'Name', $child);
        $name = normalizeNames($name_node->textContent);

        $type_node = DH::findFirstElement( 'Type', $child);

        $serviceDetails_node = DH::findFirstElement( 'ServiceDetails', $child);
        $serviceCount = 0;
        foreach( $serviceDetails_node->childNodes as $serviceDetail_node)
        {
            /** @var DOMElement $serviceDetail_node */
            if ($serviceDetail_node->nodeType != XML_ELEMENT_NODE)
                continue;
            $serviceCount++;

        }
        if( $serviceCount > 1 )
        {
            $tmp_servicegroup = $v->serviceStore->newServiceGroup($name);
        }

        foreach( $serviceDetails_node->childNodes as $serviceDetail_node)
        {
            $newService = null;

            /** @var DOMElement $serviceDetail_node */
            if( $serviceDetail_node->nodeType != XML_ELEMENT_NODE )
                continue;

            if( $type_node->textContent == "TCPorUDP" )
            {

                $sourcePort_node = DH::findFirstElement( 'SourcePort', $serviceDetail_node);
                $destinationPort_node = DH::findFirstElement( 'DestinationPort', $serviceDetail_node);
                $protocol_node = DH::findFirstElement( 'Protocol', $serviceDetail_node);

                $protocol = $protocol_node->textContent;
                if( $protocol == "TCP" )
                    $protocol = 'tcp';
                elseif( $protocol == "UDP" )
                    $protocol = 'udp';

                $destinationPort = str_replace(":", "-", $destinationPort_node->textContent);
                $sourcePort = str_replace(":", "-", $sourcePort_node->textContent);

                if( $sourcePort == "1-65535" )
                {
                    $newService = $v->serviceStore->find($protocol."-".$destinationPort);
                    if( $newService === null )
                        $newService = $v->serviceStore->newService( $protocol."-".$destinationPort, $protocol, $destinationPort );
                }
                else
                {
                    $newService = $v->serviceStore->find($protocol."-".$destinationPort."s".$sourcePort);
                    if( $newService === null )
                        $newService = $v->serviceStore->newService( $protocol."-".$destinationPort."s".$sourcePort, $protocol, $destinationPort, "", $sourcePort_node->textContent, );
                }

                /*
                 * <Services transactionid="">
                 <Name>AOL</Name>
                 <Type>TCPorUDP</Type>
                 <ServiceDetails>
                  <ServiceDetail>
                   <SourcePort>1:65535</SourcePort>
                   <DestinationPort>5190:5194</DestinationPort>
                   <Protocol>TCP</Protocol>
                  </ServiceDetail>
                 </ServiceDetails>
                </Services>
                 */
            }
            elseif( $type_node->textContent == "IP" )
            {
                #DH::DEBUGprintDOMDocument($child);
                $protocolName_node = DH::findFirstElement( 'ProtocolName', $serviceDetail_node);
                //is there also a protocol# available


                $description = "";

                $newService = $v->serviceStore->find("tmp-" . $name);
                if( $newService === null )
                {
                    $newService = $v->serviceStore->newService("tmp-" . $name, "tcp", "1-65535", $description);
                    $newService->setDescription( "protocol-id:{".$protocolName_node->textContent."}" );
                }
            }
            elseif( $type_node->textContent == "ICMP" )
            {
                #DH::DEBUGprintDOMDocument($child);
                $icmpType_node = DH::findFirstElement( 'ICMPType', $serviceDetail_node);
                $icmpCode_node = DH::findFirstElement( 'ICMPCode', $serviceDetail_node);
                $description = "";

                $newService = $v->serviceStore->find("tmp-" . $name);
                if( $newService === null )
                {
                    $newService = $v->serviceStore->newService("tmp-" . $name, "tcp", "1-65535", $description);
                    $newService->setDescription( "icmptype:{".$icmpType_node->textContent."},icmpcode:{".$icmpCode_node->textContent."}" );
                }
            }
            elseif( $type_node->textContent == "ICMPv6" )
            {
                $icmpv6Type_node = DH::findFirstElement( 'ICMPv6Type', $serviceDetail_node);
                $icmpv6Code_node = DH::findFirstElement( 'ICMPv6Code', $serviceDetail_node);

                $description = "";

                $newService = $v->serviceStore->find("tmp-" . $name);
                if( $newService === null )
                {
                    $newService = $v->serviceStore->newService("tmp-" . $name, "tcp", "1-65535", $description);
                    $newService->set_node_attribute('error', 'Service Protocol found [' . $name . '] and Protocol [ICMPv6] - Replace it by the right app-id - tcp 6500 is used');
                    $newService->setDescription( "icmpv6type:{".$icmpv6Type_node->textContent."},icmpv6code:{".$icmpv6Code_node->textContent."}" );
                }
            }
            else
            {
                PH::print_stdout($type_node->textContent);
                DH::DEBUGprintDOMDocument($child);
                mwarning( "not implemented yet" );
                #exit();
            }

            if( $serviceCount > 1 )
            {
                if( $newService !== null )
                    $tmp_servicegroup->addMember($newService);
            }
            else
            {
                if( $newService !== null && strpos( $newService->name(), "tmp-" ) === FALSE )
                {
                    $newService->setName($name);
                }

            }
        }
    }
}


function sophos_xg_objectsSERVICEGROUP( $v, $XMLroot)
{
    /** @var VirtualSystem $v */

    foreach ($XMLroot->childNodes as $child)
    {
        /** @var DOMElement $node */
        if ($child->nodeType != XML_ELEMENT_NODE)
            continue;

        if ($child->nodeName != 'ServiceGroup')
            continue;


        $name_node = DH::findFirstElement( 'Name', $child);
        $name = normalizeNames($name_node->textContent);

        $tmpGroup = $v->serviceStore->newServiceGroup($name);

        $serviceList_node = DH::findFirstElement( 'ServiceList', $child);
        if( $serviceList_node !== FALSE )
        {
            foreach( $serviceList_node->childNodes as $service  )
            {
                /** @var DOMElement $node */
                if ($service->nodeType != XML_ELEMENT_NODE)
                    continue;

                $obj_name = normalizeNames($service->textContent);
                $tmp_srv = $v->serviceStore->find($obj_name);
                if( $tmp_srv === null )
                {
                    $tmp_srv = $v->serviceStore->find("tmp-".$obj_name);
                    if( $tmp_srv === null )
                    {
                        $tmp_srv = $v->serviceStore->newService("tmp-".$obj_name, "tcp", "65000",);
                    }
                }

                if( $tmp_srv !== null )
                    $tmpGroup->addMember($tmp_srv);
            }
        }
    }
}
function sophos_xg_objectsFQDN( $v, $XMLroot)
{
    /** @var VirtualSystem $v */

    foreach ($XMLroot->childNodes as $child)
    {
        /** @var DOMElement $node */
        if ($child->nodeType != XML_ELEMENT_NODE)
            continue;

        if( $child->nodeName != 'FQDNHost' )
            continue;


        $name_node = DH::findFirstElement( 'Name', $child);
        $name = normalizeNames($name_node->textContent);

        $fqdn_node = DH::findFirstElement( 'FQDN', $child);

        $new_address = $v->addressStore->find($name);
        if( $new_address === null )
            $new_address = $v->addressStore->newAddress( $name, "fqdn", $fqdn_node->textContent );
    }
}

function sophos_xg_networkINTERFACES( $v, $XMLroot)
{
    /** @var VirtualSystem $v */

    foreach ($XMLroot->childNodes as $child)
    {
        /** @var DOMElement $node */
        if ($child->nodeType != XML_ELEMENT_NODE)
            continue;

        if ($child->nodeName != 'Interface')
            continue;



        $hardware_node = DH::findFirstElement( 'Hardware', $child);
        $hardware_name = $hardware_node->textContent;

        $name_node = DH::findFirstElement( 'Name', $child);
        $name = $name_node->textContent;

        $ipv4Configuration_node = DH::findFirstElement( 'IPv4Configuration', $child);
        $ipv6Configuration_node = DH::findFirstElement( 'IPv6Configuration', $child);

        $networkzone_node = DH::findFirstElement( 'NetworkZone', $child);
        $networkzone = $networkzone_node->textContent;

        $ipaddress_node = DH::findFirstElement( 'IPAddress', $child);
        if( $ipaddress_node !== false )
            $ipaddress = $ipaddress_node->textContent;
        else
            $ipaddress = false;

        $netmask_node = DH::findFirstElement( 'Netmask', $child);
        if( $netmask_node !== false )
            $netmask = $netmask_node->textContent;
        else
            $netmask = false;


        $status_node = DH::findFirstElement( 'Status', $child);
        $status = $status_node->textContent;

        $newInterface = $v->owner->network->ethernetIfStore->newEthernetIf( $name, "layer3" );
        $v->importedInterfaces->addInterface($newInterface);

        if( $ipv4Configuration_node->textContent == "Enable" )
        {
            if( !empty($ipaddress) )
            {
                $subnetmask = CIDR::netmask2cidr( $netmask );
                $newInterface->addIPv4Address( $ipaddress."/".$subnetmask );
            }
        }

        if( $status == "Disabled" )
        {
            $newInterface->setLinkState("down");
        }

        /** @var Zone $zone */
        #$zone = $v->zoneStore->findOrCreate($networkzone);
        #$zone->attachedInterfaces->addInterface($newInterface);

        /*
         * <Interface transactionid="">
         <IPv4Configuration>Enable</IPv4Configuration>
         <IPv6Configuration>Disable</IPv6Configuration>
         <Hardware>PortMGMT1</Hardware>
         <Name>PortMGMT1</Name>
         <NetworkZone>Management</NetworkZone>
         <IPv4Assignment>Static</IPv4Assignment>
         <IPv6Assignment/>
         <DHCPRapidCommit>Disable</DHCPRapidCommit>
         <InterfaceSpeed>Auto Negotiate</InterfaceSpeed>
         <AutoNegotiation>Enable</AutoNegotiation>
         <FEC>Off</FEC>
         <BreakoutMembers>0</BreakoutMembers>
         <BreakoutSource/>
         <MTU>1500</MTU>
         <MSS>
          <OverrideMSS>Disable</OverrideMSS>
          <MSSValue>1460</MSSValue>
         </MSS>
         <Status>Connected, 1000 Mbps - Full Duplex, FEC off</Status>
        ///// <Status>Disabled</Status>
         <MACAddress>Default</MACAddress>
         <IPAddress>172.22.89.1</IPAddress>
         <Netmask>255.255.255.224</Netmask>
        </Interface>
         */
    }
}

function sophos_xg_networkLAGS( $v, $XMLroot)
{
    /** @var VirtualSystem $v */

    foreach ($XMLroot->childNodes as $child)
    {
        /** @var DOMElement $node */
        if ($child->nodeType != XML_ELEMENT_NODE)
            continue;

        if ($child->nodeName != 'LAG')
            continue;

        //Todo: swaschkut 20250124 check what is missing
        #DH::DEBUGprintDOMDocument($child);

        $name_node = DH::findFirstElement( 'Name', $child);
        if( $name_node === false )
            continue;

        $name = $name_node->textContent;

        $ipv4Configuration_node = DH::findFirstElement( 'IPv4Configuration', $child);
        $ipv6Configuration_node = DH::findFirstElement( 'IPv6Configuration', $child);

        $ipv4Address_node = DH::findFirstElement( 'IPv4Address', $child);
        $ipv4Netmask_node = DH::findFirstElement( 'Netmask', $child);
        $subnetmask = CIDR::netmask2cidr( $ipv4Netmask_node->textContent );

        $aeInterface = $v->owner->network->aggregateEthernetIfStore->newEthernetIf( $name, "layer3" );


        $memberinterface_node = DH::findFirstElement( 'MemberInterface', $child);
        foreach( $memberinterface_node->childNodes as $interface_node )
        {
            /** @var DOMElement $node */
            if ($interface_node->nodeType != XML_ELEMENT_NODE)
                continue;

            $memberInterface = $interface_node->textContent;

            $interfaceOBJ = $v->owner->network->ethernetIfStore->newEthernetIf( $memberInterface, "aggregate-group", $name );

            #$interfaceOBJ->remove();
            /*
             *  <MemberInterface>
              <Interface>PortE1</Interface>
              <Interface>PortE2</Interface>
             </MemberInterface>
         */
        }


        /*
         * <LAG transactionid="">
         <Hardware>Uplink</Hardware>
         <Name>Uplink</Name>
         <MemberInterface>
          <Interface>PortE1</Interface>
          <Interface>PortE2</Interface>
         </MemberInterface>
         <Mode>802.3ad(LACP)</Mode>
         <NetworkZone>LAN</NetworkZone>
         <IPAssignment>Static</IPAssignment>
         <IPv4Configuration>Enable</IPv4Configuration>
         <IPv6Configuration>Disable</IPv6Configuration>
         <InterfaceSpeed>Auto Negotiate</InterfaceSpeed>
         <AutoNegotiation>Enable</AutoNegotiation>
         <FEC>Off</FEC>
         <MTU>1500</MTU>
         <MACAddress>Default</MACAddress>
         <MSS>
          <OverrideMSS>Disable</OverrideMSS>
          <MSSValue>1460</MSSValue>
         </MSS>
         <IPv4Address>10.255.255.254</IPv4Address>
         <Netmask>255.255.255.0</Netmask>
         <XmitHashPolicy>Layer2</XmitHashPolicy>
        </LAG>
         */
    }
}

function sophos_xg_networkVLANS( $v, $XMLroot)
{
    /** @var VirtualSystem $v */

    foreach ($XMLroot->childNodes as $child)
    {
        /** @var DOMElement $node */
        if ($child->nodeType != XML_ELEMENT_NODE)
            continue;

        if ($child->nodeName != 'VLAN')
            continue;

        $ipv4Enable = false;
        $ipv6Enable = false;

        //subinterface
        /*
         <VLAN transactionid="">
            <Zone>T1</Zone>
            <Interface>Uplink</Interface>
            <Hardware>Uplink.1401</Hardware>
            <Name>Uplink.1401</Name>
            <VLANID>1401</VLANID>
            <IPv4Configuration>Enable</IPv4Configuration>
            <IPv6Configuration>Disable</IPv6Configuration>
            <IPv4Assignment>Static</IPv4Assignment>
            <IPv6Address/>
            <IPv6Prefix/>
            <IPv6GatewayName/>
            <IPv6GatewayAddress/>
            <LocalIP/>
            <Status>Connected, 20000 Mbps - Full Duplex, FEC off</Status>
            <IPv6Assignment/>
            <DHCPRapidCommit/>
            <IPAddress>172.22.140.1</IPAddress>
            <Netmask>255.255.255.0</Netmask>
          </VLAN>
         */

        $zone_node = DH::findFirstElement( 'Zone', $child);
        $tmp_zone = $v->zoneStore->findOrCreate($zone_node->textContent);


        $name_node = DH::findFirstElement( 'Name', $child);
        $name = $name_node->textContent;

        //MAIN interface
        $interface_node = DH::findFirstElement( 'Interface', $child);
        //subinterface
        $hardware_node = DH::findFirstElement( 'Hardware', $child);
        //VLANID
        $vlanid_node = DH::findFirstElement( 'VLANID', $child);

        $ipv4Configuration_node = DH::findFirstElement( 'IPv4Configuration', $child);
        $ipv6Configuration_node = DH::findFirstElement( 'IPv6Configuration', $child);

        if( $ipv4Configuration_node->textContent == "Enable" )
        {
            $ipv4Enable = true;
            $ipv4Address_node = DH::findFirstElement( 'IPAddress', $child);
            $ipv4Netmask_node = DH::findFirstElement( 'Netmask', $child);
            $subnetmask = CIDR::netmask2cidr( $ipv4Netmask_node->textContent );
        }

        if( $ipv6Configuration_node->textContent == "Enable" )
        {
            /*
                <IPv6Address/>
                <IPv6Prefix/>
                <IPv6GatewayName/>
                <IPv6GatewayAddress/>
                <LocalIP/>
             */
        }

        $mainInterface = $v->owner->network->ethernetIfStore->find( $interface_node->textContent );
        $mainAEInterface = $v->owner->network->aggregateEthernetIfStore->find( $interface_node->textContent );
        if( $mainInterface === null && $mainAEInterface !== null )
            $mainInterface = $mainAEInterface;


        if( $mainInterface === null )
            $mainInterface = $v->owner->network->aggregateEthernetIfStore->newEthernetIf( $interface_node->textContent );

        #DH::DEBUGprintDOMDocument($child);
        if( $mainInterface !== null )
        {
            //create subinterface
            /** @var EthernetInterface $tmp_sub */
            $tmp_sub = $mainInterface->addSubInterface($vlanid_node->textContent, $hardware_node->textContent);
            $v->importedInterfaces->addInterface($tmp_sub);
            #$tmp_zone->attachedInterfaces->addInterface($tmp_sub);


            if($ipv4Enable)
            {
                $tmp_sub->addIPv4Address($ipv4Address_node->textContent."/".$subnetmask );
            }
            #DH::DEBUGprintDOMDocument($child);
        }
        else
        {
            derr("interface ".$interface_node->textContent." not found", null, false);
        }

    }
}

function sophos_xg_routeSTATIC( $v, $XMLroot)
{
    /** @var VirtualSystem $v */

    foreach ($XMLroot->childNodes as $child)
    {
        /** @var DOMElement $node */
        if ($child->nodeType != XML_ELEMENT_NODE)
            continue;

        if ($child->nodeName != 'UnicastRoute')
            continue;


        $ipfamiliy_node = DH::findFirstElement( 'IPFamily', $child);
        $destinationIP_node = DH::findFirstElement( 'DestinationIP', $child);
        $netmask_node = DH::findFirstElement( 'Netmask', $child);
        $subnetmask = CIDR::netmask2cidr( $netmask_node->textContent );
        $route_network = $destinationIP_node->textContent."/".$subnetmask;

        $routename = "R-".$destinationIP_node->textContent."m".$subnetmask;

        $gateway_node = DH::findFirstElement( 'Gateway', $child);
        $ip_gateway = $gateway_node->textContent;

        $interface_node = DH::findFirstElement( 'Interface', $child);


        $distance_node = DH::findFirstElement( 'Distance', $child);
        $metric = $distance_node->textContent;

        $new_router = $v->owner->network->virtualRouterStore->findVirtualRouter("default");
        if( $new_router === null )
            $new_router = $v->owner->network->virtualRouterStore->newVirtualRouter("default");


        $xml_interface = "<interface>" . $interface_node->textContent . "</interface>";
        $tmp_interface = $v->owner->network->find($interface_node->textContent);
        if( $tmp_interface != null )
        {
            $new_router->attachedInterfaces->addInterface($tmp_interface);
        }


        if( $ipfamiliy_node->textContent == "IPv4" )
            $xmlString = "<entry name=\"" . $routename . "\"><nexthop><ip-address>" . $ip_gateway . "</ip-address></nexthop><metric>" . $metric . "</metric>" . $xml_interface . "<destination>" . $route_network . "</destination></entry>";
        elseif( $ipfamiliy_node->textContent == "IPv6" )
            $xmlString = "<entry name=\"" . $routename . "\"><nexthop><ipv6-address>" . $ip_gateway . "</ipv6-address></nexthop><metric>" . $metric . "</metric>" . $xml_interface . "<destination>" . $route_network . "</destination></entry>";


        $newRoute = new StaticRoute('***tmp**', $new_router);
        $tmpRoute = $newRoute->create_staticroute_from_xml($xmlString);

        $new_router->addstaticRoute($tmpRoute);


        /*
           <UnicastRoute transactionid="">
            <IPFamily>IPv4</IPFamily>
            <DestinationIP>10.143.0.0</DestinationIP>
            <Netmask>255.255.0.0</Netmask>
            <Gateway>172.22.80.26</Gateway>
            <Interface>Uplink.804</Interface>
            <Distance>0</Distance>
            <AdministrativeDistance>1</AdministrativeDistance>
          </UnicastRoute>
         */

    }

}


function sophos_xg_rulesFIREWALL( $v, $XMLroot)
{
    /** @var VirtualSystem $v */

    foreach ($XMLroot->childNodes as $child)
    {
        /** @var DOMElement $node */
        if ($child->nodeType != XML_ELEMENT_NODE)
            continue;

        if ($child->nodeName != 'FirewallRule')
            continue;

        $name_node = DH::findFirstElement( 'Name', $child);
        $name = normalizeNames( $name_node->textContent );
        $newRule = $v->securityRules->newSecurityRule($name);


        $position_node = DH::findFirstElement( 'Position', $child);
        if( $position_node->textContent === "After" )
        {
            $after_node = DH::findFirstElement( 'After', $child);
            $after_name_node = DH::findFirstElement( 'Name', $after_node);
            $after_rule_name = normalizeNames( $after_name_node->textContent );
            $after_rule = $v->securityRules->find($after_rule_name);
            /*
             <After>
              <Name>T1-ADMCenter &gt; T1-1641-Proxmox</Name>
            </After>
             */
            if( $after_rule != null )
            {
                $v->securityRules->moveRuleAfter($newRule, $after_rule);
            }
            else
            {
                #DH::DEBUGprintDOMDocument($child);
            }

        }

/*
  <FirewallRule transactionid="">
    <Name>T2-MA &gt; T1-BYDProjectProc-SMB</Name>
    <Description/>
    <IPFamily>IPv4</IPFamily>
    <Status>Enable</Status>
    <Position>After</Position>
    <PolicyType>User</PolicyType>
    <After>
      <Name>T2-SSLVPN &gt; T1-BYDProjectProc</Name>
    </After>
    <UserPolicy>
      <Action>Accept</Action>
      <LogTraffic>Enable</LogTraffic>
      <SourceZones>
        <Zone>LAN</Zone>
        <Zone>WAN</Zone>
        <Zone>DMZ</Zone>
      </SourceZones>
      <DestinationZones>
        <Zone>T1</Zone>
      </DestinationZones>
      <Schedule>All The Time</Schedule>
      <SkipLocalDestined>Disable</SkipLocalDestined>
      <MatchIdentity>Enable</MatchIdentity>
      <WebFilter>None</WebFilter>
      <WebCategoryBaseQoSPolicy> </WebCategoryBaseQoSPolicy>
      <BlockQuickQuic>Disable</BlockQuickQuic>
      <ScanVirus>Disable</ScanVirus>
      <ZeroDayProtection>Disable</ZeroDayProtection>
      <ProxyMode>Disable</ProxyMode>
      <DecryptHTTPS>Disable</DecryptHTTPS>
      <ApplicationControl>None</ApplicationControl>
      <ApplicationBaseQoSPolicy> </ApplicationBaseQoSPolicy>
      <IntrusionPrevention>None</IntrusionPrevention>
      <TrafficShappingPolicy>None</TrafficShappingPolicy>
      <WebFilterInternetScheme>Disable</WebFilterInternetScheme>
      <ApplicationControlInternetScheme>Disable</ApplicationControlInternetScheme>
      <DSCPMarking>-1</DSCPMarking>
      <ScanSMTP>Disable</ScanSMTP>
      <ScanSMTPS>Disable</ScanSMTPS>
      <ScanIMAP>Disable</ScanIMAP>
      <ScanIMAPS>Disable</ScanIMAPS>
      <ScanPOP3>Disable</ScanPOP3>
      <ScanPOP3S>Disable</ScanPOP3S>
      <ScanFTP>Disable</ScanFTP>
      <SourceSecurityHeartbeat>Disable</SourceSecurityHeartbeat>
      <MinimumSourceHBPermitted>No Restriction</MinimumSourceHBPermitted>
      <DestSecurityHeartbeat>Disable</DestSecurityHeartbeat>
      <MinimumDestinationHBPermitted>No Restriction</MinimumDestinationHBPermitted>
      <DataAccounting>Disable</DataAccounting>
      <ShowCaptivePortal>Disable</ShowCaptivePortal>
      <Identity>
        <Member>fbra@projekt.igz.local</Member>
        <Member>fbra@igz.com</Member>
        <Member>slu@igz.com</Member>
        <Member>ski@projekt.igz.local</Member>
        <Member>slu@projekt.igz.local</Member>
        <Member>hha@igz.com</Member>
        <Member>hha@projekt.igz.local</Member>
        <Member>ski@igz.com</Member>
      </Identity>
      <SourceNetworks>
        <Network>T2-SSLVPN-Intern-192.168.248.0_24</Network>
        <Network>T2-MA-172.22.152.0_22</Network>
        <Network>T2-IGZintern-172.22.128.0_21</Network>
        <Network>T2-SSLVPN-vpn.igz.com-10.242.0.0_24</Network>
        <Network>T2-SSLVPN-ras.igz.com-10.242.2.0/24</Network>
        <Network>T2-G1-3-192.168.191.0-192.168.193.254</Network>
      </SourceNetworks>
      <Services>
        <Service>SMB</Service>
        <Service>tcp/5985</Service>
        <Service>tcp/5986</Service>
      </Services>
      <DestinationNetworks>
        <Network>T1-IGZBYDPROJPROC2-172.22.160.13_32</Network>
        <Network>T1-IGZBYDPROJPROC3-172.22.160.14_32</Network>
        <Network>T1-IGZBYDPROJPROC-172.22.160.4_32</Network>
      </DestinationNetworks>
    </UserPolicy>
  </FirewallRule>
 */
        $networkPolicy_node = DH::findFirstElement( 'NetworkPolicy', $child);
        $userPolicy_node = DH::findFirstElement( 'UserPolicy', $child);
        if( $networkPolicy_node !== false )
            $Policy_node = $networkPolicy_node;
        elseif( $userPolicy_node !== false )
            $Policy_node = $userPolicy_node;

        if( $networkPolicy_node !== false || $userPolicy_node !== false )
        {
            $action_node = DH::findFirstElement('Action', $Policy_node);
            if( $action_node->textContent === "Accept" )
            {
                $newRule->setAction("allow");
            }
            elseif( $action_node->textContent === "Drop" )
            {
                $newRule->setAction("drop");
            }
            elseif( $action_node->textContent === "Reject" )
            {
                $newRule->setAction("reset-both");
            }

            else
            {
                print "ACTION: ".$action_node->textContent."\n";
                exit();
            }
            $logTraffic_node = DH::findFirstElement('LogTraffic', $Policy_node);

            $sourceZones_node = DH::findFirstElement('SourceZones', $Policy_node);
            if ($sourceZones_node !== false)
                foreach ($sourceZones_node->childNodes as $sourceZone) {
                    /** @var DOMElement $sourceZone */
                    if ($sourceZone->nodeType != XML_ELEMENT_NODE)
                        continue;

                    $src_zone = $v->zoneStore->findOrCreate($sourceZone->textContent);
                    $newRule->from->addZone($src_zone);
                }

            $destinationZones_node = DH::findFirstElement('DestinationZones', $Policy_node);
            if ($destinationZones_node !== false)
                foreach ($destinationZones_node->childNodes as $destinationZone)
                {
                    /** @var DOMElement $destinationZone */
                    if ($destinationZone->nodeType != XML_ELEMENT_NODE)
                        continue;

                    $dst_zone = $v->zoneStore->findOrCreate($destinationZone->textContent);
                    $newRule->to->addZone($dst_zone);
                }


            $sourceNetworks_node = DH::findFirstElement('SourceNetworks', $Policy_node);
            if ($sourceNetworks_node !== false)
                foreach ($sourceNetworks_node->childNodes as $sourceNetwork)
                {
                    /** @var DOMElement $sourceNetwork */
                    if ($sourceNetwork->nodeType != XML_ELEMENT_NODE)
                        continue;

                    $addr_obj = $v->addressStore->find($sourceNetwork->textContent);
                    if ($addr_obj !== null)
                        $newRule->source->addObject($addr_obj);
                }


            $destinationNetworks_node = DH::findFirstElement('DestinationNetworks', $Policy_node);
            if ($destinationNetworks_node !== false)
                foreach ($destinationNetworks_node->childNodes as $destinationNetwork)
                {
                    /** @var DOMElement $destinationNetwork */
                    if ($destinationNetwork->nodeType != XML_ELEMENT_NODE)
                        continue;

                    $addr_obj = $v->addressStore->find($destinationNetwork->textContent);
                    if ($addr_obj !== null)
                        $newRule->destination->addObject($addr_obj);
                }


            $services_node = DH::findFirstElement('Services', $Policy_node);
            if ($services_node !== false)
            {
                $continue = false;

                foreach ($services_node->childNodes as $service_node)
                {
                    /** @var DOMElement $service_node */
                    if ($service_node->nodeType != XML_ELEMENT_NODE)
                        continue;

                    $orig_service_name = $service_node->textContent;
                    #print "Service1: " . $service_node->textContent . "\n";


                    $service_node->textContent = normalizeNames($orig_service_name);

                    //&amp;
                    $srv_obj = $v->serviceStore->find($service_node->textContent);
                    if ($srv_obj !== null)
                        $newRule->services->add($srv_obj);
                    else
                    {
                        $service_node->textContent = str_replace("(", "", $service_node->textContent);
                        $service_node->textContent = str_replace(")", "", $service_node->textContent);
                        $service_node->textContent = str_replace("RDP", "tcp/3389", $service_node->textContent);
                        if (strpos($service_node->textContent, " &amp; ") === false)
                        {
                            if (strpos($service_node->textContent, " & ") !== false)
                                $service_node->textContent = str_replace(" & ", " &amp; ", $service_node->textContent);
                            else
                                $service_node->textContent = str_replace(" ", " &amp; ", $service_node->textContent);
                        }

                        if (strpos($service_node->textContent, " &amp; ") !== false || strpos($service_node->textContent, " & ") !== false) {
                            if (strpos($service_node->textContent, " &amp; ") !== false)
                                $service_array = explode(" &amp; ", $service_node->textContent);
                            elseif (strpos($service_node->textContent, " & ") !== false)
                                $service_array = explode(" & ", $service_node->textContent);

                            foreach ($service_array as $service)
                            {
                                #print "Service2: " . $service . "\n";
                                $service_array = explode("/", $service);
                                if (count($service_array) == 2) {
                                    $srv_obj = $v->serviceStore->find($service_array[0] . "-" . $service_array[1]);
                                    if ($srv_obj === null)
                                        $srv_obj = $v->serviceStore->newService($service_array[0] . "-" . $service_array[1], $service_array[0], $service_array[1]);
                                    $newRule->services->add($srv_obj);
                                } else {
                                    print "RULE: ".$newRule->name()."\n";
                                    mwarning("Service not found '" . $orig_service_name."'", null, false);
                                    $continue = true;
                                    break;
                                }


                            }
                        } elseif (strpos($service_node->textContent, "/") !== false) {
                            $service_array = explode("/", $service_node->textContent);

                            if (strpos($service_array[0], "-") !== false)
                            {
                                $tcp_name = "tcp-" . $service_array[1];
                                $srv_obj = $v->serviceStore->find($tcp_name);
                                if ($srv_obj === null)
                                    $srv_obj = $v->serviceStore->newService($tcp_name, "tcp", $service_array[1]);
                                $newRule->services->add($srv_obj);

                                $udp_name = "udp-" . $service_array[1];
                                $srv_obj = $v->serviceStore->find($udp_name);
                                if ($srv_obj === null)
                                    $srv_obj = $v->serviceStore->newService($udp_name, "udp", $service_array[1]);
                                $newRule->services->add($srv_obj);
                            }
                            else
                            {
                                $protocol = strtolower($service_array[0]);
                                if( $protocol != "udp" && $protocol != "tcp" )
                                {
                                    mwarning("Protocol '" . $protocol . "' not allowed", null, false);
                                    continue;
                                }


                                $srv_obj = $v->serviceStore->find($protocol . "-" . $service_array[1]);
                                if ($srv_obj === null)
                                    $srv_obj = $v->serviceStore->newService($protocol . "-" . $service_array[1], $protocol, $service_array[1]);
                                $newRule->services->add($srv_obj);
                            }

                        } else {
                            $srv_obj = $v->serviceStore->find($service_node->textContent);
                            if ($srv_obj !== null)
                                $newRule->services->add($srv_obj);
                        }
                    }
                }
            }

            $schedule_node = DH::findFirstElement('Schedule', $Policy_node);

            $identity_node = DH::findFirstElement('Identity', $Policy_node);
            if( $identity_node !== false )
            {
                foreach ($identity_node->childNodes as $identity )
                {
                    /** @var DOMElement $identity */
                    if ($identity->nodeType != XML_ELEMENT_NODE)
                        continue;

                    $newRule->userID_addUser($identity->textContent);
                }
            }
            /*
             *       <Identity>
            <Member>fbra@projekt.igz.local</Member>
            <Member>fbra@igz.com</Member>
            <Member>slu@igz.com</Member>
            <Member>ski@projekt.igz.local</Member>
            <Member>slu@projekt.igz.local</Member>
            <Member>hha@igz.com</Member>
            <Member>hha@projekt.igz.local</Member>
            <Member>ski@igz.com</Member>
          </Identity>
                 */
        }
        /*
          <FirewallRule transactionid="">
            <Name>T1-ADMCenter &gt; T1-1641-Proxmox</Name>
            <Description/>
            <IPFamily>IPv4</IPFamily>
            <Status>Enable</Status>
            <Position>Top</Position>
            <PolicyType>Network</PolicyType>
            <NetworkPolicy>
              <Action>Accept</Action>
              <LogTraffic>Enable</LogTraffic>
              <SkipLocalDestined>Disable</SkipLocalDestined>
              <SourceZones>
                <Zone>LAN</Zone>
              </SourceZones>f
              <DestinationZones>
                <Zone>T1</Zone>
              </DestinationZones>
              <Schedule>All The Time</Schedule>
              <SourceNetworks>
                <Network>T1-IGZADMCENTER-192.168.181.250_32</Network>
              </SourceNetworks>
              <Services>
                <Service>HTTPS</Service>
              </Services>
              <DestinationNetworks>
                <Network>T1-ADM-Proxmox-iLO-172.22.164.2_32</Network>
              </DestinationNetworks>
         */
    }
}
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

    #$nameToNormalize = preg_replace("/[&]+/", "_", $nameToNormalize);

    return $nameToNormalize;
}






/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
function add_from_alias_list( $v, $alias_array, $alias, $address_container, $subMethod = false )
{
    global $util;

    /** @var AddressRuleContainer $address_container */

    //rework - return is always only one object, what if multiple objects are used
    if( isset($alias_array[$alias]) )
    {
        /** @var AddressGroup $tmp_addressgroup */
        $tmp_addressgroup = $v->addressStore->find( $alias );
        if( $tmp_addressgroup == null )
            $tmp_addressgroup = $v->addressStore->newAddressGroup($alias);

        #$subMethod = False;

        foreach( $alias_array[$alias] as $key => $array )
        {
            if( isset( $array['address'] ) )
                $search = $array['address'];
            elseif( isset( $array['alias'] ) )
                $search = $array['alias'];

            if( $util->debugAPI )
                print "search: ".$search."\n";

            $object = $v->addressStore->find($search);
            if( $object == null )
            {
                if( $util->debugAPI )
                    print "object not found: ".$search."\n";

                $subMethod = TRUE;
                add_from_alias_list( $v, $alias_array, $search, $address_container );
            }
            else
            {
                if( !$tmp_addressgroup->has($object) )
                {
                    if( $util->debugAPI )
                        print "add object to group: ".$object->name()."\n";
                    $tmp_addressgroup->addMember($object);
                }

                //validation needed if object is already part of rule, e.g. recursive part of group
                print "validate if object: ".$object->name()." is already part of address Container\n";
                $object_available = $address_container->hasObjectRecursive( $object );
                if( !$object_available )
                {
                    print "object not available\n";
                    $address_container->addObject($object);
                    print "add object to rule: ".$object->name()."\n";
                }
                else
                {
                    print "object available\n";
                }
            }
        }

        if( !$subMethod )
        {
            print "add group to rule: ".$tmp_addressgroup->name()."\n";
            $address_container->addObject($tmp_addressgroup);
        }
        else
        {
            #print "remove group from address store: ".$tmp_addressgroup->name()."\n";
            #$v->addressStore->remove($tmp_addressgroup);
        }
    }

    return null;
}
function add_zone_from_alias_list( $v, $alias_array, $alias, $zone_container )
{
    global $util;

    if( $util->debugAPI )
        print "search zone: ".$alias."\n";

    if( isset($alias_array[$alias]) )
    {
        foreach( $alias_array[$alias] as $array )
        {
            if(isset($array['interface']))
            {
                $zone_obj = $v->zoneStore->find($array['interface']);
                if( $zone_obj !== null )
                {
                    $zone_container->addZone($zone_obj);
                    #return $zone_obj;
                }

            }
            elseif( isset($array['alias']) )
            {
                if( isset($alias_array[$array['alias']][0]['interface']) )
                {
                    $search = $alias_array[$array['alias']][0]['interface'];
                    $zone_obj = $v->zoneStore->find($search);
                    if( $zone_obj !== null )
                    {
                        $zone_container->addZone($zone_obj);
                        #return $zone_obj;
                    }
                }
            }
        }
    }

    #if(strpos($alias, "Medlinq_Remote.in") !== False)
    #    exit();

    #return null;
}
function watchguard_getPolicy($v, $xml, $alias_array, $nat_array)
{
    global $util;

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
            if( $util->debugAPI )
                print "alias to search: '".$from_alias->textContent."'\n";

            add_from_alias_list($v, $alias_array, $from_alias->textContent, $new_secRule->source);
            /*
            $object_from_add_array = add_from_alias_list($v, $alias_array, $from_alias->textContent);
            foreach( $object_from_add_array as $object_from_add )
            {
            */
            /*
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
            */
            //}

            ################

            add_zone_from_alias_list($v, $alias_array, $from_alias->textContent, $new_secRule->from);
            /*
            if( $zone_from_add !== null && $zone_from_add->name() != "Any")
            {
                PH::print_stdout("add from zone: ".$zone_from_add->name());
                $new_secRule->from->addZone($zone_from_add);
            }
            */
        }

        ################
        $to = DH::findFirstElement('to-alias-list', $node);
        foreach ($to->childNodes as $to_alias)
        {
            if ($to_alias->nodeType != XML_ELEMENT_NODE) continue;

            //Todo: validation if alias is already available in addressStore
            #print "alias to search: '".$to_alias->textContent."'\n";

            add_from_alias_list($v, $alias_array, $to_alias->textContent, $new_secRule->destination);
            /*
            $object_to_add_array = add_from_alias_list($v, $alias_array, $to_alias->textContent);
            foreach( $object_to_add_array as $object_to_add )
            {
            */
            /*
                if ($object_to_add !== null && $object_to_add->name() !== "Any") {
                    PH::print_stdout("add dst address obj: " . $object_to_add->name());
                    $new_secRule->destination->addObject($object_to_add);
                } elseif ($object_to_add->name() !== "Any") #else
                {
                    mwarning("object: " . $to_alias->textContent . " not found");
                    $not_found[$rule_name]['to'][] = $to_alias->textContent;
                    #derr( "object: '".$to_alias->textContent."' not found" );
                }
            */
            //}
            #################

            add_zone_from_alias_list($v, $alias_array, $to_alias->textContent, $new_secRule->to);
            /*
            if( $zone_to_add !== null && $zone_to_add->name() != "Any")
            {
                PH::print_stdout("add to zone: ".$zone_to_add->name());
                $new_secRule->to->addZone($zone_to_add);
            }
            */
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

        if( $util->debugAPI )
        {
            if( $rule_name == "FTP" )
                derr("stop migration");
        }
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


        $property_xml = DH::findFirstElement('property', $node);
        $property = $property_xml->textContent;


        //Todo:
        //create addressgroup
        /*
        $tmp_addressgroup = null;
        if( $name !== "Any" )
        {
            $tmp_addressgroup = $v->addressStore->find($name);
            if( $tmp_addressgroup === null )
                $tmp_addressgroup = $v->addressStore->newAddressGroup($name);
            else
                $tmp_addressgroup = null;
        }
        */


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


                /*
                $tmp_address = $v->addressStore->find($address);
                if( $tmp_addressgroup !== null && $tmp_address !== null )
                    $tmp_addressgroup->addMember($tmp_address);
                elseif( $tmp_address !== null )
                    mwarning( "address not found" );
                */
            }
            else
            {
                $address = $address_xml->textContent;
                print "alias: ".$name." value: ".$address."\n";
                $tmp_array['address'] = $address;


                $tmp_addressgroup = $v->addressStore->find($name);
                if( $address !== "Any" )
                {
                    $tmp_address = $v->addressStore->find($address);
                    if( $tmp_address !== null && $tmp_address !== false )
                    {
                        if( $tmp_addressgroup !== null && $tmp_addressgroup->isGroup() )
                            $tmp_addressgroup->addMember($tmp_address);
                    }

                }
                /*
                else
                {
                    $tmp_address = $v->addressStore->find($name);
                    if( $tmp_address === null || $tmp_address === false )
                        $tmp_address = $v->addressStore->newAddress($name, "ip-netmask", "0.0.0.0/0");
                }

                if( $tmp_addressgroup !== null && !$tmp_addressgroup->isGroup() )
                    $tmp_addressgroup->addMember($tmp_address);
                */
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
        /** @var VirtualSystem $v */
        #DH::DEBUGprintDOMDocument($xml);
        /** @var VirtualRouter $v_router */
        $vr_name = "default";
        $tmp_vr = $pan->network->virtualRouterStore->findVirtualRouter($vr_name);
        if ($tmp_vr === null) {
            $tmp_vr = $pan->network->virtualRouterStore->newVirtualRouter($vr_name);
        }

        $tunnel_counter = 1;
        foreach ($xml->childNodes as $node)
        {
            if ($node->nodeType != XML_ELEMENT_NODE) continue;


            /** @var PANConf $pan */
            $tmp_interface_name = "tunnel.".$tunnel_counter;
            $tmp_interface = $pan->network->tunnelIfStore->newTunnelIf($tmp_interface_name);
            $tunnel_counter++;
            $v->importedInterfaces->addInterface($tmp_interface);

            #DH::DEBUGprintDOMDocument($node);

            $xml_name = DH::findFirstElement('name', $node);
            $name = $xml_name->textContent;

            PH::print_stdout("search for Zone: ".$name);
            $tmp_zone = $v->zoneStore->find($name);
            if( $tmp_zone !== null )
            {
                $tmp_zone->attachedInterfaces->addInterface($tmp_interface);
            }
            else
            {
                PH::print_stdout("Zone: ".$name." not found - create it and attach");
                $tmp_zone = $v->zoneStore->newZone($name, "layer3");
                $tmp_zone->attachedInterfaces->addInterface($tmp_interface);
            }


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
                    $routename = $name;

                    $ip_gateway = "10.10.10.10";
                    $metric = "1";

                    $xml_interface = "";
                    $xml_interface = "<interface>".$tmp_interface_name."</interface>";
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

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////






print "\n\n\n";

$util->save_our_work();

print "\n\n************ END OF Sophos XG UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";
