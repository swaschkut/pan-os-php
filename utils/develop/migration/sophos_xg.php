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



$useLogicalRouter = true;


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
        //Todo: is this of interest?
        //all information are used from Rules
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
    elseif( strpos($filename, 'rules-nat') !== false )
    {
        #sophos_xg_rulesNAT($v, $XMLroot);
    }

}


//delete unused address objects:
$unusedAdr_obj = $v->addressStore->all("(object is.unused)");
foreach($unusedAdr_obj as $adr)
{
    $v->addressStore->remove($adr, true);
    $v->addressStore->rewriteAddressStoreXML();
}

validate_interface_names($pan);



//Todo:


//Port 2 eth1/5 -> eth1/2
//Port11 eth1/3-> eth1/8
//Port12 eth1/4 -> ae1

//Port3 -> eth1/6
//Port4 -> eth1/7

$intDelete = array();
$intDelete[] = $v->owner->network->ethernetIfStore->find( "ethernet1/1" );
$intDelete[] = $v->owner->network->ethernetIfStore->find( "ethernet1/2" );
$intDelete[] = $v->owner->network->ethernetIfStore->find( "ethernet1/8" );
$intDelete[] = $v->owner->network->ethernetIfStore->find( "ethernet1/9" );
$intDelete[] = $v->owner->network->ethernetIfStore->find( "ethernet1/10" );
$intDelete[] = $v->owner->network->ethernetIfStore->find( "ethernet1/11" );
$intDelete[] = $v->owner->network->ethernetIfStore->find( "ethernet1/12" );

foreach( $intDelete as $int )
{
    /** @var EthernetInterface $int */
    $int->owner->removeEthernetIf($int);

}

$int = $v->owner->network->ethernetIfStore->find( "ethernet1/5" );
$int->setName("ethernet1/2");

$int = $v->owner->network->ethernetIfStore->find( "ethernet1/3" );
$int->setName("ethernet1/8");

$int = $v->owner->network->ethernetIfStore->find( "ethernet1/4" );
$int->setName("ae1");


$int = $v->owner->network->ethernetIfStore->newEthernetIf( "ethernet1/3", "aggregate-group", "ae1" );
$int = $v->owner->network->ethernetIfStore->newEthernetIf( "ethernet1/4", "aggregate-group", "ae1" );


#echo PH::boldText("\nVALIDATION - replace tmp services with APP-id if possible\n");
#CONVERTER::AppMigration( $v, $util->configType );

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
                        $newService = $v->serviceStore->newService( $protocol."-".$destinationPort."s".$sourcePort, $protocol, $destinationPort, "", $sourcePort, );
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

        $fqdn_Name = $fqdn_node->textContent;
        $description = "";
        if( strpos( $fqdn_Name, "*." ) === 0 )
        {
            $description = $fqdn_Name;
            $fqdn_Name = str_replace("*.", "", $fqdn_Name);
        }


        $new_address = $v->addressStore->find($name);
        if( $new_address === null )
            $new_address = $v->addressStore->newAddress( $name, "fqdn", $fqdn_Name, $description );
    }
}

function sophos_xg_networkINTERFACES( $v, $XMLroot)
{
    global $useLogicalRouter;
    /** @var VirtualSystem $v */

    foreach ($XMLroot->childNodes as $child)
    {
        /** @var DOMElement $node */
        if ($child->nodeType != XML_ELEMENT_NODE)
            continue;

        if ($child->nodeName != 'Interface')
            continue;

        $networkzone_node = DH::findFirstElement( 'NetworkZone', $child);
        $networkzone = $networkzone_node->textContent;

        $hardware_node = DH::findFirstElement( 'Hardware', $child);
        $hardware_name = $hardware_node->textContent;

        $name_node = DH::findFirstElement( 'Name', $child);
        $name = $name_node->textContent;

        $ipv4Configuration_node = DH::findFirstElement( 'IPv4Configuration', $child);
        $ipv6Configuration_node = DH::findFirstElement( 'IPv6Configuration', $child);

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

        if( $networkzone != "None" )
        {
            $tmp_zone = $v->zoneStore->find($networkzone);
            if($tmp_zone === null)
                $tmp_zone = $v->zoneStore->newZone($networkzone, "layer3");
            $tmp_zone->type = "layer3";
            $tmp_zone->attachedInterfaces->addInterface($newInterface);
        }


        if( $useLogicalRouter )
            $new_router = $v->owner->network->logicalRouterStore->findVirtualRouter("default");
        else
            $new_router = $v->owner->network->virtualRouterStore->findVirtualRouter("default");
        if( $new_router === null )
        {
            if( $useLogicalRouter )
                $new_router = $v->owner->network->logicalRouterStore->newLogicalRouter("default");
            else
                $new_router = $v->owner->network->virtualRouterStore->newVirtualRouter("default");
        }

        $new_router->attachedInterfaces->addInterface($newInterface);

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
    global $useLogicalRouter;

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
        $v->importedInterfaces->addInterface($aeInterface);

        if( $useLogicalRouter )
            $new_router = $v->owner->network->logicalRouterStore->findVirtualRouter("default");
        else
            $new_router = $v->owner->network->virtualRouterStore->findVirtualRouter("default");
        if( $new_router === null )
        {
            if( $useLogicalRouter )
                $new_router = $v->owner->network->logicalRouterStore->newLogicalRouter("default");
            else
                $new_router = $v->owner->network->virtualRouterStore->newVirtualRouter("default");
        }

        $new_router->attachedInterfaces->addInterface($aeInterface);

        
        $memberinterface_node = DH::findFirstElement( 'MemberInterface', $child);
        foreach( $memberinterface_node->childNodes as $interface_node )
        {
            /** @var DOMElement $node */
            if ($interface_node->nodeType != XML_ELEMENT_NODE)
                continue;

            $memberInterface = $interface_node->textContent;

            $interfaceOBJ = $v->owner->network->ethernetIfStore->newEthernetIf( $memberInterface, "aggregate-group", $name );
            $v->importedInterfaces->addInterface($interfaceOBJ);

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
    global $useLogicalRouter;

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
        $networkzone = $zone_node->textContent;


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


        if( $networkzone != "None" )
        {
            $tmp_zone = $v->zoneStore->find($networkzone);
            if($tmp_zone === null)
                $tmp_zone = $v->zoneStore->newZone($networkzone, "layer3");
            $tmp_zone->type = "layer3";
            $tmp_zone->attachedInterfaces->addInterface($tmp_sub);
        }

        if( $useLogicalRouter )
            $new_router = $v->owner->network->logicalRouterStore->findVirtualRouter("default");
        else
            $new_router = $v->owner->network->virtualRouterStore->findVirtualRouter("default");
        if( $new_router === null )
        {
            if( $useLogicalRouter )
                $new_router = $v->owner->network->logicalRouterStore->newLogicalRouter("default");
            else
                $new_router = $v->owner->network->virtualRouterStore->newVirtualRouter("default");
        }


        $new_router->attachedInterfaces->addInterface($tmp_sub);

    }
}

function sophos_xg_routeSTATIC( $v, $XMLroot)
{
    global $useLogicalRouter;

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
        if( $metric == 0 )
            $metric = 1;


        if( $useLogicalRouter )
            $new_router = $v->owner->network->logicalRouterStore->findVirtualRouter("default");
        else
            $new_router = $v->owner->network->virtualRouterStore->findVirtualRouter("default");
        if( $new_router === null )
        {
            if( $useLogicalRouter )
                $new_router = $v->owner->network->logicalRouterStore->newLogicalRouter("default");
            else
                $new_router = $v->owner->network->virtualRouterStore->newVirtualRouter("default");
        }



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

    $panwRegions = default_regions();

    $sophosRegions = array(
        "CD" => "Congo - Kinshasa",
        "CG" => "Congo - Brazzaville",
        "IR" => "Iran",
        "KP" => "North Korea"
    );

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

                    $src_name = normalizeNames($sourceNetwork->textContent);

                    $addr_obj = $v->addressStore->find($src_name);
                    if ($addr_obj !== null)
                        $newRule->source->addObject($addr_obj);
                    else
                    {
                        $country = $src_name;
                        if( in_array($country, $panwRegions) )
                        {
                            $key = array_search($country, $panwRegions);
                            $tmp_adr = $v->addressStore->findOrCreate($key);
                            $newRule->source->addObject($tmp_adr);
                        }
                        if( in_array($country, $sophosRegions) )
                        {
                            $key = array_search($country, $sophosRegions);
                            $tmp_adr = $v->addressStore->findOrCreate($key);
                            $newRule->source->addObject($tmp_adr);
                        }
                        if( !in_array($country, $panwRegions) && !in_array($country, $sophosRegions) )
                        {
                            mwarning( "SRC object: '".$src_name. "' not found", null, FALSE );
                        }

                    }

                }


            $destinationNetworks_node = DH::findFirstElement('DestinationNetworks', $Policy_node);
            if ($destinationNetworks_node !== false)
                foreach ($destinationNetworks_node->childNodes as $destinationNetwork)
                {
                    /** @var DOMElement $destinationNetwork */
                    if ($destinationNetwork->nodeType != XML_ELEMENT_NODE)
                        continue;

                    $dst_name = normalizeNames($destinationNetwork->textContent);

                    $addr_obj = $v->addressStore->find($dst_name);
                    if ($addr_obj !== null)
                        $newRule->destination->addObject($addr_obj);
                    else
                    {
                        $country = $dst_name;
                        if( in_array($country, $panwRegions) )
                        {
                            $key = array_search($country, $panwRegions);
                            $tmp_adr = $v->addressStore->findOrCreate($key);
                            $newRule->destination->addObject($tmp_adr);
                        }
                        if( in_array($country, $sophosRegions) )
                        {
                            $key = array_search($country, $sophosRegions);
                            $tmp_adr = $v->addressStore->findOrCreate($key);
                            $newRule->destination->addObject($tmp_adr);
                        }
                        if( !in_array($country, $panwRegions) && !in_array($country, $sophosRegions) )
                        {
                            mwarning( "DST object: '".$dst_name. "' not found", null, FALSE );
                        }
                    }

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
        }
    }
}


function sophos_xg_rulesNAT( $v, $XMLroot)
{
    /** @var VirtualSystem $v */


    foreach ($XMLroot->childNodes as $child)
    {
        /** @var DOMElement $node */
        if ($child->nodeType != XML_ELEMENT_NODE)
            continue;

        if ($child->nodeName != 'NATRule')
            continue;

        $name_node = DH::findFirstElement('Name', $child);
        $name = normalizeNames($name_node->textContent);
        $newRule = $v->natRules->newNatRule($name);


        $position_node = DH::findFirstElement('Position', $child);
        if ($position_node->textContent === "After") {
            $after_node = DH::findFirstElement('After', $child);
            $after_name_node = DH::findFirstElement('Name', $after_node);
            $after_rule_name = normalizeNames($after_name_node->textContent);
            $after_rule = $v->natRules->find($after_rule_name);
            /*
             <After>
              <Name>T1-ADMCenter &gt; T1-1641-Proxmox</Name>
            </After>
             */
            if ($after_rule != null) {
                $v->natRules->moveRuleAfter($newRule, $after_rule);
            } else {
                #DH::DEBUGprintDOMDocument($child);
            }

        }

        $status_node = DH::findFirstElement('Status', $child);
        if( $status_node->textContent === "Disabled" )
        {
            $newRule->setDisabled(true);
        }

        $LinkedFirewallrule_node = DH::findFirstElement('LinkedFirewallrule', $child);
        $secRuleName = normalizeNames($LinkedFirewallrule_node->textContent);


        $secRule = $v->securityRules->find($secRuleName);
        if( $secRule != null )
        {
            foreach( $secRule->source->getAll() as $source )
                $newRule->source->addObject($source);

            foreach( $secRule->destination->getAll() as $destination )
                $newRule->destination->addObject($destination);

            foreach( $secRule->from->getAll() as $source )
                $newRule->from->addZone($source);

            foreach( $secRule->to->getAll() as $destination )
                $newRule->to->addZone($destination);

            foreach( $secRule->services->getAll() as $service )
            {
                print "NATrule: '".$newRule->name()."'\n";
                print "add Service from secRule: '".$secRule->name()."'\n";
                print "service: '".$service->name()."'\n";
                #$newRule->service->add($service);
            }

            $zone_wan = $v->zoneStore->find("WAN");
            $newRule->to->addZone($zone_wan);
            if( $newRule->to->isAny() )
            {
                $zone_wan = $v->zoneStore->find("WAN");
                $newRule->to->addZone($zone_wan);
            }

            if( count( $newRule->to->getAll() ) > 1 )
            {
                foreach( $newRule->to->getAll() as $toZone )
                {
                    $newRule->to->removeZone($toZone, true, true);
                }
                $newRule->to->addZone($zone_wan);
            }


        }
        else
        {
            #mwarning("Secrule '".$secRuleName."' not found.", null, false);
        }


    }
}

/*
 <NATRule transactionid="">
    <Name>fw#14_migrated_NAT_Rule</Name>
    <Description>Created the NAT rule to migrate an earlier version that has NAT configuration at firewall rule level.</Description>
    <IPFamily>IPv4</IPFamily>
    <Status>Enable</Status>
    <Position>After</Position>
    <LinkedFirewallrule>LAN &gt; WAN -- Geofencing Exclusion Rule</LinkedFirewallrule>
    <TranslatedDestination>Original</TranslatedDestination>
    <TranslatedService>Original</TranslatedService>
    <OverrideInterfaceNATPolicy>Disable</OverrideInterfaceNATPolicy>
    <After>
      <Name>LAN-to-WAN-new</Name>
    </After>
    <TranslatedSource>MASQ</TranslatedSource>
  </NATRule>
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
     // false
     // true


    /*
    if( !ctype_alpha($nameToNormalize[0]) )
    {
        if( !ctype_digit($nameToNormalize[0]) )
        {
            $nameToNormalize = substr($nameToNormalize, 1);
        }
    }
    */


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

    if( $nameToNormalize[0] == "." )
        $nameToNormalize = substr($nameToNormalize, 1);


    return $nameToNormalize;
}


 function default_regions()
{
    $tmp_regions = array();

    $JSON_filename = dirname(__FILE__)."/../../../migration/parser/region.json";
    $JSON_string = file_get_contents($JSON_filename);

    $someArray = json_decode($JSON_string, TRUE);
    $tmp_regions = $someArray['region'];

    return $tmp_regions;
}


function validate_interface_names($template)
{

    $padding = "   ";
    $padding_name = substr($padding, 0, -1);


    $tmp_interfaces = $template->network->getAllInterfaces();

    $counter = 1;
    $tmp_int_name = array();
    foreach( $tmp_interfaces as $tmp_interface )
    {
        #if( $tmp_interface->type !== "tmp" && get_class( $tmp_interface ) == "EthernetInterface" )
        if( $tmp_interface->type !== "tmp" )
        {

            $int_name = $tmp_interface->name();
            if( get_class($tmp_interface) == "EthernetInterface" )
            {
                if( strpos($int_name, "ethernet") === FALSE && strpos($int_name, "ae") === FALSE && strpos($int_name, "tunnel") === FALSE )
                {
                    if( strpos($int_name, ".") === FALSE )
                    {
                        do
                        {
                            $new_name = "ethernet1/" . $counter;

                            $counter++;

                            $tmp_int = $template->network->findInterface($new_name);
                            $tmp_int_name[$int_name] = $new_name;
                        } while( $tmp_int !== null );

                    }
                    else
                    {
                        $tmp_tag = explode(".", $int_name);

                        if( isset( $tmp_int_name[$tmp_tag[0]] ) )
                            $new_name = $tmp_int_name[$tmp_tag[0]] . "." . $tmp_tag[1];
                        else
                        {
                            $new_name = null;
                            //Todo: swaschkut 20200930
                            //write Ethernetstore function remove
                            #$tmp_interface->owner->remove( $tmp_interface );
                        }
                    }



                    if( $new_name != null )
                    {
                        $addlog = "Interface: '" . $int_name . "' renamed to " . $new_name;
                        print $padding . "X " . $addlog . "\n";
                        $tmp_interface->display_references();
                        $tmp_interface->setName($new_name);

                        //todo: add description
                        #$tmp_interface->_description .= " renamed from '".$int_name."'";
                        //add migration log

                        $tmp_interface->set_node_attribute('warning', $addlog);
                    }
                }

            }
            elseif( get_class($tmp_interface) == "TunnelInterface" )
            {
                $tunnelcounter = 1;

                $validate_name = explode( ".", $int_name);
                if( $validate_name[0] == "tunnel" &&  is_numeric( $validate_name[1] ))
                    continue;

                #if( strpos( $int_name, "." ) === false ){
                do
                {
                    $new_name = "tunnel." . $tunnelcounter;

                    $tunnelcounter++;

                    $tmp_int = $template->network->findInterface($new_name);
                    $tmp_int_name[$int_name] = $new_name;
                } while( $tmp_int !== null );

                /*}
                else
                {
                    $tmp_tag = explode( ".", $int_name);
                    $new_name = $tmp_int_name[ $tmp_tag[0] ].".". $tmp_tag[1];
                }
                */

                $addlog = "Interface: '" . $int_name . "' renamed to " . $new_name;
                print $padding . "X " . $addlog . "\n";
                #$tmp_interface->display_references();
                $tmp_interface->setName($new_name);
                $tmp_interface->set_node_attribute('warning', $addlog);
            }
            else
            {
                print " - migration for interface class: " . get_class($tmp_interface) . " not implemented yet! for interface: ".$int_name."\n";
            }

            //Todo: replace from routing
            /*
                            elseif( strpos( $int_name, "ethernet" ) !== false )
                            {
                                //Todo: detailed check needed
                                print "Interface: ".$int_name." not renamed!\n";
                            }
                            elseif( strpos( $int_name, "ae" ) !== false  )
                            {
                                //Todo: detailed check needed
                                print "Interface: ".$int_name." not renamed!\n";
                            }
                            elseif( strpos( $int_name, "tunnel" ) !== false  )
                            {
                                //Todo: detailed check needed
                                print "Interface: ".$int_name." not renamed!\n";
                            }*/

        }
        else
        {
            mwarning("interface: " . $tmp_interface->name() . " is of type: " . $tmp_interface->type . " and not renamed", null, FALSE);
        }
    }
}


/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////






print "\n\n\n";

$util->save_our_work();

print "\n\n************ END OF Sophos XG UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";
