<?php

require_once('SOPHOSXGfunction.php');


//https://docs.sophos.com/nsg/sophos-firewall/19.5/Help/en-us/webhelp/onlinehelp/AdministratorHelp/BackupAndFirmware/API/index.html


class SOPHOSXG extends PARSER
{
    use SOPHOSXGfunction;

    public $useLogicalRouter = true;
    public function vendor_main()
    {

        $this->getDeviceConfig( $this->sub, $this->template, $this->template_vsys);

        $v = $this->sub;



        //Todo: read/display all files from directory:
        // argument:
        if (isset(PH::$args['directory']))
            $directory = PH::$args['directory'];
        else
            derr("argument directory not set");

        $scanned_directory = array_diff(scandir($directory), array('..', '.'));

        foreach ($scanned_directory as $filename)
        {
            PH::print_stdout("FILENAME: ".$filename);

            $xml = new DOMDocument;
            $xml->load($directory."/".$filename);
            #$xml->loadXML(file_get_contents($filename));


            $XMLroot = $xml->documentElement;

            if( strpos($filename, 'objects-ip.xml') !== false )
            {
                $this->sophos_xg_objectsIP($v, $XMLroot);
            }
            if( strpos($filename, 'objects-ipgroup') !== false )
            {
                $this->sophos_xg_objectsIPGROUP($v, $XMLroot);
            }
            elseif( strpos($filename, 'objects-fqdn') !== false )
            {
                $this->sophos_xg_objectsFQDN($v, $XMLroot);
            }
            elseif( strpos($filename, 'objects-service.xml') !== false )
            {
                $this->sophos_xg_objectsSERVICE($v, $XMLroot);
            }
            elseif( strpos($filename, 'objects-servicegroup') !== false )
            {
                $this->sophos_xg_objectsSERVICEGROUP($v, $XMLroot);
            }
            elseif( strpos($filename, 'network-interfaces') !== false )
            {
                $this->sophos_xg_networkINTERFACES($v, $XMLroot);
            }
            elseif( strpos($filename, 'network-lags') !== false )
            {
                //Todo: is this finalised???
                $this->sophos_xg_networkLAGS($v, $XMLroot);
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
                $this->sophos_xg_networkVLANS($v, $XMLroot);
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
                $this->sophos_xg_routeSTATIC($v, $XMLroot);
            }
            elseif( strpos($filename, 'rules-firewall') !== false )
            {
                $this->sophos_xg_rulesFIREWALL($v, $XMLroot);
            }
            elseif( strpos($filename, 'rules-nat') !== false )
            {
                #sophos_xg_rulesNAT($v, $XMLroot);
            }

        }

////////////////////////////////////////////////////////////////////////////////////////////
///
//delete unused address objects:
        $unusedAdr_obj = $v->addressStore->all("(object is.unused)");
        foreach($unusedAdr_obj as $adr)
        {
            $v->addressStore->remove($adr, true);
            $v->addressStore->rewriteAddressStoreXML();
        }

//delete unused service objects:
        $unusedSRV_obj = $v->serviceStore->all("(object is.unused)");
        foreach($unusedSRV_obj as $srv)
        {
            $v->serviceStore->remove($srv, true);
            $v->serviceStore->rewriteServiceStoreXML();
        }

        $SRV_objs = $v->serviceStore->all("(name regex /tcp-/)");
        foreach($SRV_objs as $srv)
        {
            $name = $srv->name();
            $new_name = str_replace("tcp-", "tcp_", $name);

            $srv->setName($new_name);
        }
////////////////////////////////////////////////////////////////////////////////////////////
        SOPHOSXG::validate_interface_names($this->pan);

////////////////////////////////////////////////////////////////////////////////////////////
        echo PH::boldText("\nVALIDATION - replace tmp services with APP-id if possible\n");
        CONVERTER::AppMigration( $v, $this->configType );

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

        if($v->owner->network->aggregateEthernetIfStore->xmlroot == null)
            $v->owner->network->aggregateEthernetIfStore->createXmlRoot();

        $v->owner->network->aggregateEthernetIfStore->xmlroot->appendChild($int->xmlroot->cloneNode(TRUE));
        $int->xmlroot->parentNode->removeChild($int->xmlroot);




        $int = $v->owner->network->ethernetIfStore->newEthernetIf( "ethernet1/3", "aggregate-group", "ae1" );
        $int = $v->owner->network->ethernetIfStore->newEthernetIf( "ethernet1/4", "aggregate-group", "ae1" );



    }
}