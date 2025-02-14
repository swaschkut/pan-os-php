<?php

require_once('SOPHOSXGfunction.php');


//https://docs.sophos.com/nsg/sophos-firewall/19.5/Help/en-us/webhelp/onlinehelp/AdministratorHelp/BackupAndFirmware/API/index.html


//Todo:
//NAT Rules migration NOT supported - swaschkut 20250210

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


        //read all files from directory - validate if SophosXG files and store in $this->data
        $this->clean_config( $directory );



        if( isset( $this->data['Interface'] ) )
            $this->sophos_xg_networkINTERFACES($v, $this->data['Interface']);

        if( isset( $this->data['LAG'] ) )
            $this->sophos_xg_networkLAGS($v, $this->data['LAG']);

        if( isset( $this->data['VLAN'] ) )
            $this->sophos_xg_networkVLANS($v, $this->data['VLAN']);

        if( isset( $this->data['IPHost'] ) )
            $this->sophos_xg_objectsIP($v, $this->data['IPHost']);

        if( isset( $this->data['IPHostGroup'] ) )
            $this->sophos_xg_objectsIPGROUP($v, $this->data['IPHostGroup']);

        if( isset( $this->data['FQDNHost'] ) )
            $this->sophos_xg_objectsFQDN($v, $this->data['FQDNHost']);

        if( isset( $this->data['Services'] ) )
            $this->sophos_xg_objectsSERVICE($v, $this->data['Services']);

        if( isset( $this->data['ServiceGroup'] ) )
            $this->sophos_xg_objectsSERVICEGROUP($v, $this->data['ServiceGroup']);


        if( isset( $this->data['MACHost'] ) )
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


        if( isset( $this->data['Zone'] ) )
        {
            //Zones are already created with Interfaces or later on with FirewallRule
        }

        if( isset( $this->data['UnicastRoute'] ) )
            $this->sophos_xg_routeSTATIC($v, $this->data['UnicastRoute']);

        if( isset( $this->data['FirewallRule'] ) )
            $this->sophos_xg_rulesFIREWALL($v, $this->data['FirewallRule']);

        if( isset( $this->data['NATRule'] ) )
        {
            $this->sophos_xg_rulesNAT($v, $this->data['NATRule']);
        }


////////////////////////////////////////////////////////////////////////////////////////////
        SOPHOSXG::validate_interface_names($this->pan);

////////////////////////////////////////////////////////////////////////////////////////////
        echo PH::boldText("\nVALIDATION - replace tmp services with APP-id if possible\n");
        CONVERTER::AppMigration( $v, $this->configType );


        #$ii = 1;
        #foreach( $v->owner->network->aggregateEthernetIfStore->getInterfaces() as $aggregateGroup )
        #    $aggregateGroup->setName("ae".$ii);

////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
/// CUSTOM

        $custom_xg330 = false;
        $custom_xg650 = false;

        if( $custom_xg330 )
        {
            ////////////////////////////////////////////////////////////////////////////////////////////
            //delete unused address objects:
            /*
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
            */

            /*
            $SRV_objs = $v->serviceStore->all("(name regex /tcp-/)");
            foreach($SRV_objs as $srv)
            {
                $name = $srv->name();
                $new_name = str_replace("tcp-", "tcp_", $name);

                $srv->setName($new_name);
            }
            */
            ////////////////////////////////////////////////////////////////////////////////////////////



            $intDelete = array();
            $intDelete[] = $v->owner->network->ethernetIfStore->find( "ethernet1/1" );
            $intDelete[] = $v->owner->network->ethernetIfStore->find( "ethernet1/2" );
            $intDelete[] = $v->owner->network->ethernetIfStore->find( "ethernet1/6" );
            $intDelete[] = $v->owner->network->ethernetIfStore->find( "ethernet1/9" );

            foreach( $intDelete as $int )
            {
                $int->owner->removeEthernetIf($int);
            }


            #$int = $v->owner->network->ethernetIfStore->find( "ethernet1/5" );
            #$int->setName("ethernet1/2");

            #$int = $v->owner->network->ethernetIfStore->find( "ethernet1/3" );
            #$int->setName("ethernet1/5");

            #$int = $v->owner->network->ethernetIfStore->find( "ethernet1/7" );
            #$int->setName("ethernet1/1");

            /** @var VirtualSystem $v */
            $int = $v->owner->network->aggregateEthernetIfStore->find( "ethernet1/13" );
            $int->setName("ae1");


            $int = $v->owner->network->ethernetIfStore->find( "ethernet1/11" );
            $int->setAE("ae1");
            $int = $v->owner->network->ethernetIfStore->find( "ethernet1/12" );
            $int->setAE("ae1");





            $rules = $v->securityRules->rules( "(src has.only T2-SSLVPN-vpn.igz.com-10.242.0.0_24)" );
            foreach( $rules as $rule )
            {
                $rule->owner->remove($rule);
            }
            $rules = $v->securityRules->rules( "(dst has.only T2-SSLVPN-vpn.igz.com-10.242.0.0_24)" );
            foreach( $rules as $rule )
            {
                $rule->owner->remove($rule);
            }

            $rules = $v->natRules->rules( "(src has.only T2-SSLVPN-vpn.igz.com-10.242.0.0_24)" );
            foreach( $rules as $rule )
            {
                $rule->owner->remove($rule);
            }

            $rules = $v->securityRules->rules();
            foreach( $rules as $rule )
            {
                $rule->setLogSetting("default");
                if( $rule->actionIsAllow() )
                {
                    //Outbound
                    $rule->setSecurityProfileGroup("Outbound");
                    //Inbound
                    #$rule->setSecurityProfileGroup("Inbound");
                }
            }

            //delete static Routing entries if interface is reds1/reds2/reds3/ethernet1/6
        }

        if( $custom_xg650 )
        {

            /*
            ////////////////////////////////////////////////////////////////////////////////////////////
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

            /*
            $SRV_objs = $v->serviceStore->all("(name regex /tcp-/)");
            foreach($SRV_objs as $srv)
            {
                $name = $srv->name();
                $new_name = str_replace("tcp-", "tcp_", $name);

                $srv->setName($new_name);
            }
            */
            ////////////////////////////////////////////////////////////////////////////////////////////


/*
            $intDelete = array();
            $intDelete[] = $v->owner->network->ethernetIfStore->find( "ethernet1/1" );
            $intDelete[] = $v->owner->network->ethernetIfStore->find( "ethernet1/2" );
            $intDelete[] = $v->owner->network->ethernetIfStore->find( "ethernet1/6" );
            $intDelete[] = $v->owner->network->ethernetIfStore->find( "ethernet1/9" );

            foreach( $intDelete as $int )
            {
                $int->owner->removeEthernetIf($int);
            }
            */


            #$int = $v->owner->network->ethernetIfStore->find( "ethernet1/5" );
            #$int->setName("ethernet1/2");

            #$int = $v->owner->network->ethernetIfStore->find( "ethernet1/3" );
            #$int->setName("ethernet1/5");

            #$int = $v->owner->network->ethernetIfStore->find( "ethernet1/7" );
            #$int->setName("ethernet1/1");



            /** @var VirtualSystem $v */
            $int = $v->owner->network->aggregateEthernetIfStore->find( "ethernet1/13" );
            $int->setName("ae1");


            $int = $v->owner->network->ethernetIfStore->find( "ethernet1/11" );
            $int->setAE("ae1");
            $int = $v->owner->network->ethernetIfStore->find( "ethernet1/12" );
            $int->setAE("ae1");



            $rules = $v->securityRules->rules();
            foreach( $rules as $rule )
            {
                $rule->setLogSetting("default");
                if( $rule->actionIsAllow() )
                {
                    //Outbound
                    $rule->setSecurityProfileGroup("Outbound");
                    //Inbound
                    #$rule->setSecurityProfileGroup("Inbound");
                }
            }
        }
    }


    function clean_config( $directory )
    {
        $scanned_directory = array_diff(scandir($directory), array('..', '.'));

        foreach ($scanned_directory as $filename)
        {
            #PH::print_stdout("FILENAME: " . $filename);

            $xml = new DOMDocument;
            $xml->load($directory . "/" . $filename);


            $XMLroot = $xml->documentElement;

            foreach($XMLroot->childNodes as $key => $node)
            {
                /** @var DOMElement $node */
                if ($node->nodeType != XML_ELEMENT_NODE)
                    continue;

                //skip all files which are not SophosXG API export
                if( $key == 1 &&  $node->nodeName != 'Login')
                    break;

                if ($node->nodeName == 'Login')
                    continue;

                $this->data[ $node->nodeName ][] = $node;
            }
        }
    }
}