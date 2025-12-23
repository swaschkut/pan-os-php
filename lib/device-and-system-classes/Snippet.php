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

class Snippet
{
    use PathableName;
    use PanSubHelperTrait;

    /** @var AddressStore */
    public $addressStore = null;
    /** @var ServiceStore */
    public $serviceStore = null;


    /** @var TagStore|null */
    public $tagStore = null;

    /** @var AppStore|null */
    public $appStore = null;

    /** @var ThreatStore|null */
    public $threatStore = null;

    protected $securityProfilebaseroot;

    /** @var SecurityProfileStore */
    public $URLProfileStore = null;

    /** @var SecurityProfileStore */
    public $customURLProfileStore = null;

    /** @var SecurityProfileStore */
    public $VirusAndWildfireProfileStore = null;

    /** @var SecurityProfileStore */
    public $DNSSecurityProfileStore = null;

    /** @var SecurityProfileStore */
    public $SaasSecurityProfileStore = null;

    /** @var SecurityProfileStore */
    public $VulnerabilityProfileStore = null;

    /** @var SecurityProfileStore */
    public $AntiSpywareProfileStore = null;

    /** @var SecurityProfileStore */
    public $FileBlockingProfileStore = null;

    /** @var SecurityProfileStore */
    #public $AntiVirusProfileStore = null;

    /** @var SecurityProfileStore */
    #public $WildfireProfileStore = null;

    /** @var SecurityProfileStore */
    public $DataFilteringProfileStore = null;

    /** @var SecurityProfileGroupStore */
    public $securityProfileGroupStore = null;

    /** @var SecurityProfileStore */
    public $DecryptionProfileStore = null;

    /** @var SecurityProfileStore */
    public $HipObjectsProfileStore = null;

    /** @var SecurityProfileStore */
    public $HipProfilesProfileStore = null;


    /** @var ScheduleStore */
    public $scheduleStore = null;



    public static $templateSnippetxml = '<entry name="**Need a Name**"></entry>';

    /** @var string */
    public $name;

    /** @var string */
    protected $_alternativeName = '';

    /** @var FawkesConf|Buckbeak|null */
    public $owner = null;

    /** @var DOMElement */
    public $xmlroot;


    protected $rulebaseroot;

    /** @var RuleStore */
    public $securityRules;

    /** @var RuleStore */
    public $natRules;

    /** @var RuleStore */
    public $decryptionRules;

    /** @var RuleStore */
    public $appOverrideRules;

    /** @var RuleStore */
    public $captivePortalRules;

    /** @var RuleStore */
    public $authenticationRules;

    /** @var RuleStore */
    public $pbfRules;

    /** @var RuleStore */
    public $qosRules;

    /** @var RuleStore */
    public $dosRules;

    /** @var RuleStore */
    public $tunnelInspectionRules;

    /** @var RuleStore */
    public $networkPacketBrokerRules;

    /** @var RuleStore */
    public $sdWanRules;


    /** @var ZoneStore */
    public $zoneStore = null;

    /** @var InterfaceContainer */
    public $importedInterfaces;

    /** @var VirtualRouterContainer */
    public $importedVirtualRouter;

    /** @var Container parentContainer in case it load as part of Panorama */
    public $parentContainer = null;

    public $version = null;

    /** @var Array */
    public $devices = array();

    public $sizeArray = array();

    /** @var FawkesConf|BuckbeakConf|null $owner */
    public function __construct( $owner, Container|null $applicableDG = null)
    {
        $this->owner = $owner;

        $this->parentContainer = $applicableDG;

        $this->version = &$owner->version;

        $this->tagStore = new TagStore($this);
        $this->tagStore->name = 'tags';

        #$this->importedInterfaces = new InterfaceContainer($this, $owner->network);
        #$this->importedVirtualRouter = new VirtualRouterContainer($this, $owner->network);

        #$this->appStore = $owner->appStore;
        $this->appStore = new AppStore($this);
        $this->appStore->name = 'customApplication';

        $this->threatStore = $owner->threatStore;

        $this->zoneStore = new ZoneStore($this);
        $this->zoneStore->setName('zoneStore');


        $this->serviceStore = new ServiceStore($this);
        $this->serviceStore->name = 'services';

        $this->addressStore = new AddressStore($this);
        $this->addressStore->name = 'addresses';


        $this->customURLProfileStore = new SecurityProfileStore($this, "customURLProfile");
        $this->customURLProfileStore->name = 'CustomURL';

        $this->URLProfileStore = new SecurityProfileStore($this, "URLProfile");
        $this->URLProfileStore->name = 'URL';

        #$this->AntiVirusProfileStore = new SecurityProfileStore($this, "AntiVirusProfile");
        #$this->AntiVirusProfileStore->name = 'AntiVirus';

        $this->VirusAndWildfireProfileStore = new SecurityProfileStore($this, "VirusAndWildfireProfile");
        $this->VirusAndWildfireProfileStore->name = 'VirusAndWildfire';

        $this->DNSSecurityProfileStore = new SecurityProfileStore($this, "DNSSecurityProfile");
        $this->DNSSecurityProfileStore->name = 'DNSSecurity';

        $this->SaasSecurityProfileStore = new SecurityProfileStore($this, "SaasSecurityProfile");
        $this->SaasSecurityProfileStore->name = 'SaasSecurity';

        $this->VulnerabilityProfileStore = new SecurityProfileStore($this, "VulnerabilityProfile");
        $this->VulnerabilityProfileStore->name = 'Vulnerability';

        $this->AntiSpywareProfileStore = new SecurityProfileStore($this, "AntiSpywareProfile");
        $this->AntiSpywareProfileStore->name = 'AntiSpyware';

        $this->FileBlockingProfileStore = new SecurityProfileStore($this, "FileBlockingProfile");
        $this->FileBlockingProfileStore->name = 'FileBlocking';

        $this->DataFilteringProfileStore = new SecurityProfileStore($this, "DataFilteringProfile");
        $this->DataFilteringProfileStore->name = 'DataFiltering';

        #$this->WildfireProfileStore = new SecurityProfileStore($this, "SecurityProfileWildFire");
        #$this->WildfireProfileStore->name = 'WildFire';


        $this->securityProfileGroupStore = new SecurityProfileGroupStore($this);
        $this->securityProfileGroupStore->name = 'SecurityProfileGroups';


        $this->DecryptionProfileStore = new SecurityProfileStore($this, "DecryptionProfile");
        $this->DecryptionProfileStore->name = 'Decryption';

        $this->HipObjectsProfileStore = new SecurityProfileStore($this, "HipObjectsProfile");
        $this->HipObjectsProfileStore->name = 'HipObjects';

        $this->HipProfilesProfileStore = new SecurityProfileStore($this, "HipProfilesProfile");
        $this->HipProfilesProfileStore->name = 'HipProfiles';


        $this->scheduleStore = new ScheduleStore($this);
        $this->scheduleStore->setName('scheduleStore');


        $this->securityRules = new RuleStore($this, 'SecurityRule');
        $this->securityRules->name = 'Security';

        $this->natRules = new RuleStore($this, 'NatRule');
        $this->natRules->name = 'NAT';

        $this->decryptionRules = new RuleStore($this, 'DecryptionRule');
        $this->decryptionRules->name = 'Decryption';

        $this->appOverrideRules = new RuleStore($this, 'AppOverrideRule');
        $this->appOverrideRules->name = 'AppOverride';

        $this->captivePortalRules = new RuleStore($this, 'CaptivePortalRule');
        $this->captivePortalRules->name = 'CaptivePortal';

        $this->authenticationRules = new RuleStore($this, 'AuthenticationRule');
        $this->authenticationRules->name = 'Authentication';

        $this->pbfRules = new RuleStore($this, 'PbfRule');
        $this->pbfRules->name = 'PBF';

        $this->qosRules = new RuleStore($this, 'QoSRule');
        $this->qosRules->name = 'QoS';

        $this->dosRules = new RuleStore($this, 'DoSRule');
        $this->dosRules->name = 'DoS';

        $this->tunnelInspectionRules = new RuleStore($this, 'TunnelInspectionRule');
        $this->tunnelInspectionRules->name = 'TunnelInspection';

        $this->networkPacketBrokerRules = new RuleStore($this, 'NetworkPacketBrokerRule', TRUE);
        $this->networkPacketBrokerRules->name = 'NetworkPacketBroker';

        $this->sdWanRules = new RuleStore($this, 'SDWanRule', TRUE);
        $this->sdWanRules->name = 'SDWan';

        #$this->dosRules->_networkStore = $this->owner->network;
        #$this->pbfRules->_networkStore = $this->owner->network;
    }

    public function load_from_templateSnippetXml( )
    {
        if( $this->owner === null )
            derr('cannot be used if owner === null');

        $fragment = $this->owner->xmlroot->ownerDocument->createDocumentFragment();

        if( !$fragment->appendXML(self::$templateSnippetxml) )
            derr('error occured while loading device group template xml');

        $element = $this->owner->snippetroot->appendChild($fragment);

        $this->load_from_domxml($element);
    }

    /**
     * !! Should not be used outside of a PANConf constructor. !!
     *
     */
    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        // this VSYS has a name ?
        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("DeviceOnPrem name not found\n", $xml);


        $tmp_parentContainer = DH::findFirstElement('parent', $xml);
        if( $tmp_parentContainer !== FALSE )
        {
            $this->parentContainer = $tmp_parentContainer->textContent;

            $parentContainer = $this->owner->findContainer( $this->parentContainer );
            if( $parentContainer === null )
                mwarning("DeviceOnPrem '$this->name' has Container '{$this->parentContainer}' listed as parent but it cannot be found in XML");
            else
            {
                $parentContainer->_childContainers[$this->name] = $this;
                $this->parentContainer = $parentContainer;

                /*
                $this->addressStore->parentCentralStore = $parentContainer->addressStore;
                $this->serviceStore->parentCentralStore = $parentContainer->serviceStore;
                $this->tagStore->parentCentralStore = $parentContainer->tagStore;
                $this->scheduleStore->parentCentralStore = $parentContainer->scheduleStore;
                $this->appStore->parentCentralStore = $parentContainer->appStore;
                $this->securityProfileGroupStore->parentCentralStore = $parentContainer->securityProfileGroupStore;
                */
                //Todo: swaschkut 20210505 - check if other Stores must be added
                //- appStore;scheduleStore/securityProfileGroupStore/all kind of SecurityProfile

                $storeType = array(
                    'addressStore', 'serviceStore', 'tagStore', 'scheduleStore', 'appStore',

                    'securityProfileGroupStore',

                    'URLProfileStore', 'VirusAndWildfireProfileStore', 'FileBlockingProfileStore',
                    //'DataFilteringProfileStore',
                    'VulnerabilityProfileStore', 'AntiSpywareProfileStore',
                    //'WildfireProfileStore',
                    'DecryptionProfileStore', 'HipObjectsProfileStore', 'customURLProfileStore',

                    'DNSSecurityProfileStore', 'SaasSecurityProfileStore'

                );

                foreach( $storeType as $type )
                    $this->$type->parentCentralStore = $parentContainer->$type;
            }
        }


        // this VSYS has a display-name ?
        $displayNameNode = DH::findFirstElement('display-name', $xml);
        if( $displayNameNode !== FALSE )
            $this->_alternativeName = $displayNameNode->textContent;


        //
        // loading the imported objects list
        //
        /*
        $importroot = DH::findFirstElementOrCreate('import', $xml);
        $networkRoot = DH::findFirstElementOrCreate('network', $importroot);
        $tmp = DH::findFirstElementOrCreate('interface', $networkRoot);
        $this->importedInterfaces->load_from_domxml($tmp);

        $tmp = DH::findFirstElementOrCreate('virtual-router', $networkRoot);
        $this->importedVirtualRouter->load_from_domxml($tmp);
        */
        //

        if( $this->owner->owner === null )
        {

            //
            // Extract Tag objects
            //
            if( $this->owner->version >= 60 )
            {
                $tmp = DH::findFirstElement('tag', $xml);
                if( $tmp !== FALSE )
                    $this->tagStore->load_from_domxml($tmp);
            }
            // End of Tag objects extraction


            //
            // Extract region objects
            //
            $tmp = DH::findFirstElement('region', $xml);
            if( $tmp !== FALSE )
                $this->addressStore->load_regions_from_domxml($tmp);
            // End of region objects extraction

            //
            // Extract address objects
            //
            $tmp = DH::findFirstElement('address', $xml);
            if( $tmp !== FALSE )
                $this->addressStore->load_addresses_from_domxml($tmp);
            // End of address objects extraction


            //
            // Extract address groups in this DV
            //
            $tmp = DH::findFirstElement('address-group', $xml);
            if( $tmp !== FALSE )
                $this->addressStore->load_addressgroups_from_domxml($tmp);
            // End of address groups extraction


            //												//
            // Extract service objects in this VSYS			//
            //												//
            $tmp = DH::findFirstElement('service', $xml);
            if( $tmp !== FALSE )
                $this->serviceStore->load_services_from_domxml($tmp);
            // End of <service> extraction


            //												//
            // Extract service groups in this VSYS			//
            //												//
            $tmp = DH::findFirstElement('service-group', $xml);
            if( $tmp !== FALSE )
                $this->serviceStore->load_servicegroups_from_domxml($tmp);
            // End of <service-group> extraction

            //
            // Extract application
            //
            $tmp = DH::findFirstElement('application', $xml);
            if( $tmp !== FALSE )
                $this->appStore->load_application_custom_from_domxml($tmp);
            // End of address extraction

            //
            // Extract application filter
            //
            $tmp = DH::findFirstElement('application-filter', $xml);
            if( $tmp !== FALSE )
                $this->appStore->load_application_filter_from_domxml($tmp);
            // End of application filter groups extraction

            //
            // Extract application groups
            //
            $tmp = DH::findFirstElement('application-group', $xml);
            if( $tmp !== FALSE )
                $this->appStore->load_application_group_from_domxml($tmp);
            // End of application groups groups extraction


            // Extract SecurityProfiles objects
            //
            $this->securityProfilebaseroot = DH::findFirstElement('profiles', $xml);
            if( $this->securityProfilebaseroot === FALSE )
                $this->securityProfilebaseroot = null;

            if( $this->owner->owner === null && $this->securityProfilebaseroot !== null )
            {
                //
                // custom URL category extraction
                //
                $tmproot = DH::findFirstElement('custom-url-category', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->customURLProfileStore->load_from_domxml($tmproot);
                }

                //
                // URL Profile extraction
                //
                $tmproot = DH::findFirstElement('url-filtering', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->URLProfileStore->load_from_domxml($tmproot);
                }

                //
                // AntiVirus Profile extraction
                //
                $tmproot = DH::findFirstElement('virus-and-wildfire-analysis', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->VirusAndWildfireProfileStore->load_from_domxml($tmproot);
                }

                //
                // FileBlocking Profile extraction
                //
                $tmproot = DH::findFirstElement('file-blocking', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->FileBlockingProfileStore->load_from_domxml($tmproot);
                }

                //
                // DataFiltering Profile extraction
                //
                $tmproot = DH::findFirstElement('data-filtering', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                    $this->DataFilteringProfileStore->load_from_domxml($tmproot);

                //
                // vulnerability Profile extraction
                //
                $tmproot = DH::findFirstElement('vulnerability', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->VulnerabilityProfileStore->load_from_domxml($tmproot);
                }

                //
                // spyware Profile extraction
                //
                $tmproot = DH::findFirstElement('spyware', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->AntiSpywareProfileStore->load_from_domxml($tmproot);
                }

                //
                // DNSSecurity Profile extraction
                //
                $tmproot = DH::findFirstElement('dns-security', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->DNSSecurityProfileStore->load_from_domxml($tmproot);
                }

                //
                // SaasSecurity Profile extraction
                //
                $tmproot = DH::findFirstElement('saas-security', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->SaasSecurityProfileStore->load_from_domxml($tmproot);
                }

                //
                // Decryption Profile extraction
                //
                $tmproot = DH::findFirstElement('decryption', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->DecryptionProfileStore->load_from_domxml($tmproot);
                }

                //
                // HipObjects Profile extraction
                //
                $tmproot = DH::findFirstElement('hip-objects', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->HipObjectsProfileStore->load_from_domxml($tmproot);
                }

                //
                // HipProfiles Profile extraction
                //
                $tmproot = DH::findFirstElement('hip-profiles', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->HipProfilesProfileStore->load_from_domxml($tmproot);
                }
            }


            //
            // Extract SecurityProfile groups in this DV
            //
            $tmp = DH::findFirstElement('profile-group', $xml);
            if( $tmp !== FALSE )
                $this->securityProfileGroupStore->load_securityprofile_groups_from_domxml($tmp);
            // End of address groups extraction

            //
            // Extract schedule objects
            //
            $tmp = DH::findFirstElement('schedule', $xml);
            if( $tmp !== FALSE )
                $this->scheduleStore->load_from_domxml($tmp);
            // End of address groups extraction

        }




        //
        // add reference to address object, if interface IP-address is using this object
        //
        /*
        foreach( $this->importedInterfaces->interfaces() as $interface )
        {
            if( $interface->isEthernetType() && $interface->type() == "layer3" )
                $interfaces = $interface->getLayer3IPv4Addresses();
            elseif( $interface->isVlanType() || $interface->isLoopbackType() || $interface->isTunnelType() )
                $interfaces = $interface->getIPv4Addresses();
            else
                $interfaces = array();


            foreach( $interfaces as $layer3IPv4Address )
            {
                if( substr_count($layer3IPv4Address, '.') != 3 )
                {
                    $object = $this->addressStore->find($layer3IPv4Address);
                    if( is_object($object) )
                        $object->addReference($interface);
                    else
                    {
                        //Todo: fix needed too many warnings - if address object is coming from other address store
                        #mwarning("interface configured objectname: " . $layer3IPv4Address . " not found.\n", $interface);
                    }

                }
            }
        }
        */
        //Todo: addressobject reference missing for: IKE gateway / GP Portal / GP Gateway (where GP is not implemented at all)


        //
        // Extract Zone objects
        //
        $tmp = DH::findFirstElement('zone', $xml);
        if( $tmp != FALSE )
        {
            $this->zoneStore->load_from_domxml($tmp);
        }

        // End of Zone objects extraction


        $this->rulebaseroot = DH::findFirstElement('rulebase', $xml);
        if( $this->rulebaseroot === FALSE )
            $this->rulebaseroot = null;

        if( $this->owner->owner === null && $this->rulebaseroot !== null )
        {
            //
            // Security Rules extraction
            //
            $tmproot = DH::findFirstElement('security', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->securityRules->load_from_domxml($tmprulesroot);
            }

            //
            // Nat Rules extraction
            //
            $tmproot = DH::findFirstElement('nat', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->natRules->load_from_domxml($tmprulesroot);
            }

            //
            // Decryption Rules extraction
            //
            $tmproot = DH::findFirstElement('decryption', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElementOrCreate('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->decryptionRules->load_from_domxml($tmprulesroot);
            }

            //
            // Decryption Rules extraction
            //
            $tmproot = DH::findFirstElement('application-override', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->appOverrideRules->load_from_domxml($tmprulesroot);
            }

            //
            // Captive Portal Rules extraction
            //
            $tmproot = DH::findFirstElement('captive-portal', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->captivePortalRules->load_from_domxml($tmprulesroot);
            }

            //
            // Authenticaiton Rules extraction
            //
            $tmproot = DH::findFirstElement('authentication', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->authenticationRules->load_from_domxml($tmprulesroot);
            }

            //
            // PBF Rules extraction
            //
            $tmproot = DH::findFirstElement('pbf', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->pbfRules->load_from_domxml($tmprulesroot);
            }

            //
            // QoS Rules extraction
            //
            $tmproot = DH::findFirstElement('qos', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->qosRules->load_from_domxml($tmprulesroot);
            }

            //
            // DoS Rules extraction
            //
            $tmproot = DH::findFirstElement('dos', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->dosRules->load_from_domxml($tmprulesroot);
            }

            //
            // tunnelinspection Rules extraction
            //
            $xmlTagName = "tunnel-inspect";
            $var = "tunnelInspectionRules";
            $tmproot = DH::findFirstElement($xmlTagName, $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->$var->load_from_domxml($tmprulesroot);
            }

            //
            // network-packet-broker Rules extraction
            //
            $xmlTagName = "network-packet-broker";
            $var = "networkPacketBrokerRules";
            $tmproot = DH::findFirstElement($xmlTagName, $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->$var->load_from_domxml($tmprulesroot);
            }

            //
            // sdwan Rules extraction
            //
            $xmlTagName = "sdwan";
            $var = "sdWanRules";
            $tmproot = DH::findFirstElement($xmlTagName, $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->$var->load_from_domxml($tmprulesroot);
            }
        }
    }

    public function &getXPath()
    {
        $str = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $this->name . "']";

        return $str;
    }

    public function isDeviceOnPrem()
    {
        return TRUE;
    }

    public function display_statistics( $debug = false, $actions = "display")
    {
        $stdoutarray = array();

        $stdoutarray['type'] = get_class( $this );

        $header = "Statistics for Snippet '" . PH::boldText($this->name) . "' | '" . $this->toString() . "'";
        $stdoutarray['header'] = $header;

        $stdoutarray['security rules'] = $this->securityRules->count();

        $stdoutarray['nat rules'] = $this->natRules->count();

        $stdoutarray['qos rules'] = $this->qosRules->count();

        $stdoutarray['pbf rules'] = $this->pbfRules->count();

        $stdoutarray['decryption rules'] = $this->decryptionRules->count();

        $stdoutarray['app-override rules'] = $this->appOverrideRules->count();

        $stdoutarray['capt-portal rules'] = $this->captivePortalRules->count();

        $stdoutarray['authentication rules'] = $this->authenticationRules->count();

        $stdoutarray['dos rules'] = $this->dosRules->count();


        $stdoutarray['address objects'] = array();
        $stdoutarray['address objects']['total'] = $this->addressStore->count();
        $stdoutarray['address objects']['address'] = $this->addressStore->countAddresses();
        $stdoutarray['address objects']['group'] = $this->addressStore->countAddressGroups();
        $stdoutarray['address objects']['tmp'] = $this->addressStore->countTmpAddresses();
        $stdoutarray['address objects']['unused'] = $this->addressStore->countUnused();

        $stdoutarray['service objects'] = array();
        $stdoutarray['service objects']['total'] = $this->serviceStore->count();
        $stdoutarray['service objects']['service'] = $this->serviceStore->countServices();
        $stdoutarray['service objects']['group'] = $this->serviceStore->countServiceGroups();
        $stdoutarray['service objects']['tmp'] = $this->serviceStore->countTmpServices();
        $stdoutarray['service objects']['unused'] = $this->serviceStore->countUnused();

        $stdoutarray['tag objects'] = array();
        $stdoutarray['tag objects']['total'] = $this->tagStore->count();
        $stdoutarray['tag objects']['unused'] = $this->tagStore->countUnused();

        $stdoutarray['securityProfileGroup objects'] = array();
        $stdoutarray['securityProfileGroup objects']['total'] = $this->securityProfileGroupStore->count();

        /*
        $stdoutarray['securityProfile objects'] = array();
        $stdoutarray['securityProfile objects']['Anti-Spyware'] = $this->AntiSpywareProfileStore->count();
        $stdoutarray['securityProfile objects']['Vulnerability'] = $this->VulnerabilityProfileStore->count();
        $stdoutarray['securityProfile objects']['WildfireAndAntivirus'] = $this->VirusAndWildfireProfileStore->count();
        $stdoutarray['securityProfile objects']['DNS-Security'] = $this->DNSSecurityProfileStore->count();
        $stdoutarray['securityProfile objects']['Saas-Security'] = $this->SaasSecurityProfileStore->count();
        $stdoutarray['securityProfile objects']['URL'] = $this->URLProfileStore->count();
        $stdoutarray['securityProfile objects']['File-Blocking'] = $this->FileBlockingProfileStore->count();
        $stdoutarray['securityProfile objects']['Decryption'] = $this->DecryptionProfileStore->count();
        */

        $stdoutarray['Anti-Spyware objects'] = array();
        $stdoutarray['Anti-Spyware objects']['total'] = $this->AntiSpywareProfileStore->count();
        $stdoutarray['Vulnerability objects'] = array();
        $stdoutarray['Vulnerability objects']['total'] = $this->VulnerabilityProfileStore->count();
        $stdoutarray['WildfireAndAntivirus objects'] = array();
        $stdoutarray['WildfireAndAntivirus objects']['total'] = $this->VirusAndWildfireProfileStore->count();

        $stdoutarray['DNS-Security objects'] = array();
        $stdoutarray['DNS-Security objects']['total'] = $this->DNSSecurityProfileStore->count();
        $stdoutarray['Saas-Security objects'] = array();
        $stdoutarray['Saas-Security objects']['total'] = $this->SaasSecurityProfileStore->count();

        $stdoutarray['URL objects'] = array();
        $stdoutarray['URL objects']['total'] = $this->URLProfileStore->count();
        $stdoutarray['custom URL objects'] = array();
        $stdoutarray['custom URL objects']['total'] = $this->customURLProfileStore->count();
        $stdoutarray['File-Blocking objects'] = array();
        $stdoutarray['File-Blocking objects']['total'] = $this->FileBlockingProfileStore->count();
        $stdoutarray['Data-Filtering objects'] = array();
        $stdoutarray['Data-Filtering objects']['total'] = $this->DataFilteringProfileStore->count();
        $stdoutarray['Decryption objects'] = array();
        $stdoutarray['Decryption objects']['total'] = $this->DecryptionProfileStore->count();

        $stdoutarray['zones'] = $this->zoneStore->count();
        $stdoutarray['apps'] = $this->appStore->count();


        $this->sizeArray['type'] = get_class( $this );
        $this->sizeArray['statstype'] = "objects";
        $this->sizeArray['header'] = $header;
        $this->sizeArray['kb Container'] = &DH::dom_get_config_size($this->xmlroot);
        $this->sizeArray['kb security rules'] = &DH::dom_get_config_size($this->securityRules->xmlroot);
        $this->sizeArray['kb nat rules'] = &DH::dom_get_config_size($this->natRules->xmlroot);
        $this->sizeArray['kb qos rules'] = &DH::dom_get_config_size($this->qosRules->xmlroot);
        $this->sizeArray['kb pbf rules'] = &DH::dom_get_config_size($this->pbfRules->xmlroot);
        $this->sizeArray['kb decrypt rules'] = &DH::dom_get_config_size($this->decryptionRules->xmlroot);
        $this->sizeArray['kb app-override rules'] = &DH::dom_get_config_size($this->appOverrideRules->xmlroot);
        $this->sizeArray['kb captive-portal rules'] = &DH::dom_get_config_size($this->captivePortalRules->xmlroot);
        $this->sizeArray['kb authentication rules'] = &DH::dom_get_config_size($this->authenticationRules->xmlroot);
        $this->sizeArray['kb dos rules'] = &DH::dom_get_config_size($this->dosRules->xmlroot);
        $this->sizeArray['kb tunnel-inspection rules'] = &DH::dom_get_config_size($this->tunnelInspectionRules->xmlroot);
        #$this->sizeArray['kb default-security rules'] = &DH::dom_get_config_size($this->defaultSecurityRules->xmlroot);
        $this->sizeArray['kb network-packet-broker rules'] = &DH::dom_get_config_size($this->networkPacketBrokerRules->xmlroot);
        $this->sizeArray['kb sdwan rules'] = &DH::dom_get_config_size($this->sdWanRules->xmlroot);

        $tmp_adr = &DH::dom_get_config_size($this->addressStore->addressRoot);
        $tmp_adrgrp = &DH::dom_get_config_size($this->addressStore->addressGroupRoot);
        $tmp_region = &DH::dom_get_config_size($this->addressStore->regionRoot);
        $this->sizeArray['kb address objects '] = $tmp_adr+$tmp_adrgrp+$tmp_region;
        $tmp_srv = &DH::dom_get_config_size($this->serviceStore->serviceRoot);
        $tmp_srvgrp = &DH::dom_get_config_size($this->serviceStore->serviceGroupRoot);
        $this->sizeArray['kb address objects '] = $tmp_srv+$tmp_srvgrp;
        $this->sizeArray['kb tag objects'] = &DH::dom_get_config_size($this->tagStore->xmlroot);

        $this->sizeArray['kb securityProfileGroup objects'] = &DH::dom_get_config_size($this->securityProfileGroupStore->xmlroot);

        $this->sizeArray['kb Anti-Spyware objects'] = &DH::dom_get_config_size($this->AntiSpywareProfileStore->xmlroot);
        $this->sizeArray['kb Vulnerability objects'] = &DH::dom_get_config_size($this->VulnerabilityProfileStore->xmlroot);
        $this->sizeArray['kb Wildfire and Antivirus objects'] = &DH::dom_get_config_size($this->VirusAndWildfireProfileStore->xmlroot);
        #$this->sizeArray['kb Wildfire objects'] = &DH::dom_get_config_size($this->WildfireProfileStore->xmlroot);
        $this->sizeArray['kb URL objects'] = &DH::dom_get_config_size($this->URLProfileStore->xmlroot);
        $this->sizeArray['kb custom URL objects'] = &DH::dom_get_config_size($this->customURLProfileStore->xmlroot);
        $this->sizeArray['kb File-Blocking objects'] = &DH::dom_get_config_size($this->FileBlockingProfileStore->xmlroot);

        $this->sizeArray['kb Decryption objects'] = &DH::dom_get_config_size($this->DecryptionProfileStore->xmlroot);
        $this->sizeArray['kb HipObject objects'] = &DH::dom_get_config_size($this->HipObjectsProfileStore->xmlroot);
        $this->sizeArray['kb HipProfile objects'] = &DH::dom_get_config_size($this->HipProfilesProfileStore->xmlroot);
        #$this->sizeArray['kb GTP objects'] = &DH::dom_get_config_size($this->GTPProfileStore->xmlroot);
        #$this->sizeArray['kb SCEP objects'] = &DH::dom_get_config_size($this->SCEPProfileStore->xmlroot);
        #$this->sizeArray['kb PacketBroker objects'] = &DH::dom_get_config_size($this->PacketBrokerProfileStore->xmlroot);
        #$this->sizeArray['kb SDWanErrorCorrection objects'] = &DH::dom_get_config_size($this->tagStore->xmlroot);
        #$this->sizeArray['kb SDWanPathQuality objects'] = &DH::dom_get_config_size($this->SDWanPathQualityProfileStore->xmlroot);
        #$this->sizeArray['kb SDWanSaasQuality objects'] = &DH::dom_get_config_size($this->SDWanSaasQualityProfileStore->xmlroot);
        #$this->sizeArray['kb SDWanTrafficDistribution objects'] = &DH::dom_get_config_size($this->SDWanTrafficDistributionProfileStore->xmlroot);
        #$this->sizeArray['kb DataObjects objects'] = &DH::dom_get_config_size($this->DataObjectsProfileStore->xmlroot);
        #$this->sizeArray['kb LogProfile objects'] = &DH::dom_get_config_size($this->LogProfileStore->xmlroot);



        if( !PH::$shadow_json && $actions == "display"  )
            PH::print_stdout( $stdoutarray, true );

        if( !PH::$shadow_json && $actions == "display-size"  )
        {
            PH::stats_remove_zero_arrays($this->sizeArray);
            PH::print_stdout( $this->sizeArray, true );
        }

        if( $actions == "display-available" )
        {
            PH::stats_remove_zero_arrays($stdoutarray);
            if( !PH::$shadow_json )
                PH::print_stdout( $stdoutarray, true );
        }

        PH::$JSON_TMP[] = $stdoutarray;


        $this->display_bp_statistics( $debug, $actions );

    }

    public function get_bp_statistics()
    {
        $sub = $this;
        $sub_ruleStore = $sub->securityRules;

        $stdoutarray = array();

        $stdoutarray['type'] = get_class( $sub );
        $stdoutarray['statstype'] = "adoption";

        $header = "BP/Visibility Statistics for Container '" . PH::boldText($sub->name) . "' | '" . $sub->toString() . "'";
        $stdoutarray['header'] = $header;

        $stdoutarray['security rules'] = $sub_ruleStore->count();

        $stdoutarray['security rules allow'] = count( $sub_ruleStore->rules( "(action is.allow)" ) );
        $stdoutarray['security rules allow enabled'] = count( $sub_ruleStore->rules( "(action is.allow) and (rule is.enabled)" ) );
        $stdoutarray['security rules allow disabled'] = count( $sub_ruleStore->rules( "(action is.allow) and (rule is.disabled)" ) );
        $stdoutarray['security rules enabled'] = count( $sub_ruleStore->rules( "(rule is.enabled)" ) );
        $stdoutarray['security rules deny'] = count( $sub_ruleStore->rules( "!(action is.allow)" ) );
        $stdoutarray['security rules deny enabled'] = count( $sub_ruleStore->rules( "!(action is.allow) and (rule is.enabled)" ) );
        $ruleForCalculation = $stdoutarray['security rules allow enabled'];

        $generalFilter = "(rule is.enabled) and ";
        $generalFilter_allow = "(rule is.enabled) and (action is.allow) and ";
        //Logging
        $stdoutarray['log at end'] = count( $sub_ruleStore->rules( $generalFilter."(log at.end)" ) );
        $stdoutarray['log at end calc'] = $stdoutarray['log at end']."/".$stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['log at end percentage'] = floor(( $stdoutarray['log at end'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['log at end percentage'] = 0;
        $stdoutarray['log at not start'] = count( $sub_ruleStore->rules( $generalFilter."!(log at.start)" ) );
        $stdoutarray['log at not start calc'] = $stdoutarray['log at not start']."/".$stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['log at not start percentage'] = floor(( $stdoutarray['log at not start'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['log at not start percentage'] = 0;

        //Log Forwarding Profiles
        $stdoutarray['log prof set'] = count( $sub_ruleStore->rules( $generalFilter."(logprof is.set)" ) );
        $stdoutarray['log prof set calc'] = $stdoutarray['log prof set']."/".$stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['log prof set percentage'] = floor(( $stdoutarray['log prof set'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['log prof set percentage'] = 0;

        //Wildfire Analysis Profiles
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "wf is.visibility" );
        $stdoutarray['wf visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['wf visibility calc'] = $stdoutarray['wf visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['wf visibility percentage'] = floor(( $stdoutarray['wf visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['wf visibility percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "wf is.best-practice" );
        $stdoutarray['wf best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['wf best-practice calc'] = $stdoutarray['wf best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['wf best-practice percentage'] = floor( ( $stdoutarray['wf best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['wf best-practice percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "wf is.adoption" );
        $stdoutarray['wf adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['wf adoption calc'] = $stdoutarray['wf adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['wf adoption percentage'] = floor(( $stdoutarray['wf adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['wf adoption percentage'] = 0;

        //Zone Protection
        $filter_array = array('query' => $generalFilter."!(from is.any) and (from all.has.from.query subquery1)", 'subquery1' => "zpp is.set" );
        $stdoutarray['zone protection'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['zone protection calc'] = $stdoutarray['zone protection']."/".$stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['zone protection percentage'] = floor( ( $stdoutarray['zone protection'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['zone protection percentage'] = 0;

        // App-ID
        $stdoutarray['app id'] = count( $sub_ruleStore->rules( $generalFilter_allow."!(app is.any)" ) );
        $stdoutarray['app id calc'] = $stdoutarray['app id']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['app id percentage'] = floor( ( $stdoutarray['app id'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['app id percentage'] = 0;

        //User-ID
        $stdoutarray['user id'] = count( $sub_ruleStore->rules( $generalFilter_allow."!(user is.any)" ) );
        $stdoutarray['user id calc'] = $stdoutarray['user id']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['user id percentage'] = floor( ( $stdoutarray['user id'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['user id percentage'] = 0;
        //Service/Port
        $stdoutarray['service port'] = count( $sub_ruleStore->rules( $generalFilter_allow."!(service is.any)" ) );
        $stdoutarray['service port calc'] = $stdoutarray['service port']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['service port percentage'] = floor( ( $stdoutarray['service port'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['service port percentage'] = 0;

        //Antivirus Profiles
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "av is.visibility" );
        $stdoutarray['av visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['av visibility calc'] = $stdoutarray['av visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['av visibility percentage'] = floor( ( $stdoutarray['av visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['av visibility percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "av is.best-practice" );
        $stdoutarray['av best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['av best-practice calc'] = $stdoutarray['av best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['av best-practice percentage'] = floor( ( $stdoutarray['av best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['av best-practice percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "av is.adoption" );
        $stdoutarray['av adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['av adoption calc'] = $stdoutarray['av adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['av adoption percentage'] = floor( ( $stdoutarray['av adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['av adoption percentage'] = 0;

        //Anti-Spyware Profiles
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "as is.visibility" );
        $stdoutarray['as visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['as visibility calc'] = $stdoutarray['as visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['as visibility percentage'] = floor( ( $stdoutarray['as visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['as visibility percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "as is.best-practice" );
        $stdoutarray['as best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['as best-practice calc'] = $stdoutarray['as best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['as best-practice percentage'] = floor( ( $stdoutarray['as best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['as best-practice percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "as is.adoption" );
        $stdoutarray['as adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['as adoption calc'] = $stdoutarray['as adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['as adoption percentage'] = floor( ( $stdoutarray['as adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['as adoption percentage'] = 0;

        //Vulnerability Profiles
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "vp is.visibility" );
        $stdoutarray['vp visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['vp visibility calc'] = $stdoutarray['vp visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['vp visibility percentage'] = floor( ( $stdoutarray['vp visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['vp visibility percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "vp is.best-practice" );
        $stdoutarray['vp best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['vp best-practice calc'] = $stdoutarray['vp best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['vp best-practice percentage'] = floor( ( $stdoutarray['vp best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['vp best-practice percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "vp is.adoption" );
        $stdoutarray['vp adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['vp adoption calc'] = $stdoutarray['vp adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['vp adoption percentage'] = floor( ( $stdoutarray['vp adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['vp adoption percentage'] = 0;

        //File Blocking Profiles
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "fb is.visibility" );
        $stdoutarray['fb visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['fb visibility calc'] = $stdoutarray['fb visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['fb visibility percentage'] = floor( ( $stdoutarray['fb visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['fb visibility percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "fb is.best-practice" );
        $stdoutarray['fb best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['fb best-practice calc'] = $stdoutarray['fb best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['fb best-practice percentage'] = floor( ( $stdoutarray['fb best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['fb best-practice percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "fb is.adoption" );
        $stdoutarray['fb adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['fb adoption calc'] = $stdoutarray['fb adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['fb adoption percentage'] = floor( ( $stdoutarray['fb adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['fb adoption percentage'] = 0;

        //Data Filtering
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "df is.visibility" );
        $stdoutarray['data visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['data visibility calc'] = $stdoutarray['data visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['data visibility percentage'] = floor( ( $stdoutarray['data visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['data visibility percentage'] = 0;
        $stdoutarray['data best-practice'] = "NOT available";
        //--
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "df is.adoption" );
        $stdoutarray['data adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['data adoption calc'] = $stdoutarray['data adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['data adoption percentage'] = floor( ( $stdoutarray['data adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['data adoption percentage'] = 0;

        //URL Filtering Profiles
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "url.site-access is.visibility" );
        $stdoutarray['url-site-access visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['url-site-access visibility calc'] = $stdoutarray['url-site-access visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-site-access visibility percentage'] = floor( ( $stdoutarray['url-site-access visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-site-access visibility percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "url.site-access is.best-practice" );
        $stdoutarray['url-site-access best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['url-site-access best-practice calc'] = $stdoutarray['url-site-access best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-site-access best-practice percentage'] = floor( ( $stdoutarray['url-site-access best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-site-access best-practice percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "url.site-access is.adoption" );
        $stdoutarray['url-site-access adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['url-site-access adoption calc'] = $stdoutarray['url-site-access adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-site-access adoption percentage'] = floor( ( $stdoutarray['url-site-access adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-site-access adoption percentage'] = 0;

        //Credential Theft Prevention
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "url.user-credential-detection is.visibility" );
        $stdoutarray['url-credential visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['url-credential visibility calc'] = $stdoutarray['url-credential visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-credential visibility percentage'] = floor( ( $stdoutarray['url-credential visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-credential visibility percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "url.user-credential-detection is.best-practice" );
        $stdoutarray['url-credential best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['url-credential best-practice calc'] = $stdoutarray['url-credential best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-credential best-practice percentage'] = floor( ( $stdoutarray['url-credential best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-credential best-practice percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "url.user-credential-detection is.adoption" );
        $stdoutarray['url-credential adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['url-credential adoption calc'] = $stdoutarray['url-credential adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-credential adoption percentage'] = floor( ( $stdoutarray['url-credential adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-credential adoption percentage'] = 0;

        //DNS List
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "dns-list is.visibility" );
        $stdoutarray['dns-list visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['dns-list visibility calc'] = $stdoutarray['dns-list visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-list visibility percentage'] = floor( ( $stdoutarray['dns-list visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-list visibility percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "dns-list is.best-practice" );
        $stdoutarray['dns-list best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['dns-list best-practice calc'] = $stdoutarray['dns-list best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-list best-practice percentage'] = floor( ( $stdoutarray['dns-list best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-list best-practice percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "dns-list is.adoption" );
        $stdoutarray['dns-list adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['dns-list adoption calc'] = $stdoutarray['dns-list adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-list adoption percentage'] = floor( ( $stdoutarray['dns-list adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-list adoption percentage'] = 0;

        //DNS Security
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "dns-security is.visibility" );
        $stdoutarray['dns-security visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['dns-security visibility calc'] = $stdoutarray['dns-security visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-security visibility percentage'] = floor( ( $stdoutarray['dns-security visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-security visibility percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "dns-security is.best-practice" );
        $stdoutarray['dns-security best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['dns-security best-practice calc'] = $stdoutarray['dns-security best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-security best-practice percentage'] = floor( ( $stdoutarray['dns-security best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-security best-practice percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "dns-security is.adoption" );
        $stdoutarray['dns-security adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['dns-security adoption calc'] = $stdoutarray['dns-security adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-security adoption percentage'] = floor( ( $stdoutarray['dns-security adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-security adoption percentage'] = 0;

        $percentageArray = array();

        $percentageArray_adoption = array();
        $percentageArray_adoption['Logging']['value'] = $stdoutarray['log at end percentage'];
        $percentageArray_adoption['Logging']['group'] = 'Logging';
        $percentageArray_adoption['Log Forwarding Profiles']['value'] = $stdoutarray['log prof set percentage'];
        $percentageArray_adoption['Log Forwarding Profiles']['group'] = 'Logging';
        $percentageArray_adoption['Wildfire Analysis Profiles']['value'] = $stdoutarray['wf visibility percentage'];
        $percentageArray_adoption['Wildfire Analysis Profiles']['group'] = 'Wildfire';
        $percentageArray_adoption['Zone Protection']['value'] = $stdoutarray['zone protection percentage'];
        $percentageArray_adoption['Zone Protection']['group'] = 'Zone Protection';
        $percentageArray_adoption['App-ID']['value'] = $stdoutarray['app id percentage'];
        $percentageArray_adoption['App-ID']['group'] = 'Apps, Users, Ports';
        $percentageArray_adoption['User-ID']['value'] = $stdoutarray['user id percentage'];
        $percentageArray_adoption['User-ID']['group'] = 'Apps, Users, Ports';
        $percentageArray_adoption['Service/Port']['value'] = $stdoutarray['service port percentage'];
        $percentageArray_adoption['Service/Port']['group'] = 'Apps, Users, Ports';

        $percentageArray_adoption['Antivirus Profiles']['value'] = $stdoutarray['av adoption percentage'];
        $percentageArray_adoption['Antivirus Profiles']['group'] = 'Threat Prevention';
        $percentageArray_adoption['Anti-Spyware Profiles']['value'] = $stdoutarray['as adoption percentage'];
        $percentageArray_adoption['Anti-Spyware Profiles']['group'] = 'Threat Prevention';
        $percentageArray_adoption['Vulnerability Profiles']['value'] = $stdoutarray['vp adoption percentage'];
        $percentageArray_adoption['Vulnerability Profiles']['group'] = 'Threat Prevention';
        $percentageArray_adoption['File Blocking Profiles']['value'] = $stdoutarray['fb adoption percentage'];
        $percentageArray_adoption['File Blocking Profiles']['group'] = 'Data Loss Prevention';
        $percentageArray_adoption['Data Filtering']['value'] = $stdoutarray['data adoption percentage'];
        $percentageArray_adoption['Data Filtering']['group'] = 'Data Loss Prevention';
        $percentageArray_adoption['URL Filtering Profiles']['value'] = $stdoutarray['url-site-access adoption percentage'];
        $percentageArray_adoption['URL Filtering Profiles']['group'] = 'URL Filtering';
        $percentageArray_adoption['Credential Theft Prevention']['value'] = $stdoutarray['url-credential adoption percentage'];
        $percentageArray_adoption['Credential Theft Prevention']['group'] = 'URL Filtering';
        #$percentageArray_adoption['DNS List']['value'] = $stdoutarray['dns-list adoption percentage'];
        $percentageArray_adoption['DNS Security']['value'] = $stdoutarray['dns-security adoption percentage'];
        $percentageArray_adoption['DNS Security']['group'] = 'DNS Security';

        $percentageArray['adoption'] = $percentageArray_adoption;

        $percentageArray_visibility = array();
        $percentageArray_visibility['Logging']['value'] = $stdoutarray['log at end percentage'];
        $percentageArray_visibility['Logging']['group'] = 'Logging';
        $percentageArray_visibility['Log Forwarding Profiles']['value'] = $stdoutarray['log prof set percentage'];
        $percentageArray_visibility['Log Forwarding Profiles']['group'] = 'Logging';
        $percentageArray_visibility['Wildfire Analysis Profiles']['value'] = $stdoutarray['wf visibility percentage'];
        $percentageArray_visibility['Wildfire Analysis Profiles']['group'] = 'Wildfire';
        $percentageArray_visibility['Zone Protection']['value'] = $stdoutarray['zone protection percentage'];
        $percentageArray_visibility['Zone Protection']['group'] = 'Zone Protection';
        $percentageArray_visibility['App-ID']['value'] = $stdoutarray['app id percentage'];
        $percentageArray_visibility['App-ID']['group'] = 'Apps, Users, Ports';
        $percentageArray_visibility['User-ID']['value'] = $stdoutarray['user id percentage'];
        $percentageArray_visibility['User-ID']['group'] = 'Apps, Users, Ports';
        $percentageArray_visibility['Service/Port']['value'] = $stdoutarray['service port percentage'];
        $percentageArray_visibility['Service/Port']['group'] = 'Apps, Users, Ports';

        $percentageArray_visibility['Antivirus Profiles']['value'] = $stdoutarray['av visibility percentage'];
        $percentageArray_visibility['Antivirus Profiles']['group'] = 'Threat Prevention';
        $percentageArray_visibility['Anti-Spyware Profiles']['value'] = $stdoutarray['as visibility percentage'];
        $percentageArray_visibility['Anti-Spyware Profiles']['group'] = 'Threat Prevention';
        $percentageArray_visibility['Vulnerability Profiles']['value'] = $stdoutarray['vp visibility percentage'];
        $percentageArray_visibility['Vulnerability Profiles']['group'] = 'Threat Prevention';
        $percentageArray_visibility['File Blocking Profiles']['value'] = $stdoutarray['fb visibility percentage'];
        $percentageArray_visibility['File Blocking Profiles']['group'] = 'Data Loss Prevention';
        $percentageArray_visibility['Data Filtering']['value'] = $stdoutarray['data visibility percentage'];
        $percentageArray_visibility['Data Filtering']['group'] = 'Data Loss Prevention';
        $percentageArray_visibility['URL Filtering Profiles']['value'] = $stdoutarray['url-site-access visibility percentage'];
        $percentageArray_visibility['URL Filtering Profiles']['group'] = 'URL Filtering';
        $percentageArray_visibility['Credential Theft Prevention']['value'] = $stdoutarray['url-credential visibility percentage'];
        $percentageArray_visibility['Credential Theft Prevention']['group'] = 'URL Filtering';
        #$percentageArray_visibility['DNS List']['value'] = $stdoutarray['dns-list visibility percentage'];
        $percentageArray_visibility['DNS Security']['value'] = $stdoutarray['dns-security visibility percentage'];
        $percentageArray_visibility['DNS Security']['group'] = 'DNS Security';

        $percentageArray['visibility'] = $percentageArray_visibility;

        $percentageArray_best_practice = array();
        $percentageArray_best_practice['Logging']['value'] = $stdoutarray['log at not start percentage'];
        $percentageArray_best_practice['Logging']['group'] = 'Logging';
        #$percentageArray_best_practice['Log Forwarding Profiles']['value'] = $stdoutarray['log prof set percentage'];

        $percentageArray_best_practice['Wildfire Analysis Profiles']['value'] = $stdoutarray['wf best-practice percentage'];
        $percentageArray_best_practice['Wildfire Analysis Profiles']['group'] = 'Wildfire';
        #$percentageArray_best_practice['Zone Protection']['value'] = '---';
        #$percentageArray_best_practice['App-ID']['value'] = $stdoutarray['app id percentage'];
        #$percentageArray_best_practice['User-ID']['value'] = $stdoutarray['user id percentage'];
        #$percentageArray_best_practice['Service/Port']['value'] = $stdoutarray['service port percentage'];

        $percentageArray_best_practice['Antivirus Profiles']['value'] = $stdoutarray['av best-practice percentage'];
        $percentageArray_best_practice['Antivirus Profiles']['group'] = 'Threat Prevention';
        $percentageArray_best_practice['Anti-Spyware Profiles']['value'] = $stdoutarray['as best-practice percentage'];
        $percentageArray_best_practice['Anti-Spyware Profiles']['group'] = 'Threat Prevention';
        $percentageArray_best_practice['Vulnerability Profiles']['value'] = $stdoutarray['vp best-practice percentage'];
        $percentageArray_best_practice['Vulnerability Profiles']['group'] = 'Threat Prevention';
        $percentageArray_best_practice['File Blocking Profiles']['value'] = $stdoutarray['fb best-practice percentage'];
        $percentageArray_best_practice['File Blocking Profiles']['group'] = 'Threat Prevention';
        #$percentageArray_best_practice['Data Filtering']['value'] = '---';
        $percentageArray_best_practice['URL Filtering Profiles']['value'] = $stdoutarray['url-site-access best-practice percentage'];
        $percentageArray_best_practice['URL Filtering Profiles']['group'] = 'URL Filtering';
        $percentageArray_best_practice['Credential Theft Prevention']['value'] = $stdoutarray['url-credential best-practice percentage'];
        $percentageArray_best_practice['Credential Theft Prevention']['group'] = 'URL Filtering';
        #$percentageArray_best_practice['DNS List']['value'] = $stdoutarray['dns-list best-practice percentage'];
        $percentageArray_best_practice['DNS Security']['value'] = $stdoutarray['dns-security best-practice percentage'];
        $percentageArray_best_practice['DNS Security']['group'] = 'DNS Security';

        $percentageArray['best-practice'] = $percentageArray_best_practice;

        $stdoutarray['percentage'] = $percentageArray;

        return $stdoutarray;
    }

    public function display_bp_statistics( $debug = false, $actions = "display" )
    {
        $stdoutarray = $this->get_bp_statistics(  );
        PH::$JSON_TMP[] = $stdoutarray;

        $header = $stdoutarray['header'];

        //Todo swaschkut 20251014
        //todo: validate if information must be changed bas on bp_sp_panw.json
        PH::validateIncludedInBPA( $stdoutarray );

        $percentageArray_adoption = $stdoutarray['percentage']['adoption'];
        $percentageArray_visibility = $stdoutarray['percentage']['visibility'];
        $percentageArray_best_practice = $stdoutarray['percentage']['best-practice'];

        if( !PH::$shadow_json && $actions == "display-bpa" )
        {
            PH::print_stdout( $header );

            $string_check = "adoption";
            PH::print_stdout($string_check);
            $tbl = new ConsoleTable();
            $tbl->setHeaders(
                array('Type', 'percentage', "%")
            );
            foreach( $percentageArray_adoption as $key => $value )
            {
                if( isset( PH::$shadow_bp_jsonfile['included-in-bpa'][$string_check][$key] ) )
                {
                    if( PH::$shadow_bp_jsonfile['included-in-bpa'][$string_check][$key] === false )
                        continue;
                }
                if( strpos($value['value'], "---") !== False )
                {
                    $string = $value['value'];
                }
                else
                {
                    $string = "";
                    $test = floor( ($value['value']/10) * 2 );
                    $string = str_pad($string, $test, "*", STR_PAD_LEFT);
                }
                $tbl->addRow(array($key, $value['value'], $string));
            }

            echo $tbl->getTable();

            $string_check = "visibility";
            PH::print_stdout($string_check);
            $tbl = new ConsoleTable();
            $tbl->setHeaders(
                array('Type', 'percentage', "%")
            );
            foreach( $percentageArray_visibility as $key => $value )
            {
                if( isset( PH::$shadow_bp_jsonfile['included-in-bpa'][$string_check][$key] ) )
                {
                    if( PH::$shadow_bp_jsonfile['included-in-bpa'][$string_check][$key] === false )
                        continue;
                }
                if( strpos($value['value'], "---") !== False )
                {
                    $string = $value['value'];
                }
                else
                {
                    $string = "";
                    $test = floor( ($value['value']/10) * 2 );
                    $string = str_pad($string, $test, "*", STR_PAD_LEFT);
                }
                $tbl->addRow(array($key, $value['value'], $string));
            }

            echo $tbl->getTable();

            $string_check = "best-practice";
            PH::print_stdout($string_check);
            $tbl = new ConsoleTable();
            $tbl->setHeaders(
                array('Type', 'percentage', "%")
            );
            foreach( $percentageArray_best_practice as $key => $value )
            {
                if( isset( PH::$shadow_bp_jsonfile['included-in-bpa'][$string_check][$key] ) )
                {
                    if( PH::$shadow_bp_jsonfile['included-in-bpa'][$string_check][$key] === false )
                        continue;
                }
                if( strpos($value['value'], "---") !== False )
                {
                    $string = $value['value'];
                }
                else
                {
                    $string = "";
                    $test = floor( ($value['value']/10) * 2 );
                    $string = str_pad($string, $test, "*", STR_PAD_LEFT);
                }
                $tbl->addRow(array($key, $value['value'], $string));
            }

            echo $tbl->getTable();

            PH::print_stdout();
        }


        #PH::$JSON_TMP[$this->name] = $stdoutarray;
        PH::$JSON_TMP[] = $stdoutarray;


        if( !PH::$shadow_json && $debug && $actions == "display-bpa" )
            PH::print_stdout( $stdoutarray, true );

    }

    /**
     * @return string
     */
    public function name()
    {
        return $this->name;
    }


    public function setName($newName)
    {
        $this->xmlroot->setAttribute('name', $newName);
        $this->name = $newName;
    }

    /**
     * @return string
     */
    public function alternativeName()
    {
        return $this->_alternativeName;
    }

    public function setAlternativeName($newName)
    {
        if( $newName == $this->_alternativeName )
            return FALSE;

        if( $newName === null || strlen($newName) == 0 )
        {
            $node = DH::findFirstElement('display-name', $this->xmlroot);
            if( $node === FALSE )
                return FALSE;

            $this->xmlroot->removeChild($node);
            return TRUE;
        }

        if( $this->owner->owner != null && get_class($this->owner->owner) ==  "Template")
        {
        }
        else
        {
            $node = DH::findFirstElementOrCreate('display-name', $this->xmlroot);
            DH::setDomNodeText($node, $newName);
        }

        $this->_alternativeName = $newName;

        return TRUE;
    }


    static public $templateXml = '<entry name="temporarynamechangemeplease"></entry>';

}
