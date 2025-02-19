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

class VirtualSystem
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
    public $AntiVirusProfileStore = null;

    /** @var ThreatPolicyStore */
    public $ThreatPolicyStore = null;

    /** @var DNSPolicyStore */
    public $DNSPolicyStore = null;

    /** @var SecurityProfileStore */
    public $VulnerabilityProfileStore = null;

    /** @var SecurityProfileStore */
    public $AntiSpywareProfileStore = null;

    /** @var SecurityProfileStore */
    public $FileBlockingProfileStore = null;

    /** @var SecurityProfileStore */
    public $DataFilteringProfileStore = null;

    /** @var SecurityProfileStore */
    public $WildfireProfileStore = null;


    /** @var SecurityProfileGroupStore */
    public $securityProfileGroupStore = null;

    /** @var SecurityProfileStore */
    public $DecryptionProfileStore = null;

    /** @var SecurityProfileStore */
    public $HipObjectsProfileStore = null;

    /** @var SecurityProfileStore */
    public $HipProfilesProfileStore = null;

    /** @var SecurityProfileStore */
    public $GTPProfileStore = null;

    /** @var SecurityProfileStore */
    public $SCEPProfileStore = null;

    /** @var SecurityProfileStore */
    public $PacketBrokerProfileStore = null;

    /** @var SecurityProfileStore */
    public $SDWanErrorCorrectionProfileStore = null;

    /** @var SecurityProfileStore */
    public $SDWanPathQualityProfileStore = null;

    /** @var SecurityProfileStore */
    public $SDWanSaasQualityProfileStore = null;

    /** @var SecurityProfileStore */
    public $SDWanTrafficDistributionProfileStore = null;

    /** @var SecurityProfileStore */
    public $DataObjectsProfileStore = null;


    /** @var ScheduleStore */
    public $scheduleStore = null;

    /** @var EDLStore */
    public $EDLStore = null;

    /** @var string */
    public $name;

    /** @var string */
    protected $_alternativeName = '';

    /** @var PANConf|null */
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
    public $defaultSecurityRules = null;

    /** @var RuleStore */
    public $networkPacketBrokerRules;

    /** @var RuleStore */
    public $sdWanRules;


    /** @var ZoneStore */
    public $zoneStore = null;

    /** @var GPGatewayStore */
    public $GPGatewayStore = null;

    /** @var GPPortalStore */
    public $GPPortalStore = null;

    /** @var CertificateStore */
    public $certificateStore = null;

    /** @var InterfaceContainer */
    public $importedInterfaces;

    /** @var VirtualRouterContainer */
    public $importedVirtualRouter;

    public $importedVisibleVsys;

    /** @var DeviceGroup $parentDeviceGroup in case it load as part of Panorama */
    public $parentDeviceGroup = null;

    public $version = null;
    public $apiCache;

    /**
     * VirtualSystem constructor.
     * @param PANConf|SharedGatewayStore $owner
     * @param DeviceGroup $applicableDG
     */
    public function __construct( $owner, $applicableDG = null)
    {
        $this->owner = $owner;

        $this->parentDeviceGroup = $applicableDG;


        $this->tagStore = new TagStore($this);
        $this->tagStore->name = 'tags';

        if( get_class($owner) == "SharedGatewayStore" )
        {
            $this->version = &$owner->owner->version;

            $this->importedInterfaces = new InterfaceContainer($this, $owner->owner->network);
            $this->importedVirtualRouter = new VirtualRouterContainer($this, $owner->owner->network);

            $this->importedVisibleVsys = array();
        }
        else
        {
            $this->version = &$owner->version;

            $this->importedInterfaces = new InterfaceContainer($this, $owner->network);
            $this->importedVirtualRouter = new VirtualRouterContainer($this, $owner->network);

            $this->importedVisibleVsys = array();
        }



        #$this->appStore = $owner->appStore;
        $this->appStore = new AppStore($this);
        $this->appStore->name = 'customApplication';

        if( get_class($owner) !== "SharedGatewayStore" )
            $this->threatStore = $owner->threatStore;

        $this->zoneStore = new ZoneStore($this);
        $this->zoneStore->setName('zoneStore');

        $this->GPGatewayStore = new GPGatewayStore($this);
        $this->GPGatewayStore->setName('GPGatewayStore');

        $this->GPPortalStore = new GPPortalStore($this);
        $this->GPPortalStore->setName('GPPortalStore');

        $this->certificateStore = new CertificateStore($this);
        $this->certificateStore->setName('certificateStore');


        $this->serviceStore = new ServiceStore($this);
        $this->serviceStore->name = 'services';

        $this->addressStore = new AddressStore($this);
        $this->addressStore->name = 'addresses';


        $this->customURLProfileStore = new SecurityProfileStore($this, "customURLProfile");
        $this->customURLProfileStore->name = 'CustomURL';

        $this->URLProfileStore = new SecurityProfileStore($this, "URLProfile");
        $this->URLProfileStore->name = 'URL';

        $this->AntiVirusProfileStore = new SecurityProfileStore($this, "AntiVirusProfile");
        $this->AntiVirusProfileStore->name = 'AntiVirus';


        $this->ThreatPolicyStore = new ThreatPolicyStore($this, "ThreatPolicy");
        $this->ThreatPolicyStore->name = 'ThreatPolicy';

        $this->DNSPolicyStore = new DNSPolicyStore($this, "DNSPolicy");
        $this->DNSPolicyStore->name = 'DNSPolicy';

        $this->VulnerabilityProfileStore = new SecurityProfileStore($this, "VulnerabilityProfile");
        $this->VulnerabilityProfileStore->name = 'Vulnerability';

        $this->AntiSpywareProfileStore = new SecurityProfileStore($this, "AntiSpywareProfile");
        $this->AntiSpywareProfileStore->name = 'AntiSpyware';

        $this->FileBlockingProfileStore = new SecurityProfileStore($this, "FileBlockingProfile");
        $this->FileBlockingProfileStore->name = 'FileBlocking';

        $this->DataFilteringProfileStore = new SecurityProfileStore($this, "DataFilteringProfile");
        $this->DataFilteringProfileStore->name = 'DataFiltering';

        $this->WildfireProfileStore = new SecurityProfileStore($this, "WildfireProfile");
        $this->WildfireProfileStore->name = 'WildFire';


        $this->securityProfileGroupStore = new SecurityProfileGroupStore($this);
        $this->securityProfileGroupStore->name = 'SecurityProfileGroups';


        $this->DecryptionProfileStore = new SecurityProfileStore($this, "DecryptionProfile");
        $this->DecryptionProfileStore->name = 'Decryption';

        $this->HipObjectsProfileStore = new SecurityProfileStore($this, "HipObjectsProfile");
        $this->HipObjectsProfileStore->name = 'HipObjects';

        $this->HipProfilesProfileStore = new SecurityProfileStore($this, "HipProfilesProfile");
        $this->HipProfilesProfileStore->name = 'HipProfiles';

        $this->GTPProfileStore = new SecurityProfileStore($this, "GTPProfile");
        $this->GTPProfileStore->name = 'GTPProfiles';

        $this->SCEPProfileStore = new SecurityProfileStore($this, "SCEPProfile");
        $this->SCEPProfileStore->name = 'SCEPProfiles';

        $this->PacketBrokerProfileStore = new SecurityProfileStore($this, "PacketBrokerProfile");
        $this->PacketBrokerProfileStore->name = 'PacketBrokerProfiles';

        $this->SDWanErrorCorrectionProfileStore = new SecurityProfileStore($this, "SDWanErrorCorrectionProfile");
        $this->SDWanErrorCorrectionProfileStore->name = 'SDWanErrorCorrectionProfiles';

        $this->SDWanPathQualityProfileStore = new SecurityProfileStore($this, "SDWanPathQualityProfile");
        $this->SDWanPathQualityProfileStore->name = 'SDWanPathQualityProfiles';

        $this->SDWanSaasQualityProfileStore = new SecurityProfileStore($this, "SDWanSaasQualityProfile");
        $this->SDWanSaasQualityProfileStore->name = 'SDWanSaasQualityProfiles';

        $this->SDWanTrafficDistributionProfileStore = new SecurityProfileStore($this, "SDWanTrafficDistributionProfile");
        $this->SDWanTrafficDistributionProfileStore->name = 'SDWanTrafficDistributionProfiles';

        $this->DataObjectsProfileStore = new SecurityProfileStore($this, "DataObjectsProfile");
        $this->DataObjectsProfileStore->name = 'DataObjectsProfileStoreProfiles';


        $this->scheduleStore = new ScheduleStore($this);
        $this->scheduleStore->setName('scheduleStore');

        $this->EDLStore = new EDLStore($this);
        $this->EDLStore->setName('EDLStore');

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

        $this->defaultSecurityRules = new RuleStore($this, 'DefaultSecurityRule', TRUE);
        $this->defaultSecurityRules->name = 'DefaultSecurity';

        $this->networkPacketBrokerRules = new RuleStore($this, 'NetworkPacketBrokerRule', TRUE);
        $this->networkPacketBrokerRules->name = 'NetworkPacketBroker';

        $this->sdWanRules = new RuleStore($this, 'SDWanRule', TRUE);
        $this->sdWanRules->name = 'SDWan';


        if( get_class($owner) === "SharedGatewayStore" )
        {
            $this->dosRules->_networkStore = $this->owner->owner->network;
            $this->pbfRules->_networkStore = $this->owner->owner->network;
        }
        else
        {
            $this->dosRules->_networkStore = $this->owner->network;
            $this->pbfRules->_networkStore = $this->owner->network;
        }

        $storeType = array(
            'addressStore', 'serviceStore', 'tagStore', 'scheduleStore', 'appStore',

            'EDLStore',

            'securityProfileGroupStore',

            'URLProfileStore', 'AntiVirusProfileStore', 'FileBlockingProfileStore', 'DataFilteringProfileStore',
            'VulnerabilityProfileStore', 'AntiSpywareProfileStore', 'WildfireProfileStore',
            'DecryptionProfileStore', 'HipObjectsProfileStore'

        );

        foreach( $storeType as $type )
        {
            if( get_class($this->owner) === "SharedGatewayStore" )
                $this->$type->parentCentralStore = $this->owner->owner->$type;
            else
                $this->$type->parentCentralStore = $this->owner->$type;
        }

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
            derr("VirtualSystem name not found\n", $xml);

        //print "VSYS '".$this->name."' found\n";

        // this VSYS has a display-name ?
        $displayNameNode = DH::findFirstElement('display-name', $xml);
        if( $displayNameNode !== FALSE )
            $this->_alternativeName = $displayNameNode->textContent;


        //
        // loading the imported objects list
        //
        $importroot = DH::findFirstElement('import', $xml);
        if( $importroot !== FALSE )
        {
            $networkRoot = DH::findFirstElementOrCreate('network', $importroot);
            $tmp = DH::findFirstElementOrCreate('interface', $networkRoot);
            if( $this->importedInterfaces !== null )
                $this->importedInterfaces->load_from_domxml($tmp);

            $tmp = DH::findFirstElement('virtual-router', $networkRoot);
            if( $tmp !== FALSE )
            {
                if( $this->importedVirtualRouter !== null )
                    $this->importedVirtualRouter->load_from_domxml($tmp);
            }

            $tmp = DH::findFirstElement('visible-vsys', $importroot);
            if( $tmp !== FALSE )
            {
                foreach( $tmp->childNodes as $child )
                {
                    if( $child->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $this->importedVisibleVsys[$child->textContent] =   $child->textContent;
                }

            }

        }

        //

        if( $this->owner->owner === null || get_class($this->owner) == "SharedGatewayStore" )
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
            //print "VSYS '".$this->name."' address objectsloaded\n" ;
            // End of address objects extraction

            //
            // Extract address objects
            //
            $tmp = DH::findFirstElement('address', $xml);
            if( $tmp !== FALSE )
                $this->addressStore->load_addresses_from_domxml($tmp);
            //print "VSYS '".$this->name."' address objectsloaded\n" ;
            // End of address objects extraction


            //
            // Extract address groups in this DV
            //
            $tmp = DH::findFirstElement('address-group', $xml);
            if( $tmp !== FALSE )
                $this->addressStore->load_addressgroups_from_domxml($tmp);
            //print "VSYS '".$this->name."' address groups loaded\n" ;
            // End of address groups extraction


            //												//
            // Extract service objects in this VSYS			//
            //												//
            $tmp = DH::findFirstElement('service', $xml);
            if( $tmp !== FALSE )
                $this->serviceStore->load_services_from_domxml($tmp);
            //print "VSYS '".$this->name."' service objects\n" ;
            // End of <service> extraction


            //												//
            // Extract service groups in this VSYS			//
            //												//
            $tmp = DH::findFirstElement('service-group', $xml);
            if( $tmp !== FALSE )
            {
                #print "VSYS '".$this->name."' service groups loaded\n" ;
                $this->serviceStore->load_servicegroups_from_domxml($tmp);
            }
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
                $tmproot = DH::findFirstElement('virus', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->AntiVirusProfileStore->load_from_domxml($tmproot);
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
                {
                    $this->DataFilteringProfileStore->load_from_domxml($tmproot);
                }

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
                // wildfire Profile extraction
                //
                $tmproot = DH::findFirstElement('wildfire-analysis', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->WildfireProfileStore->load_from_domxml($tmproot);
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

                //
                // GTP Profile extraction
                //
                $tmproot = DH::findFirstElement('gtp', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->GTPProfileStore->load_from_domxml($tmproot);
                }

                //
                // SCEP Profile extraction
                //
                $tmproot = DH::findFirstElement('scep', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->SCEPProfileStore->load_from_domxml($tmproot);
                }

                //
                // PacketBroker Profile extraction
                //
                $tmproot = DH::findFirstElement('packet-broker', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->PacketBrokerProfileStore->load_from_domxml($tmproot);
                }

                //
                // SDWan Error Correction Profile extraction
                //
                $tmproot = DH::findFirstElement('sdwan-error-correction', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->SDWanErrorCorrectionProfileStore->load_from_domxml($tmproot);
                }

                //
                // SDWan Path Quality Profile extraction
                //
                $tmproot = DH::findFirstElement('sdwan-path-quality', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->SDWanPathQualityProfileStore->load_from_domxml($tmproot);
                }

                //
                // SDWan Saas Quality Profile extraction
                //
                $tmproot = DH::findFirstElement('sdwan-saas-quality', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->SDWanSaasQualityProfileStore->load_from_domxml($tmproot);
                }

                //
                // SDWan Traffic Distribution Profile extraction
                //
                $tmproot = DH::findFirstElement('sdwan-traffic-distribution', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->SDWanTrafficDistributionProfileStore->load_from_domxml($tmproot);
                }

                //
                // DataObjects Profile extraction
                //
                $tmproot = DH::findFirstElement('data-objects', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->DataObjectsProfileStore->load_from_domxml($tmproot);
                }
            }


            //
            // Extract SecurityProfile groups in this DV
            //
            $tmp = DH::findFirstElement('profile-group', $xml);
            if( $tmp !== FALSE )
                $this->securityProfileGroupStore->load_securityprofile_groups_from_domxml($tmp);
            // End of SecurityProfile groups extraction


            //
            // Extract schedule objects
            //
            $tmp = DH::findFirstElement('schedule', $xml);
            if( $tmp !== FALSE )
                $this->scheduleStore->load_from_domxml($tmp);
            // End of schedule extraction


            //
            // Extract EDL objects
            //
            $tmp = DH::findFirstElement('external-list', $xml);
            if( $tmp !== FALSE )
                $this->EDLStore->load_from_domxml($tmp);
            // End of EDL extraction

        }

        //
        // add reference to address object, if interface IP-address is using this object
        //
        if( $this->importedInterfaces !== null)
        {
            foreach( $this->importedInterfaces->interfaces() as $interface )
            {
                if( $interface->isEthernetType() && $interface->type() == "layer3" )
                {
                    $interfacesv4 = $interface->getLayer3IPv4Addresses();
                    $interfacesv6 = $interface->getLayer3IPv6Addresses();
                    $interfaces = array_merge($interfacesv4, $interfacesv6);

                    if( !empty($interface->subInterfaces()) )
                    {
                        foreach( $interface->subInterfaces() as $subinterface )
                        {
                            $interfacesv4 = $subinterface->getLayer3IPv4Addresses();
                            $interfacesv6 = $subinterface->getLayer3IPv6Addresses();
                            $sub_interfaces = array_merge($interfacesv4, $interfacesv6);

                            foreach( $sub_interfaces as $layer3IPAddress )
                            {
                                $findobject = $this->addressStore->find($layer3IPAddress);
                                if( is_object($findobject) )
                                    $findobject->addReference($subinterface);
                            }
                        }
                    }
                }
                elseif( $interface->isVlanType() || $interface->isLoopbackType() || $interface->isTunnelType() )
                {
                    $interfacesv4 = $interface->getIPv4Addresses();
                    $interfacesv6 = $interface->getIPv6Addresses();
                    $interfaces = array_merge($interfacesv4, $interfacesv6);
                }
                //elseif( $interface->isAggregateType() )
                //{}

                else
                    $interfaces = array();


                foreach( $interfaces as $layer3IPAddress )
                {
                    $findobject = $this->addressStore->find($layer3IPAddress);
                    if( is_object($findobject) )
                        $findobject->addReference($interface);
                }
            }
        }

        //
        // Extract Zone objects
        //
        $tmp = DH::findFirstElement('zone', $xml);
        if( $tmp !== FALSE )
            $this->zoneStore->load_from_domxml($tmp);
        // End of Zone objects extraction


        $this->rulebaseroot = DH::findFirstElement('rulebase', $xml);
        if( $this->rulebaseroot === FALSE )
            $this->rulebaseroot = null;

        if( ($this->owner->owner === null || get_class($this->owner) == "SharedGatewayStore") && $this->rulebaseroot !== null )
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
            // defaultSecurity Rules extraction
            //
            /*

            $tmproot = DH::findFirstElement('default-security-rules', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->defaultSecurityRules->load_from_domxml($tmprulesroot);
            }
            */
            $sub = new Sub();
            $sub->rulebaseroot = $this->rulebaseroot;
            $sub->defaultSecurityRules = $this->defaultSecurityRules;
            $tmprulesroot = $sub->load_defaultSecurityRule( );
            if( $tmprulesroot !== FALSE )
                $this->defaultSecurityRules->load_from_domxml( $tmprulesroot);

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

        //
        // Extract Certificate objects
        //
        $tmp = DH::findFirstElement('certificate', $xml);
        if( $tmp !== FALSE )
        {
            $this->certificateStore->load_from_domxml($tmp);
        }
        // End of Certificate objects extraction

        //
        // Extract GlobalProtect objects
        //
        $tmp_globalprotect = DH::findFirstElement('global-protect', $xml);
        if( $tmp_globalprotect !== FALSE )
        {
            //
            // Extract GP Gateway objects
            //
            $tmp = DH::findFirstElement('global-protect-gateway', $tmp_globalprotect);
            if( $tmp !== FALSE )
                $this->GPGatewayStore->load_from_domxml($tmp);


            //
            // Extract GP Portal objects
            //
            $tmp = DH::findFirstElement('global-protect-portal', $tmp_globalprotect);
            if( $tmp !== FALSE )
                $this->GPPortalStore->load_from_domxml($tmp);
        }
        // End of GlobalProtect objects extraction


    }

    public function &getXPath()
    {
        $str = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $this->name . "']";

        return $str;
    }


    public function display_statistics()
    {
        $stdoutarray = array();

        $stdoutarray['type'] = get_class( $this );

        $header = "Statistics for VSYS '" . PH::boldText($this->name) . "' | '" . $this->toString() . "'";
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

        $stdoutarray['tunnel-inspection rules'] = $this->tunnelInspectionRules->count();
        $stdoutarray['default-security rules'] = $this->defaultSecurityRules->count();
        $stdoutarray['network-packet-broker rules'] = $this->networkPacketBrokerRules->count();
        $stdoutarray['sdwan rules'] = $this->sdWanRules->count();


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

        $stdoutarray['Anti-Spyware objects'] = array();
        $stdoutarray['Anti-Spyware objects']['total'] = $this->AntiSpywareProfileStore->count();
        $stdoutarray['Vulnerability objects'] = array();
        $stdoutarray['Vulnerability objects']['total'] = $this->VulnerabilityProfileStore->count();
        $stdoutarray['Antivirus objects'] = array();
        $stdoutarray['Antivirus objects']['total'] = $this->AntiVirusProfileStore->count();
        $stdoutarray['Wildfire objects'] = array();
        $stdoutarray['Wildfire objects']['total'] = $this->WildfireProfileStore->count();
        $stdoutarray['URL objects'] = array();
        $stdoutarray['URL objects']['total'] = $this->URLProfileStore->count();
        $stdoutarray['custom URL objects'] = array();
        $stdoutarray['custom URL objects']['total'] = $this->customURLProfileStore->count();
        $stdoutarray['File-Blocking objects'] = array();
        $stdoutarray['File-Blocking objects']['total'] = $this->FileBlockingProfileStore->count();
        $stdoutarray['Decryption objects'] = array();
        $stdoutarray['Decryption objects']['total'] = $this->DecryptionProfileStore->count();

        $stdoutarray['HipObject objects'] = array();
        $stdoutarray['HipObject objects']['total'] = $this->HipObjectsProfileStore->count();
        $stdoutarray['HipProfile objects'] = array();
        $stdoutarray['HipProfile objects']['total'] = $this->HipProfilesProfileStore->count();

        $stdoutarray['GTP objects'] = array();
        $stdoutarray['GTP objects']['total'] = $this->GTPProfileStore->count();
        $stdoutarray['SCEP objects'] = array();
        $stdoutarray['SCEP objects']['total'] = $this->SCEPProfileStore->count();
        $stdoutarray['PacketBroker objects'] = array();
        $stdoutarray['PacketBroker objects']['total'] = $this->PacketBrokerProfileStore->count();

        $stdoutarray['SDWanErrorCorrection objects'] = array();
        $stdoutarray['SDWanErrorCorrection objects']['total'] = $this->SDWanErrorCorrectionProfileStore->count();
        $stdoutarray['SDWanPathQuality objects'] = array();
        $stdoutarray['SDWanPathQuality objects']['total'] = $this->SDWanPathQualityProfileStore->count();
        $stdoutarray['SDWanSaasQuality objects'] = array();
        $stdoutarray['SDWanSaasQuality objects']['total'] = $this->SDWanSaasQualityProfileStore->count();
        $stdoutarray['SDWanTrafficDistribution objects'] = array();
        $stdoutarray['SDWanTrafficDistribution objects']['total'] = $this->SDWanTrafficDistributionProfileStore->count();

        $stdoutarray['DataObjects objects'] = array();
        $stdoutarray['DataObjects objects']['total'] = $this->DataObjectsProfileStore->count();


        $stdoutarray['zones'] = $this->zoneStore->count();
        $stdoutarray['apps'] = $this->appStore->count();


        #PH::$JSON_TMP[$this->name] = $stdoutarray;
        PH::$JSON_TMP[] = $stdoutarray;


        if( !PH::$shadow_json )
            PH::print_stdout( $stdoutarray, true );

    }


    public function display_bp_statistics()
    {
        $stdoutarray = array();

        $stdoutarray['type'] = get_class( $this );

        $header = "BP/Visibility Statistics for VSYS '" . PH::boldText($this->name) . "' | '" . $this->toString() . "'";
        $stdoutarray['header'] = $header;

        $stdoutarray['security rules'] = $this->securityRules->count();

        $stdoutarray['security rules allow'] = count( $this->securityRules->rules( "(action is.allow)" ) );
        $stdoutarray['security rules disabled'] = count( $this->securityRules->rules( "(rule is.disabled)" ) );
        $stdoutarray['security rules deny'] = count( $this->securityRules->rules( "!(action is.allow)" ) );
        $ruleForCalculation = $stdoutarray['security rules'] - $stdoutarray['security rules disabled'];

        //Logging
        $stdoutarray['log at end'] = count( $this->securityRules->rules( "(log at.end)" ) );
        $stdoutarray['log at end percentage'] = round(( $stdoutarray['log at end'] / $ruleForCalculation ) * 100, 0 );
        $stdoutarray['log at start'] = count( $this->securityRules->rules( "(log at.start)" ) );

        //Log Forwarding Profiles
        //Todo: what exactly need to be set? really only a logprof
        $stdoutarray['log prof set'] = count( $this->securityRules->rules( "(logprof is.set)" ) );
        $stdoutarray['log prof set percentage'] = round(( $stdoutarray['log prof set'] / $ruleForCalculation ) * 100, 0 );

        //Wildfire Analysis Profiles
        $filter_array = array('query' => "secprof has.from.query subquery1", 'subquery1' => "wf is.visibility" );
        $stdoutarray['wf visibility'] = count( $this->securityRules->rules( $filter_array ) );
        $stdoutarray['wf visibility percentage'] = round(( $stdoutarray['wf visibility'] / $ruleForCalculation ) * 100, 0 );
        $filter_array = array('query' => "secprof has.from.query subquery1", 'subquery1' => "wf is.best-practice" );
        $stdoutarray['wf best-practice'] = count( $this->securityRules->rules( $filter_array ) );
        $stdoutarray['wf best-practice percentage'] = round( ( $stdoutarray['wf best-practice'] / $ruleForCalculation ) * 100, 0 );

        //Zone Protection
        //Todo: no valid filter yet available - also how to filter? based on from and/or to zone??
        $stdoutarray['zone protection'] = "NOT available";

        // App-ID
        $stdoutarray['app id'] = count( $this->securityRules->rules( "!(app is.any)" ) );
        $stdoutarray['app id percentage'] = round( ( $stdoutarray['app id'] / $ruleForCalculation ) * 100, 0 );

        //User-ID
        $stdoutarray['user id'] = count( $this->securityRules->rules( "!(user is.any)" ) );
        $stdoutarray['user id percentage'] = round( ( $stdoutarray['user id'] / $ruleForCalculation ) * 100, 0 );

        //Service/Port
        $stdoutarray['service port'] = count( $this->securityRules->rules( "!(service is.any)" ) );
        $stdoutarray['service port percentage'] = round( ( $stdoutarray['service port'] / $ruleForCalculation ) * 100, 0 );

        //Antivirus Profiles
        $filter_array = array('query' => "secprof has.from.query subquery1", 'subquery1' => "av is.visibility" );
        $stdoutarray['av visibility'] = count( $this->securityRules->rules( $filter_array ) );
        $stdoutarray['av visibility percentage'] = round( ( $stdoutarray['av visibility'] / $ruleForCalculation ) * 100, 0 );
        $filter_array = array('query' => "secprof has.from.query subquery1", 'subquery1' => "av is.best-practice" );
        $stdoutarray['av best-practice'] = count( $this->securityRules->rules( $filter_array ) );
        $stdoutarray['av best-practice percentage'] = round( ( $stdoutarray['av best-practice'] / $ruleForCalculation ) * 100, 0 );

        //Anti-Spyware Profiles
        $filter_array = array('query' => "secprof has.from.query subquery1", 'subquery1' => "as is.visibility" );
        $stdoutarray['as visibility'] = count( $this->securityRules->rules( $filter_array ) );
        $stdoutarray['as visibility percentage'] = round( ( $stdoutarray['as visibility'] / $ruleForCalculation ) * 100, 0 );
        $filter_array = array('query' => "secprof has.from.query subquery1", 'subquery1' => "as is.best-practice" );
        $stdoutarray['as best-practice'] = count( $this->securityRules->rules( $filter_array ) );
        $stdoutarray['as best-practice percentage'] = round( ( $stdoutarray['as best-practice'] / $ruleForCalculation ) * 100, 0 );

        //Vulnerability Profiles
        $filter_array = array('query' => "secprof has.from.query subquery1", 'subquery1' => "vp is.visibility" );
        $stdoutarray['vp visibility'] = count( $this->securityRules->rules( $filter_array ) );
        $stdoutarray['vp visibility percentage'] = round( ( $stdoutarray['vp visibility'] / $ruleForCalculation ) * 100, 0 );
        $filter_array = array('query' => "secprof has.from.query subquery1", 'subquery1' => "vp is.best-practice" );
        $stdoutarray['vp best-practice'] = count( $this->securityRules->rules( $filter_array ) );
        $stdoutarray['vp best-practice percentage'] = round( ( $stdoutarray['vp best-practice'] / $ruleForCalculation ) * 100, 0 );

        //File Blocking Profiles
        $filter_array = array('query' => "secprof has.from.query subquery1", 'subquery1' => "fb is.visibility" );
        $stdoutarray['fb visibility'] = count( $this->securityRules->rules( $filter_array ) );
        $stdoutarray['fb visibility percentage'] = round( ( $stdoutarray['fb visibility'] / $ruleForCalculation ) * 100, 0 );
        $filter_array = array('query' => "secprof has.from.query subquery1", 'subquery1' => "fb is.best-practice" );
        $stdoutarray['fb best-practice'] = count( $this->securityRules->rules( $filter_array ) );
        $stdoutarray['fb best-practice percentage'] = round( ( $stdoutarray['fb best-practice'] / $ruleForCalculation ) * 100, 0 );

        //Data Filtering
        //Todo
        $stdoutarray['data visibility'] = "NOT available";
        $stdoutarray['data best-practice'] = "NOT available";

        //URL Filtering Profiles
        //Todo; separation needed
        $filter_array = array('query' => "secprof has.from.query subquery1", 'subquery1' => "url-site-access is.visibility" );
        $stdoutarray['url-site-access visibility'] = count( $this->securityRules->rules( $filter_array ) );
        $stdoutarray['url-site-access visibility percentage'] = round( ( $stdoutarray['url-site-access visibility'] / $ruleForCalculation ) * 100, 0 );
        $filter_array = array('query' => "secprof has.from.query subquery1", 'subquery1' => "url-site-access is.best-practice" );
        $stdoutarray['url-site-access best-practice'] = count( $this->securityRules->rules( $filter_array ) );
        $stdoutarray['url-site-access best-practice percentage'] = round( ( $stdoutarray['url-site-access best-practice'] / $ruleForCalculation ) * 100, 0 );

        //Credential Theft Prevention
        //Todo: no valid filter yet available
        $filter_array = array('query' => "secprof has.from.query subquery1", 'subquery1' => "url-credential is.visibility" );
        $stdoutarray['url-credential visibility'] = count( $this->securityRules->rules( $filter_array ) );
        $stdoutarray['url-credential visibility percentage'] = round( ( $stdoutarray['url-credential visibility'] / $ruleForCalculation ) * 100, 0 );
        $filter_array = array('query' => "secprof has.from.query subquery1", 'subquery1' => "url-credential is.best-practice" );
        $stdoutarray['url-credential best-practice'] = count( $this->securityRules->rules( $filter_array ) );
        $stdoutarray['url-credential best-practice percentage'] = round( ( $stdoutarray['url-credential best-practice'] / $ruleForCalculation ) * 100, 0 );

        //DNS Security
        $filter_array = array('query' => "secprof has.from.query subquery1", 'subquery1' => "dns-list is.visibility" );
        $stdoutarray['dns-list visibility'] = count( $this->securityRules->rules( $filter_array ) );
        $stdoutarray['dns-list visibility percentage'] = round( ( $stdoutarray['dns-list visibility'] / $ruleForCalculation ) * 100, 0 );
        $filter_array = array('query' => "secprof has.from.query subquery1", 'subquery1' => "dns-list is.best-practice" );
        $stdoutarray['dns-list best-practice'] = count( $this->securityRules->rules( $filter_array ) );
        $stdoutarray['dns-list best-practice percentage'] = round( ( $stdoutarray['dns-list best-practice'] / $ruleForCalculation ) * 100, 0 );


        $percentageArray = array();
        $percentageArray_visibility = array();
        $percentageArray_visibility['log at end'] = $stdoutarray['log at end percentage'];
        $percentageArray_visibility['log prof set'] = $stdoutarray['log prof set percentage'];
        $percentageArray_visibility['app id'] = $stdoutarray['app id percentage'];
        $percentageArray_visibility['user id'] = $stdoutarray['user id percentage'];
        $percentageArray_visibility['service port'] = $stdoutarray['service port percentage'];

        $percentageArray_visibility['av'] = $stdoutarray['av visibility percentage'];
        $percentageArray_visibility['as'] = $stdoutarray['as visibility percentage'];
        $percentageArray_visibility['vp'] = $stdoutarray['vp visibility percentage'];
        $percentageArray_visibility['fb'] = $stdoutarray['fb visibility percentage'];
        $percentageArray_visibility['url-site-access'] = $stdoutarray['url-site-access visibility percentage'];
        $percentageArray_visibility['url-credential'] = $stdoutarray['url-credential visibility percentage'];
        $percentageArray_visibility['dns-list'] = $stdoutarray['dns-list visibility percentage'];
        $percentageArray_visibility['wf'] = $stdoutarray['wf visibility percentage'];
        $percentageArray['visibility'] = $percentageArray_visibility;

        $percentageArray_best_practice = array();
        $percentageArray_best_practice['log at end'] = $stdoutarray['log at end percentage'];
        $percentageArray_best_practice['log prof set'] = $stdoutarray['log prof set percentage'];
        $percentageArray_best_practice['app id'] = $stdoutarray['app id percentage'];
        $percentageArray_best_practice['user id'] = $stdoutarray['user id percentage'];
        $percentageArray_best_practice['service port'] = $stdoutarray['service port percentage'];

        $percentageArray_best_practice['av'] = $stdoutarray['av best-practice percentage'];
        $percentageArray_best_practice['as'] = $stdoutarray['as best-practice percentage'];
        $percentageArray_best_practice['vp'] = $stdoutarray['vp best-practice percentage'];
        $percentageArray_best_practice['fb'] = $stdoutarray['fb best-practice percentage'];
        $percentageArray_best_practice['url-site-access'] = $stdoutarray['url-site-access best-practice percentage'];
        $percentageArray_best_practice['url-credential'] = $stdoutarray['url-credential best-practice percentage'];
        $percentageArray_best_practice['dns-list'] = $stdoutarray['dns-list best-practice percentage'];
        $percentageArray_best_practice['wf'] = $stdoutarray['wf best-practice percentage'];
        $percentageArray['best-practice'] = $percentageArray_best_practice;

        $stdoutarray['percentage'] = $percentageArray;

        #PH::$JSON_TMP[$this->name] = $stdoutarray;
        PH::$JSON_TMP[] = $stdoutarray;


        if( !PH::$shadow_json )
            PH::print_stdout( $stdoutarray, true );

    }

    public function isVirtualSystem()
    {
        return TRUE;
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

    public function setVisibleVsys( $newVisibleVsys )
    {
        if( !isset( $this->importedVisibleVsys[$newVisibleVsys] ) )
        {
            $importroot = DH::findFirstElement('import', $this->xmlroot);
            if( $importroot !== FALSE ) {
                $visibleVsysnode = DH::findFirstElementOrCreate('visible-vsys', $importroot);

                //create new DomNode
                //add new Domnode
                $tmp = DH::createElement($visibleVsysnode, "member");
                $tmp->textContent = $newVisibleVsys;
            }
        }
    }

    static public $templateXml = '<entry name="temporarynamechangemeplease"><address/><address-group/><service/><service-group/><rulebase></rulebase></entry>';

}
